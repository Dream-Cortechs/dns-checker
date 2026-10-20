"""
Services : adaptateurs entre l'API et le moteur (core/).

Règle du portage : le moteur v1 n'est PAS réécrit. On traduit seulement les clés
et on ajoute la progression (job.step) pour que le front puisse afficher où en
est un scan long.
"""

import ipaddress
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from core.blacklist import check_blacklists
from core.dns_engine import (DNS_BLACKLISTS, GLOBAL_RESOLVERS, RECORD_TYPES,
                             DNSEngine)
from core.report import generate_report_pdf
from core.security import (check_caa, check_dnssec, check_http_headers,
                           run_security_audit, scan_tls)
from core.subdomains import discover_subdomains
from core.whois_geo import get_geoip, get_whois, resolve_and_geo

from . import settings

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)


class InvalidInput(ValueError):
    """Entrée refusée avant tout appel réseau."""


def normalise_domain(value: str) -> str:
    """Nettoie et valide un nom de domaine. Accepte « https://x.fr/ » et « x.fr. »."""
    if not value:
        raise InvalidInput("Domaine manquant")
    d = value.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split("?")[0]
    d = d.split(":")[0].rstrip(".")
    if not DOMAIN_RE.match(d):
        raise InvalidInput("Nom de domaine invalide : %s" % value.strip()[:60])
    return d


def normalise_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise InvalidInput("Adresse IP invalide : %s" % (value or "")[:40])


def meta() -> dict:
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "record_types": RECORD_TYPES,
        "resolvers": GLOBAL_RESOLVERS,
        "blacklists": DNS_BLACKLISTS,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────── Écran 1 : enregistrements ───────────────────────────
def lookup(domain: str, record_type: str = "A", resolver: str = "") -> dict:
    d = normalise_domain(domain)
    rtype = (record_type or "A").upper().strip()
    if rtype not in RECORD_TYPES:
        raise InvalidInput("Type d'enregistrement inconnu : %s" % rtype)
    res = DNSEngine.query(d, rtype, resolver or None)
    return {"domain": d, "type": rtype, "resolver": res.get("resolver"),
            "records": res.get("records", []), "count": res.get("count", 0),
            "error": res.get("error")}


# ─────────────────────────── Écran 2 : sécurité email ───────────────────────────
def email_check(domain: str, selector: str = "default") -> dict:
    d = normalise_domain(domain)
    selector = (selector or "default").strip() or "default"
    mx = DNSEngine.query_mx(d)
    spf = DNSEngine.check_spf(d)
    dkim = DNSEngine.check_dkim(d, selector)
    dmarc = DNSEngine.check_dmarc(d)

    criteres = {
        "mx": {"ok": bool(mx["mx_records"]), "detail": "%d serveur(s) MX" % len(mx["mx_records"])},
        "spf": {"ok": bool(spf["has_spf"] and spf["all_mechanism"]),
                "detail": "SPF présent" if spf["has_spf"] else "SPF absent"},
        "dkim": {"ok": bool(dkim["has_dkim"]),
                 "detail": "DKIM signé (sélecteur %s)" % selector if dkim["has_dkim"]
                 else "DKIM absent (sélecteur %s)" % selector},
        "dmarc": {"ok": bool(dmarc["has_dmarc"]),
                  "detail": dmarc["policy"] or "DMARC absent"},
    }
    score = sum(1 for c in criteres.values() if c["ok"])
    return {
        "domain": d,
        "selector": selector,
        "score": score,
        "max_score": 4,
        "criteria": criteres,
        "mx": {"servers": ["P%s %s" % (p, h) for p, h in mx["mx_records"][:10]]},
        "spf": {"present": spf["has_spf"], "records": spf["spf_records"],
                "mechanism": ("Hard Fail (-all)" if spf["all_mechanism"]
                              else "Soft Fail (~all)" if spf["soft_all"] else "Aucun")},
        "dkim": {"present": dkim["has_dkim"], "selector": selector},
        "dmarc": {"present": dmarc["has_dmarc"], "policy": dmarc["policy"],
                  "records": dmarc["dmarc_records"]},
    }


# ─────────────────────────── Écran 3 : WHOIS ───────────────────────────
def whois(domain: str) -> dict:
    d = normalise_domain(domain)
    info = get_whois(d, timeout=15)
    # le champ brut est long : on ne renvoie que les 4000 premiers caractères
    if info.get("raw"):
        info["raw"] = info["raw"][:4000]
    return info


# ─────────────────────────── Écran 4 : Géolocalisation ───────────────────────────
def geo(target: str) -> dict:
    t = (target or "").strip()
    if not t:
        raise InvalidInput("Cible manquante")
    try:
        ip = normalise_ip(t)
        g = get_geoip(ip)
        return {"target": t, "ips": [{"ip": ip, "geo": g, "subdomains": []}]}
    except InvalidInput:
        d = normalise_domain(t)
        res = resolve_and_geo(d)
        return {"target": d, "ips": res.get("ips", [])}


# ─────────────────────────── Écran 5 : Blacklists ───────────────────────────
def blacklist(job, target: str) -> dict:
    t = (target or "").strip()
    job.step("Résolution de la cible", t)
    try:
        ip = normalise_ip(t)
    except InvalidInput:
        d = normalise_domain(t)
        found = DNSEngine.query(d, "A")
        if not found["records"]:
            raise InvalidInput("Impossible de résoudre %s en adresse IP" % d)
        ip = found["records"][0]
        job.step("Domaine résolu", "%s → %s" % (d, ip))
    job.running("Interrogation des %d listes" % len(DNS_BLACKLISTS))
    res = check_blacklists(ip, DNS_BLACKLISTS)
    job.step("Listes interrogées", "%d listée(s), %d à qualifier, %d en erreur"
             % (res["listed"], res["warnings"], res["errors"]))
    return res


# ─────────────────────────── Écran 6 : Propagation ───────────────────────────
def propagation(job, domain: str, record_type: str = "A") -> dict:
    import concurrent.futures

    d = normalise_domain(domain)
    rtype = (record_type or "A").upper().strip()
    if rtype not in RECORD_TYPES:
        raise InvalidInput("Type d'enregistrement inconnu : %s" % rtype)

    job.running("Interrogation de %d résolveurs" % len(GLOBAL_RESOLVERS))
    details = []
    consensus = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(DNSEngine.query, d, rtype, ip, 6): (name, ip)
                   for name, ip in GLOBAL_RESOLVERS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, ip_addr = futures[future]
            try:
                r = future.result(timeout=6)
            except Exception:
                r = {"records": [], "error": "Exception"}
            ok = r.get("error") is None and bool(r.get("records"))
            valeur = r["records"][0] if r.get("records") else (r.get("error") or "?")
            if ok:
                consensus[valeur] = consensus.get(valeur, 0) + 1
            details.append({"name": name, "ip": ip_addr, "result": valeur,
                            "ok": ok, "error": r.get("error")})

    total = len(GLOBAL_RESOLVERS)
    success = sum(1 for x in details if x["ok"])
    top = max(consensus, key=consensus.get, default="")
    details.sort(key=lambda x: (not x["ok"], x["name"]))
    job.step("Réponses collectées", "%d/%d résolveurs OK" % (success, total))
    return {
        "domain": d, "type": rtype, "total": total, "success": success,
        "consensus": top,
        "consensus_pct": round(consensus.get(top, 0) / total * 100) if consensus else 0,
        "details": details,
    }


# ─────────────────────────── Écran 7 : Sous-domaines ───────────────────────────
def subdomains(job, domain: str, bruteforce: bool = True, crtsh: bool = True) -> dict:
    d = normalise_domain(domain)
    if not bruteforce and not crtsh:
        raise InvalidInput("Choisissez au moins une méthode (brute-force ou crt.sh)")
    job.running("Découverte", "crt.sh=%s · brute-force=%s" % (crtsh, bruteforce))
    res = discover_subdomains(d, bruteforce=bruteforce, crtsh=crtsh, timeout=40)
    subs = res.get("subdomains") or {}
    job.step("Sous-domaines trouvés", "%d" % len(subs))
    return {"domain": d, "count": len(subs), "subdomains": subs,
            "sources": res.get("sources", {})}


# ─────────────────────────── Écran 8 : Audit sécurité ───────────────────────────
def security(job, domain: str, subdomains_list=None) -> dict:
    d = normalise_domain(domain)
    subs = [s for s in (subdomains_list or []) if s][:15]

    job.running("DNSSEC et CAA")
    dnssec = check_dnssec(d)
    caa = check_caa(d)

    job.running("En-têtes HTTP")
    headers = check_http_headers("https://" + d)

    job.running("Certificats TLS", "%d hôte(s)" % (len(subs) + 1))
    tls = scan_tls(d, subs)

    # ⚠️ tls["summary"] est un DICTIONNAIRE (total_tls_hosts, error_hosts, expired...).
    # Le renvoyer tel quel dans « detail » faisait planter le rendu React
    # (objet affiché comme enfant — erreur #31) : on en fait une phrase.
    resume = tls.get("summary") or {}
    if isinstance(resume, dict):
        detail_tls = "%s/%s hôte(s) valides" % (resume.get("ok", 0), resume.get("total_tls_hosts", 0))
        if resume.get("expiring_30d"):
            detail_tls += " · %s expire(nt) sous 30 j" % resume["expiring_30d"]
        if resume.get("error_hosts"):
            detail_tls += " · %s injoignable(s)" % resume["error_hosts"]
    else:
        detail_tls = str(resume)

    controle = {
        "dnssec": {"ok": bool(dnssec.get("signed")), "detail": "Zone signée" if dnssec.get("signed") else "Zone non signée"},
        "caa": {"ok": bool(caa.get("has_caa")), "detail": "%d enregistrement(s) CAA" % len(caa.get("records") or [])},
        "headers": {"ok": headers.get("score", 0) >= 4,
                    "detail": "%s/%s en-têtes de sécurité" % (headers.get("score"), headers.get("max_score"))},
        "tls": {"ok": not (tls.get("expiring_soon") or []), "detail": detail_tls},
    }
    job.step("Audit terminé", "%d/%d contrôles OK" % (sum(1 for c in controle.values() if c["ok"]), len(controle)))
    return {"domain": d, "dnssec": dnssec, "caa": caa, "http_headers": headers,
            "tls": tls, "criteria": controle,
            "score": sum(1 for c in controle.values() if c["ok"]), "max_score": len(controle)}


# ─────────────────────────── Écran 9 : Rapport PDF ───────────────────────────
def report(job, domain: str, ip: str = "") -> dict:
    d = normalise_domain(domain)
    ip_value = None
    if ip and ip.strip():
        ip_value = normalise_ip(ip)
    if not ip_value:
        a = DNSEngine.query(d, "A")
        if a.get("records"):
            ip_value = a["records"][0]
            job.step("Adresse IP du domaine", ip_value)
        else:
            job.step("Adresse IP du domaine", "non résolue — page blacklist ignorée", status="warn")

    job.running("Collecte des données", "DNS · propagation · email · WHOIS · sous-domaines · géo · sécurité")
    t0 = time.time()
    pdf = generate_report_pdf(d, ip_value)
    job.step("PDF généré", "%.1f ko en %.1f s" % (len(pdf) / 1024, time.time() - t0))

    token = secrets.token_urlsafe(16)
    name = "%s-%s.pdf" % (re.sub(r"[^a-z0-9.-]", "-", d),
                          datetime.now().strftime("%Y%m%d-%H%M"))
    path = Path(settings.CACHE_DIR) / ("%s.pdf" % token)
    path.write_bytes(pdf)
    _prune_reports()
    return {"domain": d, "ip": ip_value, "name": name, "size": len(pdf),
            "token": token, "url": "/api/report/%s/download" % token,
            "generated_at": datetime.now().strftime("%d/%m/%Y %H:%M")}


def _prune_reports() -> None:
    files = sorted(Path(settings.CACHE_DIR).glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[settings.REPORT_KEEP:]:
        try:
            old.unlink()
        except OSError:
            pass


def report_path(token: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,32}", token or ""):
        return None
    path = Path(settings.CACHE_DIR) / ("%s.pdf" % token)
    return path if path.exists() else None


# ─────────────────────────── Synthèse (accueil) ───────────────────────────
def summary(job, domain: str) -> dict:
    """Scan complet pour la vue d'ensemble : toutes les briques en un appel."""
    d = normalise_domain(domain)

    job.running("Enregistrements DNS")
    lookup_data = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "SOA"):
        r = DNSEngine.query(d, rtype)
        if r.get("records"):
            lookup_data[rtype.lower()] = r["records"]
    ip = (lookup_data.get("a") or [None])[0]
    job.step("Enregistrements lus", "%d types · IP %s" % (len(lookup_data), ip or "non résolue"))

    job.running("Propagation (24 résolveurs)")
    prop = propagation(job, d, "A")

    job.running("Sécurité email")
    mail = email_check(d)
    job.step("Email analysé", "score %d/4" % mail["score"])

    job.running("Sous-domaines")
    try:
        subs = subdomains(job, d, True, True)
    except Exception as exc:
        subs = {"count": 0, "subdomains": {}, "error": str(exc)}
        job.step("Sous-domaines", str(exc)[:80], status="warn")

    job.running("Géolocalisation")
    geo_ips = []
    try:
        seen = set()
        for fqdn, addresses in list((subs.get("subdomains") or {}).items())[:25]:
            for address in addresses:
                if address in seen or not re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
                    continue
                seen.add(address)
                infos = get_geoip(address)
                geo_ips.append({"ip": address, "geo": infos, "subdomains": [fqdn]})
    except Exception as exc:
        job.step("Géolocalisation partielle", str(exc)[:80], status="warn")

    job.running("Blacklists")
    bl = check_blacklists(ip, DNS_BLACKLISTS) if ip else None
    if bl:
        job.step("Blacklists", "%d listée(s), %d à qualifier" % (bl["listed"], bl["warnings"]))

    job.running("Audit sécurité")
    try:
        sec = security(job, d, list((subs.get("subdomains") or {}).keys())[:15])
    except Exception as exc:
        sec = None
        job.step("Audit sécurité", str(exc)[:80], status="warn")

    job.running("WHOIS")
    try:
        wh = get_whois(d, timeout=12)
        wh["raw"] = (wh.get("raw") or "")[:1200]
    except Exception:
        wh = None

    return {
        "domain": d,
        "ip": ip,
        "scanned_at": datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "lookup": lookup_data,
        "propagation": prop,
        "email": mail,
        "subdomains": {"count": subs.get("count", 0), "list": subs.get("subdomains", {})},
        "geo": {"count": len(geo_ips), "ips": geo_ips},
        "blacklist": bl,
        "security": sec,
        "whois": wh,
        "findings": findings(prop, mail, bl, sec),
    }


def findings(prop, mail, bl, sec):
    """Liste lisible des points à corriger, classés par gravité."""
    points = []
    if mail and mail["score"] < 4:
        for key, c in mail["criteria"].items():
            if not c["ok"]:
                points.append({"severity": "critique" if key in ("dkim", "dmarc") else "moyen",
                               "title": c["detail"], "detail": _conseil_email(key)})
    if bl and bl["listed"]:
        points.append({"severity": "moyen", "title": "%d blacklist(s) listent l'IP" % bl["listed"],
                       "detail": "Vérifier la réputation d'envoi et demander un retrait."})
    if bl and bl["warnings"]:
        points.append({"severity": "info",
                       "title": "%d signal(aux) de liste à qualifier" % bl["warnings"],
                       "detail": "Listage au niveau réseau (/24 ou AS) : pas un blocage de l'IP seule."})
    if sec:
        labels = {"dnssec": ("DNSSEC non activé", "Demander l'activation chez le registrar."),
                  "caa": ("CAA absent", "Restreindre les autorités de certification autorisées."),
                  "headers": None, "tls": None}
        for key, c in sec["criteria"].items():
            if c["ok"]:
                continue
            if key in labels and labels[key]:
                points.append({"severity": "moyen", "title": labels[key][0], "detail": labels[key][1]})
            elif key == "headers":
                points.append({"severity": "moyen", "title": "En-têtes HTTP incomplets",
                               "detail": c["detail"] + " — ajouter les en-têtes manquants côté serveur web."})
            elif key == "tls":
                points.append({"severity": "moyen", "title": "Certificats à surveiller", "detail": c["detail"]})
    if prop and prop["success"] < prop["total"]:
        manquants = [d["name"] for d in prop["details"] if not d["ok"]]
        points.append({"severity": "info",
                       "title": "Propagation %d/%d" % (prop["success"], prop["total"]),
                       "detail": "Sans réponse : " + ", ".join(manquants)})
    ordre = {"critique": 0, "moyen": 1, "info": 2}
    points.sort(key=lambda p: ordre.get(p["severity"], 3))
    return points


def _conseil_email(key):
    return {
        "mx": "Aucun serveur de messagerie déclaré : le domaine ne peut pas recevoir de mails.",
        "spf": "Publier un SPF avec -all pour empêcher l'usurpation de l'expéditeur.",
        "dkim": "Publier la clé publique DKIM du sélecteur utilisé par la messagerie.",
        "dmarc": "Publier une politique DMARC (p=quarantine ou p=reject) avec une adresse de rapport.",
    }.get(key, "")
