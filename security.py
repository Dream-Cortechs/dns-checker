"""
DNS CHECKER — Security Audit Module
DNSSEC · TLS Certificates · HTTP Security Headers · CAA
Cortechs © 2026
"""

import socket
import ssl
import urllib.request
import urllib.error
import concurrent.futures
import json
from datetime import datetime
from collections import defaultdict

from dns_engine import DNSEngine


# ═══════════════════════════════════════════════════════════════════════════════
# DNSSEC
# ═══════════════════════════════════════════════════════════════════════════════

def check_dnssec(domain: str, timeout: int = 6) -> dict:
    """Vérifie si le domaine est signé DNSSEC et retourne les détails."""
    result = {
        "domain": domain,
        "signed": False,
        "dnskeys": [],
        "rrsig_present": False,
        "algorithms": [],
        "details": [],
        "error": None
    }
    
    # 1. Query DNSKEY
    r = DNSEngine.query(domain, "DNSKEY", timeout=timeout)
    if r["records"]:
        result["signed"] = True
        result["dnskeys"] = r["records"]
        
        # Parse algorithm from DNSKEY records
        algo_names = {
            5: "RSA/SHA-1 (faible)", 7: "RSASHA1-NSEC3-SHA1 (faible)",
            8: "RSA/SHA-256", 10: "RSA/SHA-512",
            13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
            15: "Ed25519", 16: "Ed448"
        }
        for rec in r["records"]:
            try:
                parts = rec.split()
                algo = int(parts[2])
                result["algorithms"].append(algo_names.get(algo, f"Algo {algo}"))
            except:
                pass
    
    # 2. Check RRSIG for SOA (indicates zone is fully signed)
    r = DNSEngine.query(domain, "SOA", timeout=timeout)
    # RRSIGs are returned automatically when DO=1 but dnspython might not set it.
    # Let's query explicitly with dnssec flags
    try:
        import dns.resolver, dns.rdatatype
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout; resolver.lifetime = timeout
        ans = resolver.resolve(domain, dns.rdatatype.SOA, raise_on_no_answer=False)
        result["rrsig_present"] = bool(ans.response.find_rrset(
            ans.response.authority, dns.name.from_text(domain),
            dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.SOA
        ) if ans.response.authority else False)
    except:
        pass
    
    # 3. Check DS at parent (simplified — just note if DNSKEY exists)
    if result["signed"]:
        result["details"].append("DNSSEC active — le domaine possede des enregistrements DNSKEY")
        if result["rrsig_present"]:
            result["details"].append("RRSIG detecte — la zone est probablement signee completement")
        if result["algorithms"]:
            algos = ", ".join(set(result["algorithms"]))
            result["details"].append(f"Algorithmes: {algos}")
    else:
        result["details"].append("DNSSEC non configure — le domaine n'est pas signe")
        result["details"].append("Risque: usurpation DNS possible (cache poisoning)")
        result["details"].append("Recommandation: activer DNSSEC chez le registrar")
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# CAA — Certification Authority Authorization
# ═══════════════════════════════════════════════════════════════════════════════

def check_caa(domain: str, timeout: int = 5) -> dict:
    """Vérifie les enregistrements CAA."""
    r = DNSEngine.query(domain, "CAA", timeout=timeout)
    result = {"domain": domain, "has_caa": bool(r["records"]), "records": r["records"], "issuers": [], "analysis": []}
    
    for rec in r["records"]:
        # Format: 0 issue "letsencrypt.org"
        parts = rec.split()
        if len(parts) >= 3:
            tag = parts[1]
            value = " ".join(parts[2:]).strip('"')
            if tag == "issue":
                result["issuers"].append(value)
    
    if result["has_caa"]:
        result["analysis"].append(f"CAA configure — {len(result['issuers'])} autorite(s) autorisee(s)")
        for issuer in result["issuers"]:
            result["analysis"].append(f"  → {issuer}")
    else:
        result["analysis"].append("CAA absent — toute autorite de certification peut emettre des certificats")
        result["analysis"].append("Recommandation: ajouter un enregistrement CAA (ex: letsencrypt.org)")
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# TLS Certificate Scanner
# ═══════════════════════════════════════════════════════════════════════════════

def _get_cert(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    """Récupère le certificat TLS d'un hôte."""
    result = {
        "hostname": hostname,
        "error": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_left": None,
        "sans": [],
        "version": None,
        "tls_ok": False
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection((hostname, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            result["tls_ok"] = True
            result["version"] = ssock.version()
            
            if cert:
                # Subject
                for field in cert.get("subject", []):
                    for key, val in field:
                        if key == "commonName":
                            result["subject"] = val
                
                # Issuer
                for field in cert.get("issuer", []):
                    for key, val in field:
                        if key == "commonName":
                            result["issuer"] = val
                
                # Dates
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                if not_after:
                    result["not_before"] = not_before
                    result["not_after"] = not_after
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result["days_left"] = (expiry - datetime.now()).days
                    except:
                        try:
                            expiry = datetime.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
                            result["days_left"] = (expiry - datetime.now()).days
                        except:
                            pass
                
                # SANs
                for field in cert.get("subjectAltName", []):
                    result["sans"].append(field[1])
    
    except ssl.SSLError as e:
        result["error"] = f"SSL: {str(e)[:80]}"
    except socket.timeout:
        result["error"] = "Timeout"
    except socket.gaierror:
        result["error"] = "DNS non resolu"
    except ConnectionRefusedError:
        result["error"] = "Connexion refusee (pas de HTTPS ?)"
    except Exception as e:
        result["error"] = str(e)[:80]
    
    return result


def scan_tls(domain: str, subdomains: list = None, timeout: int = 8) -> dict:
    """Scanner TLS cert pour le domaine et ses sous-domaines."""
    results = {
        "domain": domain,
        "certificates": {},
        "total": 0,
        "expiring_soon": [],
        "errors": [],
        "summary": {}
    }
    
    targets = [domain]
    if subdomains:
        targets += subdomains
    
    # Deduplicate
    targets = list(set(targets))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_get_cert, t, 443, timeout): t for t in targets}
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result(timeout=timeout + 3)
                host = r["hostname"]
                if r["error"]:
                    results["errors"].append({"host": host, "error": r["error"]})
                else:
                    results["certificates"][host] = r
                    results["total"] += 1
                    if r.get("days_left") is not None:
                        if r["days_left"] <= 30:
                            results["expiring_soon"].append({
                                "host": host,
                                "days_left": r["days_left"],
                                "not_after": r["not_after"]
                            })
            except:
                pass
    
    # Summary
    expired = sum(1 for c in results["certificates"].values() if c.get("days_left") is not None and c["days_left"] <= 0)
    within_30 = sum(1 for c in results["certificates"].values() if c.get("days_left") is not None and 0 < c["days_left"] <= 30)
    within_90 = sum(1 for c in results["certificates"].values() if c.get("days_left") is not None and 30 < c["days_left"] <= 90)
    ok = results["total"] - expired - within_30 - within_90
    
    results["summary"] = {
        "total_tls_hosts": results["total"],
        "error_hosts": len(results["errors"]),
        "expired": expired,
        "expiring_30d": within_30,
        "expiring_90d": within_90,
        "ok": ok
    }
    
    # Audit flags
    results["flags"] = []
    if expired:
        results["flags"].append(f"CRITIQUE: {expired} certificat(s) expire(s)")
    if within_30:
        results["flags"].append(f"URGENT: {within_30} certificat(s) expire(nt) dans moins de 30 jours")
    if within_90:
        results["flags"].append(f"ATTENTION: {within_90} certificat(s) expire(nt) dans moins de 90 jours")
    if results["errors"]:
        results["flags"].append(f"{len(results['errors'])} hote(s) sans HTTPS detecte")
    
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP Security Headers
# ═══════════════════════════════════════════════════════════════════════════════

def check_http_headers(url: str, timeout: int = 8) -> dict:
    """Vérifie les en-têtes de sécurité HTTP."""
    result = {
        "url": url,
        "error": None,
        "status_code": None,
        "headers": {},
        "checks": {},
        "score": 0,
        "max_score": 6
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={"User-Agent": "dns-checker-cortechs"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            result["headers"] = dict(resp.headers)
    except urllib.error.URLError as e:
        result["error"] = f"URL: {str(e.reason)[:60]}"
        return result
    except Exception as e:
        result["error"] = str(e)[:80]
        return result
    
    headers = result["headers"]
    
    # HSTS
    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        max_age = "unknown"
        include_sub = "non"
        if "max-age=" in hsts:
            try:
                max_age = hsts.split("max-age=")[1].split(";")[0].strip()
                max_age = f"{int(max_age)//86400} jours"
            except: pass
        if "includeSubDomains" in hsts:
            include_sub = "oui"
        result["checks"]["HSTS"] = {"ok": True, "value": hsts, "detail": f"present ({max_age}, includeSubDomains: {include_sub})"}
        result["score"] += 1
    else:
        result["checks"]["HSTS"] = {"ok": False, "value": "", "detail": "Absent — HSTS non configure"}
    
    # CSP
    csp = headers.get("Content-Security-Policy", "")
    result["checks"]["CSP"] = {"ok": bool(csp), "value": csp[:120],
        "detail": "present" if csp else "Absent — CSP aide a prevenir les attaques XSS"}
    if csp: result["score"] += 1
    
    # X-Frame-Options
    xfo = headers.get("X-Frame-Options", "")
    result["checks"]["X-Frame-Options"] = {"ok": bool(xfo), "value": xfo,
        "detail": xfo if xfo else "Absent — risque de clickjacking"}
    if xfo: result["score"] += 1
    
    # X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options", "")
    result["checks"]["X-Content-Type-Options"] = {"ok": xcto == "nosniff", "value": xcto,
        "detail": "nosniff" if xcto == "nosniff" else "Absent ou incorrect"}
    if xcto == "nosniff": result["score"] += 1
    
    # Referrer-Policy
    rp = headers.get("Referrer-Policy", "")
    result["checks"]["Referrer-Policy"] = {"ok": bool(rp), "value": rp,
        "detail": rp if rp else "Absent — fuite d'information possible via Referer"}
    if rp: result["score"] += 1
    
    # Permissions-Policy
    pp = headers.get("Permissions-Policy", "")
    result["checks"]["Permissions-Policy"] = {"ok": bool(pp), "value": pp[:120] if pp else "",
        "detail": "present" if pp else "Absent — controle des API navigateur"}
    if pp: result["score"] += 1
    
    return result


def run_security_audit(domain: str, subdomains: list = None) -> dict:
    """Audit de sécurité complet: DNSSEC + TLS + HTTP Headers + CAA."""
    results = {"domain": domain}
    
    # DNSSEC
    results["dnssec"] = check_dnssec(domain)
    
    # CAA
    results["caa"] = check_caa(domain)
    
    # HTTP Headers (root domain)
    results["http_headers"] = check_http_headers(f"https://{domain}")
    
    # TLS scan (domain + subdomains)
    subs = subdomains if subdomains else []
    results["tls"] = scan_tls(domain, subs)
    
    return results
