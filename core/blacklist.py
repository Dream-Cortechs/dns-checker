"""
Blacklists DNS — vérification d'une IP sur les listes anti-spam.

Correctif par rapport à la v1 : un code de retour 127.255.255.x signifie
« requête refusée / erreur » (liste surchargée, interrogation bloquée, faute de
frappe) et NON « IP listée ». La v1 comptait ces réponses comme des listings,
ce qui affichait de faux positifs (constaté sur cortechs.fr : CBL renvoyait
127.255.255.254). Les codes 127.0.0.2 / 127.0.0.3 d'UCEPROTECT désignent un
listage au niveau du réseau (/24) ou du système autonome, pas de l'IP seule :
ils sont remontés comme « à qualifier », jamais comme un blocage individuel.
"""

import concurrent.futures
import re

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# statuts possibles
LISTEE = "listee"                 # l'IP elle-même est listée
RESEAU = "listee_reseau"          # le /24 ou l'AS est listé (UCEPROTECT L2/L3)
PROPRE = "propre"
ERREUR = "erreur"                 # requête refusée / réponse technique
INCONNU = "inconnu"               # timeout / pas de réponse

# UCEPROTECT : 127.0.0.2 = niveau /24, 127.0.0.3 = niveau AS
_RESEAU_CODES = {127: "127.0.0.2", 126: "127.0.0.3"}


def _classify(answer: str, zone: str) -> tuple:
    """Traduit une réponse DNS de blacklist en (statut, détail lisible)."""
    if answer.startswith("127.255.255."):
        return ERREUR, ("Requête refusée par la liste (code %s) — pas un listage : "
                        "à réessayer plus tard" % answer)
    if answer in ("127.0.0.2", "127.0.0.3") and "uceprotect" in zone:
        niveau = "/24 (tout le réseau)" if answer == "127.0.0.2" else "AS (tout l'opérateur)"
        return RESEAU, ("Réseau listé au niveau %s par politique — l'IP seule n'est pas "
                        "bloquée, mais des mails peuvent l'être" % niveau)
    return LISTEE, "IP listée (code %s)" % answer


def check_blacklists(ip: str, blacklists: dict, timeout: int = 4, max_workers: int = 12) -> dict:
    """Interroge chaque blacklist en parallèle. Retourne un dict prêt pour l'API."""
    if not IP_RE.match(ip or ""):
        return {"ip": ip, "error": "Adresse IP invalide", "total": 0, "listed": 0,
                "warnings": 0, "unknown": 0, "details": []}
    if not HAS_DNSPYTHON:
        return {"ip": ip, "error": "dnspython non installé", "total": len(blacklists),
                "listed": 0, "warnings": 0, "unknown": 0, "details": []}

    reversed_ip = ".".join(reversed(ip.split(".")))

    def query(item):
        name, zone = item
        entry = {"name": name, "zone": zone, "status": INCONNU, "code": None,
                 "detail": "Pas de réponse (timeout)", "query": "%s.%s" % (reversed_ip, zone)}
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            ans = resolver.resolve(entry["query"], "A")
            code = str(ans[0])
            entry["code"] = code
            entry["status"], entry["detail"] = _classify(code, zone)
        except dns.resolver.NXDOMAIN:
            entry["status"], entry["detail"] = PROPRE, "Non listée"
        except dns.resolver.NoNameservers:
            entry["status"], entry["detail"] = ERREUR, "Serveur de la liste injoignable"
        except Exception as exc:  # timeout, no answer, etc.
            entry["status"], entry["detail"] = INCONNU, "Pas de réponse (%s)" % type(exc).__name__
        return entry

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        details = list(pool.map(query, blacklists.items()))

    ordre = {LISTEE: 0, RESEAU: 1, ERREUR: 2, INCONNU: 3, PROPRE: 4}
    details.sort(key=lambda d: (ordre[d["status"]], d["name"]))
    return {
        "ip": ip,
        "total": len(details),
        "listed": sum(1 for d in details if d["status"] == LISTEE),
        "warnings": sum(1 for d in details if d["status"] == RESEAU),
        "errors": sum(1 for d in details if d["status"] == ERREUR),
        "unknown": sum(1 for d in details if d["status"] == INCONNU),
        "clean": sum(1 for d in details if d["status"] == PROPRE),
        "details": details,
    }
