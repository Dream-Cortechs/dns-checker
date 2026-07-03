"""
DNS ENGINE — Moteur de requêtes DNS (sans GUI)
Utilisé par l'app Streamlit et l'app tkinter
Cortechs © 2026
"""

import concurrent.futures
from collections import defaultdict

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "ANY"]

# Résolveurs publics mondiaux pour le test de propagation
GLOBAL_RESOLVERS = {
    "Google 🇺🇸": "8.8.8.8",
    "Google (alt) 🇺🇸": "8.8.4.4",
    "Cloudflare 🇺🇸": "1.1.1.1",
    "Cloudflare (alt) 🇺🇸": "1.0.0.1",
    "Quad9 🇺🇸": "9.9.9.9",
    "OpenDNS 🇺🇸": "208.67.222.222",
    "OpenDNS (alt) 🇺🇸": "208.67.220.220",
    "Level3 🇺🇸": "4.2.2.2",
    "Verisign 🇺🇸": "64.6.64.6",
    "Norton 🇺🇸": "199.85.126.10",
    "Neustar 🇺🇸": "156.154.70.1",
    "Dyn 🇺🇸": "216.146.35.35",
    "Quad9 🇨🇭": "149.112.112.112",
    "AdGuard 🇩🇪": "94.140.14.14",
    "DNS.WATCH 🇩🇪": "84.200.69.80",
    "Freenom 🇫🇷": "80.80.80.80",
    "Freenom (alt) 🇫🇷": "80.80.81.81",
    "FDN 🇫🇷": "80.67.169.12",
    "CensurfriDNS 🇩🇪": "91.239.100.100",
    "UncensoredDNS 🇩🇰": "91.239.100.100",
    "Comodo 🇭🇰": "8.26.56.26",
    "Yandex 🇷🇺": "77.88.8.8",
    "AliDNS 🇨🇳": "223.5.5.5",
    "CleanBrowsing 🇬🇧": "185.228.168.9",
    "SafeDNS 🇺🇸": "195.46.39.39",
    "Alternate DNS 🇨🇭": "76.76.19.19",
    "OpenNIC 🇺🇸": "192.71.245.208",
}

DNS_BLACKLISTS = {
    "Spamhaus ZEN": "zen.spamhaus.org",
    "Barracuda": "b.barracudacentral.org",
    "SpamCop": "bl.spamcop.net",
    "SORBS": "dnsbl.sorbs.net",
    "SURBL": "multi.surbl.org",
    "CBL (AbuseAt)": "cbl.abuseat.org",
    "UCEPROTECT L1": "dnsbl-1.uceprotect.net",
    "UCEPROTECT L2": "dnsbl-2.uceprotect.net",
    "UCEPROTECT L3": "dnsbl-3.uceprotect.net",
    "PSBL": "psbl.surriel.com",
    "JustSpam": "dnsbl.justspam.org",
    "WPBL": "db.wpbl.info",
}


class DNSEngine:
    """Moteur de requêtes DNS avec dnspython."""

    @staticmethod
    def query(domain: str, record_type: str, resolver_ip: str = None, timeout: int = 5) -> dict:
        if not HAS_DNSPYTHON:
            return {"error": "dnspython non installé", "records": []}
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            if resolver_ip:
                resolver.nameservers = [resolver_ip]
            answers = resolver.resolve(domain, record_type)
            records = [str(ans) for ans in answers]
            return {"records": records, "count": len(records), "resolver": resolver_ip or "Système", "error": None}
        except dns.resolver.NoAnswer:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système", "error": "Pas de réponse"}
        except dns.resolver.NXDOMAIN:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système", "error": "Domaine inexistant"}
        except dns.resolver.Timeout:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système", "error": "Timeout"}
        except dns.resolver.NoNameservers:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système", "error": "Pas de nameserver"}
        except Exception as e:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système", "error": str(e)}

    @staticmethod
    def query_mx(domain: str, resolver_ip: str = None) -> dict:
        result = DNSEngine.query(domain, "MX", resolver_ip)
        if result["records"]:
            parsed = []
            for rec in result["records"]:
                parts = rec.split()
                if len(parts) >= 2:
                    parsed.append((int(parts[0]), " ".join(parts[1:])))
            result["mx_records"] = sorted(parsed, key=lambda x: x[0])
        else:
            result["mx_records"] = []
        return result

    @staticmethod
    def check_spf(domain: str, resolver_ip: str = None) -> dict:
        result = DNSEngine.query(domain, "TXT", resolver_ip)
        spf_records = [rec.strip('"') for rec in result.get("records", []) if "v=spf1" in rec.lower()]
        return {
            "has_spf": len(spf_records) > 0,
            "spf_records": spf_records,
            "all_mechanism": any("-all" in r for r in spf_records),
            "soft_all": any("~all" in r for r in spf_records),
            "neutral_all": any("?all" in r for r in spf_records),
        }

    @staticmethod
    def check_dkim(domain: str, selector: str = "default", resolver_ip: str = None) -> dict:
        dkim_domain = f"{selector}._domainkey.{domain}"
        result = DNSEngine.query(dkim_domain, "TXT", resolver_ip)
        dkim_records = [rec.strip('"') for rec in result.get("records", []) if "v=DKIM1" in rec or "k=rsa" in rec]
        return {"selector": selector, "has_dkim": len(dkim_records) > 0, "dkim_records": dkim_records, "domain": dkim_domain}

    @staticmethod
    def check_dmarc(domain: str, resolver_ip: str = None) -> dict:
        dmarc_domain = f"_dmarc.{domain}"
        result = DNSEngine.query(dmarc_domain, "TXT", resolver_ip)
        dmarc_records = [rec.strip('"') for rec in result.get("records", []) if "v=DMARC1" in rec]
        policy = "Aucune"
        for rec in dmarc_records:
            if "p=reject" in rec:
                policy = "Reject (p=reject)"
            elif "p=quarantine" in rec:
                policy = "Quarantine (p=quarantine)"
            elif "p=none" in rec:
                policy = "None (p=none)"
        return {"has_dmarc": len(dmarc_records) > 0, "dmarc_records": dmarc_records, "policy": policy, "domain": dmarc_domain}

    @staticmethod
    def check_blacklist(ip: str) -> dict:
        results = {}
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
        except Exception:
            return {"error": "IP invalide", "results": {}}
        for name, zone in DNS_BLACKLISTS.items():
            query_name = f"{reversed_ip}.{zone}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = resolver.resolve(query_name, "A")
                results[name] = {"listed": True, "response": str(answers[0]), "status": "⚠️ LISTÉE"}
            except dns.resolver.NXDOMAIN:
                results[name] = {"listed": False, "response": "NXDOMAIN", "status": "✅ Clean"}
            except dns.resolver.Timeout:
                results[name] = {"listed": False, "response": "Timeout", "status": "⏱ Timeout"}
            except Exception as e:
                results[name] = {"listed": False, "response": str(e)[:50], "status": "❓ Inconnu"}
        return results
