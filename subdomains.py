"""
DNS CHECKER — Subdomain Discovery Module
Brute-force + Certificate Transparency + DNS resolution
Cortechs © 2026
"""

import concurrent.futures
import urllib.request
import urllib.error
import json
import ssl
import socket

from dns_engine import DNSEngine

# Common subdomains wordlist (top ~100 most common across the internet)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
    "wiki", "web", "media", "email", "images", "img", "download", "dns", "dns2",
    "video", "api", "cdn", "staging", "apps", "app", "cloud", "owa", "portal",
    "store", "db", "mailserver", "panel", "sip", "dns1", "chat", "stats", "intranet",
    "git", "help", "manage", "origin", "proxy", "remote", "server", "status",
    "stream", "www3", "backup", "gw", "jobs", "monitor", "pay", "smtp2",
    "spam", "uat", "vpn2", "web1", "web2", "archive", "bbs", "crm", "erp",
    "exchange", "ldap", "lync", "meet", "owa2", "print", "sandbox", "search",
    "sharepoint", "ws", "xmpp", "redirect", "login", "auth", "sso", "service",
    "assets", "files", "data", "go", "link", "links", "live", "svn", "lab",
    "stage", "preprod", "prod", "production", "dev1", "dev2", "qa", "ci",
]


def _crt_sh_lookup(domain: str, timeout: int = 20) -> list:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        ctx = ssl.create_default_context()
        url = f"https://crt.sh/?q=%25.{domain}&output=json&exclude=expired&deduplicate=Y"
        req = urllib.request.Request(url, headers={"User-Agent": "dns-checker-cortechs"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read())
        
        for entry in data:
            names = entry.get("name_value", "").split("\n")
            for name in names:
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith("." + domain) and name != domain:
                    subdomains.add(name)
    except Exception:
        pass
    return sorted(subdomains)


def _bruteforce_subdomains(domain: str, wordlist: list = None, timeout: int = 3, max_workers: int = 20) -> list:
    """Brute-force DNS for common subdomains."""
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST
    
    found = {}
    
    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        r = DNSEngine.query(fqdn, "A", timeout=timeout)
        if r["records"]:
            return (fqdn, r["records"])
        # Also try CNAME
        r = DNSEngine.query(fqdn, "CNAME", timeout=timeout)
        if r["records"]:
            return (fqdn, r["records"])
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_sub, sub): sub for sub in wordlist}
        for f in concurrent.futures.as_completed(futures):
            try:
                result = f.result(timeout=timeout + 2)
                if result:
                    found[result[0]] = result[1]
            except Exception:
                pass
    
    return found


def discover_subdomains(domain: str, bruteforce: bool = True, crtsh: bool = True, timeout: int = 30) -> dict:
    """Discover subdomains for a given domain using multiple techniques."""
    domain = domain.strip().lower().rstrip(".")
    results = {
        "domain": domain,
        "subdomains": {},  # fqdn → [ips]
        "sources": [],
        "count": 0,
        "error": None,
    }
    
    if bruteforce:
        results["sources"].append("bruteforce-dns")
    
    if crtsh:
        results["sources"].append("crtsh")
    
    # Parallel: bruteforce + crt.sh
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        future_bf = None
        future_ct = None
        
        if bruteforce:
            future_bf = ex.submit(_bruteforce_subdomains, domain)
        if crtsh:
            future_ct = ex.submit(_crt_sh_lookup, domain)
        
        # Collect bruteforce results
        if future_bf:
            try:
                bf_results = future_bf.result(timeout=timeout)
                for fqdn, ips in bf_results.items():
                    results["subdomains"][fqdn] = ips
            except Exception:
                pass
        
        # Collect CRT.sh results and resolve them
        if future_ct:
            try:
                ct_subs = future_ct.result(timeout=timeout)
                # Resolve CT-discovered subdomains
                to_resolve = [s for s in ct_subs if s not in results["subdomains"]]
                if to_resolve:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex2:
                        futs = {ex2.submit(lambda s=s: (s, DNSEngine.query(s, "A", timeout=4))): s for s in to_resolve}
                        for f in concurrent.futures.as_completed(futs):
                            try:
                                name, r = f.result(timeout=6)
                                if r["records"]:
                                    results["subdomains"][name] = r["records"]
                            except Exception:
                                pass
            except Exception:
                pass
    
    results["count"] = len(results["subdomains"])
    if results["count"] == 0 and not bruteforce and not crtsh:
        results["error"] = "Aucune source activée"
    
    return results
