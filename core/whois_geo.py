"""
DNS CHECKER — WHOIS + Geo-IP Engine
Cortechs © 2026
"""

import subprocess
import socket
import json
import urllib.request
import urllib.error
import re


WHOIS_SERVERS = {
    "fr": "whois.nic.fr",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "eu": "whois.eu",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "cloud": "whois.nic.cloud",
    "de": "whois.denic.de",
    "be": "whois.dns.be",
    "ch": "whois.nic.ch",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "uk": "whois.nic.uk",
}


def _whois_query(server: str, query: str, timeout: int = 10) -> str:
    """Requête WHOIS brute sur le port 43 (aucune dépendance au binaire `whois`)."""
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _whois_server_for(domain: str, timeout: int = 10):
    """Serveur WHOIS du TLD (table locale, sinon renvoi IANA)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]
    try:
        raw = _whois_query("whois.iana.org", tld, timeout)
        match = re.search(r"^whois:\s*(\S+)", raw, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def get_whois(domain: str, timeout: int = 15) -> dict:
    """Récupère les infos WHOIS d'un domaine (client TCP port 43, sans binaire externe).

    Correctif v2 : la v1 appelait le binaire `whois` puis `python-whois`, qui ne gère
    pas .fr -> résultat vide (registrar et dates à None) sur tous les domaines
    français. Le client TCP direct + les motifs AFNIC (created, anniversary, holder)
    règlent le cas.
    """
    result = {
        "domain": domain,
        "server": None,
        "raw": "",
        "registrar": None,
        "holder": None,
        "creation_date": None,
        "last_update": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "error": None,
    }

    server = _whois_server_for(domain, timeout)
    if not server:
        result["error"] = "Serveur WHOIS introuvable pour cette extension"
        return result
    result["server"] = server

    try:
        raw = _whois_query(server, domain, timeout)
    except socket.timeout:
        result["error"] = "Timeout WHOIS"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:100]
        return result

    if not raw.strip():
        result["error"] = "Aucune réponse WHOIS"
        return result

    bas = raw.lower()
    if any(m in bas for m in ("no entries found", "no match for", "not found", "no data found")):
        result["error"] = "Domaine introuvable dans le WHOIS"
        result["raw"] = raw
        return result

    result["raw"] = raw
    info = _parse_whois_raw(raw, domain)
    for key in ("registrar", "creation_date", "last_update", "expiration_date", "holder"):
        if info.get(key):
            result[key] = info[key]
    result["name_servers"] = info.get("name_servers", [])
    result["status"] = info.get("status", [])
    return result


def _parse_whois_raw(raw: str, domain: str) -> dict:
    """Parse brut de la sortie WHOIS (champs génériques + AFNIC/.fr)."""
    info = {}

    patterns = {
        "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
        "holder": [r"holder:\s*(.+)", r"Registrant Organization:\s*(.+)", r"Registrant:\s*(.+)"],
        "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Created on\.+:\s*(.+)"],
        "last_update": [r"last-update:\s*(.+)", r"Updated Date:\s*(.+)", r"Last Modified:\s*(.+)"],
        "expiration_date": [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)",
                            r"Expiration Date:\s*(.+)", r"expiry:\s*(.+)", r"anniversary:\s*(.+)"],
    }

    for field, regexes in patterns.items():
        for regex in regexes:
            match = re.search(regex, raw, re.IGNORECASE | re.MULTILINE)
            if match:
                info[field] = match.group(1).strip()[:100]
                break

    ns = set()
    for regex in (r"Name Server:\s*(.+)", r"nserver:\s*(.+)", r"Nameserver:\s*(.+)"):
        for match in re.finditer(regex, raw, re.IGNORECASE):
            value = match.group(1).strip().lower()[:80]
            if value:
                ns.add(value)
    info["name_servers"] = sorted(ns)

    statuses = set()
    for regex in (r"Domain Status:\s*(.+)", r"status:\s*(.+)"):
        for match in re.finditer(regex, raw, re.IGNORECASE):
            statuses.add(match.group(1).strip()[:60])
    info["status"] = sorted(statuses)

    return info


def get_geoip(ip: str, timeout: int = 5) -> dict:
    """Géolocalise une IP via ip-api.com (gratuit, 45 req/min)."""
    result = {
        "ip": ip,
        "country": None,
        "country_code": None,
        "city": None,
        "region": None,
        "isp": None,
        "org": None,
        "lat": None,
        "lon": None,
        "timezone": None,
        "error": None
    }
    
    # Validate IP format
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        result["error"] = "IP invalide"
        return result
    
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,regionName,isp,org,lat,lon,timezone,query"
        req = urllib.request.Request(url, headers={"User-Agent": "dns-checker-cortechs"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        
        result["country"] = data.get("country")
        result["country_code"] = data.get("countryCode")
        result["city"] = data.get("city")
        result["region"] = data.get("regionName")
        result["isp"] = data.get("isp")
        result["org"] = data.get("org")
        result["lat"] = data.get("lat")
        result["lon"] = data.get("lon")
        result["timezone"] = data.get("timezone")
        
    except urllib.error.URLError as e:
        result["error"] = f"API injoignable: {e.reason}"
    except Exception as e:
        result["error"] = str(e)[:100]
    
    return result


def resolve_and_geo(domain_or_ip: str) -> dict:
    """Résout un domaine en IP puis géolocalise."""
    result = {"input": domain_or_ip, "ips": [], "error": None}
    
    try:
        # Try direct IP
        parts = domain_or_ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            result["ips"] = [{"ip": domain_or_ip, "geo": get_geoip(domain_or_ip)}]
        else:
            # Resolve domain
            ips = socket.getaddrinfo(domain_or_ip, None)
            seen = set()
            for info in ips:
                ip = info[4][0]
                if ip not in seen and ":" not in ip:  # IPv4 only
                    seen.add(ip)
                    result["ips"].append({"ip": ip, "geo": get_geoip(ip)})
            
            if not result["ips"]:
                result["error"] = "Aucune IP trouvée"
    except socket.gaierror:
        result["error"] = "Domaine introuvable"
    except Exception as e:
        result["error"] = str(e)[:100]
    
    return result
