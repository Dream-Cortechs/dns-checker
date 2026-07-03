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


def get_whois(domain: str, timeout: int = 15) -> dict:
    """Récupère les infos WHOIS d'un domaine."""
    result = {
        "domain": domain,
        "raw": "",
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "error": None
    }
    
    try:
        # Use subprocess for reliability
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=timeout
        )
        raw = proc.stdout
        
        if not raw.strip():
            result["error"] = "Aucune réponse WHOIS"
            return result
        
        result["raw"] = raw
        
        # Try python-whois for parsing
        try:
            import whois
            w = whois.whois(domain)
            if w.registrar:
                result["registrar"] = str(w.registrar)
            if w.creation_date:
                dates = w.creation_date if isinstance(w.creation_date, list) else [w.creation_date]
                result["creation_date"] = str(dates[0])[:19] if dates else None
            if w.expiration_date:
                dates = w.expiration_date if isinstance(w.expiration_date, list) else [w.expiration_date]
                result["expiration_date"] = str(dates[0])[:19] if dates else None
            if w.name_servers:
                result["name_servers"] = [str(ns).lower() for ns in (w.name_servers if isinstance(w.name_servers, list) else [w.name_servers])]
            if w.status:
                result["status"] = [str(s) for s in (w.status if isinstance(w.status, list) else [w.status])]
        except Exception:
            # Fallback: manual parsing from raw text
            result.update(_parse_whois_raw(raw, domain))
        
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout WHOIS"
    except Exception as e:
        result["error"] = str(e)[:100]
    
    return result


def _parse_whois_raw(raw: str, domain: str) -> dict:
    """Parse brut de la sortie whois."""
    info = {}
    
    patterns = {
        "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
        "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Created on\.+:\s*(.+)"],
        "expiration_date": [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"Expiration Date:\s*(.+)"],
    }
    
    for field, regexes in patterns.items():
        for regex in regexes:
            match = re.search(regex, raw, re.IGNORECASE)
            if match:
                info[field] = match.group(1).strip()[:100]
                break
    
    # Name servers
    ns_patterns = [r"Name Server:\s*(.+)", r"nserver:\s*(.+)", r"Nameserver:\s*(.+)"]
    ns = set()
    for regex in ns_patterns:
        for match in re.finditer(regex, raw, re.IGNORECASE):
            ns.add(match.group(1).strip().lower()[:80])
    info["name_servers"] = sorted(ns)
    
    # Status
    status_patterns = [r"Domain Status:\s*(.+)", r"Status:\s*(.+)"]
    statuses = set()
    for regex in status_patterns:
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
