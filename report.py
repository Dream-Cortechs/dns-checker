"""
DNS CHECKER — Report Generator (fpdf2)
Génère un rapport PDF complet de diagnostic DNS
Cortechs © 2026 — v3.0 (WHOIS + GeoIP + Subdomains)
"""

import io
import concurrent.futures
from datetime import datetime
from fpdf import FPDF

from dns_engine import DNSEngine, GLOBAL_RESOLVERS, DNS_BLACKLISTS, RECORD_TYPES
from whois_geo import get_whois, get_geoip, resolve_and_geo
from subdomains import discover_subdomains

# ─── Fonts ───────────────────────────────────────────────────────────────────

try:
    FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    with open(FONT_REGULAR): pass
except:
    FONT_REGULAR = FONT_BOLD = FONT_MONO = None

# ─── Colors (print-friendly) ─────────────────────────────────────────────────

GOLD      = (170, 130, 40)
DARK_BG   = (10, 22, 40)
DARK_TEXT  = (25, 30, 45)
GRAY_TEXT  = (80, 85, 95)
GREEN      = (25, 130, 50)
RED        = (180, 30, 40)
YELLOW     = (180, 140, 0)
BLUE       = (40, 80, 160)
WHITE      = (255, 255, 255)


class DNSReport(FPDF):
    """Génère un rapport PDF de diagnostic DNS complet (8 sections)."""

    def __init__(self, domain: str, results: dict):
        super().__init__("P", "mm", "A4")
        self.domain = domain
        self.results = results
        self._has_fonts = FONT_REGULAR is not None
        
        if self._has_fonts:
            self.add_font("DejaVu", "", FONT_REGULAR, uni=True)
            self.add_font("DejaVu", "B", FONT_BOLD, uni=True)
            self.add_font("DejaVuMono", "", FONT_MONO, uni=True)
            self.font_name = "DejaVu"
            self.font_mono = "DejaVuMono"
        else:
            self.font_name = "Helvetica"
            self.font_mono = "Courier"
        
        self.set_auto_page_break(True, 20)
        self._sanitize_results()

    def _sanitize_results(self):
        self.results_str = self._clean_dict(self.results)

    def _clean_dict(self, d):
        if isinstance(d, dict):
            return {self._clean_str(k): self._clean_dict(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [self._clean_dict(i) for i in d]
        elif isinstance(d, str):
            return self._clean_str(d)
        return d

    def _clean_str(self, s):
        if not isinstance(s, str): return s
        import re
        return re.sub(r'[^\x00-\x7F\u00C0-\u024F\u0400-\u04FF]+', '', s)

    def _section(self, title: str):
        self.set_fill_color(25, 35, 55)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 12)
        self.cell(0, 8, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(*DARK_TEXT)
        self.ln(3)

    def _kv(self, label: str, value: str, w_label: int = 45):
        self.set_font(self.font_name, "B", 9)
        self.set_text_color(*GRAY_TEXT)
        self.cell(w_label, 5, label + ":")
        self.set_font(self.font_name, "", 9)
        self.set_text_color(*DARK_TEXT)
        self.cell(0, 5, str(value)[:80], new_x="LMARGIN", new_y="NEXT")

    def _table(self, headers, rows, col_widths=None):
        if not rows: return
        if not col_widths:
            col_widths = [190 // len(headers)] * len(headers)
        self.set_fill_color(30, 40, 60)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 7)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 5, h, fill=True)
        self.ln()
        for i, row in enumerate(rows):
            self.set_fill_color(240, 242, 245) if i % 2 == 0 else self.set_fill_color(255, 255, 255)
            self.set_text_color(*DARK_TEXT)
            self.set_font(self.font_mono if self.font_mono == "DejaVuMono" else self.font_name, "", 7)
            for j, cell in enumerate(row):
                self.cell(col_widths[j], 4.5, str(cell)[:50], fill=True)
            self.ln()
        self.ln(2)

    # ─── Pages ───────────────────────────────────────────────────────────

    def cover_page(self):
        self.add_page()
        # Dark background with gold accent
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 85, "F")
        self.set_fill_color(*GOLD)
        self.rect(0, 85, 210, 3, "F")
        
        self.set_y(16)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 24)
        self.cell(0, 9, "DNS CHECKER", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(180, 190, 210)
        self.set_font(self.font_name, "", 11)
        self.cell(0, 6, "Rapport de diagnostic DNS", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)
        # Logo
        logo_path = "/opt/dns-checker/static/cortechs-logo.png"
        try:
            self.image(logo_path, x=82, y=self.get_y(), w=46)
            self.ln(20)
        except:
            self.ln(6)
        self.set_y(max(self.get_y(), 65))
        
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 16)
        self.cell(0, 8, self.domain, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(8)
        self.set_text_color(*GRAY_TEXT)
        self.set_font(self.font_name, "", 9)
        now = datetime.now().strftime("%d/%m/%Y  %H:%M")
        self.cell(0, 5, f"Genere le {now}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, "Cortechs (c) 2026  |  dns-checker v3.0", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(8)
        # Summary chips
        secs = []
        if self.results.get("lookup"): secs.append("DNS Lookup")
        if self.results.get("propagation"): secs.append(f"Propagation ({self.results['propagation'].get('success',0)}/{self.results['propagation'].get('total',24)})")
        if self.results.get("email"): secs.append(f"Securite Email ({self.results['email'].get('score',0)}/4)")
        if self.results.get("whois"): secs.append("WHOIS")
        if self.results.get("geoip"): secs.append("Geo-IP")
        if self.results.get("subdomains"): secs.append(f"Sous-domaines ({self.results['subdomains'].get('count',0)})")
        if self.results.get("blacklist"):
            listed = self.results['blacklist'].get('listed', 0)
            total = self.results['blacklist'].get('total', 12)
            secs.append(f"Blacklists ({'PROPRE' if listed == 0 else f'{listed}/{total} LISTE'})")
        self.set_text_color(*GRAY_TEXT)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, "  |  ".join(secs), align="C", new_x="LMARGIN", new_y="NEXT")

    def dns_lookup_page(self):
        lookup = self.results.get("lookup", {})
        self.add_page()
        self._section("Enregistrements DNS")
        for rtype in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]:
            records = lookup.get(rtype.lower())
            if records:
                self.set_font(self.font_name, "B", 10)
                self.set_text_color(*GOLD)
                self.cell(0, 6, f"  {rtype} ({len(records)})", new_x="LMARGIN", new_y="NEXT")
                for i, rec in enumerate(records, 1):
                    self.set_font(self.font_mono if self.font_mono == "DejaVuMono" else self.font_name, "", 8)
                    self.set_text_color(*DARK_TEXT)
                    self.cell(0, 5, f"    {i}. {str(rec)[:100]}", new_x="LMARGIN", new_y="NEXT")
                self.ln(2)

    def propagation_page(self):
        prop = self.results.get("propagation", {})
        if not prop: return
        self.add_page()
        self._section("Propagation DNS mondiale")
        self.ln(2)
        success = prop.get("success", 0)
        total = prop.get("total", 24)
        consensus = prop.get("consensus", "N/A")
        consensus_pct = prop.get("consensus_pct", 0)
        self._kv("Resolveurs OK", f"{success}/{total}")
        self._kv("Consensus", f"{consensus_pct:.0f}%")
        self._kv("Valeur majoritaire", str(consensus)[:50])
        self.ln(3)
        headers = ["Resolveur", "IP", "Resultat", "Statut"]
        rows = []
        for item in prop.get("details", []):
            status_icon = "OK" if item.get("ok") else "FAIL" if item.get("error") else "EMPTY"
            name = item.get("name", "").split()[0][:20]
            rows.append([name, item.get("ip", ""), item.get("result", "")[:35], status_icon])
        self._table(headers, rows, [45, 38, 75, 20])

    def email_security_page(self):
        email = self.results.get("email", {})
        if not email: return
        self.add_page()
        self._section("Securite Email")
        self.ln(2)
        score = email.get("score", 0)
        color = GREEN if score >= 4 else YELLOW if score >= 2 else RED
        self.set_font(self.font_name, "B", 14)
        self.set_text_color(*color)
        self.cell(0, 8, f"Score: {score}/4", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)
        self.set_text_color(*DARK_TEXT)
        for section in ["mx", "spf", "dkim", "dmarc"]:
            data = email.get(section, {})
            titles = {"mx": "MX - Serveurs Mail", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC"}
            self.set_font(self.font_name, "B", 10)
            self.set_text_color(*GOLD)
            self.cell(0, 6, titles[section], new_x="LMARGIN", new_y="NEXT")
            self.set_font(self.font_name, "", 9)
            self.set_text_color(*DARK_TEXT)
            if section == "mx":
                for srv in data.get("servers", []):
                    self.cell(0, 5, f"  {srv}", new_x="LMARGIN", new_y="NEXT")
            elif section == "spf":
                for rec in data.get("records", []):
                    self.cell(0, 5, f"  {rec[:120]}", new_x="LMARGIN", new_y="NEXT")
            elif section == "dkim":
                self.cell(0, 5, f"  {'Present' if data.get('present') else 'Absent'} (selecteur: {data.get('selector','')})", new_x="LMARGIN", new_y="NEXT")
            elif section == "dmarc":
                self.cell(0, 5, f"  {data.get('policy','Absent') if data.get('present') else 'Absent'}", new_x="LMARGIN", new_y="NEXT")
            self.ln(3)

    def whois_page(self):
        whois = self.results.get("whois", {})
        if not whois: return
        self.add_page()
        self._section("WHOIS")
        self.ln(2)
        fields = [
            ("Bureau d'enregistrement", whois.get("registrar")),
            ("Date de creation", whois.get("creation_date")),
            ("Date d'expiration", whois.get("expiration_date")),
            ("Serveurs DNS", ", ".join(whois.get("name_servers", [])[:6])),
            ("Statut", ", ".join(whois.get("status", [])[:4])),
        ]
        for label, value in fields:
            if value:
                self._kv(label, str(value)[:80])

    def geoip_page(self):
        geoip = self.results.get("geoip", {})
        if not geoip: return
        self.add_page()
        self._section("Geolocalisation IP")
        self.ln(2)
        for entry in geoip.get("ips", []):
            ip = entry.get("ip", "")
            g = entry.get("geo", {})
            self.set_font(self.font_name, "B", 10)
            self.set_text_color(*GOLD)
            self.cell(0, 6, ip, new_x="LMARGIN", new_y="NEXT")
            self.set_font(self.font_name, "", 9)
            self.set_text_color(*DARK_TEXT)
            loc = f"{g.get('city','')}, {g.get('region','')}, {g.get('country','')}".strip(", ")
            if loc: self.cell(0, 5, f"  {loc}", new_x="LMARGIN", new_y="NEXT")
            if g.get("isp"): self.cell(0, 5, f"  ISP: {g['isp']}", new_x="LMARGIN", new_y="NEXT")
            if g.get("org"): self.cell(0, 5, f"  Org: {g['org']}", new_x="LMARGIN", new_y="NEXT")
            self.ln(3)

    def subdomains_page(self):
        subs = self.results.get("subdomains", {})
        if not subs or not subs.get("subdomains"): return
        self.add_page()
        self._section(f"Sous-domaines ({subs.get('count', 0)})")
        self.ln(2)
        sd = subs.get("subdomains", {})
        # Group by IP
        by_ip = {}
        for fqdn, ips in sorted(sd.items()):
            ip_key = ", ".join(ips[:2])
            by_ip.setdefault(ip_key, []).append(fqdn)
        for ip_key, fqdns in sorted(by_ip.items()):
            self.set_font(self.font_name, "B", 9)
            self.set_text_color(*GOLD)
            self.cell(0, 5, ip_key, new_x="LMARGIN", new_y="NEXT")
            self.set_font(self.font_name, "", 8)
            self.set_text_color(*DARK_TEXT)
            # Show as comma-separated list
            names = [f.replace("." + subs.get("domain", ""), "") for f in sorted(fqdns)]
            self.cell(0, 5, ", ".join(names[:15]), new_x="LMARGIN", new_y="NEXT")
            self.ln(2)

    def blacklist_page(self):
        bl = self.results.get("blacklist", {})
        if not bl: return
        self.add_page()
        self._section("Verification Blacklists DNS")
        self.ln(2)
        self._kv("IP testee", bl.get("ip", ""))
        listed = bl.get("listed", 0)
        total = bl.get("total", 12)
        color = GREEN if listed == 0 else RED
        self.set_font(self.font_name, "B", 11)
        self.set_text_color(*color)
        self.cell(0, 7, f"{listed}/{total} blacklists", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)
        self.set_text_color(*DARK_TEXT)
        self._table(["Blacklist", "Statut"], [[i.get("name", ""), i.get("status", "")] for i in bl.get("details", [])], [80, 100])

    def footer(self):
        self.set_y(-15)
        self.set_font(self.font_name, "", 7)
        self.set_text_color(*GRAY_TEXT)
        self.cell(0, 5, f"DNS CHECKER v3.0  |  Cortechs (c) 2026  |  {datetime.now().strftime('%d/%m/%Y %H:%M')}  |  Page {self.page_no()}/{{nb}}", align="C")

    def build(self) -> bytes:
        self.cover_page()
        if self.results.get("lookup"): self.dns_lookup_page()
        if self.results.get("propagation"): self.propagation_page()
        if self.results.get("email"): self.email_security_page()
        if self.results.get("whois"): self.whois_page()
        if self.results.get("geoip"): self.geoip_page()
        if self.results.get("subdomains"): self.subdomains_page()
        if self.results.get("blacklist"): self.blacklist_page()
        return bytes(self.output())


def run_full_report(domain: str, ip: str = None) -> dict:
    """Run all DNS checks + WHOIS + GeoIP + Subdomains for a domain."""
    results = {"domain": domain}
    
    # ─── DNS Lookup ───
    lookup = {}
    for rtype in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]:
        r = DNSEngine.query(domain, rtype)
        if r["records"]: lookup[rtype.lower()] = r["records"]
    results["lookup"] = lookup
    
    # ─── Propagation ───
    prop_details = []; success = 0; consensus = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(DNSEngine.query, domain, "A", ip_addr, 6): (name, ip_addr) 
                   for name, ip_addr in GLOBAL_RESOLVERS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, ip_addr = futures[future]
            try: r = future.result(timeout=6)
            except: r = {"records": [], "error": "Exception"}
            ok = r["error"] is None and bool(r["records"])
            if ok: success += 1; consensus[r["records"][0]] = consensus.get(r["records"][0], 0) + 1
            prop_details.append({"name": name, "ip": ip_addr, "result": r["records"][0] if r["records"] else (r.get("error") or "?"), "ok": ok, "error": r.get("error")})
    most_common = max(consensus, key=consensus.get, default="N/A")
    results["propagation"] = {"total": len(GLOBAL_RESOLVERS), "success": success, "consensus": most_common, 
                              "consensus_pct": (consensus.get(most_common, 0) / len(GLOBAL_RESOLVERS) * 100) if consensus else 0,
                              "details": sorted(prop_details, key=lambda x: (not x["ok"], x["name"]))}
    
    # ─── Email Security ───
    mx = DNSEngine.query_mx(domain); spf = DNSEngine.check_spf(domain)
    dkim = DNSEngine.check_dkim(domain, "default"); dmarc = DNSEngine.check_dmarc(domain)
    score = sum([bool(mx["mx_records"]), spf["has_spf"] and spf["all_mechanism"], dkim["has_dkim"],
                 dmarc["has_dmarc"] and ("reject" in dmarc["policy"].lower() or "quarantine" in dmarc["policy"].lower())])
    results["email"] = {"score": score,
        "mx": {"servers": [f"P{p} {h}" for p, h in mx["mx_records"][:10]]},
        "spf": {"present": spf["has_spf"], "records": spf["spf_records"],
                "mechanism": "Hard Fail (-all)" if spf["all_mechanism"] else "Soft Fail (~all)" if spf["soft_all"] else "None"},
        "dkim": {"present": dkim["has_dkim"], "selector": "default"},
        "dmarc": {"present": dmarc["has_dmarc"], "policy": dmarc["policy"]}}
    
    # ─── WHOIS ───
    try: results["whois"] = get_whois(domain, timeout=12)
    except: results["whois"] = None
    
    # ─── GeoIP ───
    try:
        geo_ip = ip or (lookup.get("a", [None])[0] if lookup.get("a") else None)
        if geo_ip: results["geoip"] = resolve_and_geo(geo_ip)
        else: results["geoip"] = None
    except: results["geoip"] = None
    
    # ─── Subdomains ───
    try: results["subdomains"] = discover_subdomains(domain, bruteforce=True, crtsh=True, timeout=20)
    except: results["subdomains"] = None
    
    # ─── Blacklist ───
    if ip:
        import dns.resolver as dnsr
        bl_details = []; listed = 0; reversed_ip = ".".join(reversed(ip.split(".")))
        for name, zone in DNS_BLACKLISTS.items():
            try:
                r = dnsr.Resolver(); r.timeout = 3; r.lifetime = 3
                listed += 1; bl_details.append({"name": name, "status": "LISTEE", "response": str(r.resolve(f"{reversed_ip}.{zone}", "A")[0])})
            except dnsr.NXDOMAIN: bl_details.append({"name": name, "status": "Clean", "response": "NXDOMAIN"})
            except: bl_details.append({"name": name, "status": "Inconnu", "response": "Timeout/Erreur"})
        results["blacklist"] = {"ip": ip, "listed": listed, "total": len(DNS_BLACKLISTS),
                                "details": sorted(bl_details, key=lambda x: (x["status"] != "LISTEE", x["name"]))}
    
    return results


def generate_report_pdf(domain: str, ip: str = None) -> bytes:
    """Generate and return a full PDF report for a domain."""
    results = run_full_report(domain, ip)
    report = DNSReport(domain, results)
    return report.build()
