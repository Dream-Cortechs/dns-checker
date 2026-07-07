"""
DNS CHECKER — Report Generator (fpdf2)
Génère un rapport PDF complet de diagnostic DNS
Cortechs © 2026 — v3.1 (improved readability)
"""

import io, re
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

GOLD      = (160, 120, 35)
DARK_BG   = (10, 22, 40)
DARK_TEXT  = (30, 30, 40)
GRAY_TEXT  = (90, 95, 105)
GREEN      = (25, 130, 50)
RED        = (180, 30, 40)
YELLOW     = (170, 130, 0)
BLUE       = (40, 80, 160)
WHITE      = (255, 255, 255)
LIGHT_ROW  = (245, 247, 250)
WHITE_ROW  = (255, 255, 255)


class DNSReport(FPDF):

    def __init__(self, domain: str, results: dict):
        super().__init__("P", "mm", "A4")
        self.domain = domain
        self.results = results
        self._has_fonts = FONT_REGULAR is not None
        if self._has_fonts:
            self.add_font("DejaVu", "", FONT_REGULAR, uni=True)
            self.add_font("DejaVu", "B", FONT_BOLD, uni=True)
            self.add_font("DejaVuMono", "", FONT_MONO, uni=True)
            self.font_name = "DejaVu"; self.font_mono = "DejaVuMono"
        else:
            self.font_name = "Helvetica"; self.font_mono = "Courier"
        self.set_auto_page_break(True, 18)
        self._clean()

    def _clean(self):
        self.clean = self._clean_dict(self.results)

    def _clean_dict(self, d):
        if isinstance(d, dict): return {self._c(k): self._clean_dict(v) for k, v in d.items()}
        elif isinstance(d, list): return [self._clean_dict(i) for i in d]
        elif isinstance(d, str): return self._c(d)
        return d

    def _c(self, s):
        if not isinstance(s, str): return s
        return re.sub(r'[^\x00-\x7F\u00C0-\u024F\u0400-\u04FF]+', '', s)

    # ─── Layout helpers ──────────────────────────────────────────────────

    def _hbar(self, title: str):
        """Section header bar."""
        self.set_fill_color(25, 35, 55)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 13)
        self.cell(0, 9, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(*DARK_TEXT)
        self.ln(4)

    def _kv(self, label: str, value: str, w: int = 50):
        self.set_font(self.font_name, "B", 8)
        self.set_text_color(*GRAY_TEXT)
        self.cell(w, 5, label + ":")
        self.set_font(self.font_name, "", 8)
        self.set_text_color(*DARK_TEXT)
        self.cell(0, 5, str(value)[:90], new_x="LMARGIN", new_y="NEXT")

    def _table(self, headers, rows, col_widths=None):
        if not rows: return
        if not col_widths: col_widths = [190 // len(headers)] * len(headers)
        # Header
        self.set_fill_color(30, 40, 60)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 8)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 6, h, fill=True)
        self.ln()
        # Rows
        for i, row in enumerate(rows):
            self.set_fill_color(*LIGHT_ROW) if i % 2 == 0 else self.set_fill_color(*WHITE_ROW)
            self.set_text_color(*DARK_TEXT)
            self.set_font(self.font_mono if self.font_mono == "DejaVuMono" else self.font_name, "", 7.5)
            for j, cell in enumerate(row):
                self.cell(col_widths[j], 5, str(cell)[:55], fill=True)
            self.ln()
        self.ln(3)

    def _status_chip(self, label: str, ok: bool):
        """Small colored status indicator."""
        color = GREEN if ok else RED
        self.set_font(self.font_name, "B", 8)
        self.set_text_color(*color)
        self.cell(0, 5, label, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*DARK_TEXT)

    # ─── Pages ───────────────────────────────────────────────────────────

    def cover_page(self):
        self.add_page()
        # Dark banner
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 90, "F")
        self.set_fill_color(*GOLD)
        self.rect(0, 90, 210, 3, "F")
        self.set_y(18)
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 26)
        self.cell(0, 10, "DNS CHECKER", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(170, 185, 210)
        self.set_font(self.font_name, "", 11)
        self.cell(0, 6, "Rapport de diagnostic DNS", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)
        # Logo
        try:
            self.image("/opt/dns-checker/static/cortechs-logo.png", x=82, y=self.get_y(), w=46)
            self.ln(20)
        except:
            self.ln(5)
        self.set_y(max(self.get_y(), 68))
        self.set_text_color(*GOLD)
        self.set_font(self.font_name, "B", 17)
        self.cell(0, 9, self.domain, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(6)
        self.set_text_color(*GRAY_TEXT)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, datetime.now().strftime("Genere le %d/%m/%Y a %H:%M"), align="C",
                  new_x="LMARGIN", new_y="NEXT")
        self.ln(10)
        # Summary grid — 2 columns
        secs = []
        p = self.results.get("propagation", {})
        e = self.results.get("email", {})
        s = self.results.get("subdomains", {})
        bl = self.results.get("blacklist", {})
        if self.results.get("lookup"): secs.append(("DNS Lookup", ""))
        if p: secs.append(("Propagation", f"{p.get('success',0)}/{p.get('total',24)} OK"))
        if e: secs.append(("Securite Email", f"Score {e.get('score',0)}/4"))
        if self.results.get("whois"): secs.append(("WHOIS", ""))
        if self.results.get("geoip"): secs.append(("Geolocalisation", ""))
        if s: secs.append(("Sous-domaines", str(s.get("count", 0))))
        if bl:
            l = bl.get("listed", 0); t = bl.get("total", 12)
            secs.append(("Blacklists", "PROPRE" if l == 0 else f"{l}/{t} LISTE"))
        # Draw 2-column grid
        x0 = self.get_x(); y0 = self.get_y()
        col_w = 85
        for i, (label, val) in enumerate(secs):
            col = i % 2
            row = i // 2
            x = 20 + col * col_w
            y = y0 + row * 10
            self.set_xy(x, y)
            self.set_fill_color(245, 247, 250)
            self.set_font(self.font_name, "B", 8)
            self.set_text_color(*GRAY_TEXT)
            self.cell(col_w - 5, 5, label, fill=True)
            self.set_xy(x, y + 5)
            self.set_font(self.font_name, "", 8)
            self.set_text_color(*DARK_TEXT)
            self.cell(col_w - 5, 5, val)
        last_row = (len(secs) + 1) // 2
        self.set_y(y0 + last_row * 10 + 5)

    def dns_lookup_page(self):
        lookup = self.results.get("lookup", {})
        self.add_page()
        self._hbar("Enregistrements DNS")
        for rtype in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]:
            records = lookup.get(rtype.lower())
            if records:
                self.set_font(self.font_name, "B", 10)
                self.set_text_color(*GOLD)
                self.cell(0, 6, f"  {rtype} ({len(records)})", new_x="LMARGIN", new_y="NEXT")
                for i, rec in enumerate(records, 1):
                    self.set_font(self.font_mono, "", 8)
                    self.set_text_color(*DARK_TEXT)
                    self.cell(0, 4.5, f"    {i}. {str(rec)[:110]}", new_x="LMARGIN", new_y="NEXT")
                self.ln(2)

    def propagation_page(self):
        prop = self.results.get("propagation", {})
        if not prop: return
        self.add_page()
        self._hbar("Propagation DNS mondiale")
        self.ln(1)
        s = prop.get("success", 0); t = prop.get("total", 24)
        c = prop.get("consensus", "N/A"); cp = prop.get("consensus_pct", 0)
        self._kv("Resolveurs OK", f"{s}/{t}")
        self._kv("Consensus", f"{cp:.0f}%")
        self._kv("Valeur majoritaire", str(c)[:55])
        self.ln(3)
        headers = ["Resolveur", "IP", "Resultat", "Statut"]
        rows = []
        for item in prop.get("details", []):
            status_icon = "OK" if item.get("ok") else "FAIL" if item.get("error") else "EMPTY"
            name = item.get("name", "").split()[0][:22]
            rows.append([name, item.get("ip", ""), item.get("result", "")[:38], status_icon])
        self._table(headers, rows, [48, 36, 72, 22])

    def email_security_page(self):
        email = self.results.get("email", {})
        if not email: return
        self.add_page()
        self._hbar("Securite Email")
        self.ln(2)
        score = email.get("score", 0)
        color = GREEN if score >= 4 else YELLOW if score >= 2 else RED
        self.set_font(self.font_name, "B", 16)
        self.set_text_color(*color)
        self.cell(0, 10, f"Score: {score}/4", new_x="LMARGIN", new_y="NEXT")
        self.ln(6)
        self.set_text_color(*DARK_TEXT)
        for section in ["mx", "spf", "dkim", "dmarc"]:
            data = email.get(section, {})
            titles = {"mx": "MX - Serveurs Mail", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC"}
            self.set_font(self.font_name, "B", 10)
            self.set_text_color(*GOLD)
            self.cell(0, 7, titles[section], new_x="LMARGIN", new_y="NEXT")
            self.set_font(self.font_name, "", 9)
            self.set_text_color(*DARK_TEXT)
            if section == "mx":
                for srv in data.get("servers", []):
                    self.cell(0, 5, f"  {srv}", new_x="LMARGIN", new_y="NEXT")
            elif section == "spf":
                for rec in data.get("records", []):
                    self.cell(0, 5, f"  {rec[:130]}", new_x="LMARGIN", new_y="NEXT")
            elif section == "dkim":
                st = "Present" if data.get("present") else "Absent"
                self.cell(0, 5, f"  {st} (selecteur: {data.get('selector','')})", new_x="LMARGIN", new_y="NEXT")
            elif section == "dmarc":
                st = data.get("policy", "Absent") if data.get("present") else "Absent"
                self.cell(0, 5, f"  {st}", new_x="LMARGIN", new_y="NEXT")
            self.ln(4)

    def whois_page(self):
        whois = self.results.get("whois", {})
        if not whois: return
        self.add_page()
        self._hbar("WHOIS")
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
                self._kv(label, str(value)[:90])

    def geoip_page(self):
        geoip = self.results.get("geoip", {})
        if not geoip: return
        self.add_page()
        self._hbar("Geolocalisation IP")
        self.ln(2)
        for entry in geoip.get("ips", []):
            ip = entry.get("ip", "")
            g = entry.get("geo", {})
            self.set_font(self.font_name, "B", 11)
            self.set_text_color(*GOLD)
            self.cell(0, 7, ip, new_x="LMARGIN", new_y="NEXT")
            self.set_font(self.font_name, "", 9)
            self.set_text_color(*DARK_TEXT)
            loc = f"{g.get('city','')}, {g.get('region','')}, {g.get('country','')}".strip(", ")
            if loc: self.cell(0, 5, f"  {loc}", new_x="LMARGIN", new_y="NEXT")
            if g.get("isp"): self.cell(0, 5, f"  ISP: {g['isp']}", new_x="LMARGIN", new_y="NEXT")
            if g.get("org"): self.cell(0, 5, f"  Org: {g['org']}", new_x="LMARGIN", new_y="NEXT")
            self.ln(4)

    def subdomains_page(self):
        subs = self.results.get("subdomains", {})
        if not subs or not subs.get("subdomains"): return
        self.add_page()
        self._hbar(f"Sous-domaines ({subs.get('count', 0)} decouverts)")
        self.ln(2)
        sd = subs.get("subdomains", {})
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
            names = [f.replace("." + subs.get("domain", ""), "") for f in sorted(fqdns)]
            self.multi_cell(0, 5, ", ".join(names[:20]))
            self.ln(2)

    def blacklist_page(self):
        bl = self.results.get("blacklist", {})
        if not bl: return
        self.add_page()
        self._hbar("Verification Blacklists DNS")
        self.ln(2)
        self._kv("IP testee", bl.get("ip", ""))
        listed = bl.get("listed", 0); total = bl.get("total", 12)
        color = GREEN if listed == 0 else RED
        self.set_font(self.font_name, "B", 12)
        self.set_text_color(*color)
        self.cell(0, 8, f"{listed}/{total} blacklists" if listed else "Aucune blacklist !", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_text_color(*DARK_TEXT)
        rows = [[i.get("name", ""), i.get("status", "")] for i in bl.get("details", [])]
        self._table(["Blacklist", "Statut"], sorted(rows, key=lambda x: (x[1] != "LISTEE", x[0])), [90, 90])

    def footer(self):
        self.set_y(-14)
        self.set_font(self.font_name, "", 6.5)
        self.set_text_color(*GRAY_TEXT)
        self.cell(0, 4, f"DNS CHECKER v3.0  |  {datetime.now().strftime('%d/%m/%Y %H:%M')}  |  Page {self.page_no()}/{{nb}}", align="C")

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
    results = {"domain": domain}
    
    # DNS Lookup
    lookup = {}
    for rtype in ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]:
        r = DNSEngine.query(domain, rtype)
        if r["records"]: lookup[rtype.lower()] = r["records"]
    results["lookup"] = lookup
    
    # Propagation
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
    mc = max(consensus, key=consensus.get, default="N/A")
    results["propagation"] = {"total": len(GLOBAL_RESOLVERS), "success": success, "consensus": mc,
                              "consensus_pct": (consensus.get(mc, 0) / len(GLOBAL_RESOLVERS) * 100) if consensus else 0,
                              "details": sorted(prop_details, key=lambda x: (not x["ok"], x["name"]))}
    
    # Email Security
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
    
    # WHOIS
    try: results["whois"] = get_whois(domain, timeout=12)
    except: results["whois"] = None
    
    # GeoIP
    try:
        geo_ip = ip or (lookup.get("a", [None])[0] if lookup.get("a") else None)
        if geo_ip: results["geoip"] = resolve_and_geo(geo_ip)
    except: pass
    
    # Subdomains
    try: results["subdomains"] = discover_subdomains(domain, bruteforce=True, crtsh=True, timeout=20)
    except: pass
    
    # Blacklist
    if ip:
        import dns.resolver as dnsr
        bl_details = []; listed = 0; reversed_ip = ".".join(reversed(ip.split(".")))
        for name, zone in DNS_BLACKLISTS.items():
            try:
                r = dnsr.Resolver(); r.timeout = 3; r.lifetime = 3
                ans = r.resolve(f"{reversed_ip}.{zone}", "A")
                listed += 1
                bl_details.append({"name": name, "status": "LISTEE", "response": str(ans[0])})
            except dnsr.NXDOMAIN: bl_details.append({"name": name, "status": "Clean", "response": "NXDOMAIN"})
            except: bl_details.append({"name": name, "status": "Inconnu", "response": "Timeout/Erreur"})
        results["blacklist"] = {"ip": ip, "listed": listed, "total": len(DNS_BLACKLISTS),
                                "details": sorted(bl_details, key=lambda x: (x["status"] != "LISTEE", x["name"]))}
    
    return results


def generate_report_pdf(domain: str, ip: str = None) -> bytes:
    results = run_full_report(domain, ip)
    report = DNSReport(domain, results)
    return report.build()
