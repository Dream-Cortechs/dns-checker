#!/usr/bin/env python3
"""
DNS CHECKER — Outil de diagnostic DNS complet
Équivalent self-hosted de whatsmydns.net + MXToolbox

Cortechs © 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import concurrent.futures
from datetime import datetime
from collections import defaultdict

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ─── Configuration ───────────────────────────────────────────────────────────

CORTECHS_DARK = "#0a1628"
CORTECHS_ACCENT = "#c9a94e"
CORTECHS_SURFACE = "#111d34"
CORTECHS_BORDER = "#1e3050"
CORTECHS_TEXT = "#e0e0e0"
CORTECHS_TEXT_SECONDARY = "#8899aa"
CORTECHS_SUCCESS = "#2ecc71"
CORTECHS_WARNING = "#f39c12"
CORTECHS_ERROR = "#e74c3c"
CORTECHS_INFO = "#3498db"

RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "ANY"]

# Résolveurs publics mondiaux pour le test de propagation
GLOBAL_RESOLVERS = {
    # Amérique du Nord
    "Google 🇺🇸": "8.8.8.8",
    "Google (alt) 🇺🇸": "8.8.4.4",
    "Cloudflare 🇺🇸": "1.1.1.1",
    "Cloudflare (alt) 🇺🇸": "1.0.0.1",
    "Quad9 🇺🇸": "9.9.9.9",
    "Level3 🇺🇸": "4.2.2.2",
    "Norton 🇺🇸": "199.85.126.10",
    "Neustar 🇺🇸": "156.154.70.1",
    "Dyn 🇺🇸": "216.146.35.35",
    "Hurricane Elec 🇺🇸": "74.82.42.42",
    "CenturyLink 🇺🇸": "205.171.3.65",
    "ControlD 🇨🇦": "76.76.2.0",
    
    # Europe
    "Quad9 🇨🇭": "149.112.112.112",
    "Quad9 (alt) 🇨🇭": "149.112.112.10",
    "AdGuard 🇩🇪": "94.140.14.14",
    "Freenom (alt) 🇫🇷": "80.80.81.81",
    "NextDNS 🇦🇹": "45.90.28.0",
    "dnsforge 🇩🇪": "176.9.93.198",
    "OpenNIC 🇩🇪": "94.247.43.254",
    "CleanBrowsing 🇬🇧": "185.228.168.9",
    "SafeDNS 🇺🇸": "195.46.39.39",
    
    # Asie / Océanie
    "Comodo 🇭🇰": "8.26.56.26",
    "Yandex 🇷🇺": "77.88.8.8",
    "AliDNS 🇨🇳": "223.5.5.5",
}

# DNSBL pour vérification blacklist
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


# ─── Style Helpers ───────────────────────────────────────────────────────────

class DarkTheme:
    """Applique le thème sombre Cortechs à l'app tkinter."""
    
    @staticmethod
    def apply(root: tk.Tk):
        root.configure(bg=CORTECHS_DARK)
        
        style = ttk.Style(root)
        style.theme_use("clam")
        
        # Configuration globale
        style.configure(".", 
            background=CORTECHS_DARK,
            foreground=CORTECHS_TEXT,
            fieldbackground=CORTECHS_SURFACE,
            borderwidth=1,
            relief="flat")
        
        # Frame
        style.configure("TFrame", background=CORTECHS_DARK)
        style.configure("Card.TFrame", background=CORTECHS_SURFACE, relief="solid")
        
        # Label
        style.configure("TLabel", 
            background=CORTECHS_DARK, 
            foreground=CORTECHS_TEXT,
            font=("Segoe UI", 10))
        style.configure("Title.TLabel", 
            font=("Segoe UI", 16, "bold"),
            foreground=CORTECHS_ACCENT)
        style.configure("Subtitle.TLabel", 
            font=("Segoe UI", 11),
            foreground=CORTECHS_TEXT_SECONDARY)
        style.configure("Status.TLabel",
            font=("Segoe UI", 9),
            foreground=CORTECHS_TEXT_SECONDARY)
        style.configure("Success.TLabel", foreground=CORTECHS_SUCCESS)
        style.configure("Warning.TLabel", foreground=CORTECHS_WARNING)
        style.configure("Error.TLabel", foreground=CORTECHS_ERROR)
        style.configure("Info.TLabel", foreground=CORTECHS_INFO)
        
        # Button
        style.configure("TButton",
            background=CORTECHS_ACCENT,
            foreground=CORTECHS_DARK,
            borderwidth=0,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"))
        style.map("TButton",
            background=[("active", "#d4b860"), ("disabled", CORTECHS_BORDER)],
            foreground=[("disabled", CORTECHS_TEXT_SECONDARY)])
        
        # Secondary button
        style.configure("Secondary.TButton",
            background=CORTECHS_SURFACE,
            foreground=CORTECHS_TEXT,
            borderwidth=1,
            padding=(12, 6),
            font=("Segoe UI", 10))
        style.map("Secondary.TButton",
            background=[("active", CORTECHS_BORDER)])
        
        # Entry
        style.configure("TEntry",
            fieldbackground=CORTECHS_SURFACE,
            foreground=CORTECHS_TEXT,
            insertcolor=CORTECHS_TEXT,
            borderwidth=1,
            padding=8)
        
        # Combobox
        style.configure("TCombobox",
            fieldbackground=CORTECHS_SURFACE,
            foreground=CORTECHS_TEXT,
            arrowcolor=CORTECHS_TEXT,
            selectbackground=CORTECHS_ACCENT,
            selectforeground=CORTECHS_DARK)
        style.map("TCombobox",
            fieldbackground=[("readonly", CORTECHS_SURFACE)],
            foreground=[("readonly", CORTECHS_TEXT)])
        
        # Notebook (tabs)
        style.configure("TNotebook",
            background=CORTECHS_DARK,
            borderwidth=0)
        style.configure("TNotebook.Tab",
            background=CORTECHS_SURFACE,
            foreground=CORTECHS_TEXT_SECONDARY,
            padding=(20, 10),
            font=("Segoe UI", 10),
            borderwidth=0)
        style.map("TNotebook.Tab",
            background=[("selected", CORTECHS_DARK)],
            foreground=[("selected", CORTECHS_ACCENT)],
            expand=[("selected", [0, 0, 0, 0])])
        
        # Treeview
        style.configure("Treeview",
            background=CORTECHS_SURFACE,
            foreground=CORTECHS_TEXT,
            fieldbackground=CORTECHS_SURFACE,
            borderwidth=0,
            rowheight=30,
            font=("Consolas", 9))
        style.configure("Treeview.Heading",
            background=CORTECHS_BORDER,
            foreground=CORTECHS_ACCENT,
            font=("Segoe UI", 9, "bold"),
            borderwidth=1,
            relief="solid")
        style.map("Treeview",
            background=[("selected", CORTECHS_ACCENT)],
            foreground=[("selected", CORTECHS_DARK)])
        
        # Progress bar
        style.configure("TProgressbar",
            background=CORTECHS_ACCENT,
            troughcolor=CORTECHS_SURFACE,
            borderwidth=0)
        
        # LabelFrame
        style.configure("TLabelframe", 
            background=CORTECHS_DARK,
            foreground=CORTECHS_ACCENT,
            borderwidth=1,
            relief="solid")
        style.configure("TLabelframe.Label",
            background=CORTECHS_DARK,
            foreground=CORTECHS_ACCENT,
            font=("Segoe UI", 10, "bold"))
        
        # Scrollbar
        style.configure("TScrollbar",
            background=CORTECHS_SURFACE,
            troughcolor=CORTECHS_DARK,
            borderwidth=0,
            arrowcolor=CORTECHS_TEXT)


# ─── DNS Engine ──────────────────────────────────────────────────────────────

class DNSEngine:
    """Moteur de requêtes DNS avec dnspython."""
    
    @staticmethod
    def query(domain: str, record_type: str, resolver_ip: str = None, timeout: int = 5) -> dict:
        """Effectue une requête DNS et retourne les résultats."""
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
            
            return {
                "records": records,
                "count": len(records),
                "resolver": resolver_ip or "Système",
                "error": None
            }
        except dns.resolver.NoAnswer:
            return {"records": [], "count": 0, "resolver": resolver_ip or "Système",
                    "error": f"Aucun enregistrement {record_type} pour ce domaine (le domaine existe mais pas ce type d'enregistrement)"}
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
        """Récupère les enregistrements MX avec priorités."""
        result = DNSEngine.query(domain, "MX", resolver_ip)
        if result["records"]:
            # Parser "10 mail.example.com" → [(10, "mail.example.com")]
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
        """Vérifie l'enregistrement SPF."""
        result = DNSEngine.query(domain, "TXT", resolver_ip)
        spf_records = []
        for rec in result.get("records", []):
            if "v=spf1" in rec.lower():
                spf_records.append(rec.strip('"'))
        
        return {
            "has_spf": len(spf_records) > 0,
            "spf_records": spf_records,
            "all_mechanism": any("-all" in r for r in spf_records),
            "soft_all": any("~all" in r for r in spf_records),
            "neutral_all": any("?all" in r for r in spf_records),
        }
    
    @staticmethod
    def check_dkim(domain: str, selector: str = "default", resolver_ip: str = None) -> dict:
        """Vérifie DKIM pour un sélecteur donné."""
        dkim_domain = f"{selector}._domainkey.{domain}"
        result = DNSEngine.query(dkim_domain, "TXT", resolver_ip)
        dkim_records = []
        for rec in result.get("records", []):
            if "v=DKIM1" in rec or "k=rsa" in rec:
                dkim_records.append(rec.strip('"'))
        
        return {
            "selector": selector,
            "has_dkim": len(dkim_records) > 0,
            "dkim_records": dkim_records,
            "domain": dkim_domain
        }
    
    @staticmethod
    def check_dmarc(domain: str, resolver_ip: str = None) -> dict:
        """Vérifie l'enregistrement DMARC."""
        dmarc_domain = f"_dmarc.{domain}"
        result = DNSEngine.query(dmarc_domain, "TXT", resolver_ip)
        dmarc_records = []
        for rec in result.get("records", []):
            if "v=DMARC1" in rec:
                dmarc_records.append(rec.strip('"'))
        
        policy = "Aucune"
        for rec in dmarc_records:
            if "p=reject" in rec:
                policy = "Reject (p=reject)"
            elif "p=quarantine" in rec:
                policy = "Quarantine (p=quarantine)"
            elif "p=none" in rec:
                policy = "None (p=none)"
        
        return {
            "has_dmarc": len(dmarc_records) > 0,
            "dmarc_records": dmarc_records,
            "policy": policy,
            "domain": dmarc_domain
        }
    
    @staticmethod
    def check_blacklist(ip: str) -> dict:
        """Vérifie une IP contre les DNSBL."""
        results = {}
        
        # Inverser l'IP pour DNSBL (1.2.3.4 → 4.3.2.1)
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
                # Si on a une réponse, l'IP est listée
                results[name] = {
                    "listed": True,
                    "response": str(answers[0]),
                    "status": "⚠️ LISTÉE"
                }
            except dns.resolver.NXDOMAIN:
                results[name] = {
                    "listed": False,
                    "response": "NXDOMAIN",
                    "status": "✅ Clean"
                }
            except dns.resolver.Timeout:
                results[name] = {
                    "listed": False,
                    "response": "Timeout",
                    "status": "⏱ Timeout"
                }
            except Exception as e:
                results[name] = {
                    "listed": False,
                    "response": str(e)[:50],
                    "status": "❓ Inconnu"
                }
        
        return results


# ─── DNS Lookup Tab ──────────────────────────────────────────────────────────

class DNSLookupTab(ttk.Frame):
    """Onglet de lookup DNS simple."""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(20, 10), padx=20)
        
        ttk.Label(header, text="🔍 DNS Lookup", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Recherche d'enregistrements DNS", 
                  style="Subtitle.TLabel").pack(side="left", padx=(15, 0))
        
        # Input row
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        # Domaine
        domain_frame = ttk.Frame(input_frame)
        domain_frame.pack(side="left", fill="x", expand=True)
        ttk.Label(domain_frame, text="Domaine").pack(anchor="w")
        self.domain_entry = ttk.Entry(domain_frame, font=("Consolas", 12))
        self.domain_entry.pack(fill="x", pady=(2, 0))
        self.domain_entry.bind("<Return>", lambda e: self.do_lookup())
        
        # Record type
        type_frame = ttk.Frame(input_frame, width=120)
        type_frame.pack(side="left", padx=(10, 0))
        type_frame.pack_propagate(False)
        ttk.Label(type_frame, text="Type").pack(anchor="w")
        self.type_combo = ttk.Combobox(type_frame, values=RECORD_TYPES, 
                                        state="readonly", font=("Consolas", 11))
        self.type_combo.set("A")
        self.type_combo.pack(fill="x", pady=(2, 0))
        
        # Resolver
        resolver_frame = ttk.Frame(input_frame, width=180)
        resolver_frame.pack(side="left", padx=(10, 0))
        resolver_frame.pack_propagate(False)
        ttk.Label(resolver_frame, text="Résolveur").pack(anchor="w")
        resolver_list = ["Système (par défaut)"] + [
            f"{name} ({ip})" for name, ip in GLOBAL_RESOLVERS.items()
        ]
        self.resolver_combo = ttk.Combobox(resolver_frame, values=resolver_list,
                                            state="readonly", font=("Segoe UI", 9))
        self.resolver_combo.set("Système (par défaut)")
        self.resolver_combo.pack(fill="x", pady=(2, 0))
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        self.search_btn = ttk.Button(btn_frame, text="🔍 Rechercher", 
                                      command=self.do_lookup)
        self.search_btn.pack(side="left")
        
        self.clear_btn = ttk.Button(btn_frame, text="Effacer", 
                                     style="Secondary.TButton",
                                     command=self.clear_results)
        self.clear_btn.pack(side="left", padx=(8, 0))
        
        # Status
        self.status_label = ttk.Label(btn_frame, text="", style="Status.TLabel")
        self.status_label.pack(side="left", padx=(15, 0))
        
        # Results
        results_frame = ttk.Frame(self)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Treeview
        columns = ("#", "value")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings",
                                  selectmode="none")
        self.tree.heading("#", text="#")
        self.tree.heading("value", text="Valeur")
        self.tree.column("#", width=50, anchor="center")
        self.tree.column("value", width=600)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Summary
        self.summary_frame = ttk.Frame(self)
        self.summary_frame.pack(fill="x", padx=20, pady=(0, 10))
    
    def get_resolver_ip(self):
        choice = self.resolver_combo.get()
        if choice == "Système (par défaut)":
            return None
        import re
        matches = re.findall(r'\(([^)]+)\)', choice)
        return matches[-1] if matches else None  # dernière occurrence = IP
    
    def do_lookup(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Erreur", "Veuillez entrer un domaine.")
            return
        
        record_type = self.type_combo.get()
        resolver_ip = self.get_resolver_ip()
        
        self.search_btn.config(state="disabled", text="⏳ Recherche...")
        self.status_label.config(text="Recherche en cours...")
        
        thread = threading.Thread(target=self._run_lookup, 
                                   args=(domain, record_type, resolver_ip))
        thread.daemon = True
        thread.start()
    
    def _run_lookup(self, domain, record_type, resolver_ip):
        result = DNSEngine.query(domain, record_type, resolver_ip)
        self.app.root.after(0, lambda: self._display_result(result, domain, record_type, resolver_ip))
    
    def _display_result(self, result, domain, record_type, resolver_ip):
        self.clear_results()
        self.search_btn.config(state="normal", text="🔍 Rechercher")
        
        if result["error"]:
            self.status_label.config(text=f"❌ {result['error']}")
            self.tree.insert("", "end", values=("", f"Erreur: {result['error']}"))
            return
        
        records = result["records"]
        for i, rec in enumerate(records, 1):
            self.tree.insert("", "end", values=(i, rec))
        
        resolver_name = resolver_ip or "système"
        self.status_label.config(
            text=f"✅ {len(records)} enregistrement(s) {record_type} trouvé(s) — Résolveur: {resolver_name}")
        
        # Résumé
        for widget in self.summary_frame.winfo_children():
            widget.destroy()
        
        summary = f"Domaine : {domain}  |  Type : {record_type}  |  Résultats : {len(records)}"
        ttk.Label(self.summary_frame, text=summary, style="Status.TLabel").pack(anchor="w")
    
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for widget in self.summary_frame.winfo_children():
            widget.destroy()
        self.status_label.config(text="")


# ─── Propagation Tab ─────────────────────────────────────────────────────────

class PropagationTab(ttk.Frame):
    """Onglet de test de propagation DNS mondiale."""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(20, 10), padx=20)
        
        ttk.Label(header, text="🌍 Propagation DNS", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Vérification multi-résolveurs (whatsmydns.net)", 
                  style="Subtitle.TLabel").pack(side="left", padx=(15, 0))
        
        # Input row
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        # Domaine
        domain_frame = ttk.Frame(input_frame)
        domain_frame.pack(side="left", fill="x", expand=True)
        ttk.Label(domain_frame, text="Domaine").pack(anchor="w")
        self.domain_entry = ttk.Entry(domain_frame, font=("Consolas", 12))
        self.domain_entry.pack(fill="x", pady=(2, 0))
        self.domain_entry.bind("<Return>", lambda e: self.do_propagation())
        
        # Record type
        type_frame = ttk.Frame(input_frame, width=120)
        type_frame.pack(side="left", padx=(10, 0))
        type_frame.pack_propagate(False)
        ttk.Label(type_frame, text="Type").pack(anchor="w")
        self.type_combo = ttk.Combobox(type_frame, values=RECORD_TYPES,
                                        state="readonly", font=("Consolas", 11))
        self.type_combo.set("A")
        self.type_combo.pack(fill="x", pady=(2, 0))
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        self.check_btn = ttk.Button(btn_frame, text="🌍 Vérifier la propagation",
                                     command=self.do_propagation)
        self.check_btn.pack(side="left")
        
        self.clear_btn = ttk.Button(btn_frame, text="Effacer",
                                     style="Secondary.TButton",
                                     command=self.clear_results)
        self.clear_btn.pack(side="left", padx=(8, 0))
        
        # Progress
        self.progress = ttk.Progressbar(btn_frame, mode="determinate", length=200)
        self.progress.pack(side="left", padx=(15, 0))
        
        self.status_label = ttk.Label(btn_frame, text="", style="Status.TLabel")
        self.status_label.pack(side="left", padx=(15, 0))
        
        # Results: canvas avec grille colorée
        results_container = ttk.Frame(self)
        results_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Treeview pour les résultats
        columns = ("resolver", "ip", "result", "status", "latency")
        self.tree = ttk.Treeview(results_container, columns=columns, show="headings")
        self.tree.heading("resolver", text="Résolveur")
        self.tree.heading("ip", text="IP")
        self.tree.heading("result", text="Résultat")
        self.tree.heading("status", text="Statut")
        self.tree.heading("latency", text="Latence")
        self.tree.column("resolver", width=170)
        self.tree.column("ip", width=140)
        self.tree.column("result", width=300)
        self.tree.column("status", width=80, anchor="center")
        self.tree.column("latency", width=80, anchor="center")
        
        scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Color tags
        self.tree.tag_configure("success", background="#1a3a2a", foreground=CORTECHS_SUCCESS)
        self.tree.tag_configure("error", background="#3a1a1a", foreground=CORTECHS_ERROR)
        self.tree.tag_configure("warning", background="#3a3510", foreground=CORTECHS_WARNING)
    
    def do_propagation(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Erreur", "Veuillez entrer un domaine.")
            return
        
        record_type = self.type_combo.get()
        
        self.check_btn.config(state="disabled", text="⏳ Vérification...")
        self.clear_results()
        
        total = len(GLOBAL_RESOLVERS)
        self.progress["maximum"] = total
        self.progress["value"] = 0
        
        thread = threading.Thread(target=self._run_propagation,
                                   args=(domain, record_type, total))
        thread.daemon = True
        thread.start()
    
    def _run_propagation(self, domain, record_type, total):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for name, ip in GLOBAL_RESOLVERS.items():
                future = executor.submit(DNSEngine.query, domain, record_type, ip, 5)
                futures[future] = (name, ip)
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                name, ip = futures[future]
                completed += 1
                try:
                    result = future.result(timeout=5)
                except Exception:
                    result = {"records": [], "error": "Exception"}
                
                results.append((name, ip, result))
                self.app.root.after(0, lambda v=completed: self.progress.configure(value=v))
        
        # Trier: succès d'abord, puis erreurs
        results.sort(key=lambda x: (x[2]["error"] is not None, x[0]))
        self.app.root.after(0, lambda: self._display_results(results, domain, record_type))
    
    def _display_results(self, results, domain, record_type):
        self.check_btn.config(state="normal", text="🌍 Vérifier la propagation")
        
        success_count = sum(1 for _, _, r in results if r["error"] is None)
        total = len(results)
        
        for name, ip, result in results:
            if result["error"]:
                status = "❌"
                result_text = result["error"]
                tag = "error"
            elif len(result["records"]) == 0:
                status = "⚠️"
                result_text = "(aucun enregistrement)"
                tag = "warning"
            else:
                status = "✅"
                result_text = result["records"][0]
                if len(result["records"]) > 1:
                    result_text += f" (+{len(result['records'])-1})"
                tag = "success"
            
            self.tree.insert("", "end", 
                values=(name, ip, result_text, status, ""),
                tags=(tag,))
        
        # Consensus
        record_values = defaultdict(list)
        for _, _, r in results:
            if r["error"] is None and r["records"]:
                record_values[", ".join(r["records"])].append(r["resolver"])
        
        most_common = max(record_values.keys(), key=lambda k: len(record_values[k]), default="Aucun")
        consensus_pct = (len(record_values[most_common]) / total * 100) if record_values else 0
        
        color = CORTECHS_SUCCESS if consensus_pct > 80 else CORTECHS_WARNING if consensus_pct > 50 else CORTECHS_ERROR
        
        self.status_label.config(
            text=f"✅ {success_count}/{total} résolveurs répondent  |  "
                 f"Consensus : {most_common} ({consensus_pct:.0f}%)")
    
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress["value"] = 0
        self.status_label.config(text="")


# ─── Email Security Tab ───────────────────────────────────────────────────────

class EmailSecurityTab(ttk.Frame):
    """Onglet de vérification sécurité email (SPF, DKIM, DMARC, MX)."""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(20, 10), padx=20)
        
        ttk.Label(header, text="📧 Sécurité Email", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="SPF · DKIM · DMARC · MX (type MXToolbox)", 
                  style="Subtitle.TLabel").pack(side="left", padx=(15, 0))
        
        # Input row
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        # Domaine
        domain_frame = ttk.Frame(input_frame)
        domain_frame.pack(side="left", fill="x", expand=True)
        ttk.Label(domain_frame, text="Domaine").pack(anchor="w")
        self.domain_entry = ttk.Entry(domain_frame, font=("Consolas", 12))
        self.domain_entry.pack(fill="x", pady=(2, 0))
        self.domain_entry.bind("<Return>", lambda e: self.do_check())
        
        # DKIM selector
        selector_frame = ttk.Frame(input_frame, width=140)
        selector_frame.pack(side="left", padx=(10, 0))
        selector_frame.pack_propagate(False)
        ttk.Label(selector_frame, text="Sélecteur DKIM").pack(anchor="w")
        self.selector_entry = ttk.Entry(selector_frame, font=("Consolas", 10))
        self.selector_entry.insert(0, "default")
        self.selector_entry.pack(fill="x", pady=(2, 0))
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        self.check_btn = ttk.Button(btn_frame, text="🔒 Vérifier la sécurité",
                                     command=self.do_check)
        self.check_btn.pack(side="left")
        
        self.clear_btn = ttk.Button(btn_frame, text="Effacer",
                                     style="Secondary.TButton",
                                     command=self.clear_results)
        self.clear_btn.pack(side="left", padx=(8, 0))
        
        self.status_label = ttk.Label(btn_frame, text="", style="Status.TLabel")
        self.status_label.pack(side="left", padx=(15, 0))
        
        # Results area — scrollable with cards
        canvas_frame = ttk.Frame(self)
        canvas_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.results_canvas = tk.Canvas(canvas_frame, bg=CORTECHS_DARK, 
                                         highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", 
                                   command=self.results_canvas.yview)
        self.results_content = ttk.Frame(self.results_canvas)
        
        self.results_content.bind("<Configure>", 
            lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all")))
        
        self.results_canvas.create_window((0, 0), window=self.results_content, 
                                           anchor="nw", tags="content")
        self.results_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.results_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Mouse wheel scroll
        self.results_canvas.bind("<MouseWheel>", 
            lambda e: self.results_canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        self.results_canvas.bind("<Button-4>", 
            lambda e: self.results_canvas.yview_scroll(-1, "units"))
        self.results_canvas.bind("<Button-5>", 
            lambda e: self.results_canvas.yview_scroll(1, "units"))
    
    def do_check(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Erreur", "Veuillez entrer un domaine.")
            return
        
        selector = self.selector_entry.get().strip() or "default"
        
        self.check_btn.config(state="disabled", text="⏳ Analyse...")
        self.clear_results()
        
        thread = threading.Thread(target=self._run_check, args=(domain, selector))
        thread.daemon = True
        thread.start()
    
    def _run_check(self, domain, selector):
        results = {}
        
        # MX
        results["mx"] = DNSEngine.query_mx(domain)
        
        # SPF
        results["spf"] = DNSEngine.check_spf(domain)
        
        # DKIM
        results["dkim"] = DNSEngine.check_dkim(domain, selector)
        
        # DMARC
        results["dmarc"] = DNSEngine.check_dmarc(domain)
        
        self.app.root.after(0, lambda: self._display_results(results, domain, selector))
    
    def _display_results(self, results, domain, selector):
        self.check_btn.config(state="normal", text="🔒 Vérifier la sécurité")
        
        # Score
        score = 0
        max_score = 4
        
        def add_card(title, icon, items, status, color):
            card = tk.Frame(self.results_content, bg=CORTECHS_SURFACE,
                           highlightbackground=CORTECHS_BORDER,
                           highlightthickness=1, bd=0, padx=15, pady=12)
            card.pack(fill="x", pady=(0, 8))
            
            # Header
            header_frame = tk.Frame(card, bg=CORTECHS_SURFACE)
            header_frame.pack(fill="x")
            
            # Status dot
            dot_color = color
            dot = tk.Canvas(header_frame, width=12, height=12, bg=CORTECHS_SURFACE, 
                           highlightthickness=0)
            dot.create_oval(1, 1, 11, 11, fill=dot_color, outline="")
            dot.pack(side="left", padx=(0, 8))
            
            tk.Label(header_frame, text=f"{icon} {title}", 
                    bg=CORTECHS_SURFACE, fg=CORTECHS_TEXT,
                    font=("Segoe UI", 11, "bold")).pack(side="left")
            
            tk.Label(header_frame, text=status, 
                    bg=CORTECHS_SURFACE, fg=color,
                    font=("Segoe UI", 10, "bold")).pack(side="right")
            
            # Items
            for label, value in items:
                item_frame = tk.Frame(card, bg=CORTECHS_SURFACE)
                item_frame.pack(fill="x", pady=(4, 0))
                tk.Label(item_frame, text=label, 
                        bg=CORTECHS_SURFACE, fg=CORTECHS_TEXT_SECONDARY,
                        font=("Segoe UI", 9)).pack(side="left")
                tk.Label(item_frame, text=value, 
                        bg=CORTECHS_SURFACE, fg=CORTECHS_TEXT,
                        font=("Consolas", 9), wraplength=500, 
                        justify="left").pack(side="right", anchor="n")
        
        # — MX —
        mx_result = results["mx"]
        if mx_result["mx_records"]:
            mx_items = []
            for prio, host in mx_result["mx_records"][:10]:
                mx_items.append((f"Priorité {prio}", host))
            mx_status = f"✅ {len(mx_result['mx_records'])} serveur(s)"
            mx_color = CORTECHS_SUCCESS
            score += 1
        elif mx_result.get("error") == "Pas de réponse":
            mx_items = [("Erreur", "Pas d'enregistrement MX")]
            mx_status = "⚠️ Aucun"
            mx_color = CORTECHS_WARNING
        else:
            mx_items = [("Erreur", mx_result.get("error", "Inconnue"))]
            mx_status = "❌ Erreur"
            mx_color = CORTECHS_ERROR
        
        add_card("MX — Serveurs mail", "📨", mx_items, mx_status, mx_color)
        
        # — SPF —
        spf_result = results["spf"]
        if spf_result["has_spf"]:
            spf_items = [(f"SPF Record", r) for r in spf_result["spf_records"]]
            mechanism = ""
            if spf_result["all_mechanism"]:
                mechanism = " 🔒 Hard Fail (-all)"
                spf_color = CORTECHS_SUCCESS
                score += 1
            elif spf_result["soft_all"]:
                mechanism = " ⚠️ Soft Fail (~all)"
                spf_color = CORTECHS_WARNING
            else:
                mechanism = " ⚠️ Neutral"
                spf_color = CORTECHS_WARNING
            spf_status = f"✅ Présent{mechanism}"
            if not spf_items:
                spf_items = [("Record", r) for r in spf_result["spf_records"]]
        else:
            spf_items = [("Erreur", "Aucun SPF trouvé")]
            spf_status = "❌ Absent"
            spf_color = CORTECHS_ERROR
        
        add_card("SPF — Sender Policy Framework", "🛡️", spf_items, spf_status, spf_color)
        
        # — DKIM —
        dkim_result = results["dkim"]
        if dkim_result["has_dkim"]:
            dkim_items = [(f"Sélecteur: {selector}", r) for r in dkim_result["dkim_records"]]
            dkim_status = "✅ Présent"
            dkim_color = CORTECHS_SUCCESS
            score += 1
        else:
            dkim_items = [
                ("Domaine vérifié", dkim_result["domain"]),
                ("Statut", "Aucun enregistrement DKIM"),
                ("Note", "Essayez d'autres sélecteurs : google, selector1, s1, mail")
            ]
            dkim_status = "❌ Absent"
            dkim_color = CORTECHS_ERROR
        
        add_card("DKIM — DomainKeys Identified Mail", "🔑", dkim_items, dkim_status, dkim_color)
        
        # — DMARC —
        dmarc_result = results["dmarc"]
        if dmarc_result["has_dmarc"]:
            dmarc_items = [(f"Record", r) for r in dmarc_result["dmarc_records"]]
            dmarc_status = f"✅ {dmarc_result['policy']}"
            if "reject" in dmarc_result["policy"]:
                dmarc_color = CORTECHS_SUCCESS
                score += 1
            elif "quarantine" in dmarc_result["policy"]:
                dmarc_color = CORTECHS_SUCCESS
                score += 1
            else:
                dmarc_color = CORTECHS_WARNING
        else:
            dmarc_items = [
                ("Domaine vérifié", dmarc_result["domain"]),
                ("Statut", "Aucun DMARC trouvé")
            ]
            dmarc_status = "❌ Absent"
            dmarc_color = CORTECHS_ERROR
        
        add_card("DMARC — Domain-based Message Auth", "📋", dmarc_items, dmarc_status, dmarc_color)
        
        # Score final
        score_frame = tk.Frame(self.results_content, bg=CORTECHS_SURFACE,
                               highlightbackground=CORTECHS_ACCENT,
                               highlightthickness=2, bd=0, padx=15, pady=12)
        score_frame.pack(fill="x", pady=(8, 0))
        
        score_color = CORTECHS_SUCCESS if score >= 3 else CORTECHS_WARNING if score >= 1 else CORTECHS_ERROR
        score_text = "🔒 Excellent" if score == 4 else "⚠️ Correct" if score >= 2 else "❌ Insuffisant"
        
        tk.Label(score_frame, text=f"📊 Score sécurité email : {score}/{max_score}",
                bg=CORTECHS_SURFACE, fg=CORTECHS_ACCENT,
                font=("Segoe UI", 12, "bold")).pack(side="left")
        tk.Label(score_frame, text=score_text,
                bg=CORTECHS_SURFACE, fg=score_color,
                font=("Segoe UI", 11, "bold")).pack(side="right")
        
        self.status_label.config(text=f"✅ Analyse terminée pour {domain} — Score {score}/{max_score}")
        
        # Reset scroll
        self.results_canvas.yview_moveto(0)
    
    def clear_results(self):
        for widget in self.results_content.winfo_children():
            widget.destroy()
        self.status_label.config(text="")


# ─── Blacklist Tab ───────────────────────────────────────────────────────────

class BlacklistTab(ttk.Frame):
    """Onglet de vérification blacklist DNS."""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(20, 10), padx=20)
        
        ttk.Label(header, text="🚫 Blacklist DNS", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Vérification DNSBL (Spamhaus, Barracuda, SpamCop...)", 
                  style="Subtitle.TLabel").pack(side="left", padx=(15, 0))
        
        # Input row
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        ip_frame = ttk.Frame(input_frame)
        ip_frame.pack(side="left", fill="x", expand=True)
        ttk.Label(ip_frame, text="Adresse IP à vérifier").pack(anchor="w")
        self.ip_entry = ttk.Entry(ip_frame, font=("Consolas", 12))
        self.ip_entry.pack(fill="x", pady=(2, 0))
        self.ip_entry.bind("<Return>", lambda e: self.do_check())
        
        # Quick resolve toggle
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(side="left", padx=(10, 0))
        ttk.Label(quick_frame, text="Domaine → IP").pack(anchor="w")
        
        self.quick_domain = ttk.Entry(quick_frame, font=("Consolas", 10), width=25)
        self.quick_domain.pack(side="left", pady=(2, 0))
        
        self.resolve_btn = ttk.Button(quick_frame, text="Résoudre",
                                       style="Secondary.TButton",
                                       command=self.resolve_domain)
        self.resolve_btn.pack(side="left", padx=(5, 0))
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        self.check_btn = ttk.Button(btn_frame, text="🚫 Vérifier les blacklists",
                                     command=self.do_check)
        self.check_btn.pack(side="left")
        
        self.clear_btn = ttk.Button(btn_frame, text="Effacer",
                                     style="Secondary.TButton",
                                     command=self.clear_results)
        self.clear_btn.pack(side="left", padx=(8, 0))
        
        self.progress = ttk.Progressbar(btn_frame, mode="determinate", length=200)
        self.progress.pack(side="left", padx=(15, 0))
        
        self.status_label = ttk.Label(btn_frame, text="", style="Status.TLabel")
        self.status_label.pack(side="left", padx=(15, 0))
        
        # Results
        results_frame = ttk.Frame(self)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        columns = ("blacklist", "listed", "response", "status")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        self.tree.heading("blacklist", text="Blacklist")
        self.tree.heading("listed", text="Listé")
        self.tree.heading("response", text="Réponse")
        self.tree.heading("status", text="Statut")
        self.tree.column("blacklist", width=180)
        self.tree.column("listed", width=70, anchor="center")
        self.tree.column("response", width=140)
        self.tree.column("status", width=120)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.tree.tag_configure("clean", foreground=CORTECHS_SUCCESS)
        self.tree.tag_configure("listed", foreground=CORTECHS_ERROR, 
                                 background="#3a1a1a")
        self.tree.tag_configure("unknown", foreground=CORTECHS_WARNING)
    
    def resolve_domain(self):
        domain = self.quick_domain.get().strip()
        if not domain:
            return
        
        try:
            ip = socket.gethostbyname(domain)
            self.ip_entry.delete(0, "end")
            self.ip_entry.insert(0, ip)
        except socket.gaierror:
            messagebox.showwarning("Erreur", f"Impossible de résoudre {domain}")
    
    def do_check(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Erreur", "Veuillez entrer une adresse IP.")
            return
        
        # Validation basique IP
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            messagebox.showwarning("Erreur", "Format IP invalide. Exemple: 1.2.3.4")
            return
        
        self.check_btn.config(state="disabled", text="⏳ Vérification...")
        self.clear_results()
        
        total = len(DNS_BLACKLISTS)
        self.progress["maximum"] = total
        self.progress["value"] = 0
        
        thread = threading.Thread(target=self._run_check, args=(ip, total))
        thread.daemon = True
        thread.start()
    
    def _run_check(self, ip, total):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            reversed_ip = ".".join(reversed(ip.split(".")))
            futures = {}
            
            for name, zone in DNS_BLACKLISTS.items():
                query_name = f"{reversed_ip}.{zone}"
                
                def do_query(qname=query_name):
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        resolver.lifetime = 3
                        answers = resolver.resolve(qname, "A")
                        return {
                            "listed": True,
                            "response": str(answers[0]),
                            "status": "⚠️ LISTÉE"
                        }
                    except dns.resolver.NXDOMAIN:
                        return {"listed": False, "response": "NXDOMAIN", "status": "✅ Clean"}
                    except dns.resolver.Timeout:
                        return {"listed": False, "response": "Timeout", "status": "⏱ Timeout"}
                    except Exception as e:
                        return {"listed": False, "response": str(e)[:50], "status": "❓ Inconnu"}
                
                futures[executor.submit(do_query)] = name
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                completed += 1
                try:
                    result = future.result(timeout=5)
                except Exception:
                    result = {"listed": False, "response": "Exception", "status": "❓ Inconnu"}
                
                results[name] = result
                self.app.root.after(0, lambda v=completed: self.progress.configure(value=v))
        
        self.app.root.after(0, lambda: self._display_results(results, ip))
    
    def _display_results(self, results, ip):
        self.check_btn.config(state="normal", text="🚫 Vérifier les blacklists")
        
        listed_count = sum(1 for r in results.values() if r["listed"])
        total = len(results)
        
        for name, result in sorted(results.items(), 
                                    key=lambda x: (not x[1]["listed"], x[0])):
            tag = "listed" if result["listed"] else "clean" if result["status"] == "✅ Clean" else "unknown"
            
            self.tree.insert("", "end",
                values=(name, "OUI" if result["listed"] else "Non",
                        result["response"], result["status"]),
                tags=(tag,))
        
        if listed_count == 0:
            status_text = f"✅ IP {ip} propre — aucune blacklist parmi {total}"
            color = CORTECHS_SUCCESS
        else:
            status_text = f"⚠️ IP {ip} listée sur {listed_count}/{total} blacklists !"
            color = CORTECHS_ERROR
        
        self.status_label.config(text=status_text)
    
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress["value"] = 0
        self.status_label.config(text="")


# ─── Main Application ────────────────────────────────────────────────────────

class DNSCheckerApp:
    """Application principale DNS Checker."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("DNS CHECKER — Diagnostic DNS · Cortechs")
        root.geometry("1000x700")
        root.minsize(800, 600)
        
        # Appliquer le thème
        DarkTheme.apply(root)
        
        # Icon
        try:
            icon = tk.PhotoImage(file="static/icon.png")
            root.iconphoto(True, icon)
        except Exception:
            pass
        
        # Build UI
        self._build_ui()
    
    def _build_ui(self):
        # Barre titre
        title_frame = tk.Frame(self.root, bg=CORTECHS_DARK, padx=20, pady=15)
        title_frame.pack(fill="x")
        
        # Logo/accent bar
        accent_bar = tk.Frame(title_frame, bg=CORTECHS_ACCENT, width=4, height=30)
        accent_bar.pack(side="left", padx=(0, 12))
        accent_bar.pack_propagate(False)
        
        tk.Label(title_frame, text="DNS CHECKER",
                bg=CORTECHS_DARK, fg=CORTECHS_ACCENT,
                font=("Segoe UI", 18, "bold")).pack(side="left")
        
        tk.Label(title_frame, text="Diagnostic DNS complet — Like whatsmydns.net + MXToolbox",
                bg=CORTECHS_DARK, fg=CORTECHS_TEXT_SECONDARY,
                font=("Segoe UI", 9)).pack(side="left", padx=(15, 0))
        
        # Version
        tk.Label(title_frame, text="v1.0",
                bg=CORTECHS_DARK, fg=CORTECHS_BORDER,
                font=("Segoe UI", 8)).pack(side="right")
        
        # Séparateur
        sep = tk.Frame(self.root, bg=CORTECHS_BORDER, height=1)
        sep.pack(fill="x")
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)
        
        # Tabs
        self.lookup_tab = DNSLookupTab(self.notebook, self)
        self.propagation_tab = PropagationTab(self.notebook, self)
        self.email_tab = EmailSecurityTab(self.notebook, self)
        self.blacklist_tab = BlacklistTab(self.notebook, self)
        
        self.notebook.add(self.lookup_tab, text="  🔍 DNS Lookup  ")
        self.notebook.add(self.propagation_tab, text="  🌍 Propagation  ")
        self.notebook.add(self.email_tab, text="  📧 Sécurité Email  ")
        self.notebook.add(self.blacklist_tab, text="  🚫 Blacklists  ")
        
        # Status bar
        status_frame = tk.Frame(self.root, bg=CORTECHS_SURFACE, height=28)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        
        tk.Label(status_frame, 
                text=f"  dnspython {'✅ installé' if HAS_DNSPYTHON else '❌ non installé'}  |  "
                     f"{len(GLOBAL_RESOLVERS)} résolveurs globaux  |  "
                     f"{len(DNS_BLACKLISTS)} blacklists DNS  |  "
                     f"Cortechs © 2026",
                bg=CORTECHS_SURFACE, fg=CORTECHS_TEXT_SECONDARY,
                font=("Segoe UI", 8), anchor="w").pack(side="left", fill="x")


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = DNSCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
