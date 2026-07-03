"""
DNS CHECKER — Streamlit Web App v3.0
Diagnostic DNS friendly-user · Cortechs © 2026
CT 115 (192.168.17.35:8506)
"""

import sys, os
sys.path.insert(0, "/opt/dns-checker")

import streamlit as st
import pandas as pd
import concurrent.futures
from datetime import datetime
from collections import defaultdict
import socket, re, io

import dns
from dns_engine import (
    DNSEngine, GLOBAL_RESOLVERS, DNS_BLACKLISTS, RECORD_TYPES,
    HAS_DNSPYTHON
)
from report import generate_report_pdf
import plotly.graph_objects as go

# ─── Geo ────────────────────────────────────────────────────────────────────

RESOLVER_GEO = {
    "Google 🇺🇸": (37.42, -122.08), "Google (alt) 🇺🇸": (37.42, -122.06),
    "Cloudflare 🇺🇸": (37.77, -122.42), "Cloudflare (alt) 🇺🇸": (37.77, -122.39),
    "Quad9 🇺🇸": (37.44, -122.14), "Level3 🇺🇸": (39.74, -104.99),
    "Norton 🇺🇸": (37.39, -122.08), "Neustar 🇺🇸": (39.01, -77.43),
    "Dyn 🇺🇸": (42.99, -71.46), "Hurricane Elec 🇺🇸": (37.26, -121.95),
    "CenturyLink 🇺🇸": (38.90, -77.01), "ControlD 🇨🇦": (43.65, -79.38),
    "Quad9 🇨🇭": (47.38, 8.54), "Quad9 (alt) 🇨🇭": (47.38, 8.55),
    "AdGuard 🇩🇪": (50.11, 8.68), "Freenom (alt) 🇫🇷": (48.86, 2.37),
    "NextDNS 🇦🇹": (48.21, 16.37), "dnsforge 🇩🇪": (50.11, 8.68),
    "OpenNIC 🇩🇪": (52.52, 13.40), "CleanBrowsing 🇬🇧": (51.51, -0.13),
    "SafeDNS 🇺🇸": (38.91, -77.04), "Comodo 🇭🇰": (22.32, 114.17),
    "Yandex 🇷🇺": (55.75, 37.62), "AliDNS 🇨🇳": (30.27, 120.15),
}

# ─── Page Config ────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="DNS CHECKER · Cortechs",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="auto"
)

# ─── CSS ────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    :root { --bg: #070d16; --surface: #0d1a2d; --border: #152540; --accent: #c9a94e; --text: #e2e8f0; --muted: #94a3b8; }
    .stApp { background: var(--bg); }
    
    /* ===== HEADER ===== */
    .topbar {
        background: linear-gradient(135deg, #0b1628 0%, #101f38 100%);
        border-bottom: 3px solid var(--accent);
        padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem;
    }
    .topbar .shield {
        background: var(--accent); color: #0a1628;
        width: 44px; height: 44px; border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        font-size: 24px; font-weight: 900;
    }
    .topbar h1 { color: var(--accent); font-size: 1.5rem; font-weight: 700; margin: 0; }
    .topbar .tagline { color: #5a7090; font-size: 0.8rem; }
    
    /* ===== STATS ROW ===== */
    .statrow { display: flex; gap: 0.6rem; padding: 0.8rem 2rem; flex-wrap: wrap; }
    .statpill {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 20px; padding: 0.4rem 1rem;
        font-size: 0.8rem; color: var(--muted);
        display: flex; align-items: center; gap: 0.4rem;
    }
    .statpill strong { color: var(--accent); }
    
    /* ===== WELCOME ===== */
    .welcome {
        text-align: center; padding: 3rem 2rem;
    }
    .welcome h2 { color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }
    .welcome p { color: var(--muted); font-size: 1rem; max-width: 600px; margin: 0 auto 1.5rem auto; }
    .example-row { display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap; margin: 1rem 0; }
    .example-chip {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 0.5rem 1rem;
        color: var(--text); font-size: 0.85rem;
        cursor: pointer; transition: all 0.15s;
    }
    .example-chip:hover { border-color: var(--accent); color: var(--accent); }
    
    /* ===== TABS ===== */
    .stTabs [data-baseweb="tab-list"] { gap: 2px; background: transparent; padding: 0 2rem; }
    .stTabs [data-baseweb="tab"] {
        background: var(--surface); color: var(--muted); border-radius: 10px 10px 0 0;
        padding: 0.5rem 1.2rem; border: 1px solid var(--border); font-size: 0.85rem;
    }
    .stTabs [aria-selected="true"] { background: #122340; color: var(--accent); border-bottom: 2px solid var(--accent); }
    
    /* ===== CARDS ===== */
    .r-card {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 10px; padding: 0.7rem 1rem; margin-bottom: 5px;
        display: flex; align-items: center; gap: 0.7rem;
    }
    .r-card .n { color: var(--muted); font-size: 0.75rem; width: 22px; text-align: right; }
    .r-card .badge {
        background: var(--accent); color: #0a1628;
        padding: 2px 8px; border-radius: 5px; font-size: 0.68rem; font-weight: 700;
    }
    .r-card .v { color: var(--text); font-family: 'Consolas', monospace; font-size: 0.85rem; word-break: break-all; flex: 1; }
    
    /* ===== KPI TILES ===== */
    .kpi {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 14px; padding: 1rem; text-align: center;
    }
    .kpi .num { font-size: 2rem; font-weight: 700; }
    .kpi .num.g { color: #4ade80; }
    .kpi .num.y { color: #facc15; }
    .kpi .num.r { color: #f87171; }
    .kpi .num.a { color: var(--accent); }
    .kpi .lbl { font-size: 0.7rem; color: var(--muted); margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.5px; }
    
    /* ===== PROP CHIPS ===== */
    .p-grid { display: flex; flex-wrap: wrap; gap: 5px; }
    .p-chip {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 4px 10px; border-radius: 6px; font-size: 0.76rem;
        border: 1px solid transparent;
    }
    .p-chip.good { background: #0a2818; border-color: #1a5a32; color: #4ade80; }
    .p-chip.warn { background: #281e08; border-color: #5a4518; color: #facc15; }
    .p-chip.bad  { background: #280a0a; border-color: #5a1515; color: #f87171; }
    .p-chip .dot { width: 7px; height: 7px; border-radius: 50%; }
    .p-chip .dot.good-bg { background: #4ade80; }
    .p-chip .dot.warn-bg { background: #facc15; }
    .p-chip .dot.bad-bg  { background: #f87171; }
    
    /* ===== SECURITY ===== */
    .sec {
        background: var(--surface); border-radius: 14px;
        padding: 1.2rem 1.4rem; margin-bottom: 0.7rem;
        border-left: 5px solid #333;
    }
    .sec.ok   { border-left-color: #4ade80; }
    .sec.warn { border-left-color: #f59e0b; }
    .sec.fail { border-left-color: #f87171; }
    .sec h4 { color: var(--text); margin: 0 0 0.3rem 0; font-size: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    .sec .s { font-weight: 700; font-size: 0.82rem; }
    .sec .d { color: var(--text); font-family: 'Consolas', monospace; font-size: 0.78rem; margin-top: 0.3rem; word-break: break-all; }
    .sec .d.mute { color: var(--muted); }
    
    /* ===== SCORE ===== */
    .score-badge {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 8px 20px; border-radius: 24px; font-weight: 700; font-size: 0.95rem;
    }
    .score-badge.high { background: #0a2818; border: 2px solid #4ade80; color: #4ade80; }
    .score-badge.med  { background: #281e08; border: 2px solid #facc15; color: #facc15; }
    .score-badge.low  { background: #280a0a; border: 2px solid #f87171; color: #f87171; }
    
    /* ===== BL CHIPS ===== */
    .bl-row { display: flex; flex-wrap: wrap; gap: 5px; margin: 0.8rem 0; }
    .bl-pill {
        padding: 5px 12px; border-radius: 16px; font-size: 0.76rem; display: inline-flex; align-items: center; gap: 4px;
    }
    .bl-pill.clean  { background: #0a2818; color: #4ade80; border: 1px solid #1a5a32; }
    .bl-pill.listed { background: #280a0a; color: #f87171; border: 1px solid #5a1515; font-weight: 700; }
    .bl-pill.unknown { background: #151525; color: #888; border: 1px solid #333; }
    
    /* ===== INPUTS ===== */
    .stTextInput input {
        background: var(--surface) !important; border: 1px solid var(--border) !important;
        color: var(--text) !important; border-radius: 10px !important; padding: 10px 14px !important;
    }
    .stTextInput input:focus { border-color: var(--accent) !important; box-shadow: 0 0 0 3px rgba(201,169,78,0.12) !important; }
    .stSelectbox>div>div { background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; }
    
    /* ===== BUTTONS ===== */
    .stButton button {
        background: var(--accent) !important; color: #0a1628 !important; font-weight: 700 !important;
        border: none !important; border-radius: 10px !important; padding: 0.5rem 1.4rem !important;
        transition: all 0.15s !important;
    }
    .stButton button:hover { background: #d4b860 !important; transform: translateY(-1px); }
    
    /* ===== SIDEBAR ===== */
    section[data-testid="stSidebar"] {
        background: #0a1320; border-right: 1px solid var(--border);
    }
    section[data-testid="stSidebar"] .stMarkdown,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] .stCaption,
    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] h3 {
        color: #e2e8f0 !important;
    }
    section[data-testid="stSidebar"] .stTextInput label {
        color: #c0cddc !important; font-size: 0.85rem !important; font-weight: 500 !important;
    }
    
    /* ===== EXPANDER ===== */
    .streamlit-expanderHeader {
        background: var(--surface) !important; border: 1px solid var(--border) !important;
        border-radius: 10px !important; color: var(--text) !important; font-weight: 600 !important;
    }
    
    /* ===== FOOTER ===== */
    .foot { text-align: center; color: #2a4060; font-size: 0.7rem; padding: 1rem; border-top: 1px solid #102038; margin-top: 2rem; }
    
    hr { border-color: var(--border); }
</style>
""", unsafe_allow_html=True)

# ─── HEADER ─────────────────────────────────────────────────────────────────

col_logo, col_title = st.columns([0.07, 0.93])
with col_logo:
    st.image("/opt/dns-checker/static/cortechs-logo.png", width=52)
with col_title:
    st.markdown("""
    <div style="padding-top:0.3rem;">
        <span style="color:#c9a94e;font-size:1.5rem;font-weight:700;">DNS CHECKER</span><br>
        <span style="color:#5a7090;font-size:0.8rem;">Diagnostic DNS mondial · Simple, rapide, complet</span>
    </div>
    """, unsafe_allow_html=True)

st.markdown('<div style="height:3px;background:linear-gradient(90deg, #c9a94e, #1a3050);margin:0.8rem 0 1.2rem 0;"></div>', unsafe_allow_html=True)

# ─── STAT PILLS ─────────────────────────────────────────────────────────────

st.markdown(f"""
<div class="statrow">
    <span class="statpill">{'✅' if HAS_DNSPYTHON else '❌'} dnspython <strong>{dns.__version__ if HAS_DNSPYTHON else 'N/A'}</strong></span>
    <span class="statpill">🌐 <strong>{len(GLOBAL_RESOLVERS)}</strong> résolveurs mondiaux</span>
    <span class="statpill">🛡️ <strong>{len(DNS_BLACKLISTS)}</strong> blacklists</span>
    <span class="statpill">📋 <strong>{len(RECORD_TYPES)}</strong> types DNS</span>
    <span class="statpill">📄 Rapport PDF inclus</span>
</div>
""", unsafe_allow_html=True)

# ─── SESSION STATE ──────────────────────────────────────────────────────────

for key in ["results_lookup", "results_prop", "results_email", "results_bl", "active_domain"]:
    if key not in st.session_state:
        st.session_state[key] = None

# ─── SIDEBAR ────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.shields.io/badge/DNS_CHECKER-v3.0-c9a94e?style=for-the-badge", width=180)
    st.markdown("---")
    
    # Quick Scan
    st.markdown("### ⚡ Scan rapide")
    st.markdown('<div style="color:#c0cddc;font-size:0.82rem;margin-bottom:0.8rem;">Tout vérifier en un clic : DNS + Email + Propagation</div>', unsafe_allow_html=True)
    
    qs_domain = st.text_input("Domaine", placeholder="ex: cortechs.fr", key="qs_domain")
    qs_ip = st.text_input("IP (optionnel)", placeholder="ex: 217.160.0.200", key="qs_ip")
    
    if st.button("⚡ Lancer le scan complet", use_container_width=True, type="primary"):
        if qs_domain:
            st.session_state.active_domain = qs_domain.strip()
            with st.spinner("Scan complet en cours..."):
                ip = qs_ip.strip() or None
                # Lookup
                lookup = {}
                for rt in ["A", "AAAA", "MX", "TXT", "NS", "SOA"]:
                    r = DNSEngine.query(qs_domain.strip(), rt)
                    if r["records"]: lookup[rt.lower()] = r["records"]
                st.session_state.results_lookup = lookup
                
                # Email
                mx = DNSEngine.query_mx(qs_domain.strip())
                spf = DNSEngine.check_spf(qs_domain.strip())
                dkim = DNSEngine.check_dkim(qs_domain.strip(), "default")
                dmarc = DNSEngine.check_dmarc(qs_domain.strip())
                st.session_state.results_email = {"mx": mx, "spf": spf, "dkim": dkim, "dmarc": dmarc}
                
                # Propagation (light: 6 resolvers)
                prop_results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                    sample = dict(list(GLOBAL_RESOLVERS.items())[:6])
                    futures = {ex.submit(DNSEngine.query, qs_domain.strip(), "A", ip_addr, 5): name 
                               for name, ip_addr in sample.items()}
                    for f in concurrent.futures.as_completed(futures):
                        name = futures[f]
                        try: r = f.result(timeout=5)
                        except: r = {"records": [], "error": "Exception"}
                        prop_results.append((name, sample[name], r))
                st.session_state.results_prop = prop_results
                
                # Blacklist if IP
                if ip:
                    import dns.resolver as dnsr
                    bl_results = {}
                    rip = ".".join(reversed(ip.split(".")))
                    for name, zone in DNS_BLACKLISTS.items():
                        try:
                            rx = dnsr.Resolver(); rx.timeout = 3; rx.lifetime = 3
                            ans = rx.resolve(f"{rip}.{zone}", "A")
                            bl_results[name] = {"listed": True, "response": str(ans[0])}
                        except dnsr.NXDOMAIN:
                            bl_results[name] = {"listed": False, "response": "NXDOMAIN"}
                        except:
                            bl_results[name] = {"listed": False, "response": "?"}
                    st.session_state.results_bl = {"ip": ip, "results": bl_results}
            st.success("✅ Scan terminé ! Voir les onglets ↓")
            st.rerun()
        else:
            st.warning("Entre un domaine d'abord")
    
    st.markdown("---")
    
    # Rapport PDF
    st.markdown("### 📄 Rapport PDF")
    st.markdown('<div style="color:#94a3b8;font-size:0.8rem;">Rapport complet de diagnostic DNS</div>', unsafe_allow_html=True)
    
    rpt_domain = st.text_input("Domaine", placeholder="cortechs.fr", key="rpt_domain")
    rpt_ip = st.text_input("IP (blacklist)", placeholder="217.160.0.200", key="rpt_ip")
    
    if st.button("📄 Générer le rapport PDF", use_container_width=True):
        if rpt_domain:
            with st.spinner("Génération du rapport..."):
                try:
                    pdf = generate_report_pdf(rpt_domain.strip(), rpt_ip.strip() or None)
                    st.download_button("📥 Télécharger", pdf,
                        f"dns-{rpt_domain.strip()}-{datetime.now():%Y%m%d-%H%M}.pdf",
                        "application/pdf", use_container_width=True)
                    st.success(f"✅ {len(pdf)//1024} Ko")
                except Exception as e:
                    st.error(str(e))
    
    st.markdown("---")
    st.markdown('<div style="color:#94a3b8;font-size:0.78rem;">Cortechs © 2026 · CT 115</div>', unsafe_allow_html=True)


# ─── TABS ───────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠  Accueil", "🔍  DNS Lookup", "🌍  Propagation", "📧  Sécurité Email", "🚫  Blacklists"
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 0: HOME / QUICK OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════

with tab1:
    # Show results if quick scan was done
    if st.session_state.results_lookup and st.session_state.active_domain:
        domain = st.session_state.active_domain
        st.success(f"### ✅ Résultats pour **{domain}**")
        
        col_a, col_b, col_c = st.columns(3)
        
        with col_a:
            lookup = st.session_state.results_lookup
            count = sum(len(v) for v in lookup.values())
            st.markdown(f'<div class="kpi"><div class="num a">{count}</div><div class="lbl">Enregistrements DNS</div></div>', unsafe_allow_html=True)
        
        with col_b:
            email = st.session_state.results_email or {}
            score = 0
            if email:
                if email["mx"]["mx_records"]: score += 1
                if email["spf"]["has_spf"] and email["spf"]["all_mechanism"]: score += 1
                if email["dkim"]["has_dkim"]: score += 1
                if email["dmarc"]["has_dmarc"] and ("reject" in email["dmarc"]["policy"].lower() or "quarantine" in email["dmarc"]["policy"].lower()): score += 1
            cls = "g" if score >= 4 else "y" if score >= 2 else "r"
            st.markdown(f'<div class="kpi"><div class="num {cls}">{score}/4</div><div class="lbl">Score Sécurité Email</div></div>', unsafe_allow_html=True)
        
        with col_c:
            prop = st.session_state.results_prop or []
            ok = sum(1 for _,_,r in prop if r["error"] is None and r["records"])
            cls = "g" if ok == len(prop) else "y"
            st.markdown(f'<div class="kpi"><div class="num {cls}">{ok}/{len(prop)}</div><div class="lbl">Résolveurs OK</div></div>', unsafe_allow_html=True)
        
        # Quick DNS records
        if lookup:
            st.markdown("#### 🔍 Enregistrements DNS")
            for rt in ["a", "aaaa", "mx", "txt", "ns", "soa"]:
                recs = lookup.get(rt)
                if recs:
                    val = ", ".join(str(r)[:60] for r in recs[:3])
                    st.markdown(f'<div style="color:#e2e8f0;font-family:Consolas,monospace;font-size:0.85rem;padding:2px 0;"><span style="color:#c9a94e;font-weight:700;">{rt.upper()}</span> — {val}</div>', unsafe_allow_html=True)
        
        # Quick email
        if email:
            st.markdown("#### 📧 Sécurité Email")
            spf = email["spf"]; dkim = email["dkim"]; dmarc = email["dmarc"]
            icons = []
            icons.append("✅" if spf["has_spf"] else "❌")
            icons.append("✅" if dkim["has_dkim"] else "❌")
            icons.append("✅" if dmarc["has_dmarc"] else "❌")
            st.markdown(f'<div style="color:#e2e8f0;font-size:0.9rem;">SPF {icons[0]} · DKIM {icons[1]} · DMARC {icons[2]}  —  <span style="color:#c9a94e;font-weight:700;">Score {score}/4</span></div>', unsafe_allow_html=True)
        
        if st.session_state.results_bl:
            bl = st.session_state.results_bl
            listed = sum(1 for r in bl["results"].values() if r["listed"])
            st.markdown("#### 🚫 Blacklists")
            color = "r" if listed else "g"
            st.markdown(f'<span style="color:{"#f87171" if listed else "#4ade80"};font-weight:700;">{listed}/{len(bl["results"])} listé</span>', unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown('<div style="color:#94a3b8;font-size:0.8rem;">Détails complets dans les onglets 🔍 🌍 📧 🚫</div>', unsafe_allow_html=True)
    else:
        # Welcome state
        st.markdown("""
        <div class="welcome">
            <h2>🔍 Bienvenue sur DNS CHECKER</h2>
            <p>Diagnostiquez n'importe quel nom de domaine en un clin d'œil. 
            DNS, propagation mondiale, sécurité email, blacklists — tout au même endroit.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Quick actions
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div class="kpi" style="cursor:default">
                <div style="font-size:2rem">🔍</div>
                <div style="font-weight:700;color:#cdd6e4;margin:0.4rem 0;">DNS Lookup</div>
                <div style="font-size:0.75rem;color:#6b7d95;">A, AAAA, MX, TXT, NS, SOA, CNAME…</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown("""
            <div class="kpi" style="cursor:default">
                <div style="font-size:2rem">🌍</div>
                <div style="font-weight:700;color:#cdd6e4;margin:0.4rem 0;">Propagation</div>
                <div style="font-size:0.75rem;color:#6b7d95;">24 résolveurs dans le monde</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown("""
            <div class="kpi" style="cursor:default">
                <div style="font-size:2rem">📧</div>
                <div style="font-weight:700;color:#cdd6e4;margin:0.4rem 0;">Sécurité Email</div>
                <div style="font-size:0.75rem;color:#6b7d95;">SPF · DKIM · DMARC · MX</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("#### 💡 Exemples de domaines à tester")
        examples = ["cortechs.fr", "google.com", "github.com", "eff.org", "gouv.fr"]
        cols = st.columns(len(examples))
        for i, ex in enumerate(examples):
            with cols[i]:
                if st.button(ex, key=f"ex_{ex}", use_container_width=True):
                    st.session_state.active_domain = ex
                    # Trigger quick scan via rerun
                    st.info(f"👉 Ouvre le panneau latéral (←) et lance un **Scan rapide** pour **{ex}**")
        
        st.markdown("---")
        st.markdown("#### 🚀 Comment ça marche ?")
        st.markdown("""
        1. **Ouvre le panneau latéral** (flèche en haut à gauche ←)
        2. **Entre un domaine** et lance le ⚡ Scan rapide
        3. **Explore les onglets** pour les détails
        4. **Génère un rapport PDF** depuis le panneau latéral
        """)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: DNS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

with tab2:
    # If quick scan results exist, show them
    if st.session_state.results_lookup and st.session_state.active_domain:
        domain = st.session_state.active_domain
        st.info(f"📋 Résultats du scan rapide pour **{domain}** — ou fais une recherche manuelle ci-dessous")
    
    st.markdown('<div style="color:#94a3b8;font-size:0.82rem;">Recherche manuelle d\'enregistrements DNS</div>', unsafe_allow_html=True)
    col_d, col_t, col_r, col_b = st.columns([2.5, 1, 2, 1])
    
    with col_d:
        domain = st.text_input("Domaine", placeholder="google.com", key="lu_domain", label_visibility="collapsed")
    with col_t:
        rt = st.selectbox("Type", RECORD_TYPES, index=0, key="lu_type", label_visibility="collapsed")
    with col_r:
        ropts = ["🖥️ Système"] + [f"{n} ({ip})" for n, ip in GLOBAL_RESOLVERS.items()]
        rchoice = st.selectbox("Résolveur", ropts, key="lu_resolver", label_visibility="collapsed")
    with col_b:
        btn = st.button("🔍 Rechercher", key="lu_btn", use_container_width=True)
    
    if btn and domain:
        rip = None
        if not rchoice.startswith("🖥️"):
            m = re.findall(r'\(([^)]+)\)', rchoice)
            if m: rip = m[-1]
        
        with st.spinner(f"Recherche {rt} pour {domain}..."):
            r = DNSEngine.query(domain.strip(), rt, rip, timeout=8)
        
        if r["error"]:
            st.error(f"❌ {r['error']}")
        elif r["records"]:
            st.success(f"**{len(r['records'])}** enregistrement(s) {rt}")
            for i, rec in enumerate(r["records"], 1):
                st.markdown(f'<div class="r-card"><span class="n">{i}</span><span class="badge">{rt}</span><span class="v">{rec}</span></div>', unsafe_allow_html=True)
        else:
            st.info("Aucun enregistrement trouvé")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: PROPAGATION
# ═══════════════════════════════════════════════════════════════════════════════

with tab3:
    st.markdown('<div style="color:#94a3b8;font-size:0.82rem;">Vérifie la propagation DNS sur 24 résolveurs dans le monde</div>', unsafe_allow_html=True)
    
    col_pd, col_pt, col_pb = st.columns([2.5, 1, 1])
    with col_pd:
        pdomain = st.text_input("Domaine", placeholder="google.com", key="pr_domain", label_visibility="collapsed")
    with col_pt:
        ptype = st.selectbox("Type", RECORD_TYPES, index=0, key="pr_type", label_visibility="collapsed")
    with col_pb:
        pbtn = st.button("🌍 Vérifier", key="pr_btn", use_container_width=True)
    
    if pbtn and pdomain:
        bar = st.progress(0); stxt = st.empty()
        results = []
        total = len(GLOBAL_RESOLVERS)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(DNSEngine.query, pdomain.strip(), ptype, ip, 6): (n, ip) for n, ip in GLOBAL_RESOLVERS.items()}
            for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
                n, ip = futs[f]
                try: res = f.result(timeout=6)
                except: res = {"records": [], "error": "Exception"}
                results.append((n, ip, res))
                bar.progress(i/total); stxt.text(f"{i}/{total} résolveurs...")
        
        bar.empty(); stxt.empty()
        results.sort(key=lambda x: (x[2]["error"] is not None or not x[2]["records"], x[0]))
        
        ok = sum(1 for _,_,r in results if r["error"] is None and r["records"])
        consensus = defaultdict(list)
        for n, ip, r in results:
            if r["error"] is None and r["records"]: consensus[r["records"][0]].append(n)
        mc = max(consensus, key=lambda k: len(consensus[k]), default="N/A")
        cpct = (len(consensus[mc])/total*100) if consensus else 0
        
        cm1, cm2, cm3, cm4 = st.columns(4)
        with cm1:
            c = "g" if ok==total else "r" if ok<total/2 else "y"
            st.markdown(f'<div class="kpi"><div class="num {c}">{ok}/{total}</div><div class="lbl">OK</div></div>', unsafe_allow_html=True)
        with cm2:
            st.markdown(f'<div class="kpi"><div class="num a">{cpct:.0f}%</div><div class="lbl">Consensus</div></div>', unsafe_allow_html=True)
        with cm3:
            st.markdown(f'<div class="kpi"><div class="num a" style="font-size:1rem;word-break:break-all;">{mc[:20]}</div><div class="lbl">Majoritaire</div></div>', unsafe_allow_html=True)
        with cm4:
            st.markdown(f'<div class="kpi"><div class="num a">{ok}</div><div class="lbl">Réponses</div></div>', unsafe_allow_html=True)
        
        # Map
        mlats, mlons, mcols, mtxts, msizes = [], [], [], [], []
        for n, ip, r in results:
            geo = RESOLVER_GEO.get(n)
            if geo:
                mlats.append(geo[0]); mlons.append(geo[1])
                if r["error"] is None and r["records"]:
                    mcols.append("#4ade80"); msizes.append(12)
                elif r["error"] is None:
                    mcols.append("#facc15"); msizes.append(9)
                else:
                    mcols.append("#f87171"); msizes.append(9)
                mtxts.append(f"{n}<br>{ip}<br>{r['records'][0] if r['records'] else r.get('error','?')}")
        
        if mlats:
            fig = go.Figure(go.Scattergeo(lon=mlons, lat=mlats, mode="markers",
                marker=dict(size=msizes, color=mcols, line=dict(width=1, color="#070d16")),
                text=mtxts, hoverinfo="text"))
            fig.update_layout(geo=dict(projection_type="natural earth", showland=True,
                landcolor="#0d1a2d", showocean=True, oceancolor="#070d16",
                showcountries=True, countrycolor="#152540", coastlinecolor="#152540",
                showframe=False, bgcolor="#070d16"),
                paper_bgcolor="#070d16", plot_bgcolor="#070d16",
                margin=dict(l=5,r=5,t=5,b=5), height=360, showlegend=False, dragmode=False)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        
        # Chips
        chips = '<div class="p-grid">'
        for n, ip, r in results:
            if r["error"] is None and r["records"]:
                cls, dot = "good", "good-bg"
                v = r["records"][0][:35]
                if len(r["records"])>1: v += f" +{len(r['records'])-1}"
            elif r["error"] is None:
                cls, dot = "warn", "warn-bg"; v = "vide"
            else:
                cls, dot = "bad", "bad-bg"; v = r["error"][:30]
            chips += f'<span class="p-chip {cls}" title="{n} ({ip})"><span class="dot {dot}"></span><strong>{n.split()[0]}</strong> {v}</span>'
        chips += '</div>'
        st.markdown(chips, unsafe_allow_html=True)
        
        with st.expander("📋 Tableau détaillé"):
            dat = [{"Résolveur": n, "IP": ip, "Résultat": (r["records"][0] if r["records"] else r.get("error","?")) + (f" +{len(r['records'])-1}" if r["records"] and len(r["records"])>1 else ""),
                    "OK": r["error"] is None and bool(r["records"])}
                   for n, ip, r in results]
            st.dataframe(pd.DataFrame(dat), use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: EMAIL SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

with tab4:
    # Show quick scan results if available
    if st.session_state.results_email and st.session_state.active_domain:
        email = st.session_state.results_email
        domain = st.session_state.active_domain
        st.success(f"📋 Résultats du scan rapide pour **{domain}**")
        
        score = 0
        if email["mx"]["mx_records"]: score += 1
        if email["spf"]["has_spf"] and email["spf"]["all_mechanism"]: score += 1
        if email["dkim"]["has_dkim"]: score += 1
        if email["dmarc"]["has_dmarc"] and ("reject" in email["dmarc"]["policy"].lower() or "quarantine" in email["dmarc"]["policy"].lower()): score += 1
        
        sc = "high" if score>=4 else "med" if score>=2 else "low"
        st.markdown(f'<div class="score-badge {sc}">📊 Score : {score}/4</div>', unsafe_allow_html=True)
        
        def sec_card(title, icon, ok, details, extra=""):
            cls = "ok" if ok else "fail"
            color = "#4ade80" if ok else "#f87171"
            status = "✅ OK" if ok else "❌ Non configuré"
            lines = "".join(f'<div class="d">{d}</div>' for d in details[:3])
            if extra: lines += f'<div class="d mute">{extra}</div>'
            return f'<div class="sec {cls}"><h4>{icon} {title}</h4><div class="s" style="color:{color}">{status}</div>{lines}</div>'
        
        mx = email["mx"]
        mx_ok = bool(mx["mx_records"])
        mx_details = [f"Priorité {p} → {h}" for p,h in mx["mx_records"][:5]]
        st.markdown(sec_card("MX — Serveurs mail", "📨", mx_ok, mx_details), unsafe_allow_html=True)
        
        spf = email["spf"]
        spf_ok = spf["has_spf"]
        mech = "🔒 Hard Fail" if spf["all_mechanism"] else "⚠️ Soft Fail" if spf["soft_all"] else ""
        spf_details = spf["spf_records"]
        st.markdown(sec_card(f"SPF {'· '+mech if mech else ''}", "🛡️", spf_ok, spf_details), unsafe_allow_html=True)
        
        dkim = email["dkim"]
        dkim_ok = dkim["has_dkim"]
        dkim_details = dkim["dkim_records"] or [f"Domaine: {dkim['domain']}"]
        extra = "Essayez: google, selector1, s1, mail" if not dkim_ok else ""
        st.markdown(sec_card("DKIM", "🔑", dkim_ok, dkim_details, extra), unsafe_allow_html=True)
        
        dmarc = email["dmarc"]
        dmarc_ok = dmarc["has_dmarc"]
        dmarc_details = dmarc["dmarc_records"] or [f"Domaine: {dmarc['domain']}"]
        st.markdown(sec_card(f"DMARC · {dmarc['policy']}" if dmarc_ok else "DMARC", "📋", dmarc_ok, dmarc_details), unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown('<div style="color:#94a3b8;font-size:0.8rem;">Analyse manuelle ci-dessous si besoin ↓</div>', unsafe_allow_html=True)
    
    st.markdown('<div style="color:#94a3b8;font-size:0.82rem;">Analyse manuelle de la sécurité email</div>', unsafe_allow_html=True)
    col_ed, col_es, col_eb = st.columns([2.5, 1.5, 1])
    with col_ed:
        edom = st.text_input("Domaine", placeholder="cortechs.fr", key="em_domain", label_visibility="collapsed")
    with col_es:
        sel = st.text_input("Sélecteur DKIM", value="default", key="em_sel", label_visibility="collapsed")
    with col_eb:
        ebtn = st.button("🔒 Analyser", key="em_btn", use_container_width=True)
    
    if ebtn and edom:
        dom = edom.strip(); selector = sel.strip() or "default"
        with st.spinner(f"Analyse de {dom}..."):
            mx = DNSEngine.query_mx(dom); spf = DNSEngine.check_spf(dom)
            dkim = DNSEngine.check_dkim(dom, selector); dmarc = DNSEngine.check_dmarc(dom)
        
        score = 0
        if mx["mx_records"]: score += 1
        if spf["has_spf"] and spf["all_mechanism"]: score += 1
        if dkim["has_dkim"]: score += 1
        if dmarc["has_dmarc"] and ("reject" in dmarc["policy"].lower() or "quarantine" in dmarc["policy"].lower()): score += 1
        
        sc = "high" if score>=4 else "med" if score>=2 else "low"
        st.markdown(f'<div class="score-badge {sc}">📊 {score}/4</div>', unsafe_allow_html=True)
        
        def sc2(title, icon, ok, details, extra=""):
            cls = "ok" if ok else "fail"; color = "#4ade80" if ok else "#f87171"
            sts = "✅" if ok else "❌"
            lines = "".join(f'<div class="d">{d}</div>' for d in details[:3])
            if extra: lines += f'<div class="d mute">{extra}</div>'
            st.markdown(f'<div class="sec {cls}"><h4>{icon} {title}</h4><div class="s" style="color:{color}">{sts}</div>{lines}</div>', unsafe_allow_html=True)
        
        sc2("MX", "📨", bool(mx["mx_records"]), [f"P{p} → {h}" for p,h in mx["mx_records"][:5]])
        mech = "🔒 Hard Fail" if spf["all_mechanism"] else "⚠️ Soft Fail" if spf["soft_all"] else ""
        sc2(f"SPF {mech}", "🛡️", spf["has_spf"], spf["spf_records"])
        sc2("DKIM", "🔑", dkim["has_dkim"], dkim["dkim_records"] or [f"{dkim['domain']}"], "Essayez: google, selector1" if not dkim["has_dkim"] else "")
        sc2("DMARC · "+dmarc["policy"] if dmarc["has_dmarc"] else "DMARC", "📋", dmarc["has_dmarc"], dmarc["dmarc_records"] or [f"{dmarc['domain']}"])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5: BLACKLISTS
# ═══════════════════════════════════════════════════════════════════════════════

with tab5:
    if st.session_state.results_bl and st.session_state.active_domain:
        bl = st.session_state.results_bl
        listed = sum(1 for r in bl["results"].values() if r["listed"])
        st.info(f"📋 Scan rapide : IP **{bl['ip']}** — {listed}/{len(bl['results'])} listé")
    
    st.markdown('<div style="color:#94a3b8;font-size:0.82rem;">Vérifie si une IP est listée sur 12 blacklists DNS</div>', unsafe_allow_html=True)
    col_ip, col_dm, col_bb = st.columns([2, 2, 1])
    with col_ip:
        bip = st.text_input("Adresse IP", placeholder="1.2.3.4", key="bl_ip", label_visibility="collapsed")
    with col_dm:
        bdom = st.text_input("Ou résoudre un domaine", placeholder="google.com", key="bl_dom2", label_visibility="collapsed")
    with col_bb:
        bbtn = st.button("🚫 Vérifier", key="bl_btn2", use_container_width=True)
    
    if bdom and not bip:
        try:
            resolved = socket.gethostbyname(bdom.strip())
            if resolved: bip = resolved
        except: pass
    
    if bbtn and bip:
        ip = bip.strip()
        if len(ip.split(".")) != 4 or not all(p.isdigit() for p in ip.split(".")):
            st.error("IP invalide — format: 1.2.3.4")
        else:
            bar = st.progress(0); txt = st.empty()
            results = {}
            total = len(DNS_BLACKLISTS)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                import dns.resolver as dnsr
                rip = ".".join(reversed(ip.split(".")))
                futs = {}
                for name, zone in DNS_BLACKLISTS.items():
                    q = f"{rip}.{zone}"
                    def dq(qn=q):
                        try:
                            rx = dnsr.Resolver(); rx.timeout=3; rx.lifetime=3
                            ans = rx.resolve(qn, "A")
                            return {"listed": True, "resp": str(ans[0])}
                        except dnsr.NXDOMAIN: return {"listed": False, "resp": "NXDOMAIN"}
                        except: return {"listed": False, "resp": "?"}
                    futs[ex.submit(dq)] = name
                
                for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
                    name = futs[f]
                    try: results[name] = f.result(timeout=5)
                    except: results[name] = {"listed": False, "resp": "?"}
                    bar.progress(i/total); txt.text(f"{i}/{total}")
            
            bar.empty(); txt.empty()
            listed = sum(1 for r in results.values() if r["listed"])
            clean = sum(1 for r in results.values() if not r["listed"] and r["resp"]=="NXDOMAIN")
            
            cm1, cm2, cm3 = st.columns(3)
            with cm1:
                c = "r" if listed else "g"
                st.markdown(f'<div class="kpi"><div class="num {c}">{listed}/{total}</div><div class="lbl">Listé</div></div>', unsafe_allow_html=True)
            with cm2:
                st.markdown(f'<div class="kpi"><div class="num g">{clean}</div><div class="lbl">Clean</div></div>', unsafe_allow_html=True)
            with cm3:
                st.markdown(f'<div class="kpi"><div class="num y">{total-listed-clean}</div><div class="lbl">Inconnu</div></div>', unsafe_allow_html=True)
            
            pills = '<div class="bl-row">'
            for name, r in sorted(results.items(), key=lambda x: (not x[1]["listed"], x[0])):
                cls = "listed" if r["listed"] else "clean" if r["resp"]=="NXDOMAIN" else "unknown"
                icon = "⚠️" if r["listed"] else "✅" if r["resp"]=="NXDOMAIN" else "⏱"
                pills += f'<span class="bl-pill {cls}">{icon} {name}</span>'
            pills += '</div>'
            st.markdown(pills, unsafe_allow_html=True)
            
            if listed:
                st.error(f"⚠️ {ip} listée sur **{listed}/{total}** blacklists")
            else:
                st.success(f"✅ {ip} est propre")
            
            with st.expander("📋 Détails"):
                dat = [{"Blacklist": n, "Listé": "OUI" if r["listed"] else "Non", "Réponse": r["resp"]}
                       for n, r in sorted(results.items(), key=lambda x: (not x[1]["listed"], x[0]))]
                st.dataframe(pd.DataFrame(dat), use_container_width=True, hide_index=True)


# ─── FOOTER ──────────────────────────────────────────────────────────────────

st.markdown(f"""
<div class="foot">
    DNS CHECKER v3.0 · Cortechs © 2026 · CT 115 (192.168.17.35:8506) · {len(GLOBAL_RESOLVERS)} résolveurs · {len(DNS_BLACKLISTS)} blacklists
</div>
""", unsafe_allow_html=True)
