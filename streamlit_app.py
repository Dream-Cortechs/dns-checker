"""
DNS CHECKER — Streamlit Web App
Diagnostic DNS complet : Lookup · Propagation · Sécurité Email · Blacklists
Cortechs © 2026 — CT 115 (192.168.17.35:8506)
"""

import sys, os
sys.path.insert(0, "/opt/dns-checker")

import streamlit as st
import pandas as pd
import time
import concurrent.futures
from datetime import datetime
from collections import defaultdict
import socket
import re

import dns
from dns_engine import (
    DNSEngine, GLOBAL_RESOLVERS, DNS_BLACKLISTS, RECORD_TYPES,
    HAS_DNSPYTHON
)

import plotly.graph_objects as go

# ─── Geo coordinates ────────────────────────────────────────────────────────

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
    initial_sidebar_state="collapsed"
)

# ─── CSS ────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    .stApp { background: #080e18; }
    
    /* ========== HEADER ========== */
    .header-bar {
        background: linear-gradient(135deg, #0d1a30 0%, #142240 100%);
        border-bottom: 3px solid #c9a94e;
        padding: 1rem 2rem;
        display: flex;
        align-items: center;
        gap: 1.2rem;
        margin-bottom: 1.5rem;
    }
    .header-bar .logo {
        width: 42px; height: 42px;
        background: #c9a94e;
        border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 22px;
        font-weight: 900;
        color: #0a1628;
    }
    .header-bar h1 { color: #c9a94e; font-size: 1.6rem; font-weight: 700; margin: 0; }
    .header-bar .sub { color: #667a99; font-size: 0.82rem; }
    
    /* ========== STAT ROW ========== */
    .stat-row {
        display: flex; gap: 1rem;
        padding: 0 2rem; margin-bottom: 1.5rem;
    }
    .stat-chip {
        background: #0f1d33;
        border: 1px solid #1a3050;
        border-radius: 10px;
        padding: 0.7rem 1.2rem;
        display: flex; align-items: center; gap: 0.6rem;
        font-size: 0.85rem; color: #c0cfe0;
    }
    .stat-chip .icon { font-size: 1.2rem; }
    .stat-chip .val { color: #c9a94e; font-weight: 700; }
    
    /* ========== TABS ========== */
    .stTabs [data-baseweb="tab-list"] { gap: 4px; background: transparent; padding: 0 2rem; }
    .stTabs [data-baseweb="tab"] {
        background: #0f1d33; color: #667a99;
        border-radius: 10px 10px 0 0; padding: 0.5rem 1.4rem;
        border: 1px solid #1a3050; font-size: 0.9rem;
        margin-right: 2px;
    }
    .stTabs [aria-selected="true"] {
        background: #152540; color: #c9a94e;
        border-bottom: 2px solid #c9a94e;
    }
    
    /* ========== CARDS ========== */
    .dns-card {
        background: #0f1d33;
        border: 1px solid #1a3050;
        border-radius: 12px;
        padding: 0.8rem 1.2rem;
        margin-bottom: 0.4rem;
        display: flex; align-items: center; gap: 0.8rem;
        transition: border-color 0.15s;
    }
    .dns-card:hover { border-color: #334d70; }
    .dns-card .num {
        background: #152540; color: #667a99;
        width: 28px; height: 28px; border-radius: 8px;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.8rem; font-weight: 700; flex-shrink: 0;
    }
    .dns-card .type-badge {
        background: #c9a94e; color: #0a1628;
        padding: 2px 10px; border-radius: 6px;
        font-size: 0.7rem; font-weight: 700; flex-shrink: 0;
    }
    .dns-card .val {
        color: #d0ddf0; font-family: 'Consolas', monospace;
        font-size: 0.9rem; word-break: break-all; flex: 1;
    }
    
    /* ========== PROPAGATION CELLS ========== */
    .prop-grid { display: flex; flex-wrap: wrap; gap: 6px; }
    .prop-chip {
        display: inline-flex; align-items: center; gap: 4px;
        padding: 5px 10px; border-radius: 8px;
        font-size: 0.78rem; font-family: 'Segoe UI', sans-serif;
        border: 1px solid transparent;
    }
    .prop-chip.ok   { background: #0a2a1a; border-color: #1a5a3a; color: #4ade80; }
    .prop-chip.warn { background: #2a2008; border-color: #5a4a18; color: #fbbf24; }
    .prop-chip.err  { background: #2a0a0a; border-color: #5a1a1a; color: #f87171; }
    .prop-chip .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .prop-chip .dot.g { background: #4ade80; }
    .prop-chip .dot.y { background: #fbbf24; }
    .prop-chip .dot.r { background: #e74c3c; }
    
    /* ========== METRIC CARDS ========== */
    .ktile {
        background: #0f1d33; border: 1px solid #1a3050;
        border-radius: 12px; padding: 1rem; text-align: center;
    }
    .ktile .big { font-size: 2rem; font-weight: 700; }
    .ktile .big.green { color: #4ade80; }
    .ktile .big.gold  { color: #c9a94e; }
    .ktile .big.red   { color: #f87171; }
    .ktile .lbl { font-size: 0.75rem; color: #667a99; margin-top: 0.2rem; }
    
    /* ========== SECURITY CARDS ========== */
    .sec-card {
        background: #0f1d33; border-radius: 14px;
        padding: 1.3rem 1.5rem; margin-bottom: 0.8rem;
        border-left: 5px solid #333;
    }
    .sec-card.pass { border-left-color: #4ade80; }
    .sec-card.warn { border-left-color: #f59e0b; }
    .sec-card.fail { border-left-color: #f87171; }
    .sec-card .sec-icon { font-size: 1.6rem; margin-right: 0.6rem; }
    .sec-card h4 { color: #e0e6f0; margin: 0; font-size: 1.05rem; display: flex; align-items: center; gap: 0.5rem; }
    .sec-card .rec { color: #c0cfe0; font-family: 'Consolas', monospace; font-size: 0.82rem; margin-top: 0.4rem; word-break: break-all; }
    .sec-card .stat { font-weight: 700; font-size: 0.85rem; }
    
    /* ========== SCORE BADGE ========== */
    .score-pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 22px; border-radius: 30px;
        font-weight: 700; font-size: 1rem; margin: 0.8rem 0;
    }
    .score-pill.great { background: #0a2a1a; border: 2px solid #4ade80; color: #4ade80; }
    .score-pill.ok    { background: #2a2008; border: 2px solid #f59e0b; color: #f59e0b; }
    .score-pill.bad   { background: #2a0a0a; border: 2px solid #f87171; color: #f87171; }
    
    /* ========== BLACKLIST CHIPS ========== */
    .bl-chip {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 6px 14px; border-radius: 20px;
        font-size: 0.8rem; margin: 3px;
    }
    .bl-chip.clean  { background: #0a2a1a; color: #4ade80; border: 1px solid #1a5a3a; }
    .bl-chip.listed { background: #2a0a0a; color: #f87171; border: 1px solid #5a1a1a; font-weight: 700; }
    .bl-chip.unknown { background: #1a1a2a; color: #94a3b8; border: 1px solid #334155; }
    
    /* ========== INPUT ========== */
    .stTextInput > div > div > input {
        background: #0f1d33 !important; border: 1px solid #1a3050 !important;
        color: #e0e6f0 !important; border-radius: 10px !important; padding: 10px 14px !important;
        font-size: 1rem !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #c9a94e !important;
        box-shadow: 0 0 0 3px rgba(201,169,78,0.15) !important;
    }
    .stSelectbox > div > div {
        background: #0f1d33 !important; border: 1px solid #1a3050 !important; border-radius: 10px !important;
    }
    
    /* ========== BUTTONS ========== */
    .stButton > button {
        background: #c9a94e !important; color: #0a1628 !important;
        font-weight: 700 !important; border: none !important;
        border-radius: 10px !important; padding: 0.55rem 1.6rem !important;
        font-size: 0.9rem !important; transition: all 0.2s !important;
    }
    .stButton > button:hover { background: #d4b860 !important; transform: translateY(-1px); }
    
    /* ========== EXPANDER ========== */
    .streamlit-expanderHeader {
        background: #0f1d33 !important; border: 1px solid #1a3050 !important;
        border-radius: 10px !important; color: #c0cfe0 !important; font-weight: 600 !important;
    }
    
    /* ========== FOOTER ========== */
    .footer {
        text-align: center; color: #3a5070; font-size: 0.72rem;
        padding: 1.2rem; border-top: 1px solid #152540; margin-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# ─── HEADER ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="header-bar">
    <div class="logo">🔍</div>
    <div>
        <h1>DNS CHECKER</h1>
        <div class="sub">Diagnostic DNS mondial · Cortechs</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── STAT CHIPS ─────────────────────────────────────────────────────────────

col_s1, col_s2, col_s3, col_s4 = st.columns(4)
with col_s1:
    icon = "✅" if HAS_DNSPYTHON else "❌"
    c = "#4ade80" if HAS_DNSPYTHON else "#f87171"
    st.markdown(f"""
    <div class="stat-chip">
        <span class="icon">{icon}</span>
        <span>dnspython <span class="val">{dns.__version__ if HAS_DNSPYTHON else 'N/A'}</span></span>
    </div>
    """, unsafe_allow_html=True)
with col_s2:
    st.markdown(f'<div class="stat-chip"><span class="icon">🌐</span><span><span class="val">{len(GLOBAL_RESOLVERS)}</span> résolveurs</span></div>', unsafe_allow_html=True)
with col_s3:
    st.markdown(f'<div class="stat-chip"><span class="icon">🛡️</span><span><span class="val">{len(DNS_BLACKLISTS)}</span> blacklists</span></div>', unsafe_allow_html=True)
with col_s4:
    st.markdown(f'<div class="stat-chip"><span class="icon">📋</span><span><span class="val">{len(RECORD_TYPES)}</span> types DNS</span></div>', unsafe_allow_html=True)


# ─── TABS ───────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍  DNS Lookup", 
    "🌍  Propagation", 
    "📧  Sécurité Email", 
    "🚫  Blacklists"
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: DNS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

with tab1:
    st.markdown("---")
    col_d, col_t, col_r, col_b = st.columns([3, 1.3, 2.2, 1])
    with col_d:
        domain = st.text_input("Domaine", placeholder="ex: google.com", key="lookup_domain", label_visibility="collapsed")
    with col_t:
        record_type = st.selectbox("Type", RECORD_TYPES, index=0, key="lookup_type", label_visibility="collapsed")
    with col_r:
        resolver_options = ["🖥️ Système (par défaut)"] + [f"{name}  ({ip})" for name, ip in GLOBAL_RESOLVERS.items()]
        resolver_choice = st.selectbox("Résolveur", resolver_options, key="lookup_resolver", label_visibility="collapsed")
    with col_b:
        lookup_btn = st.button("🔍 Rechercher", key="lookup_btn", use_container_width=True)
    
    if lookup_btn and domain:
        resolver_ip = None
        if not resolver_choice.startswith("🖥️"):
            matches = re.findall(r'\(([^)]+)\)', resolver_choice)
            if matches: resolver_ip = matches[-1]
        
        with st.spinner(f"🔍 Recherche **{record_type}** pour **{domain}**..."):
            result = DNSEngine.query(domain.strip(), record_type, resolver_ip, timeout=8)
        
        if result["error"]:
            st.error(f"❌ {result['error']}")
        elif result["records"]:
            st.success(f"✅ **{len(result['records'])}** enregistrement(s) {record_type} trouvé(s)")
            for i, rec in enumerate(result["records"], 1):
                st.markdown(f"""
                <div class="dns-card">
                    <div class="num">{i}</div>
                    <div class="type-badge">{record_type}</div>
                    <div class="val">{rec}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info(f"ℹ️ Aucun enregistrement {record_type} pour ce domaine")
        
        st.caption(f"Résolveur : **{resolver_ip or 'système'}** · {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: PROPAGATION
# ═══════════════════════════════════════════════════════════════════════════════

with tab2:
    st.markdown("---")
    col_pd, col_pt, col_pb = st.columns([3, 1.3, 1])
    with col_pd:
        prop_domain = st.text_input("Domaine", placeholder="ex: google.com", key="prop_domain", label_visibility="collapsed")
    with col_pt:
        prop_type = st.selectbox("Type", RECORD_TYPES, index=0, key="prop_type", label_visibility="collapsed")
    with col_pb:
        prop_btn = st.button("🌍 Vérifier la propagation", key="prop_btn", use_container_width=True)
    
    if prop_btn and prop_domain:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results = []
        total = len(GLOBAL_RESOLVERS)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(DNSEngine.query, prop_domain.strip(), prop_type, ip, 6): (name, ip) 
                       for name, ip in GLOBAL_RESOLVERS.items()}
            for completed, future in enumerate(concurrent.futures.as_completed(futures), 1):
                name, ip = futures[future]
                try: r = future.result(timeout=6)
                except: r = {"records": [], "error": "Exception"}
                results.append((name, ip, r))
                progress_bar.progress(completed / total)
                status_text.text(f"⏳ {completed}/{total} résolveurs...")
        
        progress_bar.empty(); status_text.empty()
        results.sort(key=lambda x: (x[2]["error"] is not None or not x[2]["records"], x[0]))
        
        success_count = sum(1 for _, _, r in results if r["error"] is None and r["records"])
        consensus = defaultdict(list)
        for name, ip, r in results:
            if r["error"] is None and r["records"]:
                consensus[r["records"][0]].append(name)
        
        most_common = max(consensus.keys(), key=lambda k: len(consensus[k]), default="N/A")
        consensus_pct = (len(consensus[most_common]) / total * 100) if consensus else 0
        
        # Metrics
        cm1, cm2, cm3, cm4 = st.columns(4)
        with cm1:
            color = "green" if success_count == total else "red" if success_count < total/2 else "gold"
            st.markdown(f'<div class="ktile"><div class="big {color}">{success_count}/{total}</div><div class="lbl">Résolveurs OK</div></div>', unsafe_allow_html=True)
        with cm2:
            st.markdown(f'<div class="ktile"><div class="big gold">{consensus_pct:.0f}%</div><div class="lbl">Consensus</div></div>', unsafe_allow_html=True)
        with cm3:
            val_color = "green" if consensus_pct > 80 else "gold" if consensus_pct > 50 else "red"
            st.markdown(f'<div class="ktile"><div class="big {val_color}" style="font-size:1.1rem;word-break:break-all;">{most_common[:25]}</div><div class="lbl">Valeur majoritaire</div></div>', unsafe_allow_html=True)
        with cm4:
            rtts = []
            st.markdown(f'<div class="ktile"><div class="big gold">{success_count}</div><div class="lbl">Réponses reçues</div></div>', unsafe_allow_html=True)
        
        # 🌍 Map
        map_lats, map_lons, map_colors, map_texts, map_sizes = [], [], [], [], []
        for name, ip, r in results:
            geo = RESOLVER_GEO.get(name)
            if geo:
                map_lats.append(geo[0]); map_lons.append(geo[1])
                if r["error"] is None and r["records"]:
                    map_colors.append("#4ade80"); map_sizes.append(12)
                elif r["error"] is None:
                    map_colors.append("#fbbf24"); map_sizes.append(9)
                else:
                    map_colors.append("#f87171"); map_sizes.append(9)
                map_texts.append(f"{name}<br>{ip}<br>{r['records'][0] if r['records'] else (r.get('error') or '?')}")
        
        if map_lats:
            fig = go.Figure(go.Scattergeo(lon=map_lons, lat=map_lats, mode="markers",
                marker=dict(size=map_sizes, color=map_colors, line=dict(width=1, color="#0a1628")),
                text=map_texts, hoverinfo="text"))
            fig.update_layout(
                geo=dict(projection_type="natural earth", showland=True, landcolor="#0f1d33",
                    showocean=True, oceancolor="#080e18", showcountries=True, countrycolor="#1a3050",
                    coastlinecolor="#1a3050", showframe=False, bgcolor="#080e18"),
                paper_bgcolor="#080e18", plot_bgcolor="#080e18",
                margin=dict(l=5, r=5, t=5, b=5), height=380, showlegend=False, dragmode=False)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        
        # Propagation chips
        st.markdown("### 🌐 Résultats par résolveur")
        chips_html = '<div class="prop-grid">'
        for name, ip, r in results:
            if r["error"] is None and r["records"]:
                cls, dot = "ok", "g"
                icon = "✅"
                val = r["records"][0][:40]
                if len(r["records"]) > 1: val += f" +{len(r['records'])-1}"
            elif r["error"] is None:
                cls, dot = "warn", "y"
                icon = "⚠️"
                val = "aucun enregistrement"
            else:
                cls, dot = "err", "r"
                icon = "❌"
                val = r["error"][:35]
            chips_html += f'<div class="prop-chip {cls}" title="{name} ({ip})"><span class="dot {dot}"></span><strong>{name.split(chr(32))[0]}</strong> {val}</div>'
        chips_html += '</div>'
        st.markdown(chips_html, unsafe_allow_html=True)
        
        # Expander with full details
        with st.expander("📋 Voir le tableau détaillé"):
            data = []
            for name, ip, r in results:
                if r["error"] is None and r["records"]:
                    val = r["records"][0]
                    extra = f" (+{len(r['records'])-1})" if len(r["records"]) > 1 else ""
                    sts = "✅"
                elif r["error"] is None:
                    val = "—"; extra = ""; sts = "⚠️"
                else:
                    val = r["error"]; extra = ""; sts = "❌"
                data.append({"Résolveur": name, "IP": ip, "Résultat": val + extra, "Statut": sts})
            st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
        
        st.caption(f"Domaine : **{prop_domain}** · Type : **{prop_type}** · {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: EMAIL SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

with tab3:
    st.markdown("---")
    col_ed, col_es, col_eb = st.columns([3, 1.8, 1])
    with col_ed:
        email_domain = st.text_input("Domaine", placeholder="ex: cortechs.fr", key="email_domain", label_visibility="collapsed")
    with col_es:
        dkim_selector = st.text_input("Sélecteur DKIM", value="default", key="dkim_selector", label_visibility="collapsed", placeholder="default")
    with col_eb:
        email_btn = st.button("🔒 Analyser", key="email_btn", use_container_width=True)
    
    if email_btn and email_domain:
        domain = email_domain.strip()
        selector = dkim_selector.strip() or "default"
        
        with st.spinner(f"🔒 Analyse sécurité email pour **{domain}**..."):
            mx = DNSEngine.query_mx(domain)
            spf = DNSEngine.check_spf(domain)
            dkim = DNSEngine.check_dkim(domain, selector)
            dmarc = DNSEngine.check_dmarc(domain)
        
        score = 0
        
        # ─── MX ───
        if mx["mx_records"]:
            border, icon, status_color = "pass", "📨", "#4ade80"
            status_txt = f"{len(mx['mx_records'])} serveur(s) MX"
            records_html = "".join(f'<div class="rec">Priorité {p} → {h}</div>' for p, h in mx["mx_records"][:10])
            score += 1
        elif mx.get("error") == "Pas de réponse" or mx.get("error", "").startswith("Aucun"):
            border, icon, status_color = "warn", "📨", "#f59e0b"
            status_txt = "Aucun MX"
            records_html = '<div class="rec">Aucun enregistrement MX</div>'
        else:
            border, icon, status_color = "fail", "📨", "#f87171"
            status_txt = mx.get("error", "Erreur")
            records_html = f'<div class="rec">{status_txt}</div>'
        
        st.markdown(f"""
        <div class="sec-card {border}">
            <h4><span class="sec-icon">{icon}</span> MX — Serveurs Mail</h4>
            <div class="stat" style="color:{status_color}">{status_txt}</div>
            {records_html}
        </div>
        """, unsafe_allow_html=True)
        
        # ─── SPF ───
        if spf["has_spf"]:
            score += 1
            if spf["all_mechanism"]:
                border, icon, color, mech = "pass", "🛡️", "#4ade80", "🔒 Hard Fail (-all)"
            elif spf["soft_all"]:
                border, icon, color, mech = "warn", "🛡️", "#f59e0b", "⚠️ Soft Fail (~all)"
            else:
                border, icon, color, mech = "warn", "🛡️", "#f59e0b", "⚠️ Neutral (?all)"
            recs = "".join(f'<div class="rec">{r}</div>' for r in spf["spf_records"])
        else:
            border, icon, color, mech = "fail", "🛡️", "#f87171", "❌ Absent"
            recs = '<div class="rec">Aucun SPF trouvé</div>'
        
        st.markdown(f"""
        <div class="sec-card {border}">
            <h4><span class="sec-icon">{icon}</span> SPF — Sender Policy Framework</h4>
            <div class="stat" style="color:{color}">{mech}</div>
            {recs}
        </div>
        """, unsafe_allow_html=True)
        
        # ─── DKIM ───
        if dkim["has_dkim"]:
            border, icon, color, stat = "pass", "🔑", "#4ade80", f"✅ Présent (sélecteur: {selector})"
            recs = "".join(f'<div class="rec">{r[:150]}</div>' for r in dkim["dkim_records"])
            score += 1
        else:
            border, icon, color, stat = "fail", "🔑", "#f87171", f"❌ Absent"
            recs = f'<div class="rec">Domaine: {dkim["domain"]}</div>'
            recs += '<div class="rec" style="color:#667a99;">Essayez: google, selector1, s1, mail</div>'
        
        st.markdown(f"""
        <div class="sec-card {border}">
            <h4><span class="sec-icon">{icon}</span> DKIM — DomainKeys Identified Mail</h4>
            <div class="stat" style="color:{color}">{stat}</div>
            {recs}
        </div>
        """, unsafe_allow_html=True)
        
        # ─── DMARC ───
        if dmarc["has_dmarc"]:
            if "reject" in dmarc["policy"].lower() or "quarantine" in dmarc["policy"].lower():
                border, icon, color = "pass", "📋", "#4ade80"
                score += 1
            else:
                border, icon, color = "warn", "📋", "#f59e0b"
            stat = f"✅ {dmarc['policy']}"
            recs = "".join(f'<div class="rec">{r}</div>' for r in dmarc["dmarc_records"])
        else:
            border, icon, color, stat = "fail", "📋", "#f87171", "❌ Absent"
            recs = f'<div class="rec">Domaine: {dmarc["domain"]}</div>'
        
        st.markdown(f"""
        <div class="sec-card {border}">
            <h4><span class="sec-icon">{icon}</span> DMARC — Domain-based Message Authentication</h4>
            <div class="stat" style="color:{color}">{stat}</div>
            {recs}
        </div>
        """, unsafe_allow_html=True)
        
        # ─── SCORE ───
        if score >= 4: sc_cls, sc_lbl = "great", "🔒 Excellent"
        elif score >= 2: sc_cls, sc_lbl = "ok", "⚠️ Correct"
        else: sc_cls, sc_lbl = "bad", "❌ Insuffisant"
        
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:1rem;margin-top:1rem;">
            <div class="score-pill {sc_cls}">📊 {score} / 4</div>
            <span style="color:#667a99;">Sécurité email pour <strong style="color:#c0cfe0;">{domain}</strong></span>
        </div>
        """, unsafe_allow_html=True)
        
        st.caption(f"Analyse terminée · {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: BLACKLISTS
# ═══════════════════════════════════════════════════════════════════════════════

with tab4:
    st.markdown("---")
    col_ip, col_dom, col_bb = st.columns([2.5, 2.5, 1])
    with col_ip:
        bl_ip = st.text_input("Adresse IP", placeholder="ex: 1.2.3.4", key="bl_ip", label_visibility="collapsed")
    with col_dom:
        bl_domain = st.text_input("Ou domaine → résoudre", placeholder="ex: google.com", key="bl_domain", label_visibility="collapsed")
    with col_bb:
        bl_btn = st.button("🚫 Vérifier", key="bl_btn", use_container_width=True)
    
    if bl_domain and not bl_ip:
        try:
            resolved = socket.gethostbyname(bl_domain.strip())
            if resolved: bl_ip = resolved
        except: pass
    
    if bl_btn and bl_ip:
        ip = bl_ip.strip()
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            st.error("Format IP invalide. Exemple: 1.2.3.4")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = {}
            total = len(DNS_BLACKLISTS)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                import dns.resolver as dnsr
                reversed_ip = ".".join(reversed(ip.split(".")))
                futures = {}
                
                for name, zone in DNS_BLACKLISTS.items():
                    qname = f"{reversed_ip}.{zone}"
                    def do_query(qn=qname):
                        try:
                            r = dnsr.Resolver(); r.timeout = 4; r.lifetime = 4
                            ans = r.resolve(qn, "A")
                            return {"listed": True, "response": str(ans[0]), "status": "⚠️ LISTÉE"}
                        except dnsr.NXDOMAIN:
                            return {"listed": False, "response": "NXDOMAIN", "status": "✅ Clean"}
                        except dnsr.Timeout:
                            return {"listed": False, "response": "Timeout", "status": "⏱ Timeout"}
                        except Exception as e:
                            return {"listed": False, "response": str(e)[:50], "status": "❓ Inconnu"}
                    futures[executor.submit(do_query)] = name
                
                for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    name = futures[future]
                    try: results[name] = future.result(timeout=5)
                    except: results[name] = {"listed": False, "response": "Exception", "status": "❓ Inconnu"}
                    progress_bar.progress(i / total)
                    status_text.text(f"⏳ {i}/{total} blacklists...")
            
            progress_bar.empty(); status_text.empty()
            
            listed_count = sum(1 for r in results.values() if r["listed"])
            clean_count = sum(1 for r in results.values() if r["status"] == "✅ Clean")
            
            # Metrics
            cm1, cm2, cm3 = st.columns(3)
            with cm1:
                c = "red" if listed_count else "green"
                st.markdown(f'<div class="ktile"><div class="big {c}">{listed_count}/{total}</div><div class="lbl">Blacklists</div></div>', unsafe_allow_html=True)
            with cm2:
                st.markdown(f'<div class="ktile"><div class="big green">{clean_count}</div><div class="lbl">Clean ✅</div></div>', unsafe_allow_html=True)
            with cm3:
                st.markdown(f'<div class="ktile"><div class="big gold">{total - listed_count - clean_count}</div><div class="lbl">Timeout / Inconnu</div></div>', unsafe_allow_html=True)
            
            # Chips
            chips_html = ""
            for name, r in sorted(results.items(), key=lambda x: (not x[1]["listed"], x[0])):
                if r["listed"]: cls = "listed"
                elif r["status"] == "✅ Clean": cls = "clean"
                else: cls = "unknown"
                chips_html += f'<span class="bl-chip {cls}" title="{r["response"]}">{name} · {r["status"]}</span>'
            st.markdown(f'<div style="margin:1rem 0;">{chips_html}</div>', unsafe_allow_html=True)
            
            if listed_count == 0:
                st.success(f"✅ **{ip}** est propre — aucune blacklist")
            else:
                st.error(f"⚠️ **{ip}** listée sur **{listed_count}/{total}** blacklists !")
            
            # Expander with details
            with st.expander("📋 Voir le tableau détaillé"):
                data = [{"Blacklist": n, "Statut": r["status"], "Réponse": r["response"], "Listé": "OUI" if r["listed"] else "Non"}
                        for n, r in sorted(results.items(), key=lambda x: (not x[1]["listed"], x[0]))]
                st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
            
            st.caption(f"IP : **{ip}** · {datetime.now().strftime('%H:%M:%S')}")


# ─── FOOTER ──────────────────────────────────────────────────────────────────

st.markdown(f"""
<div class="footer">
    DNS CHECKER v2.0 · Cortechs © 2026 · 
    {len(GLOBAL_RESOLVERS)} résolveurs · {len(DNS_BLACKLISTS)} blacklists · 
    CT 115 (192.168.17.35:8506)
</div>
""", unsafe_allow_html=True)
