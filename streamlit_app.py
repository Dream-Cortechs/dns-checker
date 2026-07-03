"""
DNS CHECKER — Streamlit Web App
Diagnostic DNS complet : Lookup · Propagation · Sécurité Email · Blacklists
Cortechs © 2026 — http://192.168.17.116:8505
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

import dns
from dns_engine import (
    DNSEngine, GLOBAL_RESOLVERS, DNS_BLACKLISTS, RECORD_TYPES,
    HAS_DNSPYTHON
)

# ─── Page Config ────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="DNS CHECKER · Cortechs",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─── Custom CSS (Dark Mode Cortechs) ────────────────────────────────────────

st.markdown("""
<style>
    /* === Global === */
    .stApp {
        background: #0a1628;
    }
    
    /* Header */
    .main-header {
        background: linear-gradient(135deg, #0a1628 0%, #111d34 100%);
        border-bottom: 2px solid #c9a94e;
        padding: 1.2rem 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .main-header h1 {
        color: #c9a94e;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0;
    }
    .main-header .subtitle {
        color: #8899aa;
        font-size: 0.85rem;
    }
    
    /* Metric cards */
    .metric-card {
        background: #111d34;
        border: 1px solid #1e3050;
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        transition: transform 0.2s, border-color 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #c9a94e;
    }
    .metric-card .value {
        font-size: 2rem;
        font-weight: 700;
        color: #c9a94e;
    }
    .metric-card .label {
        font-size: 0.8rem;
        color: #8899aa;
        margin-top: 0.3rem;
    }
    .metric-card.success .value { color: #2ecc71; }
    .metric-card.warning .value { color: #f39c12; }
    .metric-card.error .value { color: #e74c3c; }
    
    /* DNS Record card */
    .record-card {
        background: #111d34;
        border: 1px solid #1e3050;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 0.6rem;
    }
    .record-card .record-type {
        background: #c9a94e;
        color: #0a1628;
        font-weight: 700;
        font-size: 0.7rem;
        padding: 2px 8px;
        border-radius: 4px;
        display: inline-block;
        margin-right: 8px;
    }
    .record-card .record-value {
        color: #e0e0e0;
        font-family: 'Consolas', monospace;
        font-size: 0.9rem;
    }
    
    /* Propagation grid */
    .prop-cell {
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-family: 'Consolas', monospace;
        text-align: center;
    }
    .prop-cell.success {
        background: #1a3a2a;
        color: #2ecc71;
        border: 1px solid #2ecc71;
    }
    .prop-cell.error {
        background: #3a1a1a;
        color: #e74c3c;
        border: 1px solid #e74c3c;
    }
    .prop-cell.warning {
        background: #3a3510;
        color: #f39c12;
        border: 1px solid #f39c12;
    }
    
    /* Email security card */
    .sec-card {
        background: #111d34;
        border: 1px solid #1e3050;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }
    .sec-card.pass {
        border-left: 4px solid #2ecc71;
    }
    .sec-card.fail {
        border-left: 4px solid #e74c3c;
    }
    .sec-card.warn {
        border-left: 4px solid #f39c12;
    }
    .sec-card h3 {
        color: #e0e0e0;
        margin: 0 0 0.5rem 0;
        font-size: 1.1rem;
    }
    .sec-card .status {
        font-weight: 700;
        font-size: 0.9rem;
    }
    
    /* Blacklist row */
    .bl-clean { color: #2ecc71; }
    .bl-listed { color: #e74c3c; font-weight: 700; }
    .bl-unknown { color: #f39c12; }
    
    /* Score badge */
    .score-badge {
        display: inline-block;
        padding: 8px 20px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 1.1rem;
    }
    .score-excellent { background: #1a3a2a; color: #2ecc71; border: 2px solid #2ecc71; }
    .score-good { background: #3a3510; color: #f39c12; border: 2px solid #f39c12; }
    .score-bad { background: #3a1a1a; color: #e74c3c; border: 2px solid #e74c3c; }
    
    /* Footer */
    .footer {
        text-align: center;
        color: #334466;
        font-size: 0.75rem;
        padding: 1.5rem;
        border-top: 1px solid #1e3050;
        margin-top: 2rem;
    }
    
    /* Input styling */
    .stTextInput > div > div > input {
        background: #111d34 !important;
        border: 1px solid #1e3050 !important;
        color: #e0e0e0 !important;
        border-radius: 8px !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #c9a94e !important;
        box-shadow: 0 0 0 2px rgba(201, 169, 78, 0.2) !important;
    }
    
    /* Select box */
    .stSelectbox > div > div {
        background: #111d34 !important;
        border: 1px solid #1e3050 !important;
        border-radius: 8px !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: #c9a94e !important;
        color: #0a1628 !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.5rem 1.5rem !important;
        transition: all 0.2s !important;
    }
    .stButton > button:hover {
        background: #d4b860 !important;
        transform: translateY(-1px) !important;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: #0a1628;
    }
    .stTabs [data-baseweb="tab"] {
        background: #111d34;
        color: #8899aa;
        border-radius: 8px 8px 0 0;
        padding: 0.6rem 1.5rem;
        border: 1px solid #1e3050;
    }
    .stTabs [aria-selected="true"] {
        background: #1a2d4a;
        color: #c9a94e;
        border-bottom: 2px solid #c9a94e;
    }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: #c9a94e !important;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: #111d34 !important;
        border: 1px solid #1e3050 !important;
        border-radius: 8px !important;
        color: #e0e0e0 !important;
    }
    
    /* Dataframe */
    .stDataFrame {
        background: #111d34 !important;
    }
    [data-testid="stTable"] {
        background: #111d34 !important;
    }
</style>
""", unsafe_allow_html=True)


# ─── Header ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="main-header">
    <div>
        <h1>🔍 DNS CHECKER</h1>
        <div class="subtitle">Diagnostic DNS complet — Lookup · Propagation · Sécurité Email · Blacklists</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ─── Status Bar ─────────────────────────────────────────────────────────────

col_status1, col_status2, col_status3, col_status4 = st.columns(4)

with col_status1:
    color = "success" if HAS_DNSPYTHON else "error"
    icon = "✅" if HAS_DNSPYTHON else "❌"
    st.markdown(f"""
    <div class="metric-card {color}">
        <div class="value">{icon}</div>
        <div class="label">dnspython {dns.__version__ if HAS_DNSPYTHON else 'manquant'}</div>
    </div>
    """, unsafe_allow_html=True)

with col_status2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="value">{len(GLOBAL_RESOLVERS)}</div>
        <div class="label">Résolveurs globaux</div>
    </div>
    """, unsafe_allow_html=True)

with col_status3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="value">{len(DNS_BLACKLISTS)}</div>
        <div class="label">Blacklists DNS</div>
    </div>
    """, unsafe_allow_html=True)

with col_status4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="value">{len(RECORD_TYPES)}</div>
        <div class="label">Types d'enregistrements</div>
    </div>
    """, unsafe_allow_html=True)


# ─── Tabs ────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 DNS Lookup", 
    "🌍 Propagation", 
    "📧 Sécurité Email", 
    "🚫 Blacklists"
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: DNS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

with tab1:
    col_domain, col_type, col_resolver, col_btn = st.columns([3, 1.5, 2, 1])
    
    with col_domain:
        domain = st.text_input("Domaine", placeholder="ex: google.com", key="lookup_domain")
    with col_type:
        record_type = st.selectbox("Type", RECORD_TYPES, index=0, key="lookup_type")
    with col_resolver:
        resolver_options = ["Système (par défaut)"] + [
            f"{name} ({ip})" for name, ip in GLOBAL_RESOLVERS.items()
        ]
        resolver_choice = st.selectbox("Résolveur", resolver_options, key="lookup_resolver")
    with col_btn:
        st.write("")  # spacer
        st.write("")
        lookup_btn = st.button("🔍 Rechercher", key="lookup_btn", use_container_width=True)
    
    if lookup_btn and domain:
        # Parse resolver IP (dernière parenthèse = IP, ignore les éventuelles parenthèses dans le nom)
        resolver_ip = None
        if resolver_choice != "Système (par défaut)":
            import re
            matches = re.findall(r'\(([^)]+)\)', resolver_choice)
            if matches:
                resolver_ip = matches[-1]  # dernière occurrence = IP
        
        with st.spinner(f"Recherche {record_type} pour {domain}..."):
            result = DNSEngine.query(domain.strip(), record_type, resolver_ip)
        
        if result["error"]:
            st.error(f"❌ {result['error']}")
        else:
            records = result["records"]
            resolver_name = resolver_ip or "système"
            
            st.success(f"✅ {len(records)} enregistrement(s) {record_type} trouvé(s) — Résolveur: {resolver_name}")
            
            if records:
                df = pd.DataFrame({
                    "#": range(1, len(records) + 1),
                    "Valeur": records
                })
                st.dataframe(df, use_container_width=True, hide_index=True, height=min(35 * len(records) + 38, 400))
                
                # Record type badges
                st.markdown("---")
                st.caption(f"Domaine : **{domain}** | Type : **{record_type}** | Résolveur : **{resolver_name}** | {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: PROPAGATION (multi-resolver)
# ═══════════════════════════════════════════════════════════════════════════════

with tab2:
    col_pd, col_pt, col_pb = st.columns([3, 1.5, 1])
    
    with col_pd:
        prop_domain = st.text_input("Domaine", placeholder="ex: google.com", key="prop_domain")
    with col_pt:
        prop_type = st.selectbox("Type", RECORD_TYPES, index=0, key="prop_type")
    with col_pb:
        st.write("")
        st.write("")
        prop_btn = st.button("🌍 Vérifier la propagation", key="prop_btn", use_container_width=True)
    
    if prop_btn and prop_domain:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results = []
        total = len(GLOBAL_RESOLVERS)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for name, ip in GLOBAL_RESOLVERS.items():
                future = executor.submit(
                    DNSEngine.query, prop_domain.strip(), prop_type, ip, 5
                )
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
                progress_bar.progress(completed / total)
                status_text.text(f"⏳ {completed}/{total} résolveurs interrogés...")
        
        progress_bar.empty()
        status_text.empty()
        
        # Sort: success first
        results.sort(key=lambda x: (x[2]["error"] is not None, x[0]))
        
        # Build data
        data = []
        success_count = 0
        consensus = defaultdict(list)
        
        for name, ip, result in results:
            if result["error"] is None and result["records"]:
                success_count += 1
                first_record = result["records"][0]
                extra = f" (+{len(result['records'])-1})" if len(result["records"]) > 1 else ""
                status = "✅"
                consensus[first_record].append(name)
            elif result["error"] is None:
                first_record = "(aucun)"
                status = "⚠️"
            else:
                first_record = result["error"]
                status = "❌"
            
            data.append({
                "Résolveur": name,
                "IP": ip,
                "Résultat": first_record + (extra if status == "✅" and extra else ""),
                "Statut": status
            })
        
        df = pd.DataFrame(data)
        
        # Consensus
        most_common = max(consensus.keys(), key=lambda k: len(consensus[k]), default="Aucun")
        consensus_pct = (len(consensus[most_common]) / total * 100) if consensus and most_common != "Aucun" else 0
        
        col_metric1, col_metric2, col_metric3 = st.columns(3)
        
        with col_metric1:
            color_cls = "success" if success_count == total else "warning" if success_count > total/2 else "error"
            st.markdown(f"""
            <div class="metric-card {color_cls}">
                <div class="value">{success_count}/{total}</div>
                <div class="label">Résolveurs répondent</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col_metric2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="value">{consensus_pct:.0f}%</div>
                <div class="label">Consensus</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col_metric3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="value" style="font-size: 1rem; word-break: break-all;">{most_common[:30]}</div>
                <div class="label">Valeur majoritaire</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Color-code the dataframe
        def color_status(val):
            if val == "✅":
                return "color: #2ecc71"
            elif val == "⚠️":
                return "color: #f39c12"
            else:
                return "color: #e74c3c"
        
        styled_df = df.style.map(color_status, subset=["Statut"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True, height=min(35 * len(data) + 38, 600))
        
        st.caption(f"Domaine : **{prop_domain}** | Type : **{prop_type}** | Consensus : **{consensus_pct:.0f}%** | {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: EMAIL SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

with tab3:
    col_ed, col_es, col_eb = st.columns([3, 2, 1])
    
    with col_ed:
        email_domain = st.text_input("Domaine", placeholder="ex: cortechs.fr", key="email_domain")
    with col_es:
        dkim_selector = st.text_input("Sélecteur DKIM", value="default", key="dkim_selector")
    with col_eb:
        st.write("")
        st.write("")
        email_btn = st.button("🔒 Analyser", key="email_btn", use_container_width=True)
    
    if email_btn and email_domain:
        domain = email_domain.strip()
        selector = dkim_selector.strip() or "default"
        
        with st.spinner(f"Analyse sécurité email pour {domain}..."):
            mx = DNSEngine.query_mx(domain)
            spf = DNSEngine.check_spf(domain)
            dkim = DNSEngine.check_dkim(domain, selector)
            dmarc = DNSEngine.check_dmarc(domain)
        
        score = 0
        
        # ─── MX ───
        if mx["mx_records"]:
            border = "pass"
            status_icon = "✅"
            status_text = f"{len(mx['mx_records'])} serveur(s) MX"
            score += 1
        elif mx.get("error") == "Pas de réponse":
            border = "warn"
            status_icon = "⚠️"
            status_text = "Aucun MX"
        else:
            border = "fail"
            status_icon = "❌"
            status_text = mx.get("error", "Erreur")
        
        mx_html = f"""
        <div class="sec-card {border}">
            <h3>📨 MX — Serveurs Mail</h3>
            <div class="status" style="color: {'#2ecc71' if border == 'pass' else '#e74c3c' if border == 'fail' else '#f39c12'}">
                {status_icon} {status_text}
            </div>
        """
        for prio, host in mx["mx_records"][:10]:
            mx_html += f'<div style="color:#8899aa;margin-top:4px;">Priorité {prio} → <code style="color:#e0e0e0;">{host}</code></div>'
        mx_html += "</div>"
        st.markdown(mx_html, unsafe_allow_html=True)
        
        # ─── SPF ───
        if spf["has_spf"]:
            if spf["all_mechanism"]:
                border = "pass"
                status_icon = "✅"
                mechanism = "🔒 Hard Fail (-all)"
                score += 1
            elif spf["soft_all"]:
                border = "warn"
                status_icon = "⚠️"
                mechanism = "⚠️ Soft Fail (~all)"
            else:
                border = "warn"
                status_icon = "⚠️"
                mechanism = "⚠️ Neutral"
        else:
            border = "fail"
            status_icon = "❌"
            mechanism = "Absent"
        
        spf_html = f"""
        <div class="sec-card {border}">
            <h3>🛡️ SPF — Sender Policy Framework</h3>
            <div class="status" style="color: {'#2ecc71' if border == 'pass' else '#e74c3c' if border == 'fail' else '#f39c12'}">
                {status_icon} {mechanism}
            </div>
        """
        for rec in spf["spf_records"]:
            spf_html += f'<div style="color:#e0e0e0;font-family:Consolas,monospace;font-size:0.85rem;margin-top:4px;word-break:break-all;">{rec}</div>'
        spf_html += "</div>"
        st.markdown(spf_html, unsafe_allow_html=True)
        
        # ─── DKIM ───
        if dkim["has_dkim"]:
            border = "pass"
            status_icon = "✅"
            dkim_status = f"Présent (sélecteur: {selector})"
            score += 1
        else:
            border = "fail"
            status_icon = "❌"
            dkim_status = f"Absent (sélecteur: {selector})"
        
        dkim_html = f"""
        <div class="sec-card {border}">
            <h3>🔑 DKIM — DomainKeys Identified Mail</h3>
            <div class="status" style="color: {'#2ecc71' if border == 'pass' else '#e74c3c'}">
                {status_icon} {dkim_status}
            </div>
            <div style="color:#8899aa;font-size:0.8rem;margin-top:4px;">Domaine: <code>{dkim['domain']}</code></div>
        """
        for rec in dkim["dkim_records"]:
            dkim_html += f'<div style="color:#e0e0e0;font-family:Consolas,monospace;font-size:0.8rem;margin-top:2px;word-break:break-all;">{rec[:200]}</div>'
        if not dkim["has_dkim"]:
            dkim_html += '<div style="color:#8899aa;font-size:0.8rem;margin-top:4px;">Essayez: google, selector1, s1, mail</div>'
        dkim_html += "</div>"
        st.markdown(dkim_html, unsafe_allow_html=True)
        
        # ─── DMARC ───
        if dmarc["has_dmarc"]:
            if "reject" in dmarc["policy"].lower() or "quarantine" in dmarc["policy"].lower():
                border = "pass"
                score += 1
            else:
                border = "warn"
            status_icon = "✅"
            dmarc_status = dmarc["policy"]
        else:
            border = "fail"
            status_icon = "❌"
            dmarc_status = "Absent"
        
        dmarc_html = f"""
        <div class="sec-card {border}">
            <h3>📋 DMARC — Domain-based Message Authentication</h3>
            <div class="status" style="color: {'#2ecc71' if border == 'pass' else '#e74c3c' if border == 'fail' else '#f39c12'}">
                {status_icon} {dmarc_status}
            </div>
            <div style="color:#8899aa;font-size:0.8rem;margin-top:4px;">Domaine: <code>{dmarc['domain']}</code></div>
        """
        for rec in dmarc["dmarc_records"]:
            dmarc_html += f'<div style="color:#e0e0e0;font-family:Consolas,monospace;font-size:0.8rem;margin-top:2px;word-break:break-all;">{rec}</div>'
        dmarc_html += "</div>"
        st.markdown(dmarc_html, unsafe_allow_html=True)
        
        # ─── Score ───
        if score >= 4:
            score_class = "score-excellent"
            score_label = "🔒 Excellent"
        elif score >= 2:
            score_class = "score-good"
            score_label = "⚠️ Correct"
        else:
            score_class = "score-bad"
            score_label = "❌ Insuffisant"
        
        col_score1, col_score2 = st.columns([1, 3])
        with col_score1:
            st.markdown(f"""
            <div class="score-badge {score_class}">
                📊 {score}/4
            </div>
            """, unsafe_allow_html=True)
        with col_score2:
            st.markdown(f"""
            <div style="padding: 8px 0;">
                <span class="{score_class}" style="font-size: 1.1rem;">{score_label}</span>
                <span style="color: #8899aa; margin-left: 10px;">Sécurité email pour {domain}</span>
            </div>
            """, unsafe_allow_html=True)
        
        st.caption(f"Analyse terminée à {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: BLACKLISTS
# ═══════════════════════════════════════════════════════════════════════════════

with tab4:
    col_bip, col_bdomain, col_bbtn = st.columns([3, 2, 1])
    
    with col_bip:
        bl_ip = st.text_input("Adresse IP", placeholder="ex: 1.2.3.4", key="bl_ip")
    with col_bdomain:
        bl_domain = st.text_input("Ou domaine → résoudre", placeholder="ex: google.com", key="bl_domain")
    with col_bbtn:
        st.write("")
        st.write("")
        bl_btn = st.button("🚫 Vérifier", key="bl_btn", use_container_width=True)
    
    # Auto-resolve domain
    if bl_domain and not bl_ip:
        try:
            resolved = socket.gethostbyname(bl_domain.strip())
            if resolved:
                bl_ip = resolved
        except:
            pass
    
    if bl_btn and bl_ip:
        ip = bl_ip.strip()
        # Validate IP
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
                    query_name = f"{reversed_ip}.{zone}"
                    
                    def do_query(qname=query_name):
                        try:
                            res = dnsr.Resolver()
                            res.timeout = 3
                            res.lifetime = 3
                            ans = res.resolve(qname, "A")
                            return {"listed": True, "response": str(ans[0]), "status": "⚠️ LISTÉE"}
                        except dnsr.NXDOMAIN:
                            return {"listed": False, "response": "NXDOMAIN", "status": "✅ Clean"}
                        except dnsr.Timeout:
                            return {"listed": False, "response": "Timeout", "status": "⏱ Timeout"}
                        except Exception as e:
                            return {"listed": False, "response": str(e)[:50], "status": "❓ Inconnu"}
                    
                    futures[executor.submit(do_query)] = name
                
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    name = futures[future]
                    completed += 1
                    try:
                        results[name] = future.result(timeout=5)
                    except Exception:
                        results[name] = {"listed": False, "response": "Exception", "status": "❓ Inconnu"}
                    
                    progress_bar.progress(completed / total)
                    status_text.text(f"⏳ {completed}/{total} blacklists vérifiées...")
            
            progress_bar.empty()
            status_text.empty()
            
            listed_count = sum(1 for r in results.values() if r["listed"])
            
            # Metrics
            col_bm1, col_bm2, col_bm3 = st.columns(3)
            
            with col_bm1:
                color_cls = "error" if listed_count > 0 else "success"
                st.markdown(f"""
                <div class="metric-card {color_cls}">
                    <div class="value">{listed_count}/{total}</div>
                    <div class="label">Blacklists</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col_bm2:
                clean_count = sum(1 for r in results.values() if r["status"] == "✅ Clean")
                st.markdown(f"""
                <div class="metric-card success">
                    <div class="value">{clean_count}</div>
                    <div class="label">Clean</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col_bm3:
                unknown = total - listed_count - clean_count
                st.markdown(f"""
                <div class="metric-card warning">
                    <div class="value">{unknown}</div>
                    <div class="label">Timeout/Inconnu</div>
                </div>
                """, unsafe_allow_html=True)
            
            # Results table
            data = []
            for name, r in sorted(results.items(), key=lambda x: (not x[1]["listed"], x[0])):
                icon = "⚠️" if r["listed"] else "✅" if r["status"] == "✅ Clean" else "⏱"
                data.append({
                    "Blacklist": name,
                    "Statut": r["status"],
                    "Réponse": r["response"],
                    "Listé": "OUI" if r["listed"] else "Non"
                })
            
            df = pd.DataFrame(data)
            
            def color_listed(val):
                if val == "OUI":
                    return "color: #e74c3c; font-weight: 700"
                return "color: #e0e0e0"
            
            styled_df = df.style.map(color_listed, subset=["Listé"])
            st.dataframe(styled_df, use_container_width=True, hide_index=True, 
                        height=min(35 * len(data) + 38, 500))
            
            if listed_count == 0:
                st.success(f"✅ IP **{ip}** propre — aucune blacklist parmi {total}")
            else:
                st.error(f"⚠️ IP **{ip}** listée sur **{listed_count}/{total}** blacklists !")
            
            st.caption(f"Vérification terminée à {datetime.now().strftime('%H:%M:%S')}")


# ─── Footer ──────────────────────────────────────────────────────────────────

st.markdown(f"""
<div class="footer">
    DNS CHECKER v1.0 · Cortechs © 2026 · 
    {len(GLOBAL_RESOLVERS)} résolveurs · {len(DNS_BLACKLISTS)} blacklists · 
    dnspython {dns.__version__ if HAS_DNSPYTHON else 'N/A'}
</div>
""", unsafe_allow_html=True)
