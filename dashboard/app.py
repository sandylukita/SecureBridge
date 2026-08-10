"""
SecureBridge — OT Command Center & SOC Dashboard v1.5.0
Real-time SOC interface for industrial control system monitoring
Sandy Lukita | PT Optima Sarana Instrument

Run: streamlit run dashboard/app.py
"""

import sys
import os
import time
import json
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
from datetime import datetime, timedelta

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config.settings import load_config
import config.settings
import importlib
importlib.reload(config.settings)

from core.detection.model import AnomalyScorer, IncrementalScorer, classify_severity
from core.ingestion.event_reader import IncrementalEventReader
from core.advisor.incident_analyst import IncidentAnalyst
from core.discovery.asset_registry import AssetRegistry
import sys, importlib
if "core.discovery.asset_registry" in sys.modules:
    importlib.reload(sys.modules["core.discovery.asset_registry"])
from core.discovery.asset_registry import AssetRegistry
from core.threat_intel import ThreatIntelFeed
from compliance.iec62443_mapper import (
    FINDING_TO_IEC, IEC62443_REQUIREMENTS,
    SystemUnderConsideration, generate_risk_register,
    calculate_compliance_score
)

# ─────────────────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecureBridge | OT Security Command Center",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────
# Styling & Theme Consistency
# ─────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* Dark Theme Core */
    .stApp { background-color: #0b132b; color: #e0e6ed; }
    [data-testid="stSidebar"] { background-color: #162238 !important; border-right: 1px solid #233454; }
    [data-testid="stSidebar"] * { color: #e0e6ed !important; }
    .stApp > header { background-color: transparent; }

    /* Header Banner */
    .sb-header {
        background: linear-gradient(135deg, #1c2541 0%, #0b132b 100%);
        padding: 18px 26px;
        border-radius: 10px;
        border: 1px solid #1f2a44;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .sb-header h1 { margin: 0; font-size: 26px; color: #48cae4; font-weight: 700; }
    .sb-header p { margin: 4px 0 0; font-size: 13px; color: #94a3b8; }

    /* Glassmorphism Metric Cards */
    .soc-card {
        background: rgba(27, 38, 59, 0.7);
        border: 1px solid #2a3d66;
        border-radius: 10px;
        padding: 16px;
        backdrop-filter: blur(8px);
        margin-bottom: 15px;
    }
    .soc-card-title { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
    .soc-card-value { font-size: 24px; font-weight: bold; color: #ffffff; margin-top: 4px; }
    
    .status-crit { border-left: 4px solid #ff1744 !important; }
    .status-high { border-left: 4px solid #ff9100 !important; }
    .status-med  { border-left: 4px solid #ffd600 !important; }
    .status-ok   { border-left: 4px solid #00e676 !important; }

    /* Status Badges */
    .badge-live {
        background: #00e676; color: #0b132b !important;
        padding: 3px 12px; border-radius: 12px;
        font-size: 11px; font-weight: bold;
    }
    .badge-lab {
        background: #00b4d8; color: #0b132b !important;
        padding: 3px 12px; border-radius: 12px;
        font-size: 11px; font-weight: bold;
    }

    /* Expander Container */
    .stExpander { background-color: #162238 !important; border: 1px solid #233454 !important; border-radius: 8px !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────
# Cache Config & Services
# ─────────────────────────────────────────────────────────

@st.cache_resource
def get_config_v3():
    # Load config and force cache reload for provider update
    return load_config("config/lab.yaml")

@st.cache_resource
def get_scorer():
    return AnomalyScorer("data/models/ot_model.pkl")

@st.cache_resource
def get_incremental_scorer(_scorer):
    """Incremental scorer backed by on-disk cache — only new events hit the ML model."""
    return IncrementalScorer(_scorer, cache_path="data/models/score_cache.pkl")

@st.cache_resource
def get_advisor(_config):
    return IncidentAnalyst(
        provider=_config.llm.provider,
        groq_model=_config.llm.groq_model,
        gemini_model=_config.llm.gemini_model,
        ollama_model=_config.llm.ollama_model,
        ollama_host=_config.llm.ollama_host,
        claude_model=_config.llm.claude_model,
        api_timeout=_config.llm.api_timeout,
    )

@st.cache_resource
def get_threat_intel(mode):
    return ThreatIntelFeed(
        cache_path="data/threat_intel/cisa_cache.json",
        mode=mode,
    )

@st.cache_resource
def get_event_reader(_config):
    """Bounded-memory incremental event reader (O(delta-N) I/O per refresh)."""
    return IncrementalEventReader(
        log_dir=_config.log_dir,
        state_path="data/models/event_counters.json",
    )

@st.cache_data(ttl=600)
def get_cached_incident_analysis_v3(incident_dict, _config_provider):
    advisor = get_advisor(get_config_v3())
    return advisor.analyze_incident(incident_dict)

config           = get_config_v3()
scorer           = get_scorer()
incremental      = get_incremental_scorer(scorer)
advisor          = get_advisor(config)
threat_intel     = get_threat_intel(config.mode)
event_reader     = get_event_reader(config)

# Initialize Asset Registry in Session State
if "asset_registry" not in st.session_state or not hasattr(st.session_state.asset_registry, "process_events"):
    st.session_state.asset_registry = AssetRegistry()

asset_registry = st.session_state.asset_registry

# ─────────────────────────────────────────────────────────
# Data Loading — Bounded-Memory Incremental Event Processing
# ─────────────────────────────────────────────────────────

def load_events(hours: int = 24) -> pd.DataFrame:
    """Return the most-recent bounded working set from the incremental reader.

    Architecture: IncrementalEventReader reads ONLY newly-appended bytes
    since the last call (O(delta-N) disk I/O).  The working set is bounded
    at 5,000 rows via a deque — memory consumption is independent of the
    historical log size.  Persistent counters (total_events, total_critical,
    total_high) survive both Streamlit refreshes and application restarts
    via data/models/event_counters.json.

    The `hours` argument is accepted for API compatibility but is no longer
    used to scan historical data; the reader always returns the most-recent
    events up to the window size.
    """
    return event_reader.get_recent_df()

def score_events(df: pd.DataFrame) -> pd.DataFrame:
    """Score events using incremental Isolation Forest scoring.

    Only rows not yet in the on-disk cache are passed to Isolation Forest.
    Previously-seen events are served instantly from cache, reducing ML
    invocations from O(N_total) to O(N_new) on each dashboard refresh —
    the same pattern used by enterprise SIEM platforms.

    Cache is automatically invalidated when the model is retrained
    (tracked via the 'trained_at' timestamp in the model pickle metadata).
    """
    if df.empty:
        return df

    t_inc = time.time()
    scored = incremental.score_incremental(df)
    log.info(f"[TIMING] score_incremental only: {time.time()-t_inc:.2f}s")
    
    # Global Severity Capping for Known SCADA Read-Only Traffic
    if not scored.empty and "src_ip" in scored.columns and "is_write" in scored.columns:
        _is_write_bool = scored["is_write"].astype(str).str.strip().str.lower().isin(["true", "1", "1.0"])
        mask_scada_read = (scored["src_ip"] == "192.168.10.100") & (~_is_write_bool)
        mask_needs_cap = mask_scada_read & (scored["severity"].isin(["HIGH", "CRITICAL"]))
        
        if mask_needs_cap.any():
            scored.loc[mask_needs_cap, "severity"] = "MEDIUM"

    t_reg = time.time()
    # Passively update asset registry from scored results (vectorized)
    asset_registry.process_events(scored)
    log.info(f"[TIMING] asset_registry update: {time.time()-t_reg:.2f}s")

    return scored

# ─────────────────────────────────────────────────────────
# Sidebar Controls
# ─────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1c2541,#0b132b);
                padding:14px 18px;border-radius:10px;border:1px solid #2a3d66;margin-bottom:15px;">
        <span style="color:#48cae4;font-size:20px;font-weight:700;">🔐 SecureBridge</span><br>
        <span style="color:#94a3b8;font-size:11px;">OT/ICS Security Command Center v1.5.0</span>
    </div>
    """, unsafe_allow_html=True)

    # 1. Action Button at Top
    st.markdown("### 📄 Quick Actions")
    if st.button("📄 Generate IEC 62443 PDF Report", type="primary", use_container_width=True):
        with st.spinner("Generating PDF report..."):
            try:
                from compliance.report_generator import generate_report

                # Use the already-loaded df from incremental reader — no second CSV scan
                df_scored = df if "df" in dir() and not df.empty else score_events(load_events())
                active_alerts = df_scored[df_scored["anomaly_score"] >= 60] if not df_scored.empty else pd.DataFrame()
                has_crit = not active_alerts[active_alerts["severity"] == "CRITICAL"].empty if not active_alerts.empty else False
                has_high = not active_alerts[active_alerts["severity"] == "HIGH"].empty if not active_alerts.empty else False
                calc_risk = "CRITICAL" if has_crit else "HIGH" if has_high else "MEDIUM"

                client_data = {
                    "client_name": config.compliance.client_name,
                    "consultant": config.compliance.consultant_name,
                    "consulting_firm": config.compliance.consulting_firm,
                    "report_date": datetime.now().strftime("%d %B %Y"),
                    "scope": f"IT/OT Security Assessment — {config.capture.target_network}",
                    "period": datetime.now().strftime("%B %Y"),
                    "risk_level": calc_risk,
                }
                output_path = os.path.join(
                    config.compliance.report_output_dir,
                    f"securebridge_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                )
                os.makedirs(config.compliance.report_output_dir, exist_ok=True)
                generate_report(client_data, output_path)
                st.session_state["generated_pdf"] = output_path
                st.success("✅ Report generated!")
            except Exception as e:
                st.error(f"Failed to generate report: {e}")

    if "generated_pdf" in st.session_state and os.path.exists(st.session_state["generated_pdf"]):
        with open(st.session_state["generated_pdf"], "rb") as f:
            pdf_bytes = f.read()
        st.download_button(
            label="⬇️ Download PDF Report",
            data=pdf_bytes,
            file_name=os.path.basename(st.session_state["generated_pdf"]),
            mime="application/pdf",
            use_container_width=True
        )

    st.divider()

    st.markdown("### ⚙️ SOC Controls")
    hours_back = st.slider("Time window (hours)", 1, 168, 24)
    threshold = st.slider("Alert threshold", 0, 100, 60)
    ai_enabled = st.checkbox("Enable AI Threat Analysis", True)
    refresh = st.slider("Refresh interval (sec)", 5, 60, 10)

    st.divider()
    st.markdown("### 🖥️ Deployment Status")
    if config.mode == "live":
        st.markdown('<span class="badge-live">● LIVE SPAN PORT</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="badge-lab">◉ LAB DEMO MODE</span>', unsafe_allow_html=True)

    st.caption(f"Network: {config.capture.target_network}")
    st.caption(f"Threshold: {threshold}/100")

    st.divider()
    st.markdown("### 🤖 LLM Engine")
    st.caption(f"Provider: {config.llm.provider.upper()}")
    
    # Dynamically display the appropriate model based on the selected provider
    if config.llm.provider == "groq":
        model_str = config.llm.groq_model
    elif config.llm.provider == "gemini":
        model_str = config.llm.gemini_model
    elif config.llm.provider == "claude":
        model_str = config.llm.claude_model
    else:
        model_str = config.llm.ollama_model
        
    st.caption(f"Model: {model_str}")

# ─────────────────────────────────────────────────────────
# Main Content & Header
# ─────────────────────────────────────────────────────────

import time
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("SecureBridge.Timing")

t_start = time.time()
df_raw = load_events(hours_back)
log.info(f"[TIMING] load_events: {time.time()-t_start:.2f}s")

t_checkpoint = time.time()
df = score_events(df_raw)
log.info(f"[TIMING] scoring: {time.time()-t_checkpoint:.2f}s")

t_checkpoint = time.time()
has_data = not df.empty and "timestamp" in df.columns
log.info(f"[TIMING] remaining_init: {time.time()-t_checkpoint:.2f}s")

mode_badge = (
    '<span class="badge-live">● LIVE</span>'
    if config.mode == "live"
    else '<span class="badge-lab">◉ LAB DEMO</span>'
)

st.markdown(f"""
<div class="sb-header">
    <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
            <h1>🔐 SecureBridge OT Command Center</h1>
            <p>Passive ICS Security Monitoring & IEC 62443 Compliance Platform | {config.compliance.consulting_firm}</p>
        </div>
        <div>{mode_badge}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────
# Tab Navigation
# ─────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Live SOC Operations",
    "🌐 Purdue Network Topology",
    "🎛️ SCADA / HMI Process Telemetry",
    "📑 IEC 62443 Risk Register & Audit"
])

# ─────────────────────────────────────────────────────────
# TAB 1: LIVE SOC OPERATIONS
# ─────────────────────────────────────────────────────────

with tab1:
    # ── Persistent counters (survive restart) ────────────────────────────────
    _counters = event_reader.counters
    total_events_lifetime = _counters["total_events"]

    if has_data:
        recent_alerts = df[df["anomaly_score"] >= threshold]
        recent_crit   = len(df[df["severity"] == "CRITICAL"])
        recent_high   = len(df[df["severity"] == "HIGH"])
        devices_count = df["device_id"].nunique() if "device_id" in df.columns else 3
        avg_score     = df["anomaly_score"].mean()
    else:
        recent_alerts = pd.DataFrame()
        recent_crit   = 0
        recent_high   = 0
        devices_count = 3
        avg_score     = 0.0

    # Keep backward-compatible name used downstream for incident grouping
    active_alerts = recent_alerts

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(f"""
        <div class="soc-card status-crit">
            <div class="soc-card-title">Total Events Processed</div>
            <div class="soc-card-value">{total_events_lifetime:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="soc-card status-crit">
            <div class="soc-card-title">Recent Alerts <span style="font-size:9px;opacity:.6">last 5k</span></div>
            <div class="soc-card-value">{len(recent_alerts)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="soc-card status-crit">
            <div class="soc-card-title">Recent Critical <span style="font-size:9px;opacity:.6">last 5k</span></div>
            <div class="soc-card-value">{recent_crit}</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="soc-card status-ok">
            <div class="soc-card-title">Devices Monitored</div>
            <div class="soc-card-value">{devices_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with col5:
        st.markdown(f"""
        <div class="soc-card status-med">
            <div class="soc-card-title">Avg Anomaly Score</div>
            <div class="soc-card-value">{avg_score:.1f}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts Row
    c1, c2 = st.columns([2, 1])

    with c1:
        st.markdown("#### 📈 Anomaly Score Timeline")
        if has_data:
            df_plot = df.sort_values("timestamp")
            
            # [OPTIMIZATION] Downsample points for Plotly to prevent OOM on 2GB VMs
            # Browsers and Streamlit servers will crash/swap if fed 100k+ points for rendering.
            # We limit to max 1500 points for the timeline visualization.
            if len(df_plot) > 1500:
                step = len(df_plot) // 1500
                df_plot = df_plot.iloc[::step]
                
            fig = px.line(
                df_plot,
                x="timestamp",
                y="anomaly_score",
                color="device_id",
                color_discrete_sequence=["#00b4d8", "#00e676", "#ff9100"],
                labels={"anomaly_score": "Score (0-100)", "timestamp": "Time"}
            )
            fig.add_hline(y=threshold, line_dash="dash", line_color="#ff1744", annotation_text=f"Threshold ({threshold})")
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15,23,42,0.6)",
                font_color="#e0e6ed",
                margin=dict(l=20, r=20, t=30, b=20),
                height=320
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No network event data collected yet.")

    with c2:
        st.markdown("#### 🎯 Alert Severity Distribution")
        if has_data:
            sev_counts = df["severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig_pie = px.pie(
                sev_counts,
                values="count",
                names="severity",
                color="severity",
                color_discrete_map={
                    "CRITICAL": "#ff1744",
                    "HIGH": "#ff9100",
                    "MEDIUM": "#ffd600",
                    "LOW": "#00e676"
                },
                hole=0.4
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e6ed",
                margin=dict(l=10, r=10, t=20, b=10),
                height=320
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    # Active Alerts List with AI Analysis & DPI Details
    st.markdown("#### 🚨 Active Security Incidents & AI Threat Analysis")
    if not active_alerts.empty:
        # ── INCIDENT STRATEGY: Group by Asset Pair (Target + Source) ──
        # This replaces the O(N) per-alert LLM calls with O(1) batched incident calls
        import hashlib
        
        # Sort by timestamp to ensure chronological order for the timeline
        if "timestamp" in active_alerts.columns:
            active_alerts = active_alerts.sort_values("timestamp", ascending=True)
            
        if "ai_results" not in st.session_state:
            st.session_state["ai_results"] = {}
            
        grouped_incidents = active_alerts.groupby(["dst_ip", "src_ip"])
        
        for (dst_ip, src_ip), group_df in grouped_incidents:
            # Sort group to find max severity
            group_sorted = group_df.sort_values("anomaly_score", ascending=False)
            rep_alert = group_sorted.iloc[0]
            
            sev = rep_alert.get("severity", "LOW")
            max_score = float(rep_alert.get("anomaly_score", 0.0))
            dev_id = rep_alert.get("device_id", "PLC-01")
            
            # Context-Aware Semantic Role & Severity Capping
            is_write_detected = bool(group_df["is_write"].any())
            
            if src_ip == "192.168.10.100":
                if not is_write_detected:
                    role_label = "Source (SCADA)"
                else:
                    role_label = "Compromised SCADA"
            else:
                if is_write_detected:
                    role_label = "Attacker"
                elif sev in ["HIGH", "CRITICAL"]:
                    role_label = "Suspicious Source"
                else:
                    role_label = "Source"

            if sev == "CRITICAL":
                emoji = "🚨"
            elif sev == "HIGH":
                emoji = "🔴"
            elif sev == "MEDIUM":
                emoji = "🟡"
            else:
                emoji = "🟢"
                
            # Generate deterministic Incident ID
            if "timestamp" in group_df.columns:
                first_seen = group_df["timestamp"].min()
            else:
                first_seen = datetime.now()
                
            date_str = first_seen.strftime("%Y%m%d")
            raw_hash = f"{dst_ip}-{src_ip}-{date_str}"
            hash_hex = hashlib.md5(raw_hash.encode()).hexdigest()[:6].upper()
            incident_id = f"INC-{date_str}-{hash_hex}"
            
            # Build Batch Object (Now includes role_label for the LLM)
            incident_dict = {
                "incident_id": incident_id,
                "target_ip": dst_ip,
                "target_device_id": dev_id,
                "source_ip": src_ip,
                "alert_count": len(group_df),
                "severity": sev,
                "max_score": max_score,
                "role_label": role_label,
                "alerts": group_df.to_dict("records")
            }
            
            expander_title = f"{emoji} [{sev}] {incident_id} | Target: {dev_id} ({dst_ip}) | {role_label}: {src_ip} | Alerts: {len(group_df)}"
            
            # Keep expander open if AI analysis exists, OR if the button was just clicked
            is_button_clicked = st.session_state.get(f"btn_ai_{incident_id}", False)
            is_expanded = is_button_clicked or (incident_id in st.session_state.get("ai_results", {}))
            with st.expander(expander_title, expanded=is_expanded):
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("**📊 Incident Timeline (Compressed DPI)**")
                    st.json({
                        "Incident ID": incident_id,
                        "Target Asset": dst_ip,
                        "Source Asset": src_ip,
                        "Time Window": f"Last {hours_back_default if 'hours_back_default' in locals() else 24} Hours",
                        "Total Alerts": len(group_df),
                        "Max Anomaly Score": f"{max_score:.1f} / 100",
                        "Representative Event": rep_alert.get("function_name", "Unknown Function"),
                        "Is Write Command Detected": bool(group_df["is_write"].any())
                    })

                with col_right:
                    st.markdown("**🤖 Incident Analyst & Playbook**")
                    if ai_enabled:
                        if st.button(f"Generate AI Analysis", key=f"btn_ai_{incident_id}", type="primary"):
                            with st.spinner("🤖 Incident Analyst sedang memproses batch..."):
                                analysis = get_cached_incident_analysis_v3(incident_dict, config.llm.provider)
                                st.session_state["ai_results"][incident_id] = analysis
                        
                        analysis = st.session_state["ai_results"].get(incident_id)

                        if analysis:
                            if analysis.get("success", False):
                                provider_name = str(analysis.get('provider', '')).capitalize()
                                model_name = str(analysis.get('model', '')).split('/')[-1]
                                st.success(f"🟢 **AI Status:** Connected | **Provider:** {provider_name} | **Model:** {model_name} | **Latency:** {analysis.get('latency_sec')} sec")
                                st.markdown(f"**Incident Summary:** {analysis.get('threat_summary')}")
                            else:
                                st.error("🔴 **AI Status:** Offline | **Deterministic Detection Active**")
                                st.markdown(f"**Incident Summary:** {analysis.get('threat_summary')}")

                            st.markdown("**⚡ Immediate Actions:**")
                            for act in analysis.get("immediate_actions", []):
                                st.markdown(f"- {act}")
                            
                            iec_ref = analysis.get("iec62443_reference", {})
                            st.caption(f"📖 IEC 62443: {iec_ref.get('requirement')} — {iec_ref.get('title')}")
                            st.caption(f"🎯 MITRE ATT&CK: {analysis.get('mitre_attack_ics')}")
                            if analysis.get("request_id"):
                                st.caption(f"*(Req ID: {analysis.get('request_id')})*")
                        else:
                            st.info("💡 Klik tombol di atas untuk menjalankan AI Incident Analyst pada batch ini.")

                        # Interactive Firewall Playbook (Removed nested expander to fix Streamlit exception)
                        st.markdown("🛡️ **Preview Firewall Containment Rule**")
                        
                        if role_label == "Source (SCADA)":
                            fw_text = f"""# No containment action recommended
# Source {src_ip} is a known legitimate SCADA workstation performing routine read operations.
# If polling frequency is a concern, investigate SCADA configuration — do NOT block this source.
"""
                        elif role_label == "Suspicious Source":
                            fw_text = f"""# Monitoring Rule (Non-blocking) — Suspicious Activity
# Log and alert on continued activity from {src_ip}
# Recommend manual investigation before containment
iptables -A FORWARD -s {src_ip} -d {dst_ip} -j LOG --log-prefix "SECUREBRIDGE-WATCH: "
"""
                        else:
                            fw_text = f"""# Automated Edge Firewall Rule (DMZ Level 3.5 Isolation)
# Block unauthorized traffic from {src_ip} to {dst_ip}
iptables -A FORWARD -s {src_ip} -d {dst_ip} -p tcp --dport 502 -j DROP
# Log containment action
logger -t SECUREBRIDGE "CONTAINMENT: Blocked attacker {src_ip} targeting {dst_ip}"
"""
                        st.code(fw_text, language="bash")
    else:
        st.success("✅ No active alerts above threshold. Network operations normal.")

    st.markdown("---")
    st.markdown("#### 📜 Incident Timeline (Raw OT Events)")
    if has_data:
        timeline_df = df.sort_values("timestamp", ascending=False)[
            ["timestamp", "device_id", "src_ip", "dst_ip", "protocol", "function_name", "anomaly_score", "severity"]
        ].head(100)
        
        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True
        )

# ─────────────────────────────────────────────────────────
# TAB 2: PURDUE NETWORK TOPOLOGY VISUALIZER
# ─────────────────────────────────────────────────────────

with tab2:
    st.markdown("### 🌐 Purdue Model Network Topology Visualizer")
    st.caption("Passive Asset Profiling & Threat Mapping — Zero IP footprint, zero active scanning.")

    topo_data = asset_registry.get_topology_nodes_and_edges()
    nodes_df = pd.DataFrame(topo_data["nodes"])

    if not nodes_df.empty:
        # Create Purdue Model 2D Network Scatter Plot
        fig_topo = px.scatter(
            nodes_df,
            x="max_score",
            y="y_rank",
            color="status",
            size=[35] * len(nodes_df),
            hover_name="label",
            hover_data=["type", "level", "max_score"],
            color_discrete_map={"ONLINE": "#00e676", "WARNING": "#ff9100", "CRITICAL": "#ff1744"}
        )
        fig_topo.update_traces(marker=dict(line=dict(width=2, color="white")))
        fig_topo.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e0e6ed",
            yaxis=dict(
                tickmode="array",
                tickvals=[1, 2, 3, 4],
                ticktext=["Level 1 (PLCs)", "Level 2 (SCADA/HMI)", "Level 3.5 (DMZ)", "External"],
                title="Purdue Network Hierarchy"
            ),
            xaxis=dict(title="Max Anomaly Score (Threat Exposure)"),
            height=420
        )
        st.plotly_chart(fig_topo, use_container_width=True)

    if has_data:
        st.markdown("#### 🔗 Traffic Communication Matrix")
        st.caption("Aggregated communication volume between OT assets based on passive packet capture.")
        try:
            comm_matrix = pd.crosstab(df["src_ip"], df["dst_ip"])
            if not comm_matrix.empty:
                fig_matrix = px.imshow(
                    comm_matrix, 
                    labels=dict(x="Destination IP", y="Source IP", color="Packet Count"),
                    x=comm_matrix.columns, 
                    y=comm_matrix.index,
                    color_continuous_scale="Blues"
                )
                fig_matrix.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(15,23,42,0.8)",
                    font_color="#e0e6ed",
                    margin=dict(l=20, r=20, t=20, b=20),
                    height=400
                )
                st.plotly_chart(fig_matrix, use_container_width=True)
        except Exception as e:
            st.error(f"Could not render Communication Matrix: {e}")

    st.markdown("#### 📋 Passively Discovered Asset Inventory")
    assets_table = [
        {
            "IP Address": a.ip,
            "Asset Name": a.name,
            "Asset Type": a.asset_type,
            "Purdue Level": a.purdue_level,
            "Protocol": a.protocol,
            "Max Anomaly Score": f"{a.max_score:.1f}",
            "Status": a.status
        }
        for a in asset_registry.assets.values()
    ]
    st.dataframe(pd.DataFrame(assets_table), use_container_width=True)

    # ── CISA ICS-CERT Threat Intelligence Panel ───────────
    st.markdown("---")
    st.markdown("#### 🛡️ CISA ICS-CERT Threat Intelligence")
    meta = threat_intel.get_cache_metadata()
    if meta["fetched_at"]:
        sync_ts = meta["fetched_at"][:19].replace("T", " ")
        st.caption(
            f"🔄 Advisory cache synced: **{sync_ts}** | "
            f"Source: [CISA ICS-CERT](https://www.cisa.gov/cybersecurity-advisories/ics-advisories) (Public) | "
            f"{meta['total']} total advisories loaded"
        )
    else:
        st.warning("⚠️ CISA cache not found. Run: `python core/threat_intel/fetch_advisories.py`")

    # Show asset details and advisories per asset
    try:
        for asset in list(asset_registry.assets.values())[:10]:
            intel = threat_intel.get_asset_intel(asset.ip, asset.vendor)
            crit_n = intel["critical_advisories"]
            high_n = intel["high_advisories"]
            badge  = "🔴 CRITICAL" if crit_n > 0 else "🟠 HIGH" if high_n > 0 else "🟢 NORMAL"
            
            with st.expander(f"{badge} {asset.ip} — {asset.name} ({asset.asset_type})"):
                st.markdown(f"**Passive Profile:**")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"- **Vendor:** {asset.vendor} (via MAC OUI)")
                    st.write(f"- **Protocol:** {asset.protocol}")
                with col2:
                    st.write(f"- **Purdue Level:** {asset.purdue_level}")
                    st.write(f"- **Status:** {asset.status}")
                with col3:
                    st.write(f"- **Event Count:** {asset.event_count}")
                    st.write(f"- **Max Score:** {asset.max_score:.1f}")
                    
                st.caption("_Note: Firmware version and OS are deliberately omitted as passive listening cannot deterministically extract them without active DPI probing._")

                if intel["total_advisories"] > 0:
                    st.markdown(f"**Threat Intel ({intel['total_advisories']} active advisories):**")
                for adv in intel["latest_advisories"]:
                    cvss = adv.get("cvss")
                    cvss_str = f"CVSS {cvss:.1f}" if cvss else "CVSS N/A"
                    cves_str = ", ".join(adv.get("cves", [])) or "No CVE"
                    st.markdown(
                        f"**[{adv['id']}]({adv['url']})** — {adv['title']}  \n"
                        f"_{cvss_str} | {cves_str} | Published: {adv.get('published', 'N/A')}_  \n"
                        f"{adv.get('summary', '')}"
                    )
                    st.divider()
    except Exception as e:
        st.error(f"Could not render Asset Inventory details: {e}")

# ─────────────────────────────────────────────────────────

with tab3:
    st.markdown("### 🎛️ Live SCADA / HMI Process Telemetry")
    st.caption("Real-time physical process state monitoring for simulated PLCs.")

    # Simulated Gauge Gauges
    c1, c2, c3 = st.columns(3)

    # Simulated values dynamically generated
    t_val = 2850 + np.random.randint(-15, 15)
    temp_val = 74.2 + np.random.uniform(-0.5, 0.5)
    p_val = 12.4 + np.random.uniform(-0.2, 0.2)

    # Check if active write anomaly exists
    is_anomaly_active = False
    if has_data and not df.empty:
        has_write = not df[(df["is_write"] == True) & (df["anomaly_score"] >= threshold)].empty
        if has_write:
            is_anomaly_active = True
            p_val = 18.9  # Out of bounds pressure spike

    with c1:
        st.markdown("#### 🌀 PLC-01: Gas Turbine Speed")
        fig_g1 = go.Figure(go.Indicator(
            mode="gauge+number",
            value=t_val,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "RPM"},
            gauge={
                'axis': {'range': [0, 3500]},
                'bar': {'color': "#00b4d8"},
                'steps': [
                    {'range': [0, 2500], 'color': "#1b263b"},
                    {'range': [2500, 3000], 'color': "#0d4f6b"},
                    {'range': [3000, 3500], 'color': "#ff1744"}
                ]
            }
        ))
        fig_g1.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e0e6ed", height=250, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_g1, use_container_width=True)
        st.caption("Status: NORMAL OPERATING SPEED")

    with c2:
        st.markdown("#### 🌡️ PLC-02: Cooling Loop Temp")
        fig_g2 = go.Figure(go.Indicator(
            mode="gauge+number",
            value=temp_val,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "°C"},
            gauge={
                'axis': {'range': [0, 120]},
                'bar': {'color': "#00e676"},
                'steps': [
                    {'range': [0, 80], 'color': "#1b263b"},
                    {'range': [80, 100], 'color': "#ff9100"},
                    {'range': [100, 120], 'color': "#ff1744"}
                ]
            }
        ))
        fig_g2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e0e6ed", height=250, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_g2, use_container_width=True)
        st.caption("Status: TEMPERATURE OPTIMAL")

    with c3:
        st.markdown("#### ⚡ PLC-03: Valve Line Pressure")
        fig_g3 = go.Figure(go.Indicator(
            mode="gauge+number",
            value=p_val,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "BAR"},
            gauge={
                'axis': {'range': [0, 25]},
                'bar': {'color': "#ff1744" if is_anomaly_active else "#00e676"},
                'steps': [
                    {'range': [0, 15], 'color': "#1b263b"},
                    {'range': [15, 20], 'color': "#ff9100"},
                    {'range': [20, 25], 'color': "#ff1744"}
                ]
            }
        ))
        fig_g3.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e0e6ed", height=250, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_g3, use_container_width=True)

        if is_anomaly_active:
            st.error("🚨 VALVE OVERRIDE & PRESSURE SPIKE DETECTED!")
        else:
            st.caption("Status: PRESSURE STABLE")

# ─────────────────────────────────────────────────────────
# TAB 4: IEC 62443-3-2 RISK REGISTER & AUDIT
# ─────────────────────────────────────────────────────────

with tab4:
    st.markdown("### 📑 IEC 62443-3-2 Risk Register & SUC Scope")
    st.caption("Formal System Under Consideration (SUC) boundary & RS1-RS7 risk register traceability.")

    suc = SystemUnderConsideration()
    risk_reg = generate_risk_register(FINDING_TO_IEC, suc)
    comp_score = calculate_compliance_score(FINDING_TO_IEC)

    # SUC Header Card
    st.info(f"""
    **System Under Consideration (SUC):** {suc.name}  
    **Business Owner:** {suc.business_owner} | **Target Security Level:** {suc.target_sl}  
    **In-Scope Boundary Assets:** {', '.join(suc.boundary_devices)}  
    **Explicitly Excluded:** {', '.join(suc.excluded_systems)}
    """)

    col_r1, col_r2 = st.columns([1, 1])

    with col_r1:
        st.markdown("#### 📊 IEC 62443 Category Compliance Radar")
        cats = list(comp_score["categories"].keys())
        scores = [c["compliant"] / c["total"] * 100 if c["total"] > 0 else 0 for c in comp_score["categories"].values()]

        fig_radar = go.Figure(data=go.Scatterpolar(
            r=scores,
            theta=cats,
            fill='toself',
            line_color="#00b4d8"
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e6ed",
            height=300,
            margin=dict(l=40, r=40, t=30, b=30)
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    with col_r2:
        st.markdown("#### 🎯 Compliance Summary")
        st.metric("Overall Compliance Score", f"{comp_score['overall_score']}%")
        st.metric("Security Level Achieved", comp_score["security_level"])
        st.metric("Compliant Requirements", f"{comp_score['compliant_requirements']} / {comp_score['total_requirements']}")

    st.markdown("#### 📋 Formal IEC 62443-3-2 Risk Register (RS1 - RS12)")
    reg_df = pd.DataFrame([
        {
            "Risk #": r["risk_number"],
            "Zone / Asset": f"{r['zone']} ({r['asset_description']})",
            "Severity": r["severity"],
            "Unmitigated Risk": r["unmitigated_risk"],
            "Residual Risk": r["final_residual_risk"],
            "Target SL": r["target_sl"],
            "Countermeasures": r["countermeasures"],
            "Status": r["status"]
        }
        for r in risk_reg
    ])
    st.dataframe(reg_df, use_container_width=True)
