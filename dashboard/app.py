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
from core.detection.model import AnomalyScorer, classify_severity
from core.advisor.claude import ThreatAdvisor
from core.discovery.asset_registry import AssetRegistry
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
def get_config():
    return load_config("config/lab.yaml")

@st.cache_resource
def get_scorer():
    return AnomalyScorer("data/models/ot_model.pkl")

@st.cache_resource
def get_advisor(_config):
    return ThreatAdvisor(
        mode=_config.llm.mode,
        gemini_model=_config.llm.gemini_model,
        ollama_model=_config.llm.ollama_model,
        ollama_host=_config.llm.ollama_host,
        claude_model=_config.llm.claude_model,
    )

@st.cache_data(ttl=3600)
def get_cached_threat_analysis(anomaly_dict, _config_mode):
    advisor = get_advisor(get_config())
    return advisor.analyze(anomaly_dict)

config = get_config()
scorer = get_scorer()

# Initialize Asset Registry in Session State
if "asset_registry" not in st.session_state:
    st.session_state.asset_registry = AssetRegistry()

asset_registry = st.session_state.asset_registry

# ─────────────────────────────────────────────────────────
# Data Loading Function
# ─────────────────────────────────────────────────────────

def load_events(hours: int = 24) -> pd.DataFrame:
    log_dir = config.log_dir
    if not os.path.exists(log_dir):
        return pd.DataFrame()

    all_files = [
        os.path.join(log_dir, f)
        for f in os.listdir(log_dir)
        if f.endswith(".csv")
    ]
    if not all_files:
        return pd.DataFrame()

    latest_files = sorted(all_files, reverse=True)[:2]
    dfs = []
    for f in latest_files:
        try:
            df_temp = pd.read_csv(f)
            dfs.append(df_temp)
        except Exception:
            pass

    if not dfs:
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        cutoff = datetime.now() - timedelta(hours=hours)
        df_filtered = df[df["timestamp"] >= cutoff]
        if not df_filtered.empty:
            df = df_filtered

    # Smart sampling: Always preserve anomaly events + latest normal events (max 250 rows)
    anomaly_events = df[
        (df.get("anomaly_injected") == True) |
        (df.get("is_write") == True) |
        (df.get("function_code").isin([5, 6, 15, 16, 43])) |
        (df.get("src_ip") == "192.168.10.199")
    ]
    recent_events = df.tail(150)
    
    combined = pd.concat([anomaly_events, recent_events], ignore_index=False)
    combined = combined.drop_duplicates().sort_values("timestamp").tail(250)

    return combined

def score_events(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    local_scorer = AnomalyScorer("data/models/ot_model.pkl")
    scored_rows = []
    for _, row in df.iterrows():
        row_dict = row.to_dict()
        event_dict = {
            "timestamp": str(row_dict.get("timestamp", "")),
            "src_ip": str(row_dict.get("src_ip", "0.0.0.0")),
            "dst_ip": str(row_dict.get("dst_ip", "0.0.0.0")),
            "protocol": str(row_dict.get("protocol", "Modbus TCP")),
            "event_type": str(row_dict.get("event_type", "MODBUS_READ")),
            "unit_id": row_dict.get("unit_id"),
            "function_code": row_dict.get("function_code"),
            "function_name": str(row_dict.get("function_name", "")),
            "register_address": row_dict.get("register_address"),
            "value": row_dict.get("value"),
            "device_id": str(row_dict.get("device_id", "PLC-01")),
            "payload_length": row_dict.get("payload_length", 0),
            "raw_size": row_dict.get("raw_size", 64),
            "is_write": bool(row_dict.get("is_write", False)),
            "transaction_id": str(row_dict.get("transaction_id", "")),
            "anomaly_injected": bool(row_dict.get("anomaly_injected", False)),
        }
        res = local_scorer.score_event(event_dict)
        scored_rows.append(res)
        
        # Passively update asset registry
        asset_registry.process_event(res)

    return pd.DataFrame(scored_rows)

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
                
                df_temp = load_events(hours_back_default if 'hours_back_default' in locals() else 24)
                df_scored = score_events(df_temp)
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
    st.caption(f"Mode : {config.llm.mode.upper()}")
    st.caption(f"Model: {config.llm.gemini_model if config.llm.mode in ('auto', 'gemini') else config.llm.ollama_model}")

# ─────────────────────────────────────────────────────────
# Main Content & Header
# ─────────────────────────────────────────────────────────

df_raw = load_events(hours_back)
df = score_events(df_raw)
has_data = not df.empty and "timestamp" in df.columns

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
    if has_data:
        total_events = len(df)
        active_alerts = df[df["anomaly_score"] >= threshold]
        crit_count = len(df[df["severity"] == "CRITICAL"])
        high_count = len(df[df["severity"] == "HIGH"])
        med_count = len(df[df["severity"] == "MEDIUM"])
        devices_count = df["device_id"].nunique() if "device_id" in df.columns else 3
        avg_score = df["anomaly_score"].mean()
    else:
        total_events = 0
        active_alerts = pd.DataFrame()
        crit_count = 0
        high_count = 0
        med_count = 0
        devices_count = 3
        avg_score = 0.0

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(f"""
        <div class="soc-card status-crit">
            <div class="soc-card-title">Active Alerts</div>
            <div class="soc-card-value">{len(active_alerts)}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="soc-card status-crit">
            <div class="soc-card-title">Critical Severity</div>
            <div class="soc-card-value">{crit_count}</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="soc-card status-high">
            <div class="soc-card-title">High Severity</div>
            <div class="soc-card-value">{high_count}</div>
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
    st.markdown("#### 🚨 Active Security Alerts & AI Threat Analysis")
    if not active_alerts.empty:
        alerts_display = active_alerts.sort_values("anomaly_score", ascending=False).head(10)
        for _, alert in alerts_display.iterrows():
            sev = alert.get("severity", "LOW")
            score_val = alert.get("anomaly_score", 0.0)
            dev_id = alert.get("device_id", "PLC-01")
            fc_name = alert.get("function_name", "Unknown Function")
            src_ip = alert.get("src_ip", "0.0.0.0")
            dst_ip = alert.get("dst_ip", "0.0.0.0")

            expander_title = f"🔴 [{sev}] {dev_id} | Score: {score_val:.1f}/100 | {fc_name} from {src_ip}"
            
            with st.expander(expander_title):
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("**📊 Wire-Level Event Details (Passive DPI)**")
                    st.json({
                        "Device ID": dev_id,
                        "Protocol": alert.get("protocol"),
                        "Event Type": alert.get("event_type"),
                        "Function Code": alert.get("function_code"),
                        "Function Name": fc_name,
                        "Register Address": alert.get("register_address"),
                        "Source IP": src_ip,
                        "Destination IP": dst_ip,
                        "Is Write Command": alert.get("is_write"),
                        "Anomaly Score": f"{score_val:.1f} / 100",
                    })

                with col_right:
                    st.markdown("**🤖 AI Threat Analysis & Playbook**")
                    if ai_enabled:
                        analysis = get_cached_threat_analysis(alert.to_dict(), config.llm.mode)
                        st.markdown(f"**Threat Summary:** {analysis.get('threat_summary')}")
                        st.markdown("**⚡ Immediate Actions:**")
                        for act in analysis.get("immediate_actions", []):
                            st.markdown(f"- {act}")
                        
                        iec_ref = analysis.get("iec62443_reference", {})
                        st.caption(f"📖 IEC 62443: {iec_ref.get('requirement')} — {iec_ref.get('title')}")
                        st.caption(f"🎯 MITRE ATT&CK: {analysis.get('mitre_attack_ics')}")

                        # Interactive Firewall Playbook Expander
                        with st.expander("🛡️ Preview Firewall Containment Rule"):
                            st.code(f"""# Automated Edge Firewall Rule (DMZ Level 3.5 Isolation)
# Block unauthorized traffic from {src_ip} to {dst_ip}
iptables -A FORWARD -s {src_ip} -d {dst_ip} -p tcp --dport 502 -j DROP
# Log containment action
logger -t SECUREBRIDGE "CONTAINMENT: Blocked unauthorized Modbus FC{alert.get('function_code')} from {src_ip}"
""", language="bash")
    else:
        st.success("✅ No active alerts above threshold. Network operations normal.")

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
            color_discrete_map={"ONLINE": "#00e676", "WARNING": "#ff9100", "CRITICAL": "#ff1744"},
            text="label"
        )
        fig_topo.update_traces(textposition="top center", marker=dict(line=dict(width=2, color="white")))
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

# ─────────────────────────────────────────────────────────
# TAB 3: SCADA / HMI PROCESS TELEMETRY
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
