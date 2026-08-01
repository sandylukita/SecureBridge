"""
SecureBridge — OT Security Dashboard
Real-time SOC interface for industrial control system monitoring

Run: streamlit run dashboard/app.py
"""

import sys
import os
import time
import json
import pandas as pd
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

# ─────────────────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecureBridge | OT Security",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────
# Styling
# ─────────────────────────────────────────────────────────

st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    .stApp > header { background-color: transparent; }

    /* Header */
    .sb-header {
        background: linear-gradient(135deg, #1a2744 0%, #0d4f6b 100%);
        padding: 16px 24px;
        border-radius: 8px;
        margin-bottom: 16px;
        color: white;
    }
    .sb-header h1 { margin: 0; font-size: 24px; color: white; }
    .sb-header p { margin: 4px 0 0; font-size: 12px; color: #b2dfdb; }

    /* Metric cards */
    .metric-card {
        background: white;
        border-radius: 8px;
        padding: 16px;
        border-left: 4px solid #0d7377;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .metric-critical { border-left-color: #c0392b !important; }
    .metric-high     { border-left-color: #e67e22 !important; }
    .metric-ok       { border-left-color: #27ae60 !important; }

    /* Alert cards */
    .alert-critical {
        background: #fdecea; border: 1px solid #f5c6cb;
        border-left: 4px solid #c0392b;
        border-radius: 6px; padding: 12px; margin: 8px 0;
    }
    .alert-high {
        background: #fff3e0; border: 1px solid #ffe0b2;
        border-left: 4px solid #e67e22;
        border-radius: 6px; padding: 12px; margin: 8px 0;
    }
    .alert-medium {
        background: #fffde7; border: 1px solid #fff9c4;
        border-left: 4px solid #f39c12;
        border-radius: 6px; padding: 12px; margin: 8px 0;
    }

    /* Status badges */
    .badge-live {
        background: #27ae60; color: white;
        padding: 2px 10px; border-radius: 12px;
        font-size: 11px; font-weight: bold;
    }
    .badge-lab {
        background: #3498db; color: white;
        padding: 2px 10px; border-radius: 12px;
        font-size: 11px; font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────
# Load Resources
# ─────────────────────────────────────────────────────────

@st.cache_resource
def load_resources():
    config = load_config("config/lab.yaml")
    scorer = AnomalyScorer("data/models/ot_model.pkl")
    # Read LLM mode from config — supports auto/claude/ollama/air-gapped
    llm_cfg = config.llm
    advisor = ThreatAdvisor(
        mode=llm_cfg.mode,
        ollama_model=llm_cfg.ollama_model,
        ollama_host=llm_cfg.ollama_host,
        claude_model=llm_cfg.claude_model,
        max_tokens=llm_cfg.max_tokens,
    )
    return config, scorer, advisor


config, scorer, advisor = load_resources()


@st.cache_data(ttl=3600)
def get_cached_threat_analysis(event_dict: dict) -> dict:
    """Cache LLM threat analysis per unique event dict to speed up dashboard rendering"""
    return advisor.analyze(event_dict)


# ─────────────────────────────────────────────────────────
# Data Loading
# ─────────────────────────────────────────────────────────

@st.cache_data(ttl=10)
def load_events(hours_back: int = 24) -> pd.DataFrame:
    """Load recent OT events from log files."""
    log_dir = "data/logs"

    if not os.path.exists(log_dir):
        return pd.DataFrame()

    dfs = []
    for fname in os.listdir(log_dir):
        if fname.endswith(".csv"):
            path = os.path.join(log_dir, fname)
            try:
                df = pd.read_csv(path)
                dfs.append(df)
            except Exception:
                pass

    if not dfs:
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp", ascending=True)

    if df.empty:
        return df

    # Time filter: show last N hours relative to the LATEST event in the data
    # (not datetime.now()) so lab/demo CSVs are never empty due to date mismatch
    latest_ts = df["timestamp"].max()
    cutoff    = latest_ts - timedelta(hours=hours_back)
    df = df[df["timestamp"] >= cutoff]

    return df


def score_events(df: pd.DataFrame) -> pd.DataFrame:
    """Apply ML scoring to events"""
    if df.empty:
        return df
    if scorer.model is None:
        df["anomaly_score"] = 0.0
        df["severity"] = "UNKNOWN"
        df["is_anomaly"] = False
        return df
    return scorer.score_batch(df)


# ─────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────

mode_badge = (
    '<span class="badge-live">● LIVE</span>'
    if config.mode == "live"
    else '<span class="badge-lab">◉ LAB</span>'
)

st.markdown(f"""
<div class="sb-header">
    <h1>🔐 SecureBridge OT Security Dashboard {mode_badge}</h1>
    <p>AI-Powered Industrial Control System Monitoring |
       PT Optima Sarana Instrument |
       {datetime.now().strftime('%d %B %Y %H:%M')}</p>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────
# Load & Score Data
# ─────────────────────────────────────────────────────────

hours_back_default = 24
df_raw = load_events(hours_back_default)
df = score_events(df_raw)
has_data = not df.empty


# ─────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────

with st.sidebar:
    # Styled text logo instead of external placeholder image
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1a2744,#0d4f6b);
                padding:12px 16px;border-radius:8px;margin-bottom:12px;">
        <span style="color:white;font-size:18px;font-weight:700;">🔐 SecureBridge</span><br>
        <span style="color:#b2dfdb;font-size:11px;">OT Security Platform</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ Dashboard Settings")
    hours_back = st.slider("Time window (hours)", 1, 168, 24)
    threshold = st.slider("Alert threshold", 0, 100, 60)
    ai_enabled = st.checkbox("Enable AI Analysis", True)
    refresh = st.slider("Refresh interval (sec)", 5, 60, 10)

    st.divider()
    st.markdown("### 🖥️ System Status")

    if config.mode == "live":
        st.success("● Live monitoring active")
    else:
        st.info("◉ Lab/Demo mode")

    st.caption(f"Network: {config.capture.target_network}")
    st.caption(f"Threshold: {threshold}/100")
    st.caption(f"Refresh: {refresh}s")

    # LLM backend status
    st.divider()
    st.markdown("### 🤖 LLM Backend")
    llm_mode = config.llm.mode
    llm_model = config.llm.ollama_model if llm_mode in ("ollama", "air-gapped") else config.llm.claude_model
    mode_label = {
        "auto":       "Auto (Claude→Ollama)",
        "claude":     "Cloud (Claude API)",
        "ollama":     "Local (Ollama)",
        "air-gapped": "Air-Gapped (Ollama)",
    }.get(llm_mode, llm_mode)
    st.caption(f"Mode : {mode_label}")
    st.caption(f"Model: {llm_model}")

    # Report Generation Controls (Sidebar)
    st.markdown("### 📄 Compliance Report")
    if st.button("📄 Generate IEC 62443 Report", type="primary"):
        with st.spinner("Generating PDF report..."):
            try:
                from compliance.report_generator import generate_report
                
                # Determine live risk level dynamically
                active_alerts = df[df["anomaly_score"] >= threshold] if has_data and "anomaly_score" in df.columns else pd.DataFrame()
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

                with open(output_path, "rb") as f:
                    st.session_state["pdf_bytes"] = f.read()
                    st.session_state["pdf_filename"] = os.path.basename(output_path)
                st.success("✅ Report generated!")
            except Exception as e:
                st.error(f"Report generation failed: {e}")

    if "pdf_bytes" in st.session_state:
        st.download_button(
            label="⬇️ Download PDF Report",
            data=st.session_state["pdf_bytes"],
            file_name=st.session_state["pdf_filename"],
            mime="application/pdf"
        )


# ─────────────────────────────────────────────────────────
# KPI Metrics Row
# ─────────────────────────────────────────────────────────

col1, col2, col3, col4, col5 = st.columns(5)

if has_data:
    alerts = df[df["anomaly_score"] >= threshold]
    critical = alerts[alerts["severity"] == "CRITICAL"]
    high = alerts[alerts["severity"] == "HIGH"]
    devices = df["device_id"].nunique() if "device_id" in df.columns else 0
    avg_score = df["anomaly_score"].mean()
    writes = df[df.get("is_write", pd.Series(False)).astype(bool)] if "is_write" in df.columns else pd.DataFrame()
else:
    alerts = critical = high = writes = pd.DataFrame()
    devices = avg_score = 0

with col1:
    st.metric(
        "🚨 Active Alerts",
        len(alerts),
        delta="Needs attention" if len(alerts) > 0 else "All clear"
    )

with col2:
    st.metric(
        "🔴 Critical",
        len(critical),
        delta="Immediate action" if len(critical) > 0 else "None"
    )

with col3:
    st.metric(
        "🟠 High",
        len(high),
        delta="Investigate" if len(high) > 0 else "None"
    )

with col4:
    st.metric(
        "🔌 Devices Monitored",
        devices,
        delta="Active"
    )

with col5:
    st.metric(
        "📊 Avg Anomaly Score",
        f"{avg_score:.1f}/100" if has_data else "N/A"
    )

st.divider()


# ─────────────────────────────────────────────────────────
# Main Charts
# ─────────────────────────────────────────────────────────

if has_data:
    col1, col2 = st.columns([3, 2])

    with col1:
        st.subheader("📈 Anomaly Score Timeline")
        fig = go.Figure()

        # Score line
        fig.add_trace(go.Scatter(
            x=df["timestamp"],
            y=df["anomaly_score"],
            mode="lines",
            name="Anomaly Score",
            line=dict(color="#0d7377", width=1.5),
            fill="tozeroy",
            fillcolor="rgba(13, 115, 119, 0.1)"
        ))

        # Alert threshold
        fig.add_hline(
            y=threshold,
            line_dash="dash",
            line_color="#e67e22",
            annotation_text=f"Alert Threshold ({threshold})",
            annotation_position="top right"
        )

        # Critical threshold
        fig.add_hline(
            y=80,
            line_dash="dot",
            line_color="#c0392b",
            annotation_text="Critical (80)",
            annotation_position="top left"
        )

        # Mark anomaly points
        anomaly_df = df[df["anomaly_score"] >= threshold]
        if not anomaly_df.empty:
            fig.add_trace(go.Scatter(
                x=anomaly_df["timestamp"],
                y=anomaly_df["anomaly_score"],
                mode="markers",
                name="Alert",
                marker=dict(
                    color=anomaly_df["anomaly_score"].apply(
                        lambda s: "#c0392b" if s >= 80 else "#e67e22"
                    ),
                    size=8,
                    symbol="circle"
                )
            ))

        fig.update_layout(
            height=300,
            showlegend=True,
            plot_bgcolor="white",
            paper_bgcolor="white",
            yaxis=dict(range=[0, 105], gridcolor="#f0f0f0"),
            xaxis=dict(gridcolor="#f0f0f0"),
            margin=dict(l=10, r=10, t=10, b=10)
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("🎯 Alert Distribution")

        if not alerts.empty:
            severity_counts = alerts["severity"].value_counts()
            colors_map = {
                "CRITICAL": "#c0392b",
                "HIGH": "#e67e22",
                "MEDIUM": "#f39c12",
                "LOW": "#27ae60"
            }
            fig2 = go.Figure(go.Pie(
                labels=severity_counts.index,
                values=severity_counts.values,
                marker_colors=[
                    colors_map.get(s, "#95a5a6")
                    for s in severity_counts.index
                ],
                hole=0.4
            ))
            fig2.update_layout(
                height=300,
                showlegend=True,
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.success("✅ No alerts in selected time window")

    # Device status table
    if "device_id" in df.columns:
        st.subheader("🔌 Device Status")

        device_summary = df.groupby("device_id").agg(
            events=("timestamp", "count"),
            max_score=("anomaly_score", "max"),
            avg_score=("anomaly_score", "mean"),
            last_seen=("timestamp", "max"),
            writes=("is_write", "sum") if "is_write" in df.columns else ("timestamp", "count")
        ).reset_index()

        device_summary["status"] = device_summary["max_score"].apply(
            lambda s: "🔴 ALERT" if s >= threshold else "🟢 NORMAL"
        )
        device_summary["avg_score"] = device_summary["avg_score"].round(1)
        device_summary["max_score"] = device_summary["max_score"].round(1)

        st.dataframe(
            device_summary[[
                "device_id", "status", "events",
                "avg_score", "max_score", "last_seen"
            ]],
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    # ─────────────────────────────────────────────────────
    # Active Alerts with AI Analysis
    # ─────────────────────────────────────────────────────

    st.subheader("🚨 Active Alerts")

    if alerts.empty:
        st.success("✅ No active alerts — all systems nominal")
    else:
        for _, row in alerts.sort_values(
            "anomaly_score", ascending=False
        ).head(10).iterrows():

            severity = row.get("severity", "MEDIUM")
            score = row.get("anomaly_score", 0)
            device = row.get("device_id", "Unknown")
            ts = row.get("timestamp", "")

            css_class = {
                "CRITICAL": "alert-critical",
                "HIGH": "alert-high",
                "MEDIUM": "alert-medium"
            }.get(severity, "alert-medium")

            with st.expander(
                f"{'🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🔔'} "
                f"{severity} — {device} | Score: {score:.1f}/100 | {ts}"
            ):
                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown("**📊 Event Details**")
                    st.write(f"Protocol: {row.get('protocol', 'N/A')}")
                    st.write(f"Event: {row.get('event_type', 'N/A')}")
                    st.write(f"Source: {row.get('src_ip', 'N/A')}")
                    st.write(f"Destination: {row.get('dst_ip', 'N/A')}")
                    st.write(f"Function: {row.get('function_name', 'N/A')}")
                    st.write(f"Register: {row.get('register_address', 'N/A')}")

                    if row.get("is_write"):
                        st.error("⚠️ WRITE OPERATION DETECTED")

                with col_b:
                    if ai_enabled:
                        with st.spinner("🤖 AI analyzing threat..."):
                            analysis = get_cached_threat_analysis(row.to_dict())

                        st.markdown("**🤖 AI Threat Analysis**")
                        st.write(f"**{analysis.get('threat_summary', 'N/A')}**")

                        st.markdown("**⚡ Immediate Actions:**")
                        for action in analysis.get("immediate_actions", [])[:3]:
                            st.write(f"• {action}")

                        iec = analysis.get("iec62443_reference", {})
                        if iec:
                            st.caption(
                                f"📖 IEC 62443: {iec.get('requirement')} — "
                                f"{iec.get('title', '')}"
                            )

                        mitre = analysis.get("mitre_attack_ics")
                        if mitre:
                            st.caption(f"🎯 MITRE ATT&CK ICS: {mitre}")

                        if analysis.get("escalate_immediately"):
                            st.error(
                                f"🔺 ESCALATE: {analysis.get('escalation_reason', '')}"
                            )
                    else:
                        st.info("Enable AI Analysis in sidebar for threat intelligence")

else:
    # No data state
    st.info(
        "📡 Waiting for OT network data...\n\n"
        "Run the monitor to start collecting events:\n"
        "```bash\npython core/capture/monitor.py config/lab.yaml\n```"
    )

    # Demo placeholder
    st.markdown("### 📋 Platform Capabilities")
    st.markdown("""
    **SecureBridge monitors and protects:**
    - ✅ Modbus TCP protocol (PLCs, RTUs)
    - ✅ DNP3 (SCADA communications)
    - ✅ OPC-UA (IT/OT bridge)
    - ✅ S7comm (Siemens PLCs)

    **AI-powered detection:**
    - ✅ Behavioral anomaly detection (Isolation Forest ML)
    - ✅ LLM threat analysis (Claude API)
    - ✅ IEC 62443 compliance mapping
    - ✅ Automated PDF reports (EN + Bahasa Indonesia)
    """)


# ─────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────

st.divider()
st.caption(
    "🔐 SecureBridge OT Security Platform | "
    "Sandy Lukita | PT Optima Sarana Instrument | "
    "IEC 62443 | Purdue Model | Claude API + Ollama (Air-Gapped)"
)

# Auto-refresh
time.sleep(refresh)
st.rerun()
