# 🔐 SecureBridge
### AI-Powered OT/ICS Security Platform

> **Built by:** Sandy Lukita | PT Optima Sarana Instrument  
> **Status:** Active Development — Live Deployment Ready  
> **Version:** 1.4.0  

---

## What is SecureBridge?

SecureBridge is an **agentless OT/ICS security monitoring platform**
designed for industrial instrumentation companies and their clients
in the oil & gas sector.

It bridges the gap between enterprise OT security tools (Dragos,
Claroty — $100k+/year) and companies that need industrial security
without enterprise budgets.

```
[OT Devices]  →  [SPAN / Mirror Port]  →  [Passive Capture]
                   no IP, no TX                    │
                                         pyshark.LiveCapture
                                         BPF: tcp/502 · tcp/44818 · udp/47808
                                                    │
                                        [Protocol Analysis]
                                        Modbus TCP · EtherNet/IP · BACnet/IP
                                                    │
                                       [ML Anomaly Detection]
                                       19-feature Isolation Forest
                                       delta_time · fc_risk · unknown_ip
                                                    │
                                        [LLM Threat Analysis]
                             Gemini API / Claude API / Local Ollama (llama3.1)
                                                    │
                              ┌─────────────────────┴──────────────────┐
                              │                                         │
                    [Live Dashboard]                        [Compliance Reports]
                    Real-time SOC view                      IEC 62443 PDF
                                                            Bahasa Indonesia
```

---

## Core Features

### 1. Passive Network Capture — pyshark.LiveCapture
Zero-impact monitoring via **pyshark** (TShark/libpcap wrapper) on a SPAN mirror port.
The monitoring interface has **no IP address** and cannot initiate connections.

- **BPF filter** targets only OT protocol ports — no promiscuous noise
- **Automatic fallback** to raw sockets if TShark is unavailable
- Same passive architecture used by **Nozomi Networks** and **Claroty**

```python
# Interview answer:
# "We use pyshark.LiveCapture() on a SPAN mirror port with a BPF filter
#  targeting TCP 502 (Modbus), TCP 44818 (EtherNet/IP), UDP 47808 (BACnet).
#  The interface has no IP — it cannot initiate connections."
```

### 2. Multi-Protocol OT Analysis
Deep packet inspection for industrial protocols:
- **Modbus TCP** (port 502) — register read/write monitoring, FC-level classification
- **EtherNet/IP** (port 44818) — Rockwell / Allen-Bradley PLC traffic
- **BACnet/IP** (port 47808) — Building automation and HVAC systems
- **DNP3** — SCADA communications

### 3. AI Anomaly Detection — 19-Feature Isolation Forest

Feature engineering built on OT behavioral baselines:

| Feature Group | Features | Detects |
|---|---|---|
| **Time** | hour, is_business_hours, is_weekend | Off-hours activity |
| **Delta Time** | packet_delta_time, rolling_std, is_burst | DDoS / scan bursts |
| **FC Risk** | function_code_risk (0-10) | Write & recon commands |
| **Value** | value, rolling_mean, deviation | Sensor manipulation |
| **Network** | src_ip_hash, is_unknown_src_ip | Unauthorized access |
| **Register** | register_address, addr_delta | Sequential scan |
| **Protocol** | is_write, payload_size, transaction_rate | Behavioral baseline |

Real-time scoring uses a **sliding EventWindow** (20 events) so rolling
features are computed on real context — not a meaningless single-row snapshot.

### 4. Hybrid LLM Threat Advisor — Gemini + Claude + Ollama

Four flexible LLM backends, identical output schema, automatic routing:

| Mode | Primary Backend | Cost | Inference Speed | When to Use |
|---|---|---|---|---|
| `auto` | Gemini → Claude → Ollama → Rules | **$0** (Free Tier) | Sub-second | **Default** — intelligent multi-tier routing |
| `gemini` | Google Gemini (`gemini-flash-latest`) | **$0** (Free Tier) | **< 1s** | Cloud Showcase & Azure Lab Demo |
| `claude` | Anthropic Claude (`claude-sonnet-4-6`) | API Cost | 2–3s | Complex threat reasoning & enterprise |
| `ollama` / `air-gapped` | Local Ollama (`llama3.1` / `qwen2.5`) | **$0** (Local) | 5–10s | **Air-gapped OT networks** (zero egress) |
| *(fallback)* | Rule-based deterministic | $0 | Instant | Guaranteed fallback if all LLMs offline |

For every analyzed threat, all modes return the same structured JSON schema:
`threat_summary`, `possible_causes`, `immediate_actions`,
`iec62443_reference`, `mitre_attack_ics`, `escalate_immediately`.

The dashboard and reporting engine never need to know which backend responded.

```python
# Interview answer:
# "SecureBridge supports flexible deployment modes. For cloud showcases or Azure labs,
#  we use Google Gemini API (Free tier, sub-second inference). For air-gapped OT sites,
#  we deploy local Ollama (llama3.1) so telemetry data never leaves the plant network."
```

### 5. Real-Time SOC Dashboard
Streamlit-based dashboard:
- Live device status and health
- Anomaly timeline and scoring
- AI-powered alert analysis (Gemini / Claude / Ollama) with instant response caching
- Persistent one-click PDF report generation in sidebar

### 6. Compliance Report Generator
Automated PDF reports in English and Bahasa Indonesia:
- Dynamic risk scoring based on active telemetry
- IEC 62443 compliance scoring & audit-ready mapping
- Detailed findings with 3-phase remediation roadmap
- Executive summary for management

### 7. Multi-Channel Alerting
Instant notifications via:
- Email (SMTP)
- Telegram Bot
- Dashboard alerts

---

## 🛡️ Case Study & Real-World Scenario Compliance

SecureBridge has been **100% verified** against 7 critical real-world OT security scenarios defined in [`study-case.md`](study-case.md):

| Scenario | Focus Area | Verification Status | Key Capability |
|---|---|:---:|---|
| **Scenario 1** | IEC 62443 Audit & Air-Gapped Deployment | ✅ **100% Verified** | Local Ollama (`llama3.1`) + PDF report generator |
| **Scenario 2** | IT Ransomware Spreading to Industrial DMZ | ✅ **100% Verified** | Burst/scan detection + Level 3.5 containment playbook |
| **Scenario 3** | Rogue Contractor & Physical Bypass | ✅ **100% Verified** | Wire-level Pyshark DPI + `value_deviation` outlier scoring |
| **Scenario 4** | Safety Interlock Bypass & Logic Tampering | ✅ **100% Verified** | FC=15/16/43 high-risk weighting + integrity warning playbook |
| **Scenario 5** | Multi-Site Remote Infrastructure (GCC Grid) | ✅ **100% Verified** | On-premise Edge processing + lightweight <2KB alert JSON |
| **Scenario 6** | Air-Gapped Notification & Local Routing | ✅ **100% Verified** | Zero external inbound/outbound cloud dependency |
| **Scenario 7** | Supply Chain Attack & Trojanized Firmware | ✅ **100% Verified** | Signature-independent behavioral baseline (Isolation Forest) |

---

## Architecture

```
SecureBridge/
│
├── core/
│   ├── capture/
│   │   ├── monitor.py         # LiveMonitor: pyshark-first + raw socket fallback
│   │   └── pyshark_capture.py # PysharkCapture: LiveCapture + BPF + multi-protocol
│   │
│   ├── detection/
│   │   └── model.py           # 19-feature Isolation Forest + EventWindow scorer
│   │
│   └── advisor/
│       └── claude.py          # Hybrid ThreatAdvisor (Gemini + Claude + Ollama + Fallback)
│
├── dashboard/
│   └── app.py                 # Streamlit SOC dashboard with response caching
│
├── compliance/
│   ├── iec62443_mapper.py     # IEC 62443 requirement mapping
│   └── report_generator.py   # PDF report generation
│
├── alerts/
│   └── notifier.py            # Multi-channel alert engine
│
├── config/
│   ├── settings.py            # CaptureConfig & LLMConfig management
│   ├── live.yaml              # SPAN port deployment config (air-gapped default)
│   └── lab.yaml               # Lab/demo config (auto mode with Gemini API)
│
└── data/
    ├── models/                # Trained Isolation Forest (pkl)
    ├── reports/               # Generated PDF reports
    └── logs/                  # OT event CSV (ML training data)
```

---

## Two Deployment Modes

### Live Production Mode — Air-Gapped SPAN Port Deployment

```yaml
# config/live.yaml
mode: live
capture:
  interface: "eth1"          # SPAN / mirror port — no IP needed
  use_pyshark: true
  bpf_filter: "tcp port 502 or tcp port 44818 or udp port 47808"
  target_network: "192.168.40.0/24"
llm:
  mode: air-gapped           # PRODUCTION: 100% local — zero data egress
  ollama_model: llama3.1     # Run: ollama pull llama3.1
  ollama_host: http://localhost:11434
```

**Prerequisites:**
- Windows: [Npcap](https://npcap.com) + Wireshark (for TShark)
- Linux: `sudo apt install tshark` + run as root / `CAP_NET_RAW`
- Connect interface to SPAN/mirror port (no IP assignment needed)

### Lab / Azure Showcase Mode — Ultra-Fast & Free Tier

```yaml
# config/lab.yaml
mode: lab
simulator:
  enabled: true
  plc_count: 3              # 3 simulated PLCs with realistic Modbus traffic
llm:
  mode: auto                # Auto routes: Gemini API -> Claude -> Ollama -> Rules
  gemini_model: gemini-flash-latest
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/sandylukita/SecureBridge
cd SecureBridge

# Setup Environment
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Configure Environment Variables (.env)
cp .env.example .env
# Set GEMINI_API_KEY=your-api-key-here in .env for free sub-second AI analysis

# Lab Mode — Run Dashboard
streamlit run dashboard/app.py

# Train ML model on collected traffic
python core/detection/model.py train data/logs/ot_events_YYYYMMDD.csv

# Live Mode (SPAN port, run as Administrator)
python core/capture/monitor.py config/live.yaml
```

---

## Tech Stack

| Component | Technology |
|---|---|
| **Network Capture** | pyshark 0.6 (TShark / libpcap / Npcap) |
| **Capture Fallback** | Python `socket.SOCK_RAW` |
| **BPF Filter** | `tcp port 502 or tcp port 44818 or udp port 47808` |
| **Protocol Parsers** | pymodbus + custom Modbus/EtherNet-IP/BACnet parsers |
| **ML Detection** | scikit-learn — Isolation Forest (19 features) |
| **LLM — Cloud Showcase** | Google Gemini API (`gemini-flash-latest`) — Free tier, sub-second |
| **LLM — Cloud High-End** | Anthropic Claude API (`claude-sonnet-4-6`) |
| **LLM — Local Air-Gapped**| Ollama (`llama3.1` / `qwen2.5`) — zero data egress |
| **LLM Fallback** | Rule-based engine with MITRE ATT&CK ICS tags |
| **Dashboard** | Streamlit + Plotly |
| **PDF Reports** | ReportLab |
| **Alerts** | smtplib + python-telegram-bot |
| **Config** | PyYAML + python-dotenv |
| **Data** | Pandas + CSV |

---

## Deployment Requirements

### Live Client Site (Air-Gapped)
- Python 3.10+
- Network tap or SPAN port access (read-only, no IP)
- Windows: Npcap + Wireshark installed
- Linux: tshark + root / CAP_NET_RAW
- On-premise local Ollama instance (`llama3.1`)

### Azure / Cloud Showcase Lab
- Python 3.10+ or Azure VM (`Standard_B2s`, 4GB RAM)
- Any OS (Windows / Linux / Mac)
- `GEMINI_API_KEY` in `.env` (Free Tier)
- See [`AZURE-DEPLOYMENT-GUIDE.md`](AZURE-DEPLOYMENT-GUIDE.md) for step-by-step Azure VM deployment & cost optimization guide.

---

## 📖 User Manual & Documentation
- 📘 **Complete User Manual**: See [`USER-GUIDE.md`](USER-GUIDE.md) for end-to-end instructions from installation to SOC dashboard & PDF compliance reports.
- ☁️ **Azure Showcase Guide**: See [`AZURE-DEPLOYMENT-GUIDE.md`](AZURE-DEPLOYMENT-GUIDE.md) for Azure deployment & free-tier setup.
- 🛡️ **Case Study Matrix**: See [`study-case.md`](study-case.md) for 7 verified operational OT security scenarios.

---

## Developed By

**Sandy Lukita**  
IT & OT Security Consultant  
PT Optima Sarana Instrument  

20+ years critical infrastructure experience:  
BBC News · USAID SINAR · Fujitsu · Bakriesumatera

📧 sandylukita@gmail.com
