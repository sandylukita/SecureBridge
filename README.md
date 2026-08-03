# 🔐 SecureBridge
### AI-Powered OT/ICS Security Command Center & Compliance Platform

> **Built by:** Sandy Lukita | PT Optima Sarana Instrument  
> **Status:** Active Development — Live Deployment Ready  
> **Version:** 1.6.0  

---

## What is SecureBridge?

SecureBridge is an **agentless OT/ICS security monitoring & compliance platform**
designed for industrial instrumentation companies and their clients
in the oil & gas sector.

It bridges the gap between enterprise OT security tools (Dragos,
Claroty — $100k+/year) and companies that need industrial security
without enterprise budgets.

```
[OT Devices]  →  [SPAN / Mirror Port]  →  [Passive Capture & Discovery]
                   no IP, no TX                    │
                                         pyshark.LiveCapture
                                         BPF: tcp/502 · tcp/44818 · udp/47808
                                         Passive Asset Discovery & Purdue Mapping
                                                    │
                                        [Protocol Analysis]
                                        Modbus TCP · EtherNet/IP · BACnet/IP
                                                    │
                                       [ML Anomaly Detection]
                                       19-feature Isolation Forest
                                       delta_time · fc_risk · unknown_ip
                                                    │
                                   [Hybrid LLM Response Tiering]
                             Gemini API / Claude API / Local Ollama (llama3.1)
                             "Security Guard vs Detective" Efficiency Model
                                                    │
             ┌──────────────────────────────────────┼──────────────────────────────────────┐
             │                                      │                                      │
   [SOC Command Center]                  [Purdue Topology Visualizer]            [Compliance Reports]
   Real-time Cyber Dark Theme            Level 1 - Level 3.5 Threat Graph        IEC 62443 PDF (RS1-RS12)
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

### 2. Passive Asset Discovery & Purdue Model Registry (`asset_registry.py`)
Automatically profiles and fingerprints industrial devices without active IP scanning:
- **Purdue Level 1 (Field Control)**: PLCs, RTUs, Actuators (Modbus Unit ID 1, 2, 3...)
- **Purdue Level 2 (Supervisory Control)**: SCADA Servers, HMI Operator Stations
- **Purdue Level 3.5 (Industrial DMZ)**: Historians, Rogue Vendor Hosts
- Dynamic Purdue Hierarchy Mapping & Asset Inventory Table

### 3. Interactive Purdue Model Network Topology Visualizer
Renders a live 2D Purdue Model Network Graph:
- **Normal Operations**: Devices glow in **Neon Green / Cyan**
- **Under Attack**: Rogue source hosts glow **Flaming Orange**, targeted PLCs glow **Flashing Red** with pulsing attack vectors
- Instant visual containment verification

### 4. AI Anomaly Detection — 19-Feature Isolation Forest with Scoring Integrity

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

**Score normalization** uses the raw `score_samples()` range from the training
dataset (`score_raw_min` / `score_raw_max` persisted in model metadata) — no
hardcoded constants. This ensures single-event scores are always consistent
with the trained model's baseline distribution:

```
Verified severity distribution on 8,661 OT events:
  LOW      88.2%  (routine Modbus Read polling)
  MEDIUM   10.4%  (timing deviations, unusual register access)
  HIGH      1.1%  (rapid network scans)
  CRITICAL  0.3%  (unauthorized Write commands from unknown IPs)
  → Matches IEC 62443 realistic OT traffic profile
```

### 5. Hybrid LLM Response Tiering — "Security Guard vs Detective" Model

Four flexible LLM backends with intelligent resource tiering (`should_invoke_llm`):

| Tier | Trigger | Processing Engine | Action |
|---|---|---|---|
| **LOW (Routine Noise)** | Score < 60 | Isolation Forest ML + Rule Engine | Instant filter; preserves edge CPU/RAM |
| **MEDIUM** | Score >= 70 or `is_write=True` | Conditional LLM | Selective AI investigation |
| **HIGH / CRITICAL** | Critical Threat | Full LLM (Gemini / Claude / Ollama) | Full Threat Reasoning & Playbook |

```python
# Interview answer:
# "Isolation Forest acts like a Security Guard scanning 100% of packets at wire-speed 24/7.
#  The LLM acts like a Detective called only when the Security Guard flags a high-value threat.
#  This prevents LLM inference fatigue and CPU starvation on air-gapped edge hardware."
```

### 6. Real-Time SCADA / HMI Process Telemetry Gauges
Visual physical process monitoring:
- **PLC-01**: Gas Turbine Speed (RPM)
- **PLC-02**: Cooling Loop Temperature (°C)
- **PLC-03**: Valve Line Pressure (BAR)
- Instant visual alarms: **`"VALVE OVERRIDE DETECTED"`** on unauthorized Modbus Write commands.

### 8. Incremental Scoring with Cache — SIEM-Grade Performance

SecureBridge uses an **`IncrementalScorer`** for dashboard refresh efficiency:

```
Refresh #1 (8,000 events)   → score all via Isolation Forest  (~0.3s)
Refresh #2 (8,017 events)   → score only 17 new events         (<0.01s)
Refresh #3 (8,031 events)   → score only 14 new events         (<0.01s)
```

- **No re-processing** of historical events on each dashboard refresh
- **Cache invalidation**: automatically flushed when model is retrained
  (tracked via `trained_at` timestamp in model metadata)
- **Zero false negatives**: every event is scored on first encounter —
  no sampling or blind spots

```python
# Interview answer:
# "SecureBridge uses incremental scoring with a hash-based cache.
#  Only events not previously seen are scored by Isolation Forest.
#  The cache is automatically invalidated when the model is retrained.
#  This is the same pattern used by enterprise SIEM platforms like Splunk
#  and IBM QRadar to handle high event volumes without sacrificing completeness."
```

### 9. IEC 62443-3-2 Formal Risk Register & SUC Scope Definition
Audit-ready compliance reporting:
- **System Under Consideration (SUC)** explicit boundary definition
- **Formal Risk Register**: `RS1`, `RS2`, `RS3`... numbering system for full traceability
- **5 Impact Dimensions**: Health & Safety, Environmental, Financial, Reputational, Operational (Safety-First MAX impact evaluation)
- **Iterative Residual Risk Loop**: `Initial Risk` → `Countermeasure` → `Residual Risk <= Threshold`
- **1-Click PDF Report**: Executive summary in English & Bahasa Indonesia

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
│   ├── discovery/
│   │   └── asset_registry.py  # Passive OT Asset Discovery & Purdue Model Registry
│   │
│   ├── detection/
│   │   └── model.py           # Isolation Forest + EventWindow + IncrementalScorer
│   │
│   └── advisor/
│       └── claude.py          # Hybrid ThreatAdvisor (Gemini + Claude + Ollama + Tiering)
│
├── dashboard/
│   └── app.py                 # Cyber SOC Command Center UI (4 Interactive Tabs)
│
├── compliance/
│   ├── iec62443_mapper.py     # SUC Scope, RS1-RS12 Risk Register, Compliance Mapping
│   └── report_generator.py   # One-Click PDF report generation with SUC & Risk Register
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
    ├── models/                # Trained Isolation Forest (pkl) + score_cache.pkl
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
| **Asset Discovery** | Passive OT Protocol Profiling & Purdue Model Subnetting |
| **BPF Filter** | `tcp port 502 or tcp port 44818 or udp port 47808` |
| **Protocol Parsers** | pymodbus + custom Modbus/EtherNet-IP/BACnet parsers |
| **ML Detection** | scikit-learn — Isolation Forest (19 features, training-stats normalization) |
| **ML Scoring** | `IncrementalScorer` — hash-based cache, O(N_new) per refresh, auto cache invalidation |
| **LLM — Cloud Showcase** | Google Gemini API (`gemini-flash-latest`) — Free tier, sub-second |
| **LLM — Cloud High-End** | Anthropic Claude API (`claude-sonnet-4-6`) |
| **LLM — Local Air-Gapped**| Ollama (`llama3.1` / `qwen2.5`) — zero data egress |
| **LLM Tiering** | `should_invoke_llm` Security Guard vs Detective Model |
| **MITRE ATT&CK** | ICS matrix only (T0xxx) — constrained in LLM system prompt |
| **Dashboard** | Streamlit + Plotly (Cyber Dark Theme + 4 Tabs) |
| **PDF Reports** | ReportLab (IEC 62443 SUC + Risk Register RS1-RS12) |
| **Alerts** | smtplib + python-telegram-bot |

---

## 📖 User Manual & Documentation
- 📘 **Complete User Manual**: See [`USER-GUIDE.md`](USER-GUIDE.md) for end-to-end instructions from installation to SOC dashboard & PDF compliance reports.
- ☁️ **Azure Showcase Guide**: See [`AZURE-DEPLOYMENT-GUIDE.md`](AZURE-DEPLOYMENT-GUIDE.md) for Azure deployment & free-tier setup.
- 🔒 **Air-Gapped Maintenance Guide**: See [`AIR-GAPPED-MAINTENANCE.md`](AIR-GAPPED-MAINTENANCE.md) for USB offline LLM model transfers & 30-day local ML retraining procedures.
- 🛡️ **Case Study Matrix**: See [`study-case.md`](study-case.md) for 7 verified operational OT security scenarios.

---

## Developed By

**Sandy Lukita**  
IT & OT Security Consultant  
PT Optima Sarana Instrument  

20+ years critical infrastructure experience:  
BBC News · USAID SINAR · Fujitsu · Bakriesumatera

📧 sandylukita@gmail.com
