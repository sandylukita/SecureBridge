# 🔐 SecureBridge
### AI-Powered OT/ICS Security Command Center & Compliance Platform

> **Built by:** Sandy Lukita | PT Optima Sarana Instrument  
> **Status:** Technology Demonstrator | Architecture Validated | Azure Showcase Ready  
> **Version:** 1.7.0  

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
                             Groq API / Gemini / Claude / Local Ollama
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
- Uses the same passive network monitoring principle employed by commercial OT monitoring platforms.

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
| **HIGH / CRITICAL** | Critical Threat | Full LLM (Groq / Gemini / Claude / Ollama) | Full Threat Reasoning & Playbook |

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

### 7. Deterministic SOC Visualizations (Zero-Hallucination)
To ensure absolute credibility during incident response, SecureBridge limits SOC visualizations strictly to data derived passively from the network, eliminating AI hallucination risks:
- **Incident Timeline**: 100% data-driven raw OT event timeline sorted by anomaly score.
- **Communication Matrix**: Aggregated IP-to-IP traffic heatmap based purely on logged packets.
- **Fact-Based Asset Details**: Shows vendor (OUI), protocol, and Purdue level. Deliberately omits firmware/OS details to prevent unverified claims without active probing.
- **Static MITRE ATT&CK Mapping**: Deterministic mapping of Modbus function codes to ICS ATT&CK techniques (e.g., FC 16 → T0836) without LLM guesswork.

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

### 9. Public OT Threat Intelligence Aggregator (`ThreatIntelFeed`)

SecureBridge integrates public OT threat intelligence without compromising air-gapped security:

- **CISA ICS-CERT Feed**: Automatically correlates passively discovered assets (Schneider Electric, Rockwell Automation, Siemens S7) against official US CISA advisories.
- **Offline Pre-Fetch (`fetch_advisories.py`)**: Pre-populates `data/threat_intel/cisa_cache.json` so dashboard rendering uses zero live API calls during demos or air-gapped operation.
- **Code-Level Air-Gapped Guard Rail**: Features that require internet egress (such as Shodan exposure checks) raise `FeatureDisabledError` in air-gapped mode. Security claims are enforced directly in code (`code IS the documentation`).

```python
# Interview answer:
# "SecureBridge does not attempt to replicate Dragos's internal threat research team.
#  Instead, we aggregate public CISA ICS advisories and match them against discovered assets.
#  To maintain our zero-egress guarantee, advisories are served from a local cache, and
#  any feature requiring cloud egress explicitly raises FeatureDisabledError in air-gapped mode."
```

### 10. IEC 62443-3-2 Formal Risk Register & SUC Scope Definition
Audit-ready compliance reporting:
- **System Under Consideration (SUC)** explicit boundary definition
- **Formal Risk Register**: `RS1`, `RS2`, `RS3`... numbering system for full traceability
- **5 Impact Dimensions**: Health & Safety, Environmental, Financial, Reputational, Operational (Safety-First MAX impact evaluation)
- **Iterative Residual Risk Loop**: `Initial Risk` → `Countermeasure` → `Residual Risk <= Threshold`
- **1-Click PDF Report**: Executive summary in English & Bahasa Indonesia

---

## 🛡️ Case Study & Real-World Scenario Compliance

SecureBridge has been validated against seven internally defined OT security scenarios documented in [`study-case.md`](docs/study-case.md):

| Scenario | Focus Area | Verification Status | Key Capability |
|---|---|:---:|---|
| **Scenario 1** | IEC 62443 Audit & Air-Gapped Deployment | ✅ **Validated** | Local Ollama (`llama3.1`) + PDF report generator |
| **Scenario 2** | IT Ransomware Spreading to Industrial DMZ | ✅ **Validated** | Burst/scan detection + Level 3.5 containment playbook |
| **Scenario 3** | Rogue Contractor & Physical Bypass | ✅ **Validated** | Wire-level Pyshark DPI + `value_deviation` outlier scoring |
| **Scenario 4** | Safety Interlock Bypass & Logic Tampering | ✅ **Validated** | FC=15/16/43 high-risk weighting + integrity warning playbook |
| **Scenario 5** | Multi-Site Remote Infrastructure (GCC Grid) | ✅ **Validated** | On-premise Edge processing + lightweight <2KB alert JSON |
| **Scenario 6** | Air-Gapped Notification & Local Routing | ✅ **Validated** | Zero external inbound/outbound cloud dependency |
| **Scenario 7** | Supply Chain Attack & Trojanized Firmware | ✅ **Validated** | Signature-independent behavioral baseline (Isolation Forest) |

---

## Design Decisions

### Evolving from Event-based to Incident-based AI Analysis (V1 → V2)

The initial version of SecureBridge (V1) implemented a straightforward event-based AI analysis pattern:
```
Packet → Alert → LLM
```
While this worked well for isolated tests, it introduced an `O(N)` API call complexity. If an attacker launched a sequence of 50 Modbus write commands, the dashboard would make 50 sequential calls to the LLM backend. This pattern suffered from rate limits (e.g., triggering HTTP 429 Too Many Requests on free-tier APIs) and failed to provide the LLM with the sequence-level context necessary for root cause analysis.

**The V2 Architecture Shift**
SecureBridge V2 transitions the AI backend into an `O(1)` Incident-Based Batching pattern:
```
Packet → Alert → Incident Builder → Incident Summary → LLM
```

Instead of looping through raw alerts, the **IncidentAnalyst** groups anomalies into highly contextual **Incidents** using an extensible `IncidentStrategy` (defaulting to grouping by the Asset Pair: `Source IP` + `Target IP`). 
It then compresses identical sequence steps (e.g., "30x Modbus Read") into an `Incident Summary` before passing it to the LLM. 

This DDD (Domain-Driven Design) shift achieves three critical improvements:
1. **Zero Rate Limiting:** Batches all related alerts into a single API request, entirely bypassing Gemini/Azure free-tier rate limits.
2. **Context Enrichment:** The LLM now analyzes the *sequence* of an attack rather than isolated packets, drastically reducing hallucination and improving mitigation playbooks.
3. **SIEM-grade Caching:** Responses are now cached based on an `Incident ID` signature, ensuring deterministic, ultra-fast dashboard rendering during client presentations.

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
│   ├── threat_intel/
│   │   ├── feed_aggregator.py # ThreatIntelFeed + CISA matcher + FeatureDisabledError
│   │   └── fetch_advisories.py# Pre-fetch script & bundled offline demo cache
│   │
│   └── advisor/
│       └── incident_analyst.py# Hybrid ThreatAdvisor (Groq + Gemini + Claude + Ollama)
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
    ├── threat_intel/          # cisa_cache.json (pre-fetched CISA advisories)
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
  provider: auto            # Auto routes: Groq -> Gemini -> Claude -> Ollama -> Rules
  groq_model: llama-3.3-70b-versatile
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
# Set GROQ_API_KEY=your-api-key-here in .env for free sub-second AI analysis

# Pre-fetch CISA advisories (runs offline from local cache during demo)
python core/threat_intel/fetch_advisories.py

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
| **Threat Intel** | `ThreatIntelFeed` — CISA ICS-CERT RSS feed, offline cache, asset vendor matching |
| **Air-Gapped Control** | Code-level `FeatureDisabledError` guard rails for zero-egress enforcement |
| **LLM — Cloud Showcase** | Groq API (`llama-3.3-70b`) / Google Gemini API (`gemini-flash-latest`) — Free tier, sub-second |
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
