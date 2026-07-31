# 🔐 SecureBridge
### AI-Powered OT/ICS Security Platform

> **Built by:** Sandy Lukita | PT Optima Sarana Instrument  
> **Status:** Active Development — Live Deployment  
> **Version:** 1.0.0  

---

## What is SecureBridge?

SecureBridge is an **agentless OT/ICS security monitoring platform** 
designed for industrial instrumentation companies and their clients 
in the oil & gas sector.

It bridges the gap between enterprise OT security tools (Dragos, 
Claroty — $100k+/year) and companies that need industrial security 
without enterprise budgets.

```
[OT Devices]  →  [Passive Capture]  →  [Protocol Analysis]
                                               │
                                    [ML Anomaly Detection]
                                               │
                                    [LLM Threat Analysis]
                                    (Claude API)
                                               │
                              ┌────────────────┴──────────────┐
                              │                               │
                    [Live Dashboard]              [Compliance Reports]
                    Real-time SOC view            IEC 62443 PDF
                                                  Bahasa Indonesia
```

---

## Core Features

### 1. Agentless OT Network Monitor
Passive packet capture — zero impact on OT operations.  
No agent installation required on legacy OT devices.

### 2. Protocol-Aware Analysis
Deep packet inspection for industrial protocols:
- **Modbus TCP** — register read/write monitoring
- **DNP3** — SCADA communications
- **OPC-UA** — IT/OT bridge monitoring
- **S7comm** — Siemens PLC detection

### 3. AI Anomaly Detection
Isolation Forest ML model trained on device-specific baselines.  
Detects behavioral deviations invisible to signature-based tools.

### 4. LLM Threat Advisor
Claude API integration for intelligent threat analysis:
- Plain-English explanation of anomalies
- Ranked root cause analysis
- IEC 62443-aligned response actions
- Severity classification

### 5. Real-Time Dashboard
Streamlit-based SOC dashboard:
- Live device status and health
- Anomaly timeline and scoring
- AI-powered alert analysis
- Network topology view

### 6. Compliance Report Generator
Automated PDF reports in English and Bahasa Indonesia:
- IEC 62443 compliance scoring
- Detailed findings with remediation roadmap
- Executive summary for management
- Audit-ready documentation

### 7. Multi-Channel Alerting
Instant notifications via:
- Email (SMTP)
- Telegram Bot
- Dashboard alerts

---

## Architecture

```
SecureBridge/
│
├── core/
│   ├── capture/          # Passive network monitoring (Scapy)
│   │   └── monitor.py    # Agentless packet capture engine
│   │
│   ├── protocols/        # Industrial protocol parsers
│   │   ├── modbus.py     # Modbus TCP deep inspection
│   │   ├── dnp3.py       # DNP3 protocol analysis
│   │   └── opcua.py      # OPC-UA monitoring
│   │
│   ├── detection/        # ML anomaly detection
│   │   ├── baseline.py   # Baseline establishment
│   │   ├── model.py      # Isolation Forest engine
│   │   └── scorer.py     # Anomaly scoring
│   │
│   └── advisor/          # LLM threat analysis
│       └── claude.py     # Claude API integration
│
├── dashboard/
│   └── app.py            # Streamlit SOC dashboard
│
├── compliance/
│   ├── iec62443_mapper.py # IEC 62443 requirement mapping
│   └── report_generator.py # PDF report generation
│
├── alerts/
│   └── notifier.py       # Multi-channel alert engine
│
├── config/
│   ├── settings.py       # Configuration management
│   ├── live.yaml         # Live deployment config
│   └── lab.yaml          # Lab/demo config
│
├── data/
│   ├── models/           # Trained ML models
│   ├── reports/          # Generated PDF reports
│   └── logs/             # Traffic and event logs
│
└── tests/
    └── test_*.py         # Test suite
```

---

## Two Deployment Modes

### Live Mode (PT Optima Client Sites)
```yaml
# config/live.yaml
mode: live
capture:
  interface: eth1          # Real network interface
  target_network: 192.168.30.0/24
protocols:
  - modbus
  - dnp3
alerts:
  telegram: true
  email: true
```

### Lab/Demo Mode (Showcase)
```yaml
# config/lab.yaml  
mode: lab
capture:
  interface: loopback      # Simulated traffic
  target_network: 127.0.0.1
simulator:
  enabled: true
  plc_count: 3
  inject_anomalies: true   # For demo purposes
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/[username]/SecureBridge
cd SecureBridge

# Install
pip install -r requirements.txt

# Configure
cp config/lab.yaml config/active.yaml
# Edit config/active.yaml with your settings

# Run dashboard
streamlit run dashboard/app.py

# Run monitor (separate terminal)
python core/capture/monitor.py
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Network Capture | Python Scapy |
| Protocol Analysis | pymodbus, custom parsers |
| ML Detection | scikit-learn (Isolation Forest) |
| LLM Analysis | Anthropic Claude API |
| Dashboard | Streamlit + Plotly |
| PDF Reports | ReportLab |
| Alerts | smtplib + python-telegram-bot |
| Config | PyYAML |
| Data | Pandas + CSV/SQLite |

---

## Deployment

### Live Client Site Requirements
- Python 3.10+
- Network tap or SPAN port access
- Read-only access to OT network segment
- Internet access for Claude API (alerts only)

### Lab Requirements
- Python 3.10+
- Any OS (Windows/Linux/Mac)
- ModRSsim2 for Modbus simulation

---

## Developed By

**Sandy Lukita**  
IT & OT Security Consultant  
PT Optima Sarana Instrument  

20+ years critical infrastructure experience:  
BBC News · USAID SINAR · Fujitsu · Bakriesumatera

📧 sandylukita@gmail.com
