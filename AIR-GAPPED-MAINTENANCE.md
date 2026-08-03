# 🔒 SecureBridge — Air-Gapped Maintenance & Model Update Guide

Document Version: 1.0  
Author: Sandy Lukita | PT Optima Sarana Instrument  
Target Audience: On-Site OT Security Engineers & Field Consultants  

---

## 🎯 OVERVIEW

Critical OT infrastructure (Oil & Gas refineries, offshore platforms, power plants) operates in **strictly air-gapped networks** with zero inbound or outbound internet connectivity.

This document details the operational procedures for:
1. **Offline LLM Model Updates** (Ollama Docker volume export / USB transfer).
2. **30-Day Local ML Retraining** (Isolation Forest `ot_model.pkl`).
3. **Response Tiering Strategy** (Security Guard vs. Detective model).

---

## 💾 1. OFFLINE LLM MODEL TRANSFER (AIR-GAPPED SITES)

Base LLM models (e.g. `llama3.1:8b` or `qwen2.5:14b`) are updated **infrequently (every 6 to 12 months)**.

### Method A: Docker Volume Backup & Restore (Recommended)

#### Step 1 — On Engineer's Connected Workstation (Online):

```bash
# 1. Pull the target model on your online machine
docker pull ollama/ollama
docker run -d -v ollama_data:/root/.ollama --name temp-ollama ollama/ollama
docker exec temp-ollama ollama pull llama3.1

# 2. Export the Docker volume containing model weights into a compressed archive
docker run --rm -v ollama_data:/data -v $(pwd):/backup alpine tar czf /backup/ollama-llama31.tar.gz -C /data .

# 3. Copy ollama-llama31.tar.gz to an encrypted corporate USB drive
```

#### Step 2 — On Client Air-Gapped Server (Offline):

```bash
# 1. Plug in USB and create target volume
docker volume create ollama_data

# 2. Unpack model archive into the Docker volume
docker run --rm -v ollama_data:/data -v $(pwd):/backup alpine tar xzf /backup/ollama-llama31.tar.gz -C /data

# 3. Launch SecureBridge in Air-Gapped mode
docker compose --profile airgapped up -d

# 4. Verify local model availability without internet
docker exec securebridge-ollama ollama list
```

---

## 🤖 2. LOCAL ML ANOMALY MODEL RETRAINING (EVERY 30 DAYS)

Unlike the base LLM (which changes rarely), the **Isolation Forest ML Anomaly Model (`ot_model.pkl`)** must be retrained **every 30 days** on local plant traffic to adapt to process shifts and new legitimate equipment.

```
[Local Plant Traffic (30 Days)]  ──>  [Feature Extraction (19 Features)]  ──>  [Local Retraining Script]  ──>  [Updated ot_model.pkl]
```

### Local Retraining Command:

```bash
# Run inside SecureBridge environment on site
python core/detection/model.py train data/logs/ot_events_YYYYMMDD.csv
```

### Why Local Retraining Matters:
- The ML model learns the **exact baseline** of that specific plant (PLCs, Modbus registers, cycle times).
- **Zero data egress**: Training occurs 100% on-premise on site hardware.
- The base LLM weight remains untouched; only the lightweight ~5MB `.pkl` model updates.

---

## 🛡️ 3. EVENT RESPONSE TIERING (SECURITY GUARD VS DETECTIVE)

To prevent CPU/RAM starvation on air-gapped edge servers, SecureBridge enforces **Response Tiering (`should_invoke_llm`)**:

```
[Wire-Level Network Telemetry]
              │
              ▼
    [Isolation Forest ML]  ◄── "Security Guard" (Filters 100% of packets 24/7)
              │
    ┌─────────┴─────────┐
    │                   │
(LOW Severity)   (HIGH / CRITICAL)
    │                   │
    ▼                   ▼
[Rule Engine]    [Local Ollama LLM]  ◄── "Detective" (Invoked only for high-value threats)
(Instant)        (Deep Analysis)
```

| Event Tier | Frequency | Processing Engine | Action |
|---|---|---|---|
| **LOW (Noise)** | ~85–90% | Isolation Forest ML + Rule Engine | Fast filter; no LLM invocation |
| **MEDIUM** | ~7–10% | Conditional LLM (`score >= 70` or `is_write=True`) | Selective AI investigation |
| **HIGH / CRITICAL** | < 1–3% | Full Local LLM (`llama3.1`) | Full Threat Reasoning & Mitigation Playbook |

---

## 📋 MAINTENANCE CADENCE SUMMARY

| Component | Update Frequency | Transfer Method | Impact on Operations |
|---|---|---|---|
| **Base LLM Weights (`llama3.1`)** | Every 6–12 months | Encrypted USB Tarball | Zero downtime |
| **ML Baseline (`ot_model.pkl`)** | **Every 30 days** | Local Python Retrain | Seamless reload (<1 sec) |
| **Threat Intel / IEC 62443 Matrix** | Monthly | Config YAML Sync | Hot-reload |
