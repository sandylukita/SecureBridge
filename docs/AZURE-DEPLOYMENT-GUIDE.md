# ☁️ SecureBridge — Azure Showcase Lab Deployment Guide

Document Version: 1.1  
Target Audience: System Engineers, Consultants, Sales Engineering  
Purpose: Step-by-Step Playbook for Deploying SecureBridge on Microsoft Azure for Remote Client Demos & Showcase Labs.

---

## 🎯 EXECUTIVE SUMMARY & COST PROFILE

This guide details how to deploy SecureBridge to **Microsoft Azure** as an online showcase lab. By combining a lightweight Azure Virtual Machine with **Groq Cloud API** and **Google Gemini API (Free Tier)**, you get an ultra-fast, publicly accessible OT SOC Security Dashboard at minimal cost.

```
[Client / Interviewer] ──(HTTPS/HTTP Port 8501)──> [Azure Network Security Group]
                                                           │
                                                           ▼
                                                [Azure Ubuntu VM (B2s)]
                                                 ├── Streamlit SOC Dashboard
                                                 ├── Modbus Traffic Simulator (Auto-Inject)
                                                 ├── 19-Feature Isolation Forest
                                                 └── Groq / Gemini Cloud API (<1.5s AI)
```

### 💰 Cost Comparison Profile

| Metric | Local Ollama on Azure | Groq / Gemini API on Azure (Recommended) |
|---|---|---|
| **Azure VM Size** | `Standard_D4s_v5` (16 GB RAM) | **`Standard_B2s` (4 GB RAM)** |
| **Azure Monthly Cost** | ~$70 – $100 / month | **~$12 – $15 / month** (or free with Azure credits) |
| **LLM Inference Cost** | $0 | **$0 (Groq & Google Gemini Free Tiers)** |
| **Inference Speed** | 5 – 10 seconds | **Sub-second to ~1.5s** |
| **Setup Complexity** | High (large model download) | **Zero (One-line API key in `.env`)** |

---

## 📋 PREREQUISITES

1. An active **Microsoft Azure Account** (Pay-As-You-Go or Free Trial).
2. A free **Groq API Key** from [Groq Console](https://console.groq.com/keys) (Recommended, ultra-fast) or **Google Gemini API Key** from [Google AI Studio](https://aistudio.google.com/app/apikey).
3. SSH terminal client (Windows PowerShell, Windows Terminal, or macOS/Linux Terminal).

---

## 🚀 STEP-BY-STEP AZURE PORTAL SETUP

### Step 1: Create an Azure Virtual Machine

1. Log in to the [Azure Portal](https://portal.azure.com).
2. Search for **Virtual Machines** and click **Create** > **Azure virtual machine**.
3. Configure the **Basics** tab:
   - **Subscription**: Select your active subscription.
   - **Resource Group**: Create new e.g. `rg-securebridge-demo`.
   - **Virtual Machine Name**: `vm-securebridge-demo`.
   - **Region**: Select closest region e.g. `(Asia Pacific) Southeast Asia`, `(Asia Pacific) Korea Central`, or `(US) East US`.
   - **Image**: **Ubuntu Server 22.04 LTS - x64 Gen2** (or 24.04 LTS).
   - **Size**: **Standard_B2s** (2 vCPUs, 4 GiB memory).
   - **Authentication Type**: SSH public key (or Password for quick setup).

### Step 2: Configure Network Security Group (NSG) Inbound Rule

1. Navigate to your created VM > **Networking** (or **Network security group**).
2. Under **Inbound port rules**, click **Add inbound port rule**.
3. Configure rule parameters:
   - **Source**: `Any`
   - **Source port ranges**: `*`
   - **Destination**: `Any`
   - **Service**: `Custom`
   - **Destination port ranges**: `8501`
   - **Protocol**: `TCP`
   - **Action**: `Allow`
   - **Priority**: `1010`
   - **Name**: `Allow-Streamlit-Dashboard`
4. Click **Add**.

### Step 3: Configure Azure DNS Domain Name

1. Go to VM Overview page > **DNS name** (click *Not configured*).
2. Set **DNS name label** e.g. `securebridge-demo`.
3. Save. Your public URL will be:
   `http://securebridge-demo.<region>.cloudapp.azure.com:8501`

---

## 💻 STEP-BY-STEP TERMINAL COMMANDS

Connect to your Azure VM via SSH:

```bash
ssh azureuser@securebridge-demo.<region>.cloudapp.azure.com
# or via Public IP: ssh azureuser@<YOUR_AZURE_PUBLIC_IP>
```

### 1. Install Docker & Git (One-Liner Script)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone SecureBridge Repository

```bash
git clone https://github.com/sandylukita/SecureBridge
cd SecureBridge
```

### 3. Configure Environment Variables (`.env`)

Create your `.env` file and insert your API keys:

```bash
cat << 'EOF' > .env
# SecureBridge Azure Showcase Environment
GROQ_API_KEY=gsk_your-groq-api-key-here
GEMINI_API_KEY=your-gemini-api-key-here
SECUREBRIDGE_MODE=lab
EOF
```

### 4. Verify Configuration (`config/lab.yaml`)

The default configuration automatically enables the auto-inject simulator and hybrid AI routing:

```yaml
mode: lab

simulator:
  enabled: true
  plc_count: 3
  polling_interval: 5            # seconds
  inject_anomalies: true         # Auto-injects 6 distinct OT incident scenarios

llm:
  provider: auto                 # Auto-routes: Groq -> Gemini -> Claude -> Ollama -> Rules
  groq_model: qwen/qwen3.8-27b    # Or llama-3.1-8b-instant
  gemini_model: gemini-flash-latest
  api_timeout: 15
```

### 5. Launch SecureBridge Container Stack

```bash
sudo docker compose up -d --build
```

### 6. Verify Container Status

```bash
sudo docker compose ps
sudo docker compose logs -f simulator | grep AUTO-INJECT
```

You will see the simulator generating baseline traffic and auto-injecting 6 distinct OT incident scenarios:
- **Write Single Register (CRITICAL)** — unauthorized control action (`192.168.10.199`)
- **Abnormal Polling Frequency (HIGH)** — network scan signature (`192.168.10.199`)
- **FC43 Device Identification (HIGH)** — asset reconnaissance scan (`192.168.10.198`)
- **Traffic Burst / DoS (HIGH)** — rapid sub-100ms request flood (`192.168.10.197`)
- **Cross-PLC Routing (MEDIUM)** — SCADA accessing unexpected PLC-03 (`192.168.10.100`)
- **Baseline Deviation (MEDIUM)** — out-of-range register access pattern (`192.168.10.196`)

---

## 🌐 ACCESS YOUR LIVE SHOWCASE LAB

Open your web browser and navigate to:

```
http://securebridge-demo.<your-region>.cloudapp.azure.com:8501
```

You will see the **SecureBridge SOC Security Command Center** live with:
- **3 Simulated Modbus PLCs** actively sending physical process telemetry
- **19-Feature Isolation Forest** scoring real-time anomalies with SIEM-grade incremental caching
- **Active OT Security Incidents** displaying auto-populated scenarios with Risk Indicators & Operational Context
- **Recommended Response Playbooks** aligned with the `INVESTIGATE → VALIDATE → CONTAIN` methodology
- **Instant AI Threat Investigation** powered by **Groq / Gemini API** (< 1.5s latency)
- **IEC 62443 PDF Compliance Report Generation** directly in the sidebar

---

## 🔄 AUTO-START ON VM REBOOT (SYSTEMD SETUP)

To ensure SecureBridge automatically starts whenever the Azure VM restarts:

```bash
sudo cat << 'EOF' > /etc/systemd/system/securebridge.service
[Unit]
Description=SecureBridge OT Security Docker Stack
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/azureuser/SecureBridge
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable securebridge.service
```

---

## ⚡ COST SAVING TIP: AZURE AUTO-SHUTDOWN

To avoid incurring charges when you are not performing client demos:

1. In Azure Portal, navigate to your VM > **Auto-shutdown** (under Operations).
2. Toggle **Enabled**: `On`.
3. Set **Scheduled shutdown time**: e.g., `19:00:00` (7:00 PM).
4. Set **Time zone**: `SE Asia Standard Time` (or your local timezone).
5. Save.

*When you need to perform a client demo, simply click **Start** on the Azure VM Overview page. The systemd service will automatically launch SecureBridge within 30 seconds!*

---

## 🗣️ CLIENT PITCH & INTERVIEW NARRATIVE

> *"For remote showcases and lab demonstrations, we host SecureBridge on a lightweight Azure VM integrated with Groq & Google Gemini Cloud APIs for sub-second threat analysis and automated realistic OT incident scenarios. When deploying at live critical infrastructure sites (e.g. Oil & Gas refineries), SecureBridge switches to 100% Air-Gapped mode running on-premise local Ollama LLMs so that zero network telemetry ever leaves the plant boundary."*
