# 📋 SecureBridge Client Deployment Playbook
**PT Optima Sarana Instrument — OT Security Consulting**  
**Consultant:** Sandy Lukita  
**Version:** 1.0 | Confidential — Internal Use

---

## Overview

Dokumen ini adalah panduan lengkap step-by-step untuk deployment SecureBridge di site client. Ikuti urutan ini tanpa skip untuk memastikan deployment yang aman dan professional.

```
DAY 1          DAY 2          DAY 3          DAY 4-5
──────         ──────         ──────         ───────
Assessment  →  Setup      →  Baseline   →  Handover
& Discovery    & Deploy       Collection     & Report
```

---

## Pre-Site Checklist (Sebelum Berangkat)

Pastikan semua ini sudah siap sebelum ke site client:

```
LAPTOP SANDY:
□ SecureBridge folder lengkap (sudah tested di lab)
□ Docker Desktop running dan tested
□ USB drive berisi Docker images (untuk air-gapped)
□ .env.example sudah disiapkan (tanpa credentials)
□ config/live.yaml template sudah disiapkan
□ Nmap portable (untuk network discovery)
□ Wireshark portable (untuk verify SPAN traffic)

DOKUMEN:
□ NDA / Confidentiality Agreement (minta tanda tangan hari 1)
□ Engagement Letter / SOW sudah ditandatangani
□ Assessment checklist (printed)
□ Emergency contact client (IT person on-site)

AKSES:
□ Konfirmasi ada dedicated PC/server untuk SecureBridge
□ Konfirmasi ada akses ke managed switch (credentials)
□ Konfirmasi nama kontak IT on-site
□ Konfirmasi jadwal tidak ada maintenance window hari 2-3
```

---

# DAY 1 — ASSESSMENT & DISCOVERY

## Tujuan Hari 1
Memahami environment client secara menyeluruh sebelum menyentuh apapun. **Jangan install apapun di hari 1.**

---

## Step 1.1 — Kickoff Meeting (09:00 — 1 jam)

**Peserta:** Sandy + IT PIC client + Management (kalau bisa)

**Yang dibahas:**

1. Tujuan engagement dan expected outcome
2. Scope: sistem apa yang akan dimonitor, sistem apa yang OUT of scope
3. Rules of engagement: jam kerja, eskalasi, approval process
4. Timeline dan deliverables
5. Tanda tangan NDA kalau belum

**Yang harus Sandy tanyakan:**

```
□ "Siapa yang harus saya hubungi kalau ada pertanyaan teknis?"
□ "Apakah ada maintenance window yang harus kami hindari?"
□ "Apakah ada sistem yang TIDAK boleh disentuh sama sekali?"
□ "Berapa jumlah perangkat OT yang aktif saat ini?"
□ "Apakah switch jaringan OT managed atau unmanaged?"
□ "Apakah site ini air-gapped atau ada akses internet?"
□ "Apakah sudah pernah ada insiden keamanan sebelumnya?"
```

---

## Step 1.2 — Physical Site Walk (10:00 — 1-2 jam)

**Bawa:** Notebook, kamera HP (minta izin foto), assessment checklist

**Yang diamati dan dicatat:**

### Network Infrastructure
```
□ Jumlah switch dan lokasi fisiknya
□ Brand/model switch (Cisco, Hirschmann, Moxa, unmanaged?)
□ Apakah ada label pada kabel/port?
□ Kondisi kabel (terstruktur/berantakan?)
□ Lokasi server/PC yang ada
□ Apakah ada network diagram yang tersedia?
□ Router/modem internet — brand dan model
□ WiFi access point — lokasi dan coverage area
```

### OT/Control Systems
```
□ Jenis PLC yang digunakan (Siemens, Allen-Bradley, Mitsubishi?)
□ Apakah ada SCADA workstation? OS apa?
□ Apakah ada HMI terminal? Standalone atau networked?
□ Protokol yang digunakan (tanyakan ke engineer lapangan)
□ Apakah OT network terpisah dari IT? (VLAN? Physical?)
□ Apakah ada firewall antara IT dan OT?
```

### Security Posture (observasi visual)
```
□ Apakah ada password tertempel di monitor/perangkat?
□ Apakah ada USB yang tertancap di workstation OT?
□ Apakah ada PC lama/end-of-life yang masih digunakan?
□ Siapa saja yang punya akses fisik ke ruang kontrol?
□ Apakah ada CCTV di area server/kontrol?
```

---

## Step 1.3 — Network Discovery (13:00 — 2 jam)

**PENTING:** Minta izin tertulis sebelum jalankan Nmap. Scan di jam sepi (bukan jam produksi peak).

```bash
# Discovery scan — ringan, tidak invasif
nmap -sn 192.168.1.0/24 -oN scan_it_network.txt

# OT network (kalau diizinkan)
nmap -sn 192.168.30.0/24 -oN scan_ot_network.txt

# Identify OS dan services (hanya di IT network)
nmap -sV -O 192.168.1.0/24 -oN scan_detailed.txt
```

**Yang dicatat dari hasil scan:**
```
□ Jumlah device aktif per subnet
□ IP range yang digunakan
□ Device dengan port tidak wajar terbuka
□ Device yang tidak dikenal (unknown hostname/MAC)
□ OS yang sudah end-of-life (Windows XP, Server 2003, dll)
```

---

## Step 1.4 — Stakeholder Interview (15:00 — 1 jam)

Interview engineer lapangan atau operator yang paling tahu sistem:

```
□ "Pola kerja normal sistem seperti apa? Shift jam berapa?"
□ "Kapan terakhir kali ada perubahan pada sistem kontrol?"
□ "Pernah ada kejadian perangkat mati/hang tiba-tiba?"
□ "Vendor/teknisi luar sering masuk ke sistem ini?"
□ "Kalau ada masalah, prosedur eskalasi ke mana?"
□ "Software apa saja yang terinstall di workstation SCADA?"
```

---

## Step 1.5 — Day 1 Report (16:00 — 30 menit)

Tulis ringkasan temuan hari 1 langsung sebelum pulang:

```markdown
# Day 1 Summary — [Nama Client] — [Tanggal]

## Environment Overview
- Jumlah device IT: X
- Jumlah device OT: X  
- Switch type: managed/unmanaged
- IT/OT segmentation: ya/tidak/partial

## Top 3 Immediate Concerns
1. [Temuan paling kritis]
2. [Temuan kedua]
3. [Temuan ketiga]

## Confirmed for Day 2
- PC/server untuk SecureBridge: [hostname/IP]
- Switch untuk SPAN: [model/location]
- IT PIC on-site: [nama + HP]
- Approved scan window: [jam]
```

---

# DAY 2 — SETUP & DEPLOYMENT

## Tujuan Hari 2
Deploy SecureBridge di environment client. Target: dashboard running sebelum jam 15:00.

---

## Step 2.1 — Prepare Deployment Server (09:00 — 1 jam)

### Opsi A: PC/Server Windows Client
```powershell
# Cek Docker sudah terinstall
docker --version

# Kalau belum, download Docker Desktop
# https://www.docker.com/products/docker-desktop/
# Install dan restart

# Verify setelah restart
docker run hello-world
```

### Opsi B: Server Linux Client
```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify
docker --version
docker-compose --version
```

### Opsi C: Air-Gapped (tidak ada internet)
```bash
# Di laptop Sandy (sudah disiapkan sebelumnya):
# Load images dari USB

docker load < /media/usb/sb_dashboard.tar
docker load < /media/usb/sb_simulator.tar
docker load < /media/usb/ollama.tar

# Verify images loaded
docker images | grep securebridge
docker images | grep ollama
```

---

## Step 2.2 — Copy SecureBridge (09:30 — 15 menit)

### Via Git (ada internet):
```bash
git clone https://github.com/sandylukita/SecureBridge
cd SecureBridge
```

### Via USB (air-gapped):
```bash
# Copy dari USB
cp -r /media/usb/SecureBridge /opt/securebridge
cd /opt/securebridge
```

---

## Step 2.3 — Configure Client Environment (09:45 — 30 menit)

```bash
# 1. Buat .env dari template
cp .env.example .env

# 2. Edit .env
nano .env
```

```bash
# Isi di .env:
ANTHROPIC_API_KEY=sk-ant-...    # Kalau ada internet
SECUREBRIDGE_MODE=auto           # atau air-gapped
TELEGRAM_TOKEN=...               # Kalau mau alert Telegram
TELEGRAM_CHAT_ID=...
```

```bash
# 3. Buat config untuk client ini
cp config/live.yaml config/active.yaml
nano config/active.yaml
```

```yaml
# Isi di config/active.yaml:
mode: live

capture:
  interface: "eth1"              # Sesuaikan dengan NIC yang ke SPAN port
  target_network: "10.0.30.0/24" # OT network range client — dari hasil Day 1

compliance:
  client_name: "PT Nusantara Instrumen"  # Nama client
  consultant_name: "Sandy Lukita"
  consulting_firm: "PT Optima Sarana Instrument"

alerts:
  telegram_enabled: true         # Kalau sudah setup Telegram
  min_severity: "HIGH"
```

---

## Step 2.4 — Configure SPAN Port (10:15 — 1 jam)

**Ini dikerjakan BERSAMA network engineer client.**

### Cisco IOS (paling umum):
```cisco
! Masuk ke switch
enable
configure terminal

! Lihat interface yang ada
show interfaces status

! Setup SPAN session
! Source: VLAN OT yang mau dimonitor
! Destination: port yang ke PC SecureBridge

monitor session 1 source vlan 20        ! VLAN SCADA
monitor session 1 source vlan 30 rx     ! VLAN PLC (receive only)
monitor session 1 destination interface GigabitEthernet0/24

! Verify
show monitor session 1

exit
write memory
```

### Hirschmann (common di industrial):
```
Via web interface:
Network → VLANs → Port Mirror
Source Port: pilih port yang ke OT devices
Destination Port: pilih port yang ke PC SecureBridge
Direction: RX only (receive — passive monitoring)
Apply
```

### Moxa (common di factory):
```
Via web UI:
Port Mirror → Enable
Mirror Source: select OT ports
Mirror Target: port ke SecureBridge
Apply and Save
```

### Verify SPAN bekerja:
```bash
# Di PC SecureBridge, jalankan Wireshark
# Filter: tcp.port == 502
# Kalau muncul traffic Modbus → SPAN berhasil

# Via command line:
sudo tcpdump -i eth1 -c 20 port 502
# Harus muncul packet capture dari OT devices
```

---

## Step 2.5 — Deploy SecureBridge (11:30 — 30 menit)

```bash
cd SecureBridge

# Standard deployment (ada internet)
docker-compose up -d

# Air-gapped dengan Ollama
docker-compose --profile airgapped up -d

# Monitor startup
docker-compose logs -f

# Tunggu sampai semua service UP
docker-compose ps
```

**Expected output:**
```
NAME                        STATUS          PORTS
securebridge-simulator      Up              
securebridge-dashboard      Up              0.0.0.0:8501->8501/tcp
securebridge-ollama         Up              11434/tcp (kalau airgapped)
```

---

## Step 2.6 — Verify Dashboard (12:00 — 30 menit)

```bash
# Buka di browser
http://localhost:8501
# atau dari PC lain di network:
http://[IP-server-securebridge]:8501
```

**Checklist verify:**
```
□ Dashboard loading tanpa error
□ Header menampilkan nama client yang benar
□ Mode indicator: LIVE (bukan LAB)
□ Devices Monitored > 0 (kalau SPAN sudah benar)
□ Timeline chart menampilkan data real-time
□ System status panel menampilkan konfigurasi yang benar
```

---

## Step 2.7 — Verify Traffic Capture (12:30 — 30 menit)

```bash
# Cek log file
ls -la data/logs/
cat data/logs/ot_events_$(date +%Y%m%d).csv | head -20

# Harus ada data dengan:
# - device_id (PLC-01, RTU-01, dll)
# - protocol (Modbus TCP)
# - function_code, register_address
# - timestamp yang real-time
```

Kalau tidak ada data → kembali ke Step 2.4, cek SPAN port configuration.

---

## Step 2.8 — Day 2 Handover Brief (15:00 — 30 menit)

Update IT PIC client:
```
□ Dashboard bisa diakses di: http://[IP]:8501
□ Data collection sudah berjalan
□ Jangan restart server ini selama 48 jam
□ Kalau ada masalah: [nomor HP Sandy]
□ Besok (Day 3) kita mulai training ML model
```

---

# DAY 3 — BASELINE & ML TRAINING

## Tujuan Hari 3
Establish normal behavior baseline dan train ML model dengan data real dari environment client.

---

## Step 3.1 — Review Data Collection (09:00 — 30 menit)

```bash
cd SecureBridge

# Cek jumlah events yang terkumpul
wc -l data/logs/ot_events_$(date +%Y%m%d).csv

# Preview data
head -50 data/logs/ot_events_$(date +%Y%m%d).csv

# Target: minimal 1000 events sebelum train model
# Idealnya: 5000-10000 events (sekitar 4-8 jam monitoring)
```

---

## Step 3.2 — Train ML Model (09:30 — 15 menit)

```bash
# Train model dengan data real client
python core/detection/model.py train \
  data/logs/ot_events_$(date +%Y%m%d).csv

# Expected output:
# Loaded X events
# Training Isolation Forest...
# Model saved: data/models/ot_model.pkl
# Training samples: XXXX
# Avg anomaly score: XX.X
```

**Tuning kalau terlalu banyak alerts:**
```bash
# Edit core/detection/model.py
# Ubah contamination dari 0.05 ke 0.02
# Lalu retrain

# Edit config/active.yaml
# Ubah anomaly_threshold dari 60 ke 70
```

---

## Step 3.3 — Restart Dashboard dengan Model Baru (09:45)

```bash
docker-compose restart dashboard

# Verify model loaded
docker-compose logs dashboard | grep "Model loaded"
```

---

## Step 3.4 — Test Alert System (10:00 — 30 menit)

### Test Telegram Alert:
```python
# Jalankan di Python shell
import sys
sys.path.insert(0, '.')
from config.settings import load_config
from alerts.notifier import AlertNotifier

config = load_config('config/active.yaml')
notifier = AlertNotifier(config.alerts)

notifier.send(
    alert_message="🧪 TEST ALERT — SecureBridge di [Nama Client]\nSistem monitoring aktif dan berfungsi normal.",
    severity="HIGH",
    device_id="TEST-01",
    subject="[TEST] SecureBridge Alert System"
)
```

Pastikan alert masuk di Telegram/email client.

---

## Step 3.5 — Generate Test Report (10:30 — 15 menit)

```bash
# Via dashboard:
# Sidebar → klik "Generate Report"
# Download PDF

# Via command line:
python compliance/report_generator.py
# Output: data/reports/securebridge_report_YYYYMMDD_HHMI.pdf
```

Review PDF report:
```
□ Nama client benar
□ Risk level sesuai temuan
□ 12 findings terdokumentasi
□ Remediation roadmap ada
□ Ringkasan Bahasa Indonesia ada
□ Consultant name dan company benar
```

---

## Step 3.6 — Monitoring Review (11:00 — 1 jam)

Duduk dengan IT PIC client, review bersama:

```
□ Apakah semua device OT sudah terdeteksi?
□ Apakah ada device yang tidak dikenal muncul?
□ Apakah ada alert yang perlu diinvestigasi?
□ Apakah baseline terlihat normal?
□ Tanyakan: "Apakah ada aktivitas maintenance hari ini
  yang bisa menyebabkan traffic tidak normal?"
```

---

## Step 3.7 — Day 3 Summary Update (13:00)

Kirim update tertulis ke management client:

```
Subject: SecureBridge Deployment Day 3 Update — [Nama Client]

Bapak/Ibu [Nama],

Update progress deployment SecureBridge:

✅ Network monitoring aktif (24/7 sejak kemarin)
✅ X perangkat OT terdeteksi dan dimonitor
✅ AI model sudah di-training dengan X events
✅ Alert system sudah ditest dan berfungsi

Temuan awal yang perlu diperhatikan:
- [Temuan 1 kalau ada]
- [Temuan 2 kalau ada]

Besok kita akan melakukan handover session dan
generate final compliance report.

Sandy Lukita
IT & OT Security Consultant
PT Optima Sarana Instrument
```

---

# DAY 4-5 — HANDOVER & REPORTING

## Tujuan Hari 4-5
Transfer knowledge ke client, generate final report, dan close engagement.

---

## Step 4.1 — Dashboard Training untuk Client (09:00 — 2 jam)

Walk through dashboard dengan operator/IT client:

### Modul 1: Understanding the Dashboard (30 menit)
```
□ Explain KPI metrics: Active Alerts, Critical, High, Devices
□ Explain Anomaly Score Timeline — apa artinya spike?
□ Explain Alert Distribution pie chart
□ Explain Device Status table
□ Explain threshold settings di sidebar
```

### Modul 2: Responding to Alerts (45 menit)
```
□ Cara buka dan baca detail alert
□ Cara interpret AI Analysis
□ Cara execute Immediate Actions
□ Kapan harus escalate ke Sandy
□ Cara dokumentasi incident

Latihan: Sandy inject anomaly, client respond
□ Anomaly muncul di dashboard
□ Client klik alert
□ Client baca AI analysis
□ Client identify action yang tepat
□ Client document di log
```

### Modul 3: Report Generation (15 menit)
```
□ Cara generate PDF report
□ Kapan report harus di-generate (monthly? per incident?)
□ Siapa yang menerima report
□ Bagaimana report digunakan untuk audit PT Energi Nusantara
```

---

## Step 4.2 — Handover Document (11:00 — 1 jam)

Buat dokumen handover yang ditandatangani kedua pihak:

```markdown
# SecureBridge Handover Document
Client: [Nama Client]
Date: [Tanggal]
Consultant: Sandy Lukita — PT Optima Sarana Instrument

## System Access
Dashboard URL: http://[IP]:8501
Server location: [Ruangan/rack]
Server credentials: [Serahkan dalam amplop tertutup]

## Key Contacts
PT Optima emergency: sandylukita@gmail.com | [HP]
On-site IT PIC: [Nama] | [HP]

## Alert Response Procedure
CRITICAL alert → Immediately call Sandy: [HP]
HIGH alert → Investigate within 2 hours
MEDIUM alert → Review in daily check
LOW alert → Review in weekly report

## Maintenance Schedule
Monthly: Sandy reviews logs and retrains ML model
Quarterly: Sandy generates compliance report
Annual: Full reassessment

## What NOT to Do
❌ Jangan restart server tanpa koordinasi
❌ Jangan ubah config tanpa hubungi Sandy
❌ Jangan connect device baru ke OT network tanpa izin
❌ Jangan ignore CRITICAL alert lebih dari 1 jam

## Signatures
Client Representative: _________ Date: _______
Sandy Lukita: __________________ Date: _______
```

---

## Step 4.3 — Final Compliance Report (13:00 — 1 jam)

Generate final version dengan semua findings:

```bash
# Update findings status berdasarkan apa yang sudah
# di-remediate selama engagement

# Generate final report
python compliance/report_generator.py

# Review PDF sebelum diserahkan
# Pastikan:
□ Executive summary akurat
□ Semua 12 findings terdokumentasi
□ Remediation roadmap realistis
□ Compliance score mencerminkan kondisi actual
□ Ringkasan Bahasa Indonesia clear dan bisa dibaca management
□ Consultant signature block lengkap
```

---

## Step 4.4 — Closing Meeting (15:00 — 1 jam)

**Peserta:** Sandy + IT PIC + Management

**Agenda:**
```
1. Present final compliance report (15 menit)
2. Review top 5 findings dan remediation priority (15 menit)
3. Confirm ongoing support arrangement (10 menit)
4. Q&A (15 menit)
5. Next steps dan timeline (5 menit)
```

**Kalimat closing yang effective:**

> *"Dari engagement 5 hari ini, kami berhasil setup monitoring 24/7 untuk X perangkat OT Bapak/Ibu. SecureBridge sudah mendeteksi X anomali, yang paling kritis adalah [finding]. Dengan menyelesaikan remediation roadmap yang kami berikan, PT Energi Nusantara akan melihat progress keamanan yang signifikan dan Bapak/Ibu siap untuk proses audit Q1 2027.*

> *Untuk ongoing support, kami rekomendasikan retainer bulanan untuk review laporan dan retraining model — ini memastikan sistem terus akurat seiring perubahan environment. Saya bisa kirim proposal retainer minggu depan."*

---

## Step 4.5 — Post-Engagement (Minggu Berikutnya)

```
□ Kirim invoice untuk engagement fee
□ Kirim proposal retainer (kalau relevan)
□ Anonymize case study untuk portfolio
□ Update GitHub dengan lessons learned (tanpa data client)
□ Request LinkedIn recommendation dari client contact
□ Add to CRM/contact list untuk follow-up quarterly
```

---

# TROUBLESHOOTING GUIDE

## Problem: Dashboard tidak loading

```bash
# Cek container status
docker-compose ps

# Cek logs
docker-compose logs dashboard

# Restart
docker-compose restart dashboard

# Hard reset kalau perlu
docker-compose down
docker-compose up -d
```

---

## Problem: Tidak ada data masuk (0 devices)

```bash
# 1. Verify SPAN port di switch
# Login ke switch, cek monitor session

# 2. Cek network interface
ip addr show  # Linux
ipconfig       # Windows

# 3. Test manual capture
sudo tcpdump -i eth1 -c 20
# Kalau tidak ada packet → SPAN belum benar

# 4. Cek config
cat config/active.yaml | grep interface
# Pastikan interface name benar (eth0? eth1? ens33?)
```

---

## Problem: Terlalu banyak false alerts

```bash
# Opsi 1: Naikkan threshold
# Edit config/active.yaml:
# anomaly_threshold: 60 → 75

# Opsi 2: Collect lebih banyak baseline data dulu
# Tunggu 48 jam sebelum train model

# Opsi 3: Retrain dengan contamination lebih rendah
# Edit core/detection/model.py:
# contamination=0.05 → contamination=0.02

# Opsi 4: Cek apakah ada maintenance activity
# Tanya client: "Ada backup, update, atau maintenance kemarin?"
```

---

## Problem: Ollama tidak mau start (air-gapped)

```bash
# Cek RAM tersedia
free -h  # Butuh minimal 8GB free

# Cek disk space
df -h    # Butuh minimal 10GB free

# Manual pull model kalau gagal di startup
docker exec -it securebridge-ollama ollama pull llama3.1

# Verify model ada
docker exec -it securebridge-ollama ollama list
```

---

## Problem: PDF report error

```bash
# Install dependency yang mungkin kurang
pip install reportlab --break-system-packages

# Cek output directory ada
mkdir -p data/reports

# Test generate manual
python compliance/report_generator.py

# Cek error message yang muncul
```

---

# QUICK REFERENCE CARD

**Cetak ini dan bawa ke site:**

```
╔═══════════════════════════════════════════════════╗
║     SECUREBRIDGE QUICK REFERENCE                  ║
║     PT Optima Sarana Instrument                   ║
╠═══════════════════════════════════════════════════╣
║  DEPLOY:    docker-compose up -d                  ║
║  AIRGAP:    docker-compose --profile airgapped up ║
║  STATUS:    docker-compose ps                     ║
║  LOGS:      docker-compose logs -f dashboard      ║
║  STOP:      docker-compose down                   ║
║  RESTART:   docker-compose restart dashboard      ║
║  TRAIN ML:  python core/detection/model.py train  ║
║             data/logs/ot_events_YYYYMMDD.csv      ║
║  REPORT:    python compliance/report_generator.py ║
╠═══════════════════════════════════════════════════╣
║  DASHBOARD: http://[server-ip]:8501               ║
║  EMERGENCY: sandylukita@gmail.com                 ║
╚═══════════════════════════════════════════════════╝
```

---

*SecureBridge Client Deployment Playbook v1.0*  
*Sandy Lukita | PT Optima Sarana Instrument*  
*sandylukita@gmail.com*
