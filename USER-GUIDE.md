# 📖 SecureBridge — Panduan Pengguna Lengkap (End-to-End User Manual)

Dokumen Version: 1.7.0  
Penulis: Sandy Lukita | PT Optima Sarana Instrument  
Tujuan: Panduan Operasional Lengkap dari Instalasi, Konfigurasi, Monitoring Pasif, Passive Asset Discovery, Penggunaan Cyber SOC Dashboard (4 Tab Interaktif), Incremental ML Scoring, Public Threat Intelligence Feed (CISA), hingga Pembuatan Laporan PDF Audit IEC 62443 (RS1-RS12).

---

## 📑 DAFTAR ISI

1. [Persyaratan Sistem & Prasyarat](#1-persyaratan-sistem--prasyarat)
2. [Instalasi & Setup Lingkungan](#2-instalasi--setup-lingkungan)
3. [Konfigurasi Mode Operasional (`lab.yaml` vs `live.yaml`)](#3-konfigurasi-mode-operasional)
4. [Menjalankan Monitoring Pasif & Simulator Traffic](#4-menjalankan-monitoring-pasif--simulator-traffic)
5. [Panduan Penggunaan Cyber SOC Command Center (4 Tab Interaktif)](#5-panduan-penggunaan-cyber-soc-command-center)
6. [Membaca & Memahami AI Threat Analysis & Containment Playbook](#6-membaca--memahami-ai-threat-analysis--containment-playbook)
7. [Membuat Laporan PDF Audit Kepatuhan IEC 62443 & SUC Scope](#7-membuat-laporan-pdf-audit-kepatuhan-iec-62443--suc-scope)
8. [Troubleshooting & Solusi Masalah Umum](#8-troubleshooting--solusi-masalah-umum)

---

## 1. PERSYARATAN SISTEM & PRASYARAT

### 💻 Kebutuhan Perangkat Lunak (Software)
- **Sistem Operasi**: Windows 10/11, Ubuntu Linux 20.04/22.04, atau macOS.
- **Python**: Versi **3.10** atau lebih baru (direkomendasikan Python 3.11).
- **Packet Capture Engine (Untuk Live Mode di SPAN Port)**:
  - **Windows**: Install [Npcap](https://npcap.com/) (Centang opsi *"Install Npcap in WinPcap API-compatible Mode"*) + [Wireshark](https://www.wireshark.org/) (untuk komponen `tshark.exe`).
  - **Linux**: Install TShark via package manager (`sudo apt install -y tshark libpcap-dev`).

### 🤖 Kebutuhan LLM (Pilih Salah Satu Sesuai Kebutuhan)
1. **Opsi A — Showcase / Lab Demo (Gratis & Kilat)**:
   - Google Gemini API Key dari [Google AI Studio](https://aistudio.google.com/app/apikey) (`GEMINI_API_KEY`).
2. **Opsi B — Produksi Klien 100% Air-Gapped (On-Premise)**:
   - [Ollama](https://ollama.com/) terinstall di server lokal + Model `llama3.1` (`ollama pull llama3.1`).
   - Panduan transfer offline USB & retrain ML 30-hari: Lihat [`AIR-GAPPED-MAINTENANCE.md`](AIR-GAPPED-MAINTENANCE.md).
3. **Opsi C — Cloud High-End**:
   - Anthropic Claude API Key (`ANTHROPIC_API_KEY`).

---

## 2. INSTALASI & SETUP LINGKUNGAN

### Langkah 1: Clone Repository
Buka Terminal (atau PowerShell di Windows), jalankan:

```bash
git clone https://github.com/sandylukita/SecureBridge.git
cd SecureBridge
```

### Langkah 2: Buat & Aktifkan Python Virtual Environment

* **Di Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\activate
  ```

* **Di Linux / macOS**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### Langkah 3: Install Dependensi Python

```bash
pip install -r requirements.txt
```

### Langkah 4: Setup Environment Variable (`.env`)

Buat file `.env` di direktori utama `SecureBridge/` (atau salin dari template `.env.example`):

```bash
# Isi file .env
GEMINI_API_KEY=AIzaSyYourGeminiApiKeyHere...
ANTHROPIC_API_KEY=your-claude-api-key-here
```

---

## 3. KONFIGURASI MODE OPERASIONAL

SecureBridge mendukung dua konfigurasi utama di folder `config/`:

### A. Demo / Lab Mode (`config/lab.yaml`)
Digunakan untuk simulasi, testing, showcase, dan presentasi tanpa memerlukan hardware jaringan fisik:

```yaml
mode: lab
simulator:
  enabled: true
  plc_count: 3               # Simulasi 3 PLC Modbus (PLC-01, PLC-02, PLC-03)
  polling_interval: 5        # Interval pengiriman data (detik)
llm:
  mode: auto                 # Auto memilih Gemini API -> Claude -> Ollama -> Rule-based
  gemini_model: gemini-flash-latest
```

### B. Live Production Mode (`config/live.yaml`)
Digunakan saat terhubung ke **SPAN / Mirror Port** switch jaringan pabrik:

```yaml
mode: live
capture:
  interface: "eth1"           # Nama Network Interface Card yang terhubung ke SPAN Port
  use_pyshark: true
  bpf_filter: "tcp port 502 or tcp port 44818 or udp port 47808"
  target_network: "192.168.40.0/24"
llm:
  mode: air-gapped            # 100% lokal di site OT — zero data egress
  ollama_model: llama3.1
  ollama_host: http://localhost:11434
```

---

## 4. MENJALANKAN MONITORING PASIF & SIMULATOR TRAFFIC

### Mode 1: Menjalankan Simulator Lab & Injeksi Anomali (Demo)

Jika Anda ingin mensimulasikan traffic OT dan menguji pemicuan alert anomali:

```bash
# 1. Jalankan traffic simulator di background
python core/capture/monitor.py config/lab.yaml

# 2. Injeksi anomali serangan (unauthorized write & network scan)
python inject_demo.py
```

### Mode 2: Melatih / Update Model ML (Isolation Forest)

Untuk melatih ulang model Machine Learning Isolation Forest pada dataset log terbaru:

```bash
python core/detection/model.py train data/logs/ot_events_YYYYMMDD.csv
```
> *Model yang dilatih akan disimpan ke `data/models/ot_model.pkl`.*

### Mode 3: Live Capture di SPAN Port Industri (Production)

*(Membutuhkan akses Administrator/Root)*:

* **Windows (PowerShell as Administrator)**:
  ```powershell
  python core/capture/monitor.py config/live.yaml
  ```
* **Linux**:
  ```bash
  sudo ./venv/bin/python core/capture/monitor.py config/live.yaml
  ```

### Mode 4: Menjalankan Menggunakan Docker Compose (Containerized)

```bash
# Mode Demo / Lab (Cloud API)
docker compose up -d

# Mode Air-Gapped (Termasuk Local Ollama Container)
docker compose --profile airgapped up -d
```

---

## 5. PANDUAN PENGGUNAAN CYBER SOC COMMAND CENTER (4 TAB INTERAKTIF)

Untuk membuka antarmuka visual SOC Command Center:

```bash
streamlit run dashboard/app.py
```

Buka peramban (browser) di alamat: **`http://localhost:8501`**

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🔐 SecureBridge OT Security Command Center v1.5.0                      [◉ LAB DEMO]    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [📊 Live SOC Operations] [🌐 Purdue Network Topology] [🎛️ SCADA Telemetry] [📑 IEC 62443]│
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 🚨 Active Alerts: 21   🔴 Critical: 1   🟠 High: 20   🔌 Devices: 3   📊 Avg Score: 78   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Dashboard v1.5.0 dilengkapi dengan **4 Tab Interaktif Utama**:

### 📊 Tab 1: Live SOC Operations
- **Metric Cards KPI**: Menampilkan `Active Alerts`, `Critical Severity`, `High Severity`, `Devices Monitored`, dan `Avg Anomaly Score`.
- **Anomaly Score Timeline**: Grafik garis real-time fluktuasi skor deviasi jaringan.
- **Alert Severity Distribution**: Grafik pie perbandingan severitas (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Expander Alert & DPI Details**: Detail paket deep packet inspection (DPI) + analisis ancaman AI.
- **Firewall Playbook Generator**: Tombol `🛡️ Preview Firewall Containment Rule` untuk men-generate perintah `iptables` isolasi IP penyerang.

### 🌐 Tab 2: Purdue Network Topology Visualizer & Threat Intel
- **Passive Asset Profiling**: Memetakan perangkat secara pasif tanpa active scanning (0% dampak pada PLC).
- **2D Purdue Model Hierarchy Scatter Graph**: Memvisualisasikan perangkat pada Purdue Layer 1 (PLCs), Layer 2 (SCADA/HMI), dan Layer 3.5 (Industrial DMZ).
- **Attacked Node Highlighting**: Perangkat penyerang menyala **ORANGE TERBAKAR**, PLC target menyala **MERAH BERKEDIP**.
- **Asset Inventory Table**: Tabel inventaris IP address, Asset Name, Asset Type, Purdue Level, dan status ancaman.
- **🛡️ CISA ICS-CERT Threat Intelligence Panel**: Panel rekomendasi kerentanan publik yang mengorelasikan aset vendor terdeteksi (Schneider Electric, Rockwell Automation, Siemens S7) dengan data resmi CISA advisories.

### 🎛️ Tab 3: SCADA / HMI Process Telemetry
- **Live Physical Gauges**: Meteran visual kondisi fisik pabrik:
  - **PLC-01**: Gas Turbine Speed (RPM).
  - **PLC-02**: Cooling Loop Temperature (°C).
  - **PLC-03**: Valve Line Pressure (BAR).
- **Process Overrides Alarm**: Banner peringatan **`🚨 VALVE OVERRIDE & PRESSURE SPIKE DETECTED!`** muncul saat terjadi perintah write ilegal di Modbus.

### 📑 Tab 4: IEC 62443 Risk Register & Audit Scope
- **SUC Scope Card**: Definisi batas-batas System Under Consideration (In-Scope Boundary Assets vs Explicitly Excluded).
- **Compliance Radar Chart**: Persentase kepatuhan terhadap 7 kategori dasar IEC 62443.
- **Formal Risk Register Table**: Tabel penomoran risiko `RS1` hingga `RS12` dengan skor *Unmitigated Risk* dan *Residual Risk*.

---

## 5b. ARSITEKTUR ML SCORING — MENGAPA DASHBOARD CEPAT & AMAN

SecureBridge v1.6.0 menggunakan dua lapisan scoring yang bekerja bersama:

### Layer 1: Isolation Forest (Sumber Kebenaran)
- Setiap event di-score menggunakan **statistik dari training data** (`score_raw_min`/`score_raw_max` tersimpan di model pickle).
- Tidak ada hardcoded rule yang menaikkan atau menurunkan skor — Isolation Forest adalah **satu-satunya** penentu anomaly score.
- Distribusi yang dihasilkan realistis: ~88% LOW, ~10% MEDIUM, ~1% HIGH, <1% CRITICAL.

### Layer 2: IncrementalScorer (Efisiensi SIEM-Grade)
```
Refresh #1 (8.000 event)   → Isolation Forest score semua    (~0.3 detik)
Refresh #2 (8.017 event)   → Hanya 17 event baru di-score    (<0.01 detik)
Refresh #3 (8.031 event)   → Hanya 14 event baru di-score    (<0.01 detik)
```
- **Cache disimpan** di `data/models/score_cache.pkl`.
- **Auto-invalidasi**: jika model di-retrain, cache otomatis dihapus saat refresh berikutnya (dideteksi via `trained_at` timestamp di model metadata).
- **Zero false negative**: setiap event baru tetap melalui Isolation Forest — tidak ada blind spot.

> Ini adalah pendekatan yang sama yang digunakan oleh platform SIEM enterprise (Splunk, IBM QRadar) untuk memproses data volume tinggi tanpa mengorbankan kelengkapan deteksi.

---

## 5c. PUBLIC THREAT INTELLIGENCE FEED & AIR-GAPPED GUARD RAILS (v1.7.0)

SecureBridge v1.7.0 mengintegrasikan agregator threat intelligence publik (`ThreatIntelFeed`) dengan prinsip proteksi air-gapped ketat:

### 1. Zero Live API Call pada Dashboard Rendering
- Data CISA ICS advisories di-prefetch menggunakan script `python core/threat_intel/fetch_advisories.py`.
- Hasil sinkronisasi disimpan di `data/threat_intel/cisa_cache.json`.
- Dashboard **100% membaca data dari cache lokal**, sehingga rendering UI instan dan bebas risiko kegagalan koneksi internet saat demo/operasional.

### 2. "Code IS the Documentation" — Code-Level Enforcement
- Setiap fitur yang berpotensi mengirim metadata ke luar jaringan (seperti Shodan exposure check) diproteksi secara langsung di level kode:
  ```python
  if self.mode == "air-gapped":
      raise FeatureDisabledError(
          "Shodan check disabled in air-gapped mode — "
          "querying external API violates zero-egress principle"
      )
  ```
- Pembuktian air-gapped tidak hanya mengandalkan teks dokumen/README, melainkan diuji dan ditegakkan langsung oleh mesin Python interpreter (*Exception handling*).

---

## 6. MEMBACA & MEMAHAMI AI THREAT ANALYSIS & CONTAINMENT PLAYBOOK

Saat membuka expander alert di **Tab 1: Live SOC Operations**:

### Kolom Kiri — 📊 Event Details (Raw Network DPI)
- **Protocol & Function Code**: Memperlihatkan instruksi spesifik (misal: `Modbus FC06 Write Single Register`).
- **Source & Destination IP**: Mengidentifikasi IP asal dan IP PLC tujuan.
- **Memory Address & Value**: Memperlihatkan register yang dimodifikasi (misal: `Address 40001 = 9999`).

### Kolom Kanan — 🤖 AI Threat Analysis & Containment
1. **Threat Summary**: Ringkasan ancaman dalam bahasa manusia yang mudah dipahami.
2. **⚡ Immediate Actions**: Langkah penanganan darurat yang aman bagi operasi pabrik.
3. **📖 IEC 62443 Reference**: Pemetaan ke persyaratan standar keselamatan industri.
4. **🛡️ Preview Firewall Containment Rule**: Meng-generate perintah CLI otomatis untuk mengisolasi penyerang:
   ```bash
   iptables -A FORWARD -s 192.168.10.199 -d 192.168.40.10 -p tcp --dport 502 -j DROP
   ```

---

## 7. MEMBUAT LAPORAN PDF AUDIT KEPATUHAN IEC 62443 & SUC SCOPE

 SecureBridge menyediakan fitur **One-Click Executive PDF Audit Report** yang memuat analisis teknis, SUC scope, dan Risk Register formal:

### Langkah Pembuatan Laporan:

1. Di peramban dashboard, lihat **Sidebar Sebelah Kiri** di bagian paling atas di seksi **`📄 Quick Actions`**.
2. Klik tombol merah **`📄 Generate IEC 62443 PDF Report`**.
3. Tunggu 2-3 detik hingga muncul notifikasi **`✅ Report generated!`**.
4. Tombol biru **`⬇️ Download PDF Report`** akan muncul secara otomatis di bawahnya.
5. Klik tombol tersebut untuk mengunduh file PDF (contoh nama file: `securebridge_report_20260803_1530.pdf`).

---

## 8. TROUBLESHOOTING & SOLUSI MASALAH UMUM

### ❓ Masalah 1: Graph atau data alert terlihat kosong (0 Active Alerts)
- **Penyebab**: Traffic simulator belum berjalan atau file log CSV hanya berisi polling read normal.
- **Solusi**: Jalankan `python inject_demo.py` di terminal untuk menyuntikkan anomali serangan secara otomatis.

### ❓ Masalah 2: `Pyshark / TShark Exception: TShark not found`
- **Penyebab**: TShark belum terinstall atau jalurnya belum masuk ke Environment PATH.
- **Solusi**: Install Wireshark di Windows (pastikan `C:\Program Files\Wireshark` ada di PATH) atau `sudo apt install -y tshark` di Linux.

### ❓ Masalah 3: Live Monitoring gagal membaca interface di Windows
- **Penyebab**: Membutuhkan hak akses Administrator untuk sniffing raw socket / Npcap.
- **Solusi**: Klik kanan PowerShell -> **Run as Administrator**, lalu jalankan script monitor.

### ❓ Masalah 4: Skor anomali berubah tidak konsisten setelah model di-retrain
- **Penyebab**: Cache `score_cache.pkl` masih berisi skor dari model sebelumnya.
- **Solusi**: Cache akan otomatis di-invalidasi pada refresh berikutnya — tidak perlu tindakan manual. Jika ingin flush manual, hapus file `data/models/score_cache.pkl` lalu refresh dashboard.

### ❓ Masalah 5: Dashboard menampilkan pie chart 100% merah (semua CRITICAL)
- **Penyebab**: OT Risk Floor hardcode aktif (versi lama), atau data hanya berisi event anomali tanpa baseline normal.
- **Solusi**: Pastikan menggunakan SecureBridge v1.5.1+. Jalankan simulator untuk mengisi data baseline normal: `python core/capture/monitor.py config/lab.yaml`.
