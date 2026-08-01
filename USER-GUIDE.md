# 📖 SecureBridge — Panduan Pengguna Lengkap (End-to-End User Manual)

Dokumen Version: 1.0  
Penulis: Sandy Lukita | PT Optima Sarana Instrument  
Tujuan: Panduan Operasional Lengkap dari Instalasi, Konfigurasi, Monitoring Pasif, Penggunaan Dashboard SOC, hingga Pembuatan Laporan PDF Audit IEC 62443.

---

## 📑 DAFTAR ISI

1. [Persyaratan Sistem & Prasyarat](#1-persyaratan-sistem--prasyarat)
2. [Instalasi & Setup Lingkungan](#2-instalasi--setup-lingkungan)
3. [Konfigurasi Mode Operasional (`lab.yaml` vs `live.yaml`)](#3-konfigurasi-mode-operasional)
4. [Menjalankan Monitoring Pasif & Simulator Traffic](#4-menjalankan-monitoring-pasif--simulator-traffic)
5. [Panduan Penggunaan Streamlit SOC Dashboard](#5-panduan-penggunaan-streamlit-soc-dashboard)
6. [Membaca & Memahami AI Threat Analysis (Gemini / Ollama / Claude)](#6-membaca--memahami-ai-threat-analysis)
7. [Membuat Laporan PDF Audit Kepatuhan IEC 62443](#7-membuat-laporan-pdf-audit-kepatuhan-iec-62443)
8. [ Troubleshooting & Solusi Masalah Umum](#8-troubleshooting--solusi-masalah-umum)

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
   - Google Gemini API Key dari [Google AI Studio](https://aistudio.google.com/app/apikey).
2. **Opsi B — Produksi Klien 100% Air-Gapped (On-Premise)**:
   - [Ollama](https://ollama.com/) terinstall di server lokal + Model `llama3.1` (`ollama pull llama3.1`).
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
  polling_interval: 5             # Interval pengiriman data (detik)
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

### Mode 1: Menjalankan Simulator Lab (Pengujian / Demo)

Jika Anda ingin mensimulasikan traffic OT dan mengumpulkan event log baru:

```bash
python core/capture/monitor.py config/lab.yaml
```
> *Engine simulator akan mengirimkan traffic Modbus ke 3 PLC fiktif dan mencatat event secara otomatis ke `data/logs/ot_events_YYYYMMDD.csv`.*

### Mode 2: Melatih / Update Model ML (Isolation Forest)

Jika Anda ingin melatih ulang model Machine Learning pada dataset log terbaru:

```bash
python core/detection/model.py train data/logs/ot_events_20260731.csv
```
> *Model yang dilatih akan disimpan ke `data/models/ot_model.pkl`.*

### Mode 3: Live Capture di SPAN Port Industri (Production)

*(Membutuhkan akses Administrator/Root)*:

* **Windows (Buka PowerShell as Administrator)**:
  ```powershell
  python core/capture/monitor.py config/live.yaml
  ```
* **Linux**:
  ```bash
  sudo ./venv/bin/python core/capture/monitor.py config/live.yaml
  ```

---

### Mode 4: Menjalankan Menggunakan Docker & Docker Compose (Containerized)

Jika Anda ingin menjalankan seluruh ekosistem SecureBridge (Simulator + Dashboard + Ollama Local) di dalam kontainer terisolasi:

#### 1. Jalankan Mode Lab / Demo (Menggunakan Gemini / Cloud API)

```bash
docker compose up -d
```
> *Menjalankan Dashboard SOC, Simulator Traffic, dan Model Trainer di dalam kontainer Docker terisolasi (`it_zone`, `dmz_zone`, `ot_zone`).*

#### 2. Jalankan Mode Air-Gapped (Termasuk Container Local Ollama)

```bash
docker compose --profile airgapped up -d
```
> *Secara otomatis menjalankan container Ollama (`securebridge-ollama`) dan men-download model `llama3.1` di dalam jaringan terisolasi.*

#### 3. Perintah Pengelolaan Container

```bash
# Cek status semua container yang berjalan
docker compose ps

# Lihat log real-time dari Dashboard SOC
docker compose logs -f dashboard

# Menghentikan semua container
docker compose down
```

---

## 5. PANDUAN PENGGUNAAN STREAMLIT SOC DASHBOARD

Untuk membuka antarmuka visual SOC Dashboard:

```bash
streamlit run dashboard/app.py
```

Buka peramban (browser) di alamat: **`http://localhost:8501`**

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🔐 SecureBridge OT Security Dashboard  [◉ LAB]                                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 🚨 Active Alerts: 645   🔴 Critical: 12   🟠 High: 45   🔌 Devices: 3   📊 Avg Score: 37  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [📈 Timeline Chart: Anomaly Score]               [🎯 Alert Severity Pie Chart]          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 🔌 Device Status Table (PLC-01, PLC-02, PLC-03)                                        │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 🚨 Active Alerts & AI Threat Analysis (Expander View)                                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Navigasi & Fitur Utama Dashboard:

1. **Header Badge**: Menampilkan status mode aktif (`◉ LAB` atau `● LIVE`), waktu lokal, dan identitas perusahaan.
2. **Kartu Metric KPI (Baris Atas)**:
   - **Active Alerts**: Jumlah total event yang melebihi alert threshold (default >= 60).
   - **Critical / High**: Jumlah anomali dengan severitas kritis dan tinggi.
   - **Devices Monitored**: Jumlah perangkat PLC/RTU aktif yang terpantau.
   - **Avg Anomaly Score**: Rata-rata skor deviasi jaringan.
3. **Grafik Timeline Anomali**: Menampilkan fluktuasi skor anomali terhadap waktu. Garis putus-putus oranye menunjukkan batas threshold peringatan.
4. **Grafik Distribusi Alert**: Pie chart perbandingan severitas (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
5. **Tabel Device Status**: Ringkasan kesehatan per PLC, jumlah event, skor rata-rata, skor maksimum, dan timestamp *last seen*.
6. **Sidebar Kontrol (Sebelah Kiri)**:
   - Slider **Time window (hours)**: Mengatur rentang waktu tampilan data (1 - 168 jam).
   - Slider **Alert threshold**: Mengatur ambang batas skor pemicu alert.
   - Checkbox **Enable AI Analysis**: Mengaktifkan/menonaktifkan analisis AI otomatis.
   - **LLM Backend Info**: Menampilkan mode AI yang sedang aktif (`Auto`, `Gemini`, `Ollama`, atau `Claude`).
   - Tombol **`📄 Generate IEC 62443 Report`**: Memicu pembuatan laporan audit PDF.

---

## 6. MEMBACA & MEMAHAMI AI THREAT ANALYSIS

Saat Anda menglik salah satu alert di tabel **🚨 Active Alerts**, expander akan terbuka menampilkan dua kolom:

### Kolom Kiri — 📊 Event Details (Raw Network DPI)
- **Protocol**: Protocol OT yang terdeteksi (misal: `Modbus TCP`).
- **Event**: Jenis instruksi (misal: `MODBUS_WRITE` atau `MODBUS_READ`).
- **Source IP & Destination IP**: IP pengirim dan IP tujuan PLC.
- **Function**: Nama Function Code (misal: `Write Single Register` atau `Read Holding Registers`).
- **Register**: Alamat memory register PLC yang diakses.
- **Write Indicator**: Peringatan merah jika terdapat perintah modifikasi data (`WRITE OPERATION DETECTED`).

### Kolom Kanan — 🤖 AI Threat Analysis
AI secara otomatis menerjemahkan deviasi statistik menjadi narasi keamanan industri:
1. **Threat Summary**: Penjelasan 1 kalimat dalam bahasa manusia mengenai apa yang terjadi.
2. **⚡ Immediate Actions**: 3 langkah penanganan darurat yang aman untuk operasional pabrik (prioritas ketersediaan proses fisik).
3. **📖 IEC 62443 Reference**: Pemetaan ke klausul persyaratan keselamatan industri (misal: `SR 2.1 Authorization Enforcement`, `SR 5.2 Zone Boundary Protection`).
4. **🎯 MITRE ATT&CK ICS Tag**: Teknik taktik serangan OT (misal: `T0836 Modify Parameter`, `T0846 Remote System Discovery`).
5. **Escalation Warning**: Peringatan merah jika anomali membutuhkan intervensi manusia segera.

---

## 7. MEMBUAT LAPORAN PDF AUDIT KEPATUHAN IEC 62443

 SecureBridge menyediakan fitur **One-Click Executive PDF Audit Report** yang dirancang khusus untuk memenuhi standar audit ISO/IEC 62443 dan laporan manajemen C-Level:

### Langkah Pembuatan Laporan:

1. Di peramban dashboard, lihat **Sidebar Sebelah Kiri** di bagian **`📄 Compliance Report`**.
2. Klik tombol merah **`📄 Generate IEC 62443 Report`**.
3. Tunggu 2-3 detik hingga muncul notifikasi **`✅ Report generated!`**.
4. Tombol biru **`⬇️ Download PDF Report`** akan muncul secara otomatis di bawahnya.
5. Klik tombol tersebut untuk mengunduh file PDF (contoh nama file: `securebridge_report_20260801_1530.pdf`).

### Isi File Laporan PDF yang Dihasilkan:
- **Cover Page Executive**: Memuat nama klien, nama konsultan (*Sandy Lukita*), nama perusahaan (*PT Optima Sarana Instrument*), scope jaringan, dan tingkat risiko keseluruhan.
- **Executive Summary Scorecard**: Skor persentase kepatuhan IEC 62443 & Security Level.
- **Technical Security Findings**: Detail teknis temuan anomali jaringan.
- **Compliance Mapping Matrix**: Pemetaan ke System Requirements (SR 1.1, SR 2.1, SR 3.1, SR 4.5, SR 5.1, SR 6.2).
- **Remediation Roadmap 3-Fase**: 
  - *Fase 1 (Immediate / 0-30 Hari)*: Tindakan darurat.
  - *Fase 2 (Short-term / 30-90 Hari)*: Perbaikan segmentasi Purdue Model.
  - *Fase 3 (Medium-term / 90-180 Hari)*: Peningkatan prosedur pemantauan berkelanjutan.
- **Ringkasan Eksekutif (Bahasa Indonesia)**: Ringkasan khusus untuk jajaran Direksi & Manajemen Pabrik.

---

## 8. TROUBLESHOOTING & SOLUSI MASALAH UMUM

### ❓ Masalah 1: `Pyshark / TShark Exception: TShark not found`
- **Penyebab**: TShark belum terinstall atau jalurnya belum masuk ke Environment PATH.
- **Solusi**: 
  - *Windows*: Install Wireshark. Pastikan `C:\Program Files\Wireshark` ada di System PATH.
  - *Linux*: Jalankan `sudo apt install -y tshark`.

### ❓ Masalah 2: Live Monitoring gagal membaca interface di Windows
- **Penyebab**: Membutuhkan hak akses Administrator untuk sniffing raw socket / Npcap.
- **Solusi**: Klik kanan PowerShell -> **Run as Administrator**, baru jalankan script monitor.

### ❓ Masalah 3: Gemini API Error `429 Quota Exceeded` atau `404 Model Not Found`
- **Penyebab**: Model name yang diset di YAML tidak cocok atau kuota API tercapai.
- **Solusi**: Di `config/lab.yaml`, pastikan `gemini_model: gemini-flash-latest` atau ubah `mode: auto`.

### ❓ Masalah 4: Laporan PDF tidak muncul saat diklik
- **Penyebab**: Folder output belum terbuat atau masalah izin file.
- **Solusi**: Aplikasi secara otomatis membuat folder `data/reports/`. Jika masih berkendala, pastikan folder `data/reports/` memiliki izin tulis (write permission).
