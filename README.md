# ShieldNet IDS — Sistem Deteksi Intrusi Kolaboratif dan Terpusat

Sistem Deteksi Intrusi (IDS) berbasis **Isolation Forest** untuk router MikroTik yang bekerja secara kolaboratif: satu node diserang, seluruh node dalam jaringan langsung terlindungi secara otomatis.

## Arsitektur

```
[MikroTik Node 1] ──┐
[MikroTik Node 2] ──┼──► [Golang :8080] ◄──► [Python Analyst]
[MikroTik Node N] ──┘          │                     │
                          TimescaleDB ◄───────────────┘
                                │
                   Distribusi access-list via API
                                │
          [MikroTik 1]  [MikroTik 2]  [MikroTik N]

[Browser] ◄── HTMX + Tailwind ──► [Golang :8080]
[Browser] ◄────── Grafana :3000 ──► [TimescaleDB]
```

## Dokumentasi

| Dokumen | Isi |
|---|---|
| [docs/SOP-operasional-sistem.md](docs/SOP-operasional-sistem.md) | **Panduan operasional lengkap**: menjalankan dari awal, mematikan/restart, test/evaluasi, backup, pembersihan Docker, troubleshooting |
| [docs/architecture.md](docs/architecture.md) | Arsitektur sistem dan detail mekanisme deteksi Isolation Forest |
| [docs/SOP-tambah-node-mikrotik.md](docs/SOP-tambah-node-mikrotik.md) | Prosedur menambahkan router MikroTik baru |

## Prasyarat

- Docker Engine 20.x+
- Docker Compose v2.x+
- `make` (untuk menjalankan perintah Makefile)
- `netcat` (`nc`) untuk pengujian syslog

## Instalasi dan Menjalankan

### 1. Clone atau siapkan direktori proyek

```bash
cd thesis-ids
```

### 2. Salin file konfigurasi

```bash
cp .env.example .env
# Edit .env sesuai kebutuhan (opsional, nilai default sudah siap pakai)
```

### 3. Jalankan sistem

```bash
make up
```

Sistem akan memulai semua service secara otomatis:
- **Web Interface**: http://localhost:8080 (login: `admin` / `admin123`)
- **Grafana Dashboard**: http://localhost:3000 (login: `admin` / `admin123`)

### 4. Simulasi serangan (untuk demo tesis)

```bash
make test
```

Perintah ini menjalankan simulasi 3 fase (skrip `evaluation/simulate.py`, ± 40 detik):
- **Fase 1** — baseline normal 30 IP unik (melatih model Isolation Forest)
- **Fase 2** — serangan: brute force SSH, port scanning, flood
- **Fase 3** — analisis ulang agar model yang sudah adaptif memvonis serangan

Hasil yang diharapkan di `/intrusions`: IP normal → `allow`; brute force & flood
→ `monitor`; port scan → `block` (mendemonstrasikan ketiga tingkat keputusan).
Baseline Fase 1 wajib ada karena Isolation Forest butuh **minimal 10 IP unik**
untuk terlatih — detail lengkap di
[docs/SOP-operasional-sistem.md](docs/SOP-operasional-sistem.md#6-simulasi-serangan-make-test).

### 5. Evaluasi kuantitatif (untuk data hasil tesis)

```bash
make evaluate
```

Mengirim skenario trafik berlabel (normal, brute force, port scan, flood),
menunggu hasil analisis, lalu menampilkan **confusion matrix, accuracy,
precision, recall, F1-score, false positive rate, dan waktu respons deteksi**.
Beri jeda minimal 10 menit (jendela analisis) antar-run agar hasil tidak
terkontaminasi data run sebelumnya.

## Perintah Makefile

| Perintah | Keterangan |
|---|---|
| `make build` | Build semua Docker image |
| `make up` | Jalankan semua service (background) |
| `make down` | Hentikan semua service |
| `make logs` | Lihat log semua service secara live |
| `make restart` | Restart semua service |
| `make clean` | Hapus semua container, image, dan volume |
| `make test` | Kirim syslog dummy untuk simulasi |
| `make evaluate` | Evaluasi kuantitatif deteksi (confusion matrix, precision/recall/F1, waktu respons) |
| `make status` | Cek status semua container |

## Alur Kerja Sistem

1. Router MikroTik mengirim syslog via UDP ke port 514
2. Golang Collector menerima, mem-parsing, dan menyimpan ke TimescaleDB
3. Golang mempublikasikan event ke **Redis Stream**
4. Python Analyst mengkonsumsi event dari stream
5. Python mengambil data historis dari TimescaleDB
6. Python menjalankan analisis **Isolation Forest**
7. Python mempublikasikan hasil ke **Redis Pub/Sub**
8. Golang menerima hasil, mendistribusikan `ids-blocked` address-list ke **semua node MikroTik**
9. Grafana menampilkan statistik real-time dari TimescaleDB

## Logika Prioritas Deteksi

```
Syslog baru masuk
       ↓
Cek WHITELIST aktif? → YA → Simpan saja, tidak ada tindakan
       ↓ TIDAK
Cek BLACKLIST aktif? → YA → Langsung blokir di semua node (bypass ML)
       ↓ TIDAK
Kirim ke Python Analyst via Redis
       ↓
Terima hasil analisis Isolation Forest
       ↓
is_intrusion = true → Distribusikan pemblokiran ke semua node
is_intrusion = false → Monitor, tidak ada tindakan
```

## Struktur Halaman Web

| Halaman | URL | Akses |
|---|---|---|
| Login | `/login` | Publik |
| Dashboard | `/dashboard` | Semua user |
| Data Syslog | `/syslogs` | Semua user |
| Deteksi Intrusi | `/intrusions` | Semua user |
| Node MikroTik | `/nodes` | Admin, Operator |
| Whitelist/Blacklist | `/access-list` | Admin, Operator |
| Manajemen User | `/users` | Admin |

## Grafana Dashboards

| Dashboard | URL | Keterangan |
|---|---|---|
| Ringkasan IDS | `/d/ids-overview` | Statistik keseluruhan sistem |
| Detail Intrusi | `/d/ids-intrusions` | Skor anomali, distribusi, akurasi |
| Per Node | `/d/ids-nodes` | Aktivitas per router MikroTik |

## Konfigurasi MikroTik

Agar router MikroTik mengirim syslog ke sistem ini, jalankan perintah berikut di terminal MikroTik:

```
/system logging action add name=remote target=remote remote=<IP_SERVER> remote-port=514
/system logging add action=remote topics=firewall
/system logging add action=remote topics=system
```

Untuk mengaktifkan firewall yang mencatat traffic:
```
/ip firewall filter add chain=input action=log log-prefix="FW:" place-before=0
```

## Teknologi yang Digunakan

| Komponen | Teknologi |
|---|---|
| Backend & Web | Go 1.24, HTMX, Tailwind CSS, Chart.js |
| Machine Learning | Python 3.11, Scikit-learn (Isolation Forest) |
| Database | TimescaleDB (PostgreSQL + ekstensi time-series) |
| Message Broker | Redis 7 (Stream + Pub/Sub) |
| Visualisasi | Grafana |
| Containerisasi | Docker, Docker Compose |

## Troubleshooting

**Web tidak bisa diakses setelah `make up`:**
```bash
make logs  # Lihat log untuk error
make status  # Cek apakah semua container running
```

**Python Analyst tidak mendeteksi intrusi:**
- Pastikan sudah ada minimal 10 IP berbeda di tabel `syslogs`
- Jalankan `make test` beberapa kali untuk mengisi data

**Distribusi ke MikroTik gagal:**
- Pastikan node MikroTik terdaftar dan aktif di halaman `/nodes`
- Verifikasi IP, port, username, dan password MikroTik sudah benar
- Pastikan API MikroTik sudah diaktifkan: `/ip service enable api`
