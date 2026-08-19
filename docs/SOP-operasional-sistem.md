# SOP: Operasional Sistem ShieldNet IDS (Docker)

Dokumen ini adalah panduan operasional lengkap untuk menjalankan, mematikan,
me-restart, menguji, mengevaluasi, dan merawat sistem ShieldNet IDS yang
berjalan di atas Docker. Semua perintah dijalankan dari direktori proyek
`thesis-ids/` kecuali disebutkan lain.

---

## Daftar Isi

1. [Prasyarat](#1-prasyarat)
2. [Menjalankan Sistem dari Awal (First Run)](#2-menjalankan-sistem-dari-awal-first-run)
3. [Verifikasi Sistem Berjalan Sehat](#3-verifikasi-sistem-berjalan-sehat)
4. [Mematikan dan Me-restart Sistem](#4-mematikan-dan-me-restart-sistem)
5. [Menjalankan Ulang Setelah Mengubah Kode](#5-menjalankan-ulang-setelah-mengubah-kode)
6. [Simulasi Serangan (make test)](#6-simulasi-serangan-make-test)
7. [Evaluasi Kuantitatif (make evaluate)](#7-evaluasi-kuantitatif-make-evaluate)
8. [Melihat Log dan Debugging](#8-melihat-log-dan-debugging)
9. [Akses Langsung ke Database dan Redis](#9-akses-langsung-ke-database-dan-redis)
10. [Backup dan Restore Data (Penting untuk Data Tesis)](#10-backup-dan-restore-data-penting-untuk-data-tesis)
11. [Pembersihan (Cleanup) Docker](#11-pembersihan-cleanup-docker)
12. [Troubleshooting Umum](#12-troubleshooting-umum)
13. [Referensi Cepat Semua Perintah](#13-referensi-cepat-semua-perintah)

---

## 1. Prasyarat

| Kebutuhan | Versi Minimum | Cara Cek |
|---|---|---|
| Docker Engine / Docker Desktop | 20.x | `docker --version` |
| Docker Compose | v2.x | `docker compose version` |
| GNU Make | — | `make --version` |

**Pastikan Docker daemon berjalan** sebelum perintah apa pun:

```bash
docker info
# Jika error "Cannot connect to the Docker daemon" → jalankan Docker Desktop
# (macOS: buka aplikasi Docker Desktop, tunggu ikon paus stabil)
```

Port yang akan dipakai di host (pastikan tidak bentrok dengan aplikasi lain):

| Port Host | Service | Keterangan |
|---|---|---|
| 8080 | Web Interface (Golang) | dapat diubah via `WEB_PORT` di `.env` |
| 514/udp | Penerima syslog | dapat diubah via `SYSLOG_UDP_PORT` |
| 3000 | Grafana | dapat diubah via `GRAFANA_PORT` |
| 5432 | TimescaleDB | akses langsung database (opsional) |
| 6380 | Redis | dipetakan ke 6379 di dalam container |

---

## 2. Menjalankan Sistem dari Awal (First Run)

```bash
# 1. Masuk ke direktori proyek
cd thesis-ids

# 2. Siapkan file konfigurasi (make up melakukan ini otomatis jika belum ada)
cp .env.example .env
# Edit .env bila perlu — nilai default sudah siap pakai untuk pengujian

# 3. Build semua Docker image (Golang Collector + Python Analyst)
make build

# 4. Jalankan semua service di background
make up
```

Apa yang terjadi saat `make up`:

1. TimescaleDB start → `db/init.sql` dieksekusi otomatis **hanya pada run
   pertama** (membuat schema, hypertable, dan user default)
2. Redis start dengan konfigurasi `redis/redis.conf`
3. Golang Collector dan Python Analyst menunggu healthcheck database & Redis
   lulus, baru ikut start (`depends_on: condition: service_healthy`)
4. Grafana start dengan datasource dan 3 dashboard yang ter-provision otomatis

**Kredensial default setelah first run:**

| Layanan | URL | Username / Password |
|---|---|---|
| Web Interface | http://localhost:8080 | `admin` / `admin123` (juga: `operator`/`operator123`, `viewer`/`viewer123`) |
| Grafana | http://localhost:3000 | `admin` / `admin123` |

---

## 3. Verifikasi Sistem Berjalan Sehat

```bash
# Status semua container + penggunaan CPU/memori
make status
```

Output yang diharapkan: kelima container berstatus `Up` (TimescaleDB dan Redis
berstatus `Up (healthy)`):

```
ids-timescaledb   Up (healthy)
ids-redis         Up (healthy)
ids-golang        Up
ids-python        Up
ids-grafana       Up
```

Verifikasi lanjutan per komponen:

```bash
# Golang Collector siap menerima syslog?
docker logs ids-golang --tail 20
# Cari baris: "Syslog receiver aktif di UDP port 514" dan "Web server berjalan"

# Python Analyst terhubung dan siap analisis?
docker logs ids-python --tail 20
# Cari baris: "Sistem Python Analyst siap. Menunggu event syslog..."

# Database bisa di-query?
docker exec ids-timescaledb psql -U ids_user -d ids_thesis -c "SELECT COUNT(*) FROM syslogs;"

# Uji end-to-end tercepat: kirim simulasi lalu lihat dashboard
make test
```

---

## 4. Mematikan dan Me-restart Sistem

### Mematikan

```bash
# Hentikan dan HAPUS semua container — DATA TETAP AMAN
# (data tersimpan di Docker volume: database, model ML, dashboard Grafana)
make down
```

`make down` **tidak menghapus data**. Saat `make up` lagi, seluruh syslog,
hasil deteksi, user, node, dan model ML yang sudah terlatih kembali seperti semula.

Alternatif yang lebih ringan (hentikan tanpa menghapus container):

```bash
docker compose stop      # pause semua service
docker compose start     # lanjutkan lagi (lebih cepat dari make up)
```

### Me-restart

```bash
# Restart semua service (tanpa rebuild image)
make restart

# Restart HANYA satu service (lebih cepat, service lain tidak terganggu)
docker compose restart golang-collector
docker compose restart python-analyst
docker compose restart grafana
```

Kapan perlu restart:

| Situasi | Perintah |
|---|---|
| Mengubah nilai di `.env` | `make down && make up` (restart saja tidak membaca ulang `.env`) |
| Service terlihat hang / tidak merespons | `docker compose restart <nama-service>` |
| Mengubah kode Go / Python | **Bukan restart** — perlu rebuild, lihat bagian 5 |
| Mengubah dashboard Grafana di `grafana/provisioning/` | `docker compose restart grafana` |

---

## 5. Menjalankan Ulang Setelah Mengubah Kode

Kode Go dan Python di-COPY ke dalam image saat build — mengubah file di host
**tidak otomatis** terbawa ke container. Setelah mengubah kode:

```bash
# Rebuild + recreate hanya service yang berubah (cara tercepat):
docker compose up -d --build golang-collector    # jika mengubah kode Go
docker compose up -d --build python-analyst      # jika mengubah kode Python

# Atau rebuild semuanya:
make build && make up
```

> **Catatan khusus:** jika parameter model berubah signifikan (mis. daftar
> fitur), hapus model lama agar dilatih ulang dari nol:
> ```bash
> docker compose down
> docker volume rm thesis-ids_model_data
> make up
> ```

---

## 6. Simulasi Serangan (make test)

Menguji fungsional deteksi end-to-end dengan syslog dummy berformat MikroTik asli.
Skrip: `evaluation/simulate.py`. Durasi ± 40 detik (termasuk jeda pelatihan model).

```bash
make test
```

### Apa yang di-generate

Simulasi mengirim syslog dari dalam jaringan Docker ke port 514 dalam **tiga fase**:

| Fase | Yang dikirim | Jumlah | Tujuan |
|---|---|---|---|
| **Fase 1 — Baseline normal** | 30 IP unik (`192.168.1.10`–`192.168.1.39`), trafik jinak: 3–8 koneksi ke port 80/443/53 | ~165 pesan | Melatih model Isolation Forest dengan pola "normal" |
| **Fase 2 — Serangan** | Brute force (`10.10.10.99`, 20 pesan `login failure`), Port scan (`172.16.0.50`, 25 port berbeda), Flood (`203.0.113.77`, 35 request cepat 1 port) | 80 pesan | Pola serangan yang harus terdeteksi |
| **Fase 3 — Analisis ulang** | Pengiriman ulang singkat tiap IP serangan (4 pesan/IP) | 12 pesan | Memicu analisis dengan model yang sudah adaptif |

### Mengapa perlu Fase 1 (baseline)?

Isolation Forest **unsupervised** — ia mengenali serangan sebagai *penyimpangan*
dari pola normal. Tanpa baseline, tidak ada "normal" yang bisa jadi acuan.
Dua syarat teknis:

1. **Minimal 10 IP unik** agar model bisa dilatih (`model.py` menolak data
   pelatihan < 10 sampel). Mengirim serangan dari 3 IP saja — berapa kali pun
   diulang — **tidak akan** menghasilkan deteksi karena model tak pernah terlatih.
2. **Baseline harus jinak & wajar** (volume rendah, sedikit port, tanpa login
   gagal). Baseline yang justru berisi banyak anomali membuat serangan "terlihat
   normal" bagi model.

> **Catatan untuk analisis tesis:** ini adalah karakteristik nyata anomaly
> detection — kualitas deteksi bergantung pada representativeness data normal.
> Baseline yang seragam-sempurna maupun yang sudah tercemar serangan sama-sama
> menurunkan sensitivitas. Simulasi ini juga menunjukkan efek *retrain otomatis*:
> Fase 3 menganalisis ulang serangan setelah model beradaptasi.

### Hasil yang diharapkan

Setelah ± 10–15 detik dari selesainya simulasi, di
`http://localhost:8080/intrusions` (atau query `intrusion_results`) akan terlihat
pola berikut (skor bisa bervariasi sedikit antar-run, tren tetap konsisten):

| IP | Skenario | Skor anomali | Vonis | Aksi |
|---|---|---|---|---|
| 192.168.1.10–39 | Normal | positif (≈ 0 s.d. +0.05) | bukan intrusi | `allow` |
| 10.10.10.99 | Brute force | ≈ −0.29 | **intrusi** | `monitor` |
| 203.0.113.77 | Flood | ≈ −0.18 | **intrusi** | `monitor` |
| 172.16.0.50 | Port scan | ≈ −0.31 | **intrusi** | **`block`** (skor < −0.3 & confidence ≥ 0.75) → distribusi ke semua node |

Ini sekaligus mendemonstrasikan **ketiga tingkat keputusan** sistem: `allow`,
`monitor`, dan `block` (respons bertingkat). Periksa juga:

- Log analisis: `docker logs ids-python --tail 30` → baris `[INTRUSI] IP=...`
- Log distribusi: `docker logs ids-golang | grep Mendistribusikan` → aksi `block`
- Grafana: dashboard "IDS - Detail Intrusi" (pie chart distribusi aksi)

> **Untuk demo sidang yang bersih**, mulai dari state kosong agar hasil tidak
> tercampur data lama:
> ```bash
> docker exec ids-timescaledb psql -U ids_user -d ids_thesis -c "TRUNCATE syslogs, intrusion_results;"
> docker exec ids-python sh -c 'rm -f /app/models/*.pkl'
> docker compose restart python-analyst && sleep 6
> make test
> ```

---

## 7. Evaluasi Kuantitatif (make evaluate)

Eksperimen berlabel untuk menghasilkan **data hasil tesis**: confusion matrix,
accuracy, precision, recall, F1-score, false positive rate, dan waktu respons.

```bash
# Jalankan evaluasi (± 1-2 menit)
make evaluate

# Simpan output ke file untuk lampiran tesis
make evaluate | tee hasil-evaluasi-run01.txt
```

**Prosedur yang disarankan untuk data tesis:**

1. Pastikan sistem sudah berjalan sehat (`make status`)
2. Jalankan `make evaluate`, simpan output tiap run ke file terpisah
3. **Beri jeda minimal 10 menit antar-run** (satu jendela analisis) — skrip
   akan menampilkan peringatan otomatis jika residu run sebelumnya terdeteksi
4. Ulangi ≥ 10 run, laporkan rata-rata ± standar deviasi tiap metrik
5. Untuk analisis sensitivitas: ubah parameter di `.env`
   (mis. `ANOMALY_THRESHOLD`, `IF_CONTAMINATION`), lalu `make down && make up`,
   dan ulangi pengukuran

Bagian akhir output berupa JSON — mudah diolah lanjut (Excel/Python) untuk
tabel dan grafik di Bab 4.

---

## 8. Melihat Log dan Debugging

```bash
# Log semua service secara live (Ctrl+C untuk keluar)
make logs

# Log satu container saja
docker logs ids-golang  -f --tail 100   # penerimaan syslog + distribusi blokir
docker logs ids-python  -f --tail 100   # analisis Isolation Forest + retrain
docker logs ids-grafana --tail 50
docker logs ids-timescaledb --tail 50

# Cari kejadian spesifik
docker logs ids-python 2>&1 | grep INTRUSI          # semua deteksi intrusi
docker logs ids-python 2>&1 | grep "Model berhasil" # kapan model dilatih
docker logs ids-golang 2>&1 | grep "blokir"         # aktivitas pemblokiran

# Masuk ke shell container (inspeksi manual)
docker exec -it ids-python sh
docker exec -it ids-golang sh
```

---

## 9. Akses Langsung ke Database dan Redis

### TimescaleDB (psql)

```bash
# Buka shell SQL interaktif
docker exec -it ids-timescaledb psql -U ids_user -d ids_thesis
```

Query yang sering dipakai:

```sql
-- 20 syslog terbaru
SELECT time, node_id, source_ip, event_type, dest_port
FROM syslogs ORDER BY time DESC LIMIT 20;

-- Hasil deteksi terbaru
SELECT time, source_ip, ROUND(anomaly_score::numeric,3) AS skor,
       is_intrusion, ROUND(confidence::numeric,2) AS conf, action_taken, distributed
FROM intrusion_results ORDER BY time DESC LIMIT 20;

-- Rekap jumlah data per tabel
SELECT 'syslogs' AS tabel, COUNT(*) FROM syslogs
UNION ALL SELECT 'intrusion_results', COUNT(*) FROM intrusion_results;

-- Rekap aksi 24 jam terakhir
SELECT action_taken, COUNT(*) FROM intrusion_results
WHERE time > NOW() - INTERVAL '24 hours' GROUP BY action_taken;
```

Inisialisasi ulang schema secara manual (tanpa menghapus volume):

```bash
make db-init
```

### Redis (redis-cli)

```bash
docker exec -it ids-redis redis-cli

# Perintah berguna di dalam redis-cli:
XLEN ids:syslog:stream                      # jumlah pesan di stream
XINFO GROUPS ids:syslog:stream              # status consumer group Python
XREVRANGE ids:syslog:stream + - COUNT 5     # 5 pesan terakhir
SUBSCRIBE ids:analysis:result               # pantau hasil analisis real-time
```

---

## 10. Backup dan Restore Data (Penting untuk Data Tesis)

Lakukan backup **sebelum** eksperimen besar atau pembersihan apa pun — data
syslog dan hasil deteksi adalah bukti penelitian Anda.

```bash
# Backup seluruh database ke file SQL di host
docker exec ids-timescaledb pg_dump -U ids_user ids_thesis > backup-$(date +%Y%m%d).sql

# Restore dari backup (database harus dalam keadaan kosong/baru)
docker exec -i ids-timescaledb psql -U ids_user -d ids_thesis < backup-20260710.sql

# Backup model ML yang sudah terlatih (dari Docker volume)
docker cp ids-python:/app/models ./backup-models/
```

---

## 11. Pembersihan (Cleanup) Docker

### Tingkat 1 — Reset data proyek saja (schema dibuat ulang, image tetap)

```bash
docker compose down -v
# -v menghapus SEMUA volume proyek: database, model ML, data Grafana.
# make up berikutnya = kondisi pabrik (init.sql jalan lagi, model dilatih ulang)
```

Gunakan saat: ingin memulai eksperimen dari kondisi bersih tanpa rebuild.

### Tingkat 2 — Bersihkan total proyek ini (container + image + volume)

```bash
make clean
# Ada konfirmasi (y/N). Menghapus container, image hasil build, dan semua volume
# proyek ini. Proyek Docker LAIN di mesin Anda tidak tersentuh.
```

Gunakan saat: selesai penelitian, atau ingin build ulang dari nol total.

### Tingkat 3 — Bersihkan sampah Docker global (lintas proyek — HATI-HATI)

```bash
# Aman: hanya menghapus yang benar-benar tidak terpakai (dangling)
docker container prune        # container yang sudah Exited
docker image prune            # layer image tak bertuan (dangling)
docker builder prune          # cache build lama (sering makan puluhan GB)

# Lihat siapa yang memakan disk sebelum memutuskan:
docker system df

# AGRESIF — menghapus SEMUA image/network yang tidak sedang dipakai container
# berjalan, TERMASUK milik proyek lain. Jangan jalankan saat sistem IDS mati,
# karena image ShieldNet ikut terhapus:
docker system prune -a

# PALING BERBAHAYA — ikut menghapus semua volume tak terpakai (DATA HILANG):
docker system prune -a --volumes
```

> **Aturan aman:** selama sistem ShieldNet sedang `Up`, `docker system prune -a`
> tidak akan menghapus image/volume yang sedang dipakai. Tetap lakukan
> **backup (bagian 10) sebelum pembersihan tingkat mana pun**.

### Ringkasan efek tiap tingkat

| Perintah | Container | Image | Volume (data) | Lingkup |
|---|---|---|---|---|
| `make down` | dihapus | tetap | **tetap** | proyek ini |
| `docker compose down -v` | dihapus | tetap | **DIHAPUS** | proyek ini |
| `make clean` | dihapus | dihapus | **DIHAPUS** | proyek ini |
| `docker image/container/builder prune` | exited saja | dangling saja | tetap | global |
| `docker system prune -a --volumes` | semua idle | semua idle | **DIHAPUS** | **global** |

---

## 12. Troubleshooting Umum

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop belum jalan | Buka Docker Desktop, tunggu stabil, ulangi perintah |
| `port is already allocated` saat `make up` | Port 8080/3000/5432/514 dipakai aplikasi lain | Ubah `WEB_PORT`/`GRAFANA_PORT`/`SYSLOG_UDP_PORT` di `.env`, lalu `make down && make up`; cari pemakai port: `lsof -i :8080` |
| Container `ids-golang`/`ids-python` restart terus | DB/Redis belum sehat, atau error kode | `docker logs ids-golang --tail 50` untuk lihat error persisnya |
| Web 8080 tidak bisa diakses | Container belum Up / crash | `make status` lalu `make logs` |
| `make test` tidak memunculkan deteksi | Model belum terlatih (data < 10 IP unik) | Jalankan `make test` 2–3 kali, atau `make evaluate` (sudah termasuk trafik latar) |
| Semua skor anomali = 0 | Model belum terlatih | Sama seperti di atas; cek `docker logs ids-python \| grep -i model` |
| Perubahan kode tidak berefek | Lupa rebuild image | `docker compose up -d --build <service>` (bagian 5) |
| Perubahan `.env` tidak berefek | Restart tidak membaca ulang env | `make down && make up` |
| `make evaluate` memberi peringatan residu | Run sebelumnya < 10 menit yang lalu | Tunggu hingga 10 menit sejak run terakhir |
| Distribusi ke MikroTik gagal | Node tidak aktif / kredensial API salah | Cek halaman `/nodes` → "Cek Koneksi"; pastikan `/ip service enable api` di router |
| Disk penuh oleh Docker | Cache build & image lama menumpuk | `docker system df` lalu `docker builder prune` + `docker image prune` |

---

## 13. Referensi Cepat Semua Perintah

| Perintah | Fungsi |
|---|---|
| `make build` | Build semua Docker image dari source code |
| `make up` | Jalankan semua service (background); buat `.env` otomatis jika belum ada |
| `make down` | Hentikan & hapus container — **data tetap aman** |
| `make restart` | Restart semua service tanpa rebuild |
| `make status` | Status container + penggunaan CPU/memori |
| `make logs` | Log semua service secara live |
| `make test` | Simulasi serangan (normal, brute force, port scan) |
| `make evaluate` | Evaluasi kuantitatif berlabel (metrik untuk Bab 4) |
| `make db-init` | Eksekusi ulang schema database secara manual |
| `make clean` | Hapus total container+image+volume proyek (dengan konfirmasi) |
| `docker compose stop` / `start` | Pause / lanjutkan tanpa menghapus container |
| `docker compose restart <svc>` | Restart satu service saja |
| `docker compose up -d --build <svc>` | Rebuild + jalankan ulang satu service setelah ubah kode |
| `docker compose down -v` | Reset data proyek (hapus semua volume proyek) |
| `docker exec -it ids-timescaledb psql -U ids_user -d ids_thesis` | Shell SQL database |
| `docker exec -it ids-redis redis-cli` | Shell Redis |
| `docker exec ids-timescaledb pg_dump -U ids_user ids_thesis > backup.sql` | Backup database |
| `docker system df` | Lihat pemakaian disk oleh Docker |
| `docker builder prune` / `docker image prune` | Bersihkan cache build / image tak bertuan (aman) |
