# Panduan Deploy ShieldNet IDS ke VPS (Production)

Panduan ini menjelaskan langkah lengkap men-deploy sistem ke VPS production,
mulai dari menarik kode dari repository hingga sistem siap menerima log dari
router MikroTik.

**Prasyarat:**
- VPS Ubuntu 24.04 LTS (minimal 2 vCPU / 2 GB RAM / 25 GB SSD; disarankan 4 GB RAM)
- Docker dan Docker Compose sudah terinstal
- Akses SSH dengan user non-root yang tergabung dalam grup `docker`
- (Opsional) Domain yang mengarah ke IP VPS, bila ingin HTTPS

Seluruh perintah dijalankan di VPS kecuali disebutkan lain.

---

## 1. Persiapan Awal

### 1.1 Pastikan Docker aktif saat boot

Container memakai `restart: always`, tetapi daemon Docker sendiri harus
diaktifkan agar sistem otomatis hidup kembali setelah VPS reboot:

```bash
sudo systemctl enable --now docker
```

### 1.2 Tarik kode dari repository

```bash
cd ~
git clone https://github.com/hermanspace/shieldnet-ids.git
cd shieldnet-ids
```

Untuk pembaruan di kemudian hari cukup `git pull` (lihat Bagian 8).

---

## 2. Konfigurasi Environment (.env)

Salin templat lalu edit:

```bash
cp .env.example .env
nano .env
```

**Wajib diganti untuk production:**

| Variabel | Nilai production |
|---|---|
| `DB_PASSWORD` | Password kuat, contoh hasil `openssl rand -hex 16` |
| `SESSION_SECRET` | Minimal 32 karakter acak: `openssl rand -hex 32` |
| `GRAFANA_ADMIN_PASSWORD` | Password kuat |
| `MIKROTIK_DEFAULT_USERNAME` / `PASSWORD` | Kredensial user API IDS yang Anda buat di router (bukan `admin/admin`) |

**Biarkan sesuai bawaan (sudah hasil tuning evaluasi):**
`ANOMALY_THRESHOLD=0.0`, `BLOCK_SCORE_THRESHOLD=-0.05`,
`BLOCK_CONFIDENCE_THRESHOLD=0.60`, serta parameter Isolation Forest.
Ambang ini juga bisa diubah belakangan dari web UI (menu **Decision Engine**)
tanpa restart.

Cara cepat membuat nilai acak:

```bash
echo "DB_PASSWORD kandidat : $(openssl rand -hex 16)"; echo "SESSION_SECRET kandidat: $(openssl rand -hex 32)"
```

> **Catatan:** file `.env` tidak pernah ikut ke repository (ada di `.gitignore`).
> Simpan salinannya di tempat aman.

---

## 3. Firewall (UFW)

> **Penting:** port yang di-publish Docker **menembus UFW** (Docker menulis
> aturan iptables sendiri). Karena itu `docker-compose.yml` sudah mengikat
> TimescaleDB (5432), Redis (6380), dan Grafana (3000) ke `127.0.0.1` —
> ketiganya tidak pernah terekspos ke internet apa pun aturan UFW-nya.
> Yang terekspos hanya port dashboard dan syslog, dan itulah yang diatur di sini.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH

# Dashboard web — batasi ke IP admin bila memungkinkan:
sudo ufw allow 8080/tcp
# (lebih ketat) sudo ufw allow from IP_RUMAH_ANDA to any port 8080 proto tcp

# Syslog UDP — HANYA dari IP setiap router MikroTik/CHR:
sudo ufw allow from IP_CHR_1 to any port 514 proto udp
sudo ufw allow from IP_CHR_2 to any port 514 proto udp
sudo ufw allow from IP_CHR_3 to any port 514 proto udp
sudo ufw allow from IP_CHR_4 to any port 514 proto udp

sudo ufw enable
sudo ufw status verbose
```

Bila node berada di belakang NAT dan memakai tunnel WireGuard (lihat 6.3),
buka juga port WireGuard (mis. `sudo ufw allow 51820/udp`) dan izinkan 514/udp
dari subnet tunnel (mis. `sudo ufw allow from 10.99.0.0/24 to any port 514 proto udp`).

---

## 4. Build dan Jalankan

```bash
make build   # build image golang-collector dan python-analyst
make up      # jalankan 5 container; skema database otomatis dibuat dari db/init.sql
```

Verifikasi:

```bash
make status
```

Semua container harus berstatus `Up` (timescaledb dan redis `healthy`).
Lihat log bila ada masalah:

```bash
make logs
```

Buka dashboard: `http://IP_VPS:8080` — login awal `admin / admin123`.

---

## 5. Pengamanan Akun (WAJIB, langsung setelah login pertama)

Kredensial bawaan (`admin123` dkk.) tercantum di repository publik, sehingga
harus segera diganti:

1. Login sebagai `admin`, buka **Manajemen User**.
2. Buat user admin baru dengan username dan password kuat.
3. Logout, login dengan admin baru.
4. **Nonaktifkan atau hapus** ketiga user bawaan: `admin`, `operator`, `viewer`.
5. (Bila Grafana dipakai) ganti password admin Grafana — akses via SSH tunnel:
   `ssh -L 3000:localhost:3000 user@IP_VPS` lalu buka `http://localhost:3000`.

Grafana saat ini tidak dipakai di menu dashboard. Bila ingin menghemat RAM:

```bash
docker compose stop grafana
```

---

## 6. Menghubungkan Router MikroTik

### 6.1 Konfigurasi setiap router

Ikuti prosedur lengkap di [SOP-tambah-node-mikrotik.md](SOP-tambah-node-mikrotik.md).
Ringkasnya, di setiap router:

1. Aktifkan **API service** (port 8728), batasi *Available From* = IP VPS.
2. Buat **user khusus IDS** (bukan admin) dengan policy `api, read, write`.
3. Pasang **rule logging firewall** (`log-prefix`, sebelum rule drop apa pun).
4. Arahkan **remote syslog** ke VPS: target IP VPS, port 514, topics `firewall` dan `system`.
5. Buat **rule drop** untuk address-list `ids-blocked` (chain input dan forward) —
   tanpa rule ini blacklist terdistribusi tetapi tidak memblokir apa pun.

### 6.2 Daftarkan node di dashboard

Menu **Node MikroTik** → tambah node: node ID, IP router, port API 8728,
kredensial user IDS, lokasi. Kemudian **hapus dua node contoh**
(`router-01` / `router-02`, IP 192.168.1.x) yang berasal dari seed database.

### 6.3 Router di belakang NAT (tanpa IP publik)

Syslog (router → VPS) tetap jalan karena arahnya outbound. Yang terhalang NAT
adalah distribusi blacklist (VPS → router, API 8728). Solusinya tunnel
WireGuard (bawaan RouterOS v7): router menginisiasi tunnel ke VPS dengan
`persistent-keepalive=25s`, lalu node didaftarkan memakai IP tunnel-nya.
Lisensi CHR gratis tidak menghalangi ini — batasannya hanya throughput
1 Mbps per interface, jauh di atas kebutuhan syslog + API.

### 6.4 Verifikasi ujung-ke-ujung

1. Menu **Data Syslog**: log dari router harus muncul dengan `node_id` yang
   benar (bukan `unknown-...`) beberapa detik setelah ada aktivitas.
2. Uji dari luar: lakukan beberapa kali login gagal ke salah satu router,
   lalu pantau menu **Deteksi Intrusi**.
3. Uji blokir manual: menu **Whitelist / Blacklist** → tambahkan IP uji ke
   blacklist → periksa `/ip firewall address-list print` di semua router;
   IP harus muncul di list `ids-blocked`.

---

## 7. Uji Sistem Menyeluruh (opsional tapi disarankan)

Simulasi serangan sintetis (trafik latar + brute force + port scan + flood):

```bash
make test
```

Evaluasi kuantitatif dengan ground truth berlabel (confusion matrix,
precision/recall/F1/FPR, waktu respons):

```bash
make evaluate
```

> Beri jeda minimal `ANALYSIS_WINDOW_MINUTES` (bawaan 10 menit) antar-run
> `make evaluate` agar residu jendela analisis run sebelumnya tidak mencemari
> hasil. Pastikan juga tidak ada override aktif di menu Decision Engine bila
> hasilnya akan dilaporkan, agar konsisten dengan konfigurasi tertulis.

---

## 8. Operasional dan Pemeliharaan

### Memperbarui sistem ke versi terbaru

```bash
cd ~/shieldnet-ids && git pull && make build && make up
```

(`make up` membuat ulang hanya container yang image-nya berubah; data database
aman karena tersimpan di Docker volume.)

### Backup database

```bash
docker exec ids-timescaledb pg_dump -U ids_user -d ids_thesis | gzip > backup-ids-$(date +%F).sql.gz
```

Jadwalkan harian via cron bila sistem dipakai jangka panjang.

### Melihat penggunaan resource

```bash
make status
```

### Menghentikan / menghapus

```bash
make down          # stop semua container (data tetap ada)
make clean         # HATI-HATI: menghapus container + volume + SEMUA DATA
```

---

## 9. (Opsional) HTTPS untuk Dashboard

Untuk akses dashboard melalui domain dengan sertifikat otomatis, pasang Caddy
di VPS sebagai reverse proxy:

```bash
sudo apt install -y caddy
```

Isi `/etc/caddy/Caddyfile`:

```
ids.domain-anda.com {
    reverse_proxy localhost:8080
}
```

```bash
sudo systemctl reload caddy
sudo ufw allow 80,443/tcp
```

Setelah itu port 8080 bisa ditutup dari publik
(`sudo ufw delete allow 8080/tcp`) sehingga dashboard hanya diakses via HTTPS.

---

## Ringkasan Checklist Production

- [ ] `.env` diisi: password DB, `SESSION_SECRET`, password Grafana, kredensial API MikroTik
- [ ] UFW aktif: SSH + 8080 (dibatasi) + 514/udp hanya dari IP router
- [ ] `make build && make up` — semua container `Up (healthy)`
- [ ] User bawaan `admin/operator/viewer` diganti dan dinonaktifkan
- [ ] Node contoh `router-01/02` dihapus, node nyata terdaftar
- [ ] Setiap router: API + user IDS + logging + remote syslog + rule drop `ids-blocked`
- [ ] Verifikasi: syslog masuk ber-`node_id` benar, blokir manual sampai ke address-list semua node
- [ ] `make test` / `make evaluate` berjalan baik
- [ ] Backup database terjadwal
