# SOP: Menambahkan Node MikroTik Baru ke ShieldNet IDS

Dokumen ini menjelaskan prosedur lengkap menambahkan router MikroTik baru ke sistem
deteksi intrusi, mulai dari konfigurasi di sisi MikroTik hingga pendaftaran di
web interface ShieldNet IDS.

---

## Prasyarat

Sebelum memulai, pastikan:
- Router MikroTik sudah terpasang dan dapat diakses jaringan
- Server ShieldNet IDS sedang berjalan (`make status` menampilkan semua container `Up`)
- Anda memiliki akun dengan role **admin** atau **operator** di web interface
- Anda mengetahui IP address router MikroTik yang akan ditambahkan

---

## Gambaran Alur

```
[Konfigurasi MikroTik]          [Pendaftaran di ShieldNet]
        │                                   │
 1. Aktifkan API service           4. Login ke web interface
 2. Buat user khusus IDS           5. Daftarkan node baru
 3. Konfigurasi firewall log       6. Verifikasi koneksi
    + aktifkan syslog remote       7. Test pengiriman syslog
```

---

## Bagian 1: Konfigurasi di Router MikroTik

### 1.1 Aktifkan API Service

API MikroTik dibutuhkan agar ShieldNet IDS bisa mendistribusikan pemblokiran
(menambahkan IP ke address-list `ids-blocked`) ke router ini secara otomatis.

#### Via Winbox (GUI)

1. Buka **Winbox**, hubungkan ke router MikroTik
2. Navigasi ke menu **IP → Services**
3. Cari entry **api** (port 8728)
4. Double-click entry `api` → centang **Enabled** → klik **OK**

   ```
   IP → Services
   ┌─────────────────────────────────────────────────┐
   │ Name    Port   Available From   Certificate  TLS │
   │ api     8728   (kosong=semua)                    │ ← Enable ini
   │ api-ssl 8729                                     │
   │ ftp     21                                       │
   └─────────────────────────────────────────────────┘
   ```

5. Opsional (disarankan untuk keamanan): isi kolom **Available From** dengan
   IP address server ShieldNet IDS agar API hanya bisa diakses dari server tersebut

#### Via Terminal / Command

```
/ip service enable api
/ip service set api port=8728
```

Untuk membatasi akses API hanya dari IP server IDS (ganti `192.168.0.10` dengan IP server):

```
/ip service set api address=192.168.0.10/32
```

Verifikasi API aktif:

```
/ip service print
```

Output yang diharapkan: kolom `DISABLED` pada baris `api` **tidak** tercentang.

---

### 1.2 Buat User Khusus untuk ShieldNet IDS

Disarankan membuat user terpisah dengan hak akses minimum yang diperlukan,
bukan menggunakan user `admin` utama.

#### Via Winbox (GUI)

1. Navigasi ke **System → Users**
2. Klik tombol **+** (Add)
3. Isi form:
   - **Name:** `ids-user` (atau nama lain sesuai preferensi)
   - **Password:** buat password yang kuat
   - **Group:** pilih **read** (untuk monitoring) atau buat group baru

4. Karena ShieldNet perlu menambahkan address-list, group `read` tidak cukup.
   Buat **group baru** dengan izin yang diperlukan:
   - Navigasi ke tab **Groups** → klik **+**
   - **Name:** `ids-group`
   - Centang policy: **read**, **write**, **api**
   - Klik **OK**

5. Kembali ke tab **Users**, set **Group** ke `ids-group`
6. Klik **OK**

#### Via Terminal / Command

```
# Buat group dengan policy minimal yang diperlukan
/user group add name=ids-group policy=read,write,api,!local,!telnet,!ssh,!ftp,!reboot,!password,!policy,!test,!winbox,!web,!sniff,!sensitive,!romon

# Buat user baru
/user add name=ids-user password=IDS_Password_Kuat group=ids-group

# Verifikasi
/user print
```

> **Catatan:** Gunakan password yang kuat. Password ini akan disimpan di database
> ShieldNet IDS (terenkripsi di level database).

---

### 1.3 Konfigurasi Firewall untuk Pencatatan Log

MikroTik perlu dikonfigurasi agar setiap paket yang masuk melalui firewall
dicatat (log) dan dikirimkan ke ShieldNet IDS.

#### Via Winbox (GUI)

1. Navigasi ke **IP → Firewall → Filter Rules**
2. Klik tombol **+** untuk menambahkan rule baru
3. Tab **General:**
   - **Chain:** `input` (untuk traffic yang masuk ke router)
   - **Action:** `log`
   - **Log Prefix:** `FW:` (prefix ini dikenali parser ShieldNet IDS)
   - Letakkan rule ini **di posisi paling atas** (sebelum rule DROP/ACCEPT)

   ```
   Tab General:
   ┌──────────────────────────────────┐
   │ Chain:    input                  │
   │ Protocol: (kosong = semua)       │
   │ Action:   log                    │
   │ Log Prefix: FW:                  │
   └──────────────────────────────────┘
   ```

4. Ulangi untuk chain `forward` jika ingin memantau traffic yang melewati router:
   - Chain: `forward`, Action: `log`, Log Prefix: `FW:`

#### Via Terminal / Command

```
# Log semua traffic yang masuk ke router
/ip firewall filter add chain=input action=log log-prefix="FW:" place-before=0 comment="ShieldNet IDS logging"

# Log traffic yang melewati router (opsional, untuk memantau client)
/ip firewall filter add chain=forward action=log log-prefix="FW:" place-before=0 comment="ShieldNet IDS forward logging"

# Verifikasi rule sudah ada di posisi atas
/ip firewall filter print
```

> **Penting:** Rule logging harus berada **sebelum** rule DROP apa pun,
> atau traffic yang di-drop tidak akan sempat dicatat.

---

### 1.4 Konfigurasi Pengiriman Syslog ke ShieldNet IDS

MikroTik perlu mengirim log ke server ShieldNet IDS via UDP port 514.
Ganti `IP_SERVER_IDS` dengan IP address server yang menjalankan ShieldNet IDS.

#### Via Winbox (GUI)

**Langkah A — Buat Logging Action (tujuan pengiriman log):**

1. Navigasi ke **System → Logging → tab Actions**
2. Klik **+** untuk menambahkan action baru
3. Isi:
   - **Name:** `remote-ids`
   - **Type:** `remote`
   - **Remote Address:** `IP_SERVER_IDS` (contoh: `192.168.0.10`)
   - **Remote Port:** `514`
   - **Syslog Facility:** `daemon`
   - **Syslog Severity:** `info`
4. Klik **OK**

   ```
   System → Logging → Actions
   ┌──────────────────────────────────────┐
   │ Name:           remote-ids           │
   │ Type:           remote               │
   │ Remote Address: 192.168.0.10         │ ← IP server ShieldNet IDS
   │ Remote Port:    514                  │
   │ Syslog Facility: daemon              │
   │ Syslog Severity: info               │
   └──────────────────────────────────────┘
   ```

**Langkah B — Aktifkan Pengiriman Log Firewall:**

1. Masih di **System → Logging**, pindah ke tab **Rules**
2. Klik **+** untuk menambahkan rule baru
3. Isi:
   - **Topics:** `firewall`
   - **Action:** `remote-ids` (yang baru dibuat)
4. Klik **OK**
5. Ulangi untuk topic `system` agar event login juga terkirim

   ```
   System → Logging → Rules
   ┌──────────────────────────┐
   │ Topics: firewall         │  ← Tambahkan ini
   │ Action: remote-ids       │
   └──────────────────────────┘
   ┌──────────────────────────┐
   │ Topics: system           │  ← Tambahkan ini juga
   │ Action: remote-ids       │
   └──────────────────────────┘
   ```

#### Via Terminal / Command

```
# Langkah A: Buat action yang mengarah ke server ShieldNet IDS
# Ganti 192.168.0.10 dengan IP server IDS yang sebenarnya
/system logging action add name=remote-ids target=remote remote=192.168.0.10 remote-port=514 syslog-facility=daemon

# Langkah B: Aktifkan pengiriman log firewall dan system
/system logging add action=remote-ids topics=firewall
/system logging add action=remote-ids topics=system

# Verifikasi
/system logging print
/system logging action print
```

---

### 1.5 Buat Address List untuk Pemblokiran Otomatis

ShieldNet IDS akan menambahkan IP penyerang ke address-list bernama `ids-blocked`.
Buat firewall rule yang menggunakan address-list tersebut untuk memblokir traffic.

#### Via Winbox (GUI)

1. Navigasi ke **IP → Firewall → Filter Rules**
2. Klik **+** untuk menambahkan rule baru
3. Tab **General:**
   - **Chain:** `input`
   - **Src. Address List:** `ids-blocked`
   - **Action:** `drop`
4. Tab **Advanced:**
   - Biarkan kosong
5. Letakkan rule ini **setelah** rule logging tapi **sebelum** rule ACCEPT
6. Klik **OK**

   ```
   Rule DROP untuk IP yang ada di ids-blocked:
   ┌──────────────────────────────────────────┐
   │ Chain:           input                    │
   │ Src. Address List: ids-blocked            │
   │ Action:          drop                     │
   │ Log:             yes (opsional)           │
   │ Log Prefix:      BLOCKED:                 │
   └──────────────────────────────────────────┘
   ```

7. Ulangi untuk chain `forward` jika perlu memblokir traffic yang melewati router

#### Via Terminal / Command

```
# Buat rule DROP untuk IP dalam ids-blocked (chain input)
/ip firewall filter add chain=input src-address-list=ids-blocked action=drop comment="ShieldNet IDS: block malicious IPs" place-before=1

# Opsional: Blokir juga di chain forward
/ip firewall filter add chain=forward src-address-list=ids-blocked action=drop comment="ShieldNet IDS: block forward"

# Buat address-list kosong sebagai placeholder (opsional, IDS akan membuatnya otomatis)
/ip firewall address-list add list=ids-blocked address=0.0.0.0 disabled=yes comment="placeholder - managed by ShieldNet IDS"

# Verifikasi urutan rule
/ip firewall filter print
```

Urutan rule yang benar:

```
Urutan  Chain    Action  Keterangan
──────  ──────   ──────  ─────────────────────────────────
0       input    log     ShieldNet IDS logging       ← harus paling atas
1       input    drop    src-list=ids-blocked        ← tepat setelah logging
2+      input    ...     rule-rule lainnya
```

---

### 1.6 Konfigurasi Log untuk Mendeteksi Login Gagal (Opsional)

Untuk mendeteksi brute force SSH/Winbox, aktifkan logging untuk event login:

#### Via Terminal / Command

```
# Aktifkan logging untuk percobaan login gagal
/system logging add action=remote-ids topics=info,account

# Untuk SSH brute force lebih spesifik
/ip ssh set strong-crypto=yes
```

---

### 1.7 Verifikasi Konfigurasi MikroTik

Sebelum mendaftarkan node ke ShieldNet IDS, verifikasi semua konfigurasi sudah benar:

```
# 1. Cek API service aktif
/ip service print where name=api
# Kolom DISABLED harus tidak tercentang

# 2. Cek user IDS ada
/user print where name=ids-user

# 3. Cek logging action ada
/system logging action print where name=remote-ids

# 4. Cek logging rules aktif
/system logging print where action=remote-ids

# 5. Cek firewall rules
/ip firewall filter print
# Pastikan rule log ada di posisi 0 dan rule ids-blocked ada

# 6. Test kirim log manual
/log info "ShieldNet IDS test connection"
# Pesan ini seharusnya muncul di ShieldNet IDS dalam beberapa detik
```

---

## Bagian 2: Pendaftaran Node di ShieldNet IDS

### 2.1 Login ke Web Interface

1. Buka browser, akses `http://IP_SERVER_IDS:8080`
2. Login dengan akun **admin** atau **operator**

   ```
   Akun default: admin / admin123
   URL: http://localhost:8080/login
   ```

---

### 2.2 Daftarkan Node Baru

1. Navigasi ke menu **Node MikroTik** (sidebar kiri)
2. Klik tombol **Tambah Node**
3. Isi form dengan informasi router MikroTik yang baru dikonfigurasi:

   | Field | Contoh Nilai | Keterangan |
   |---|---|---|
   | **Node ID** | `router-03` | Nama unik, gunakan format konsisten |
   | **IP Address** | `192.168.2.1` | IP router MikroTik (bukan IP server IDS) |
   | **API Port** | `8728` | Port API MikroTik (default 8728) |
   | **Username** | `ids-user` | User yang dibuat di Langkah 1.2 |
   | **Password** | `IDS_Password_Kuat` | Password user tersebut |
   | **Lokasi** | `Gedung B - Lantai 3` | Keterangan fisik (opsional, untuk identifikasi) |

4. Klik **Simpan**

---

### 2.3 Verifikasi Koneksi API MikroTik

Setelah node ditambahkan, halaman **Node MikroTik** akan menampilkan daftar node.
Klik tombol **Cek Koneksi** pada node yang baru ditambahkan untuk memverifikasi
bahwa ShieldNet IDS bisa terhubung ke API MikroTik.

**Jika koneksi berhasil:**
- Status berubah menjadi `Aktif` (hijau)
- Tombol Cek Koneksi menampilkan "Terhubung"

**Jika koneksi gagal, periksa:**
- IP address dan port sudah benar
- Username dan password sesuai dengan yang dibuat di Langkah 1.2
- API service di MikroTik sudah aktif (`/ip service print`)
- Tidak ada firewall yang memblokir port 8728 antara server IDS dan router
- Jika `Available From` di-set di MikroTik, pastikan IP server IDS sudah diizinkan

---

### 2.4 Verifikasi Penerimaan Syslog

Setelah node terdaftar, verifikasi bahwa syslog dari MikroTik sudah diterima:

1. Navigasi ke menu **Data Syslog**
2. Filter berdasarkan **Node**: masukkan ID node yang baru ditambahkan
3. Pastikan ada data yang masuk

Jika tidak ada data syslog:

**Di MikroTik:**
```
# Kirim log test manual
/log info "ShieldNet IDS connectivity test from router-03"
```

**Di server IDS:**
```bash
# Cek apakah UDP 514 terbuka dan menerima data
docker logs ids-golang --tail=50 | grep "514\|syslog\|udp"

# Atau cek langsung database
docker exec ids-timescaledb psql -U ids_user -d ids_thesis \
  -c "SELECT node_id, COUNT(*) FROM syslogs GROUP BY node_id ORDER BY count DESC;"
```

---

## Bagian 3: Verifikasi End-to-End

### 3.1 Test Simulasi Serangan (Opsional)

Untuk memastikan deteksi berjalan untuk node baru, lakukan simulasi dari dalam
jaringan (gunakan IP yang tidak terdaftar di whitelist):

```bash
# Dari server IDS: kirim syslog simulasi untuk node baru
docker exec ids-python python3 -c "
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dst = ('golang-collector', 514)

# Simulasi brute force SSH dari IP palsu ke node baru
# Format: gunakan node_id yang sesuai (router-03 di contoh ini)
msgs = [
    '<134>May  1 10:00:{:02d} router-03 firewall: in:ether1 out:bridge, proto TCP (SYN), 203.0.113.99:{}->10.0.0.1:22, len 60'.format(i % 60, 40000 + i)
    for i in range(1, 21)
]
for m in msgs:
    sock.sendto(m.encode(), dst)
    time.sleep(0.1)
sock.close()
print('Test selesai')
"
```

Kemudian periksa:
- **Dashboard:** counter intrusi naik
- **Deteksi Intrusi:** ada entry baru untuk IP `203.0.113.99`
- **Grafana:** data muncul di dashboard Node MikroTik (setelah ~1 menit refresh)

---

### 3.2 Verifikasi Distribusi Pemblokiran

Jika terdeteksi sebagai intrusi dengan action `block`, ShieldNet IDS seharusnya
otomatis menambahkan IP ke address-list `ids-blocked` di **semua** node aktif
termasuk node yang baru ditambahkan.

Verifikasi di MikroTik:

```
# Cek address-list ids-blocked di MikroTik
/ip firewall address-list print where list=ids-blocked
```

Jika IP muncul di sana, distribusi otomatis berhasil.

---

## Referensi Cepat: Semua Command MikroTik

Berikut ringkasan semua command yang dibutuhkan dalam urutan yang benar.
Ganti nilai dalam `< >` dengan nilai yang sesuai.

```
# ============================================================
# BLOK 1: Aktifkan API Service
# ============================================================
/ip service enable api
/ip service set api port=8728 address=<IP_SERVER_IDS>/32

# ============================================================
# BLOK 2: Buat User untuk ShieldNet IDS
# ============================================================
/user group add name=ids-group policy=read,write,api,!local,!telnet,!ssh,!ftp,!reboot,!password,!policy,!test,!winbox,!web,!sniff,!sensitive,!romon
/user add name=ids-user password=<PASSWORD_KUAT> group=ids-group

# ============================================================
# BLOK 3: Konfigurasi Firewall Logging
# ============================================================
/ip firewall filter add chain=input action=log log-prefix="FW:" place-before=0 comment="ShieldNet IDS logging"
/ip firewall filter add chain=forward action=log log-prefix="FW:" place-before=1 comment="ShieldNet IDS forward logging"

# ============================================================
# BLOK 4: Konfigurasi Pengiriman Syslog ke Server IDS
# ============================================================
/system logging action add name=remote-ids target=remote remote=<IP_SERVER_IDS> remote-port=514 syslog-facility=daemon
/system logging add action=remote-ids topics=firewall
/system logging add action=remote-ids topics=system
/system logging add action=remote-ids topics=info,account

# ============================================================
# BLOK 5: Buat Rule Blokir untuk ids-blocked
# ============================================================
/ip firewall filter add chain=input src-address-list=ids-blocked action=drop comment="ShieldNet IDS: block" place-before=1
/ip firewall filter add chain=forward src-address-list=ids-blocked action=drop comment="ShieldNet IDS: block forward" place-before=2

# ============================================================
# BLOK 6: Verifikasi
# ============================================================
/ip service print
/user print
/system logging print
/system logging action print
/ip firewall filter print
```

---

## Troubleshooting

### Koneksi API Gagal

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| `connection refused` | API service tidak aktif | `/ip service enable api` |
| `authentication failed` | Username/password salah | Cek di `/user print` |
| `connection timeout` | Firewall memblokir port 8728 | Tambahkan rule allow port 8728 dari IP server IDS |
| `address not allowed` | IP server tidak di whitelist | `/ip service set api address=IP_SERVER/32` |

### Syslog Tidak Diterima

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| Tidak ada data di halaman Syslog | Logging action salah | Cek IP di `/system logging action print` |
| Data ada tapi node tidak dikenali | Node ID tidak cocok | Pastikan hostname MikroTik sesuai |
| Data terlambat | Network latency | Normal, biasanya < 5 detik |

### Pemblokiran Tidak Terdistribusi

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| `distributed=false` di DB | Node tidak aktif | Aktifkan node di halaman Node MikroTik |
| Address-list kosong di MikroTik | Koneksi API terputus | Cek log Golang: `docker logs ids-golang` |
| IP tidak diblokir padahal detected | Action = "monitor" bukan "block" | Normal — skor belum cukup rendah untuk blokir |

### Melihat Log Sistem untuk Debugging

```bash
# Log Golang Collector (penerimaan syslog + distribusi)
docker logs ids-golang -f --tail=100

# Log Python Analyst (analisis Isolation Forest)
docker logs ids-python -f --tail=100

# Query database langsung
docker exec ids-timescaledb psql -U ids_user -d ids_thesis -c \
  "SELECT node_id, source_ip, event_type, time FROM syslogs ORDER BY time DESC LIMIT 20;"
```
