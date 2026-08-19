# Dokumentasi Arsitektur Sistem Deteksi Intrusi Kolaboratif

## Ringkasan

ShieldNet IDS adalah sistem deteksi intrusi jaringan yang dirancang untuk melindungi
beberapa router MikroTik secara terpusat dan kolaboratif. Sistem menggunakan algoritma
**Isolation Forest** (machine learning unsupervised) untuk mendeteksi anomali trafik
tanpa memerlukan dataset berlabel.

Keunggulan utama: ketika satu node mendeteksi serangan dari IP tertentu, informasi
pemblokiran otomatis didistribusikan ke **semua node** yang terdaftar, memberikan
perlindungan kolaboratif secara real-time.

---

## Komponen Sistem

### 1. Golang Collector (`:8080`)

**Tanggung Jawab:**
- Menerima syslog dari semua router MikroTik via UDP port 514
- Mem-parsing pesan syslog ke format terstruktur
- Menyimpan syslog ke TimescaleDB
- Mempublikasikan event ke Redis Stream untuk analisis Python
- Menerima hasil analisis dari Redis Pub/Sub
- Mendistribusikan access-list ke semua node MikroTik via API
- Menyediakan web interface untuk manajemen sistem

**Teknologi:** Go 1.24, pgx/v5, go-redis/v9, go-routeros/v3, gorilla/sessions

### 2. Python Analyst

**Tanggung Jawab:**
- Mengkonsumsi event syslog dari Redis Stream
- Mengambil data historis dari TimescaleDB untuk konteks analisis
- Mengekstrak fitur-fitur relevan dari data syslog
- Melatih dan menjalankan model Isolation Forest
- Mempublikasikan hasil analisis ke Redis Pub/Sub

**Teknologi:** Python 3.11, scikit-learn, pandas, numpy, psycopg2, redis-py

### 3. TimescaleDB

**Tanggung Jawab:**
- Menyimpan semua data syslog (hypertable time-series)
- Menyimpan hasil analisis intrusi
- Menyimpan konfigurasi node MikroTik dan user
- Menyimpan whitelist dan blacklist
- Menyediakan data untuk Grafana

**Teknologi:** TimescaleDB (PostgreSQL + ekstensi time-series)

### 4. Redis

**Tanggung Jawab:**
- **Stream** (`ids:syslog:stream`): Notifikasi syslog baru dari Golang ke Python
- **Pub/Sub** (`ids:analysis:result`): Hasil analisis dari Python ke Golang

**Teknologi:** Redis 7, Consumer Group untuk stream

### 5. Grafana (`:3000`)

**Tanggung Jawab:**
- Visualisasi statistik real-time dari TimescaleDB
- 3 dashboard: ringkasan sistem, detail intrusi, statistik per node
- Auto-provisioning sehingga siap pakai tanpa konfigurasi manual

**Teknologi:** Grafana, PostgreSQL datasource dengan dukungan TimescaleDB

---

## Alur Data Detail

### Alur 1: Penerimaan dan Penyimpanan Syslog

```
MikroTik ──UDP 514──► syslog/receiver.go
                             │
                      syslog/parser.go (parsing regex)
                             │
                      Cek whitelist (database)
                       ├── YA → simpan saja, selesai
                       └── TIDAK ↓
                      Cek blacklist (database)
                       ├── YA → simpan + blokir langsung
                       └── TIDAK ↓
                      database/repository.go (INSERT syslogs)
                             │
                      redis/publisher.go (XADD ke stream)
```

### Alur 2: Analisis Machine Learning

```
Redis Stream (ids:syslog:stream)
        │
modules/consumer.py (XREADGROUP)
        │
modules/database.py (SELECT historis 10 menit)
        │
modules/preprocessor.py (ekstrak 9 fitur)
        │
modules/model.py (Isolation Forest predict)
        │ is_intrusion + anomaly_score + confidence + action
modules/publisher.py (PUBLISH ke ids:analysis:result)
```

### Alur 3: Distribusi Pemblokiran

```
Redis Pub/Sub (ids:analysis:result)
        │
redis/subscriber.go (handler di Golang)
        │
database/repository.go (INSERT intrusion_results)
        │ jika is_intrusion=true AND action=block
mikrotik/distributor.go
        │ goroutine paralel untuk setiap node
        ├── node 1: /ip/firewall/address-list/add list=ids-blocked
        ├── node 2: /ip/firewall/address-list/add list=ids-blocked
        └── node N: /ip/firewall/address-list/add list=ids-blocked
        │
database.MarkIntrusionDistributed (UPDATE distributed=true)
```

### Alur 4: Manajemen Whitelist dan Blacklist

Whitelist dan blacklist adalah mekanisme **override manual** yang bekerja di luar
alur ML — operator dapat menambah atau menghapus aturan, dan sistem secara otomatis
menyinkronkan perubahan tersebut ke semua node MikroTik yang aktif.

```
Operator klik "Tambah" di web interface
        │
handlers/access_list.go (AddAccessList)
        │
        ├── list_type = "blacklist"
        │         │
        │   database.InsertAccessList()          ← simpan ke DB
        │         │
        │   go mikrotik.DistributeBlock(ip)      ← blokir di SEMUA node MikroTik
        │         │ goroutine paralel
        │         ├── node 1: /ip/firewall/address-list/add list=ids-blocked
        │         ├── node 2: /ip/firewall/address-list/add list=ids-blocked
        │         └── node N: /ip/firewall/address-list/add list=ids-blocked
        │
        └── list_type = "whitelist"
                  │
            database.InsertAccessList()          ← simpan ke DB
                  │
            go mikrotik.RemoveBlock(ip)          ← HAPUS dari ids-blocked semua node
                  │ (jika IP sebelumnya pernah diblokir)
                  ├── node 1: /ip/firewall/address-list/remove
                  ├── node 2: /ip/firewall/address-list/remove
                  └── node N: /ip/firewall/address-list/remove

Operator klik "Hapus" di web interface
        │
handlers/access_list.go (DeleteAccessList)
        │
database.GetAccessListByID(id)               ← cek tipe entry sebelum dihapus
        │
database.DeleteAccessList(id)               ← hapus dari DB
        │
        ├── entry.ListType = "blacklist"
        │         │
        │   go mikrotik.RemoveBlock(ip)      ← hapus dari ids-blocked semua node
        │
        └── entry.ListType = "whitelist"
                  │
            (tidak ada aksi ke MikroTik)
```

**Tabel perilaku lengkap Whitelist / Blacklist:**

| Aksi Operator | Efek di Database | Efek di MikroTik |
|---|---|---|
| Tambah IP ke **blacklist** | INSERT ke `access_list` | IP ditambahkan ke `ids-blocked` di **semua node** |
| Tambah IP ke **whitelist** | INSERT ke `access_list` | IP dihapus dari `ids-blocked` di **semua node** (jika ada) |
| Hapus entry **blacklist** | DELETE dari `access_list` | IP dihapus dari `ids-blocked` di **semua node** |
| Hapus entry **whitelist** | DELETE dari `access_list` | Tidak ada perubahan di MikroTik |

**Perilaku whitelist saat syslog masuk** (alur penerimaan):

IP yang ada di whitelist aktif dilewati sepenuhnya — tidak dianalisis ML dan
tidak diblokir meskipun polanya mencurigakan. Pengecekan ini dilakukan di
`golang-collector/cmd/main.go` sebelum event dipublikasikan ke Redis Stream.

**File kode yang terlibat:**

| File | Fungsi | Tanggung Jawab |
|---|---|---|
| `golang-collector/internal/web/handlers/access_list.go` | `AddAccessList()` | Simpan ke DB + trigger distribusi ke MikroTik |
| `golang-collector/internal/web/handlers/access_list.go` | `DeleteAccessList()` | Lookup entry → hapus DB → trigger remove dari MikroTik |
| `golang-collector/internal/database/repository.go` | `GetAccessListByID()` | Ambil data entry sebelum dihapus (diperlukan untuk tahu IP-nya) |
| `golang-collector/internal/mikrotik/distributor.go` | `DistributeBlock()` | Tambah IP ke `ids-blocked` di semua node secara paralel |
| `golang-collector/internal/mikrotik/distributor.go` | `RemoveBlock()` | Hapus IP dari `ids-blocked` di semua node secara paralel |

---

## Mekanisme Deteksi: Isolation Forest

Bagian ini menjelaskan secara rinci bagaimana Python Analyst menentukan apakah
sebuah koneksi merupakan serangan atau bukan. Penjelasan disertai referensi kode
beserta lokasi file agar dapat dipelajari langsung.

### Gambaran Besar: Apa itu Isolation Forest?

Isolation Forest adalah algoritma machine learning **unsupervised** — artinya model
belajar sendiri dari data tanpa memerlukan label "ini serangan" atau "ini normal".
Algoritma ini bekerja berdasarkan satu premis sederhana:

> **Anomali lebih mudah diisolasi daripada data normal.**

Data normal umumnya berkelompok — banyak titik data yang berdekatan sehingga butuh
banyak pembelahan untuk memisahkan satu titik. Data anomali cenderung terpencil —
hanya butuh sedikit pembelahan untuk mengisolasinya.

Sistem membangun **100 pohon keputusan acak** (disebut *isolation trees*). Setiap
pohon mencoba mengisolasi sebuah titik data dengan memilih fitur dan nilai pembelahan
secara acak berulang kali. Panjang jalur rata-rata melewati 100 pohon tersebut
menjadi **skor anomali** — jalur pendek berarti anomali, jalur panjang berarti normal.

```
                    [unique_dest_ports > 15?]          ← pembelahan acak
                    /                      \
       [fail_ratio > 0.8?]          [requests_per_min > 100?]
       /            \                /                \
  [terisolasi]  [lanjut...]    [lanjut...]       [lanjut...]
  path length=2                 path length=3+
  (anomali)                     (normal)
```

Referensi kode: `python-analyst/modules/model.py` — kelas `IDSModel`

### Di Mana Tepatnya Isolation Forest Bekerja

Isolation Forest adalah **satu-satunya algoritma machine learning** dalam
sistem ini (tidak ada estimator lain di seluruh codebase). Algoritma bekerja
di dua titik eksekusi, keduanya di `python-analyst/modules/model.py`:

| Titik | Lokasi | Apa yang Terjadi |
|---|---|---|
| **Pelatihan** | `model.py:64-71` (metode `train()`) | `IsolationForest(...).fit(X_scaled)` — membangun 100 pohon isolasi dari agregat per-IP 24 jam terakhir |
| **Inferensi** | `model.py:98` (metode `predict()`) | `decision_function()` — satu-satunya sumber skor anomali di seluruh sistem |
| **Vonis intrusi** | `model.py:101` | `is_intrusion = anomaly_score < ANOMALY_THRESHOLD` — murni turunan skor IF |

Komponen lain di sekitarnya **bukan ML**: `StandardScaler` = preprocessing;
`classifyEvent()` (Golang) dan `extract_features()` = feature engineering
berbasis aturan di hulu; confidence + `determine_action()` = decision engine
di hilir yang menerjemahkan skor IF menjadi aksi; whitelist/blacklist =
override manual di luar jalur ML.

---

### Langkah 1 — Entry Point: Menerima Event dari Redis

**File:** `python-analyst/main.py` — fungsi `process_syslog_event(fields)`

Setiap kali Golang menerima syslog baru dan menyimpannya ke database, Golang
mempublikasikan notifikasi ke Redis Stream. Python membaca notifikasi ini dan
memulai proses analisis.

```python
# python-analyst/main.py, fungsi process_syslog_event()
def process_syslog_event(fields: dict):
    source_ip = fields.get('source_ip', '')  # IP yang akan dianalisis
    records = fetch_syslogs_for_analysis(source_ip, config.ANALYSIS_WINDOW_MINUTES)
    features = extract_features(records)
    is_intrusion, anomaly_score, confidence = ids_model.predict(features)
    action = ids_model.determine_action(is_intrusion, anomaly_score, confidence)
    publisher.publish_result(source_ip, is_intrusion, anomaly_score, confidence, action)
```

Pesan yang diterima dari Redis Stream berisi:

| Field | Contoh | Keterangan |
|---|---|---|
| `source_ip` | `10.10.10.99` | IP yang akan dianalisis |
| `event_type` | `login_fail` | Tipe event yang memicu notifikasi |
| `node_id` | `router-01` | Node asal syslog |
| `timestamp` | `1746094800` | Unix timestamp kejadian |

Redis Stream dikelola oleh **Consumer Group** (`ids-python-analyst`) sehingga setiap
pesan hanya diproses tepat satu kali meskipun ada beberapa instance Python berjalan.

**File:** `python-analyst/modules/consumer.py` — kelas `SyslogConsumer`, metode `consume()`

```python
# Baca maksimal 10 pesan sekaligus, block 2 detik jika stream kosong
messages = self.client.xreadgroup(
    groupname=config.CONSUMER_GROUP,   # "ids-python-analyst"
    consumername=config.CONSUMER_NAME, # "analyst-1"
    streams={config.SYSLOG_STREAM_KEY: '>'},  # '>' = hanya pesan baru
    count=10,
    block=2000
)
# Setelah berhasil diproses, kirim ACK agar tidak diproses ulang
self.client.xack(config.SYSLOG_STREAM_KEY, config.CONSUMER_GROUP, message_id)
```

---

### Langkah 2 — Pengambilan Data Historis dari Database

**File:** `python-analyst/modules/database.py` — fungsi `fetch_syslogs_for_analysis()`

Satu syslog tunggal tidak cukup untuk mendeteksi pola serangan. Sistem mengambil
**semua syslog dari IP yang sama dalam 10 menit terakhir** sebagai konteks analisis.

```python
# python-analyst/modules/database.py
query = """
    SELECT time, source_ip, source_port, dest_port, event_type, protocol, node_id
    FROM syslogs
    WHERE source_ip = %s
      AND time > NOW() - INTERVAL '%s minutes'  -- 10 menit terakhir
    ORDER BY time DESC
    LIMIT 1000
"""
```

Jendela waktu 10 menit (`ANALYSIS_WINDOW_MINUTES=10`) dikonfigurasi di `python-analyst/config.py`
dan dapat diubah via environment variable `ANALYSIS_WINDOW_MINUTES` di file `.env`.

Mengapa 10 menit? Ini adalah kompromi antara:
- Terlalu pendek (misal 1 menit): tidak cukup data untuk mendeteksi serangan lambat
- Terlalu panjang (misal 1 jam): terlalu banyak data, analisis lambat, terlalu banyak false positive

---

### Langkah 3 — Ekstraksi Fitur

**File:** `python-analyst/modules/preprocessor.py` — fungsi `extract_features()`

Dari ratusan baris syslog mentah, sistem merangkumnya menjadi **9 angka** (vektor fitur)
yang merepresentasikan perilaku satu IP. Inilah yang sesungguhnya dianalisis oleh model.

```python
# python-analyst/modules/preprocessor.py
def extract_features(syslog_records: List[Dict]) -> Optional[np.ndarray]:
    df = pd.DataFrame(syslog_records)

    total_requests      = len(df)
    unique_dest_ports   = df['dest_port'].nunique()
    unique_src_ports    = df['source_port'].nunique()
    login_fails         = (df['event_type'] == 'login_fail').sum()
    port_scans          = (df['event_type'] == 'port_scan').sum()
    brute_forces        = (df['event_type'] == 'brute_force').sum()
    requests_per_minute = _calculate_request_rate(df)
    port_diversity_ratio = unique_dest_ports / total_requests   # 0.0 – 1.0
    fail_ratio           = login_fails / total_requests          # 0.0 – 1.0

    return np.array([total_requests, unique_dest_ports, unique_src_ports,
                     login_fails, port_scans, brute_forces,
                     requests_per_minute, port_diversity_ratio, fail_ratio])
```

Tabel fitur dan relevansinya terhadap jenis serangan:

| # | Fitur | Cara Hitung | Nilai Normal | Nilai Mencurigakan | Serangan Terkait |
|---|---|---|---|---|---|
| 1 | `total_requests` | `COUNT(*)` semua record | 1–20 | > 100 | DDoS, flood |
| 2 | `unique_dest_ports` | `COUNT(DISTINCT dest_port)` | 1–3 | > 20 | Port scanning |
| 3 | `unique_src_ports` | `COUNT(DISTINCT source_port)` | 1–10 | > 50 | — |
| 4 | `login_fails` | Count event `login_fail` | 0–2 | > 10 | Brute force |
| 5 | `port_scans` | Count event `port_scan` | 0 | > 0 | Port scanning |
| 6 | `brute_forces` | Count event `brute_force` | 0 | > 0 | Brute force |
| 7 | `requests_per_minute` | `total / durasi_menit` | 1–10 | > 50 | Flood, DDoS |
| 8 | `port_diversity_ratio` | `unique_ports / total` | < 0.1 | ≈ 1.0 | Port scanning |
| 9 | `fail_ratio` | `login_fails / total` | 0.0 | ≈ 1.0 | Brute force SSH |

Contoh vektor fitur dari tiga skenario berbeda:

```
IP normal (browsing web):
  [5, 1, 3, 0, 0, 0, 2.1, 0.20, 0.00]
   ^  ^  ^  ^  ^  ^   ^    ^     ^
   5  1  3  0  0  0  2/min 20%  0%

IP brute force SSH (10.10.10.99):
  [20, 1, 18, 20, 0, 0, 12.0, 0.05, 1.00]
   20 port  18   20            12/min 5% 100%gagal

IP port scanning (172.16.0.50):
  [30, 30, 1, 0, 0, 0, 18.0, 1.00, 0.00]
   30  30            0  18/min 100% 0%
```

Klasifikasi tipe event dilakukan di sisi Golang sebelum disimpan ke database:

**File:** `golang-collector/internal/syslog/parser.go` — fungsi `classifyEvent()`

```go
// golang-collector/internal/syslog/parser.go
func classifyEvent(message string) string {
    lower := strings.ToLower(message)
    switch {
    case strings.Contains(lower, "login failure"):  return "login_fail"
    case strings.Contains(lower, "port scan"):      return "port_scan"
    case strings.Contains(lower, "brute"):          return "brute_force"
    case strings.Contains(lower, "syn flood"):      return "syn_flood"
    case strings.Contains(lower, "firewall"):       return "firewall_block"
    default:                                         return "general"
    }
}
```

---

### Langkah 4 — Normalisasi (StandardScaler)

**File:** `python-analyst/modules/model.py` — metode `train()` dan `predict()`

Sebelum data masuk ke model, semua fitur dinormalisasi menggunakan `StandardScaler`.
Normalisasi penting karena fitur memiliki skala yang sangat berbeda:
- `total_requests` bisa mencapai ratusan
- `fail_ratio` hanya berkisar 0.0–1.0

Tanpa normalisasi, `total_requests` akan mendominasi keputusan model.

```python
# python-analyst/modules/model.py, metode train()
self.scaler = StandardScaler()
X_scaled = self.scaler.fit_transform(X)
# StandardScaler: (nilai - rata_rata) / standar_deviasi
# Hasilnya: semua fitur memiliki rata-rata 0 dan standar deviasi 1
```

**Penting:** Saat prediksi, scaler yang sama (dengan parameter yang sudah dihitung
saat training) digunakan kembali sehingga skala konsisten:

```python
# python-analyst/modules/model.py, metode predict()
features_scaled = self.scaler.transform(features.reshape(1, -1))
# Gunakan scaler yang SAMA dari training, bukan fit ulang
```

Scaler dan model disimpan bersama ke disk menggunakan `joblib`:

```python
# python-analyst/modules/model.py, metode save() dan load()
joblib.dump(self.model,  "/app/models/isolation_forest.pkl")
joblib.dump(self.scaler, "/app/models/scaler.pkl")
```

Volume Docker `model_data` memastikan kedua file ini tidak hilang saat container restart.

---

### Langkah 5 — Pelatihan Model Isolation Forest

**File:** `python-analyst/modules/model.py` — metode `train()`

Model dilatih menggunakan data agregat semua IP dari 24 jam terakhir:

```python
# python-analyst/modules/model.py
self.model = IsolationForest(
    n_estimators  = 100,   # Jumlah pohon isolasi (semakin banyak, semakin stabil)
    contamination = 0.1,   # Estimasi proporsi anomali dalam data (10%)
    max_samples   = 256,   # Jumlah sampel per pohon (256 = default optimal)
    random_state  = 42,    # Seed acak untuk reproduksibilitas
    n_jobs        = -1     # Gunakan semua CPU core
)
self.model.fit(X_scaled)
```

**Penjelasan parameter:**

`n_estimators=100`: Sistem membangun 100 pohon keputusan independen. Setiap pohon
memilih fitur dan nilai pembelahan secara acak. Skor akhir adalah rata-rata dari
semua pohon sehingga lebih stabil.

`contamination=0.1`: Parameter ini memberi tahu model bahwa diperkirakan 10% data
dalam training set adalah anomali. Ini mempengaruhi penentuan threshold internal
model (bukan threshold yang kita gunakan untuk klasifikasi manual di kode).

`max_samples=256`: Setiap pohon hanya menggunakan 256 sampel acak dari total data.
Ini disengaja — subsampling justru membantu karena anomali lebih mudah terlihat
di dataset yang lebih kecil.

**Data pelatihan** diambil oleh fungsi `fetch_training_data()` di
`python-analyst/modules/database.py`:

```python
# python-analyst/modules/database.py
query = """
    SELECT
        source_ip,
        COUNT(*) as total_requests,
        COUNT(DISTINCT dest_port) as unique_dest_ports,
        COUNT(DISTINCT source_port) as unique_src_ports,
        COUNT(CASE WHEN event_type = 'login_fail' THEN 1 END) as login_fails,
        COUNT(CASE WHEN event_type = 'port_scan' THEN 1 END) as port_scans,
        COUNT(CASE WHEN event_type = 'brute_force' THEN 1 END) as brute_forces,
        EXTRACT(EPOCH FROM (MAX(time) - MIN(time))) as duration_seconds
    FROM syslogs
    WHERE time > NOW() - INTERVAL '24 hours'
    GROUP BY source_ip
    HAVING COUNT(*) >= 2  -- Minimal 2 syslog agar bisa dihitung polanya
"""
```

Setiap baris hasil query mewakili satu IP — inilah yang diubah menjadi vektor fitur
untuk melatih model.

---

### Langkah 6 — Prediksi dan Penentuan Skor

**File:** `python-analyst/modules/model.py` — metode `predict()`

```python
# python-analyst/modules/model.py
def predict(self, features: np.ndarray) -> Tuple[bool, float, float]:
    features_scaled = self.scaler.transform(features.reshape(1, -1))

    # decision_function() mengembalikan skor kontinu:
    # positif = normal, negatif = anomali
    anomaly_score = self.model.decision_function(features_scaled)[0]

    # Bandingkan dengan threshold (default -0.1)
    is_intrusion = anomaly_score < config.ANOMALY_THRESHOLD  # ANOMALY_THRESHOLD = -0.1

    # Keyakinan = kepastian skor × kecukupan data (dua faktor independen)
    distance_from_threshold = abs(anomaly_score - config.ANOMALY_THRESHOLD)
    score_certainty = min(0.5 + distance_from_threshold * 2, 1.0)

    total_requests = float(features[0])
    data_sufficiency = min(total_requests / config.CONFIDENCE_FULL_SAMPLES, 1.0)

    confidence = score_certainty * data_sufficiency

    return is_intrusion, float(anomaly_score), float(confidence)
```

**Interpretasi skor anomali (`decision_function`):**

```
Skor     Arti                        Contoh Situasi
──────   ─────────────────────────   ──────────────────────────────────
> +0.2   Normal jelas                Browsing biasa, 1-5 request
  0.0    Batas normal/anomali        —
 -0.1    THRESHOLD (garis klasifikasi)
 -0.2    Mencurigakan                Beberapa percobaan login
 -0.4    Anomali kuat                Brute force aktif
 -0.8    Sangat anomali              Port scan agresif / flood
```

**Perhitungan keyakinan (confidence) — dua faktor independen:**

1. **Kepastian skor** (`score_certainty`): jarak skor dari threshold klasifikasi.
   Skor di zona abu-abu (dekat threshold) = kepastian rendah.
2. **Kecukupan data** (`data_sufficiency`): jumlah record yang mendasari analisis
   (fitur `total_requests`), dibagi `CONFIDENCE_FULL_SAMPLES` (default 10).
   Skor ekstrem yang hanya didukung 2–3 record belum layak dipercaya penuh.

```
skor = -0.5, 20 record:
  score_certainty  = min(0.5 + |-0.5-(-0.1)| × 2, 1.0) = 1.0
  data_sufficiency = min(20/10, 1.0) = 1.0
  confidence       = 1.0 × 1.0 = 1.0 (100%)

skor = -0.5, 3 record (skor ekstrem tapi bukti sedikit):
  score_certainty  = 1.0
  data_sufficiency = min(3/10, 1.0) = 0.3
  confidence       = 1.0 × 0.3 = 0.3 (30%) — tidak cukup untuk blokir

skor = -0.15, 20 record (zona abu-abu):
  score_certainty  = min(0.5 + 0.05 × 2, 1.0) = 0.6
  data_sufficiency = 1.0
  confidence       = 0.6 (60%)
```

Faktor kecukupan data membuat syarat `confidence >= 0.75` pada penentuan aksi
benar-benar independen dari syarat skor: tanpa faktor ini, setiap skor di bawah
-0.3 otomatis menghasilkan confidence ≥ 0.9 sehingga syarat keyakinan redundan.

---

### Langkah 7 — Penentuan Aksi

**File:** `python-analyst/modules/model.py` — metode `determine_action()`

```python
# python-analyst/modules/model.py
def determine_action(self, is_intrusion: bool, anomaly_score: float, confidence: float) -> str:
    if not is_intrusion:
        return "allow"

    # Blokir hanya jika DUA syarat independen terpenuhi
    # (default: BLOCK_CONFIDENCE_THRESHOLD=0.75, BLOCK_SCORE_THRESHOLD=-0.3)
    if confidence >= config.BLOCK_CONFIDENCE_THRESHOLD and anomaly_score < config.BLOCK_SCORE_THRESHOLD:
        return "block"

    # Jika terdeteksi intrusi tapi tidak cukup yakin untuk blokir, pantau dulu
    return "monitor"
```

Tabel keputusan aksi:

| Kondisi | Aksi | Efek di Sistem |
|---|---|---|
| `is_intrusion = False` | `allow` | Tidak ada tindakan |
| `is_intrusion = True` AND (`confidence < 75%` OR `score >= -0.3`) | `monitor` | Disimpan ke DB, tidak diblokir |
| `is_intrusion = True` AND `confidence >= 75%` AND `score < -0.3` | `block` | Diblokir di **semua** node MikroTik |

Alasan dua syarat untuk `block` (bukan hanya `is_intrusion = True`):
- **Mengurangi false positive**: sekali IP diblokir di semua node, butuh intervensi manual untuk membuka kembali
- **Safety net skor**: skor di antara -0.1 dan -0.3 masih bisa jadi traffic anomali yang tidak berbahaya
- **Safety net bukti**: berkat faktor kecukupan data pada confidence, skor ekstrem
  yang hanya didukung sedikit record (< 10) berstatus `monitor`, bukan langsung diblokir

---

### Langkah 8 — Publikasi Hasil ke Redis

**File:** `python-analyst/modules/publisher.py` — metode `publish_result()`

Hasil analisis dikirim ke Golang via Redis Pub/Sub dalam format JSON:

```python
# python-analyst/modules/publisher.py
result = {
    "source_ip":     "10.10.10.99",
    "is_intrusion":  True,
    "anomaly_score": -0.52,
    "confidence":    0.84,
    "action":        "block"
}
self.client.publish("ids:analysis:result", json.dumps(result))
```

Golang menerima pesan ini di:

**File:** `golang-collector/internal/redis/subscriber.go`

Kemudian meneruskannya ke handler:

**File:** `golang-collector/cmd/main.go` — fungsi `handleAnalysisResult()`

```go
// golang-collector/cmd/main.go
func handleAnalysisResult(result redis.AnalysisResult) {
    database.SaveIntrusionResult(result)       // Simpan ke DB
    if result.IsIntrusion && result.Action == "block" {
        mikrotik.DistributeBlock(result.SourceIP)  // Blokir di semua node
    }
}
```

Distribusi pemblokiran dilakukan secara paralel:

**File:** `golang-collector/internal/mikrotik/distributor.go`

```go
// golang-collector/internal/mikrotik/distributor.go
for _, node := range activeNodes {
    wg.Add(1)
    go func(n database.MikroTikNode) {
        defer wg.Done()
        client := mikrotik.NewClient(n.IPAddress, n.Username, n.Password)
        client.RunCommand("/ip/firewall/address-list/add",
            "=list=ids-blocked",
            "=address=" + sourceIP,
            "=timeout=1d",  // Blokir selama 1 hari
            "=comment=IDS: blocked by ShieldNet"
        )
    }(node)
}
wg.Wait()
```

---

### Langkah 9 — Retrain Otomatis

**File:** `python-analyst/main.py` — fungsi `check_and_retrain()`
**File:** `python-analyst/modules/model.py` — metode `retrain_if_needed()`

Model dilatih ulang secara otomatis setiap kali ada 100 syslog baru masuk
(dikonfigurasi via `MODEL_RETRAIN_INTERVAL`). Ini membuat model adaptif terhadap
perubahan pola trafik.

```python
# python-analyst/main.py
def check_and_retrain():
    new_syslog_count = count_syslogs_since(last_train_time)
    if ids_model.retrain_if_needed(new_syslog_count):
        last_train_time = datetime.now()

# python-analyst/modules/model.py
def retrain_if_needed(self, syslog_count_since_last_train: int) -> bool:
    if syslog_count_since_last_train < config.MODEL_RETRAIN_INTERVAL:
        return False  # Belum waktunya
    training_data = database.fetch_training_data(hours=24)
    if self.train(training_data):
        self.save()   # Simpan ke /app/models/isolation_forest.pkl
        return True
```

Siklus lengkap retrain:

```
Syslog baru masuk setiap saat
        ↓
counter naik (count_syslogs_since last_train_time)
        ↓ setiap 100 syslog
fetch_training_data(hours=24)       ← ambil semua IP dari 24 jam terakhir
        ↓
extract_features_from_aggregated()  ← hitung 9 fitur per IP
        ↓
StandardScaler.fit_transform()      ← normalisasi ulang dengan rata-rata baru
        ↓
IsolationForest.fit()               ← latih 100 pohon baru
        ↓
joblib.dump(model + scaler)         ← simpan ke disk (Docker volume model_data)
```

---

### Ringkasan Alur Keseluruhan dengan Contoh Nyata

Skenario: IP `10.10.10.99` sedang melakukan brute force SSH ke `router-01`.

```
1. MikroTik router-01 mencatat 20 koneksi TCP port 22 dari 10.10.10.99 dalam 2 menit
   → Mengirim 20 syslog via UDP ke port 514

2. Golang (syslog/receiver.go + syslog/parser.go):
   → Parse: source_ip=10.10.10.99, dest_port=22, protocol=TCP
   → classifyEvent(): "login_fail" (karena log firewall MikroTik berisi "failure")
   → Simpan ke tabel syslogs (20 row baru)
   → XADD ke ids:syslog:stream: {source_ip: "10.10.10.99", event_type: "login_fail"}

3. Python consumer.py:
   → XREADGROUP membaca event dari stream
   → Panggil process_syslog_event({source_ip: "10.10.10.99"})

4. Python database.py (fetch_syslogs_for_analysis):
   → SELECT * FROM syslogs WHERE source_ip='10.10.10.99'
     AND time > NOW() - INTERVAL '10 minutes'
   → Dapat 20 baris

5. Python preprocessor.py (extract_features):
   → total_requests      = 20
   → unique_dest_ports   = 1  (hanya port 22)
   → login_fails         = 20 (semua gagal)
   → requests_per_minute = 10.0
   → fail_ratio          = 1.0  ← sangat mencurigakan
   → port_diversity_ratio= 0.05 ← rendah (hanya 1 port)
   Vektor: [20, 1, 18, 20, 0, 0, 10.0, 0.05, 1.0]

6. Python model.py (predict):
   → Normalisasi vektor menggunakan scaler tersimpan
   → Isolation Forest: 20 request semua ke port 22 semua gagal
     → pohon-pohon mengisolasinya dengan sangat cepat (jalur pendek)
   → anomaly_score = -0.52
   → is_intrusion = True  (-0.52 < -0.10 threshold)
   → score_certainty  = min(0.5 + |(-0.52)-(-0.1)| × 2, 1.0) = 1.0
   → data_sufficiency = min(20/10, 1.0) = 1.0
   → confidence = 1.0 × 1.0 = 1.0

7. Python model.py (determine_action):
   → is_intrusion=True, confidence=1.0 >= 0.75, score=-0.52 < -0.3
   → action = "block"

8. Python publisher.py:
   → PUBLISH ids:analysis:result: {"source_ip":"10.10.10.99","is_intrusion":true,
     "anomaly_score":-0.52,"confidence":1.0,"action":"block"}

9. Golang redis/subscriber.go → cmd/main.go (handleAnalysisResult):
   → INSERT ke intrusion_results
   → Panggil mikrotik.DistributeBlock("10.10.10.99")

10. Golang mikrotik/distributor.go:
    → Goroutine paralel ke semua node aktif
    → router-01: /ip/firewall/address-list/add list=ids-blocked address=10.10.10.99
    → router-02: /ip/firewall/address-list/add list=ids-blocked address=10.10.10.99
    → UPDATE intrusion_results SET distributed=true WHERE source_ip='10.10.10.99'
```

---

## Model Isolation Forest

### Fitur yang Digunakan (9 fitur)

| Fitur | Keterangan | Relevansi |
|---|---|---|
| `total_requests` | Total request dalam jendela waktu | Volume traffic tinggi = mencurigakan |
| `unique_dest_ports` | Jumlah port tujuan berbeda | Tinggi = indikasi port scan |
| `unique_src_ports` | Jumlah port asal berbeda | - |
| `login_fails` | Jumlah kegagalan login | Tinggi = indikasi brute force |
| `port_scans` | Count event tipe port_scan | - |
| `brute_forces` | Count event tipe brute_force | - |
| `requests_per_minute` | Frekuensi request/menit | Tinggi = indikasi flood/DDoS |
| `port_diversity_ratio` | Rasio port unik / total request | Mendekati 1 = port scan |
| `fail_ratio` | Rasio kegagalan / total request | Tinggi = brute force |

### Parameter Model

| Parameter | Nilai Default | Env Variable | Keterangan |
|---|---|---|---|
| `n_estimators` | 100 | `IF_N_ESTIMATORS` | Jumlah pohon isolasi |
| `contamination` | 0.1 | `IF_CONTAMINATION` | Estimasi proporsi anomali (10%) |
| `max_samples` | 256 | `IF_MAX_SAMPLES` | Sampel per pohon |
| `random_state` | 42 | — | Untuk reproduksibilitas |
| `ANOMALY_THRESHOLD` | -0.1 | `ANOMALY_THRESHOLD` | Batas skor untuk klasifikasi intrusi |
| `BLOCK_SCORE_THRESHOLD` | -0.3 | `BLOCK_SCORE_THRESHOLD` | Batas skor untuk aksi blokir otomatis |
| `BLOCK_CONFIDENCE_THRESHOLD` | 0.75 | `BLOCK_CONFIDENCE_THRESHOLD` | Batas keyakinan untuk aksi blokir otomatis |
| `CONFIDENCE_FULL_SAMPLES` | 10 | `CONFIDENCE_FULL_SAMPLES` | Jumlah record agar faktor kecukupan data penuh |
| `ANALYSIS_WINDOW_MINUTES` | 10 | `ANALYSIS_WINDOW_MINUTES` | Jendela historis per analisis |
| `MODEL_RETRAIN_INTERVAL` | 100 | `MODEL_RETRAIN_INTERVAL` | Jumlah syslog baru sebelum retrain |

### Interpretasi Skor

- **Skor > 0**: Traffic normal
- **Skor antara -0.1 dan 0**: Mencurigakan, perlu monitoring
- **Skor < -0.1**: Anomali, terdeteksi sebagai intrusi
- **Skor < -0.3 dengan keyakinan ≥ 75%**: Langsung diblokir

### Siklus Pelatihan

- Model di-retrain setiap **100 syslog baru** masuk (dapat dikonfigurasi)
- Data pelatihan: semua IP dengan minimal 2 request dalam **24 jam terakhir**
- Model disimpan ke disk menggunakan `joblib` agar tidak perlu retrain saat restart

---

## Skema Database

### Hypertable TimescaleDB

```sql
-- Tabel utama syslog (partisi otomatis per waktu)
syslogs (time TIMESTAMPTZ, node_id, node_ip, source_ip,
         source_port, dest_port, event_type, protocol, raw_message)

-- Hasil analisis machine learning
intrusion_results (time TIMESTAMPTZ, source_ip, anomaly_score,
                   is_intrusion, confidence, action_taken,
                   distributed, distributed_to)
```

### Tabel Konfigurasi

```sql
mikrotik_nodes (id, node_id, ip_address, api_port,
                username, password, location, is_active)

users (id, username, password, role, full_name, is_active, last_login)

access_list (id, ip_address, list_type, reason,
             added_by, is_active, expires_at)
```

---

## Komunikasi Redis

### Stream: Golang → Python

```
Key    : ids:syslog:stream
Group  : ids-python-analyst
Fields : source_ip, event_type, node_id, timestamp
```

Python menggunakan `XREADGROUP` dengan Consumer Group agar pesan tidak
diproses dua kali jika ada beberapa instance Python berjalan.

### Pub/Sub: Python → Golang

```
Channel : ids:analysis:result
Payload : {"source_ip":"x.x.x.x","is_intrusion":true,
           "anomaly_score":-0.85,"confidence":0.92,"action":"block"}
```

---

## Sistem Peran (RBAC)

| Peran | Dashboard | Syslog | Intrusi | Node | Access List | User |
|---|---|---|---|---|---|---|
| **Admin** | ✓ | ✓ | ✓ + override | ✓ | ✓ | ✓ |
| **Operator** | ✓ | ✓ | ✓ + override | ✓ | ✓ | ✗ |
| **Viewer** | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## Pertimbangan Keamanan

1. **Password**: Di-hash menggunakan bcrypt (cost factor 10)
2. **Session**: Cookie terenkripsi dengan secret key via gorilla/sessions
3. **Akses API MikroTik**: Credential disimpan di database, tidak di environment
4. **Pemblokiran otomatis**: Timeout 24 jam untuk mencegah pemblokiran permanen yang salah
5. **Whitelist sebagai override**: Selalu diperiksa sebelum analisis ML

---

## Keterbatasan Sistem

1. Tidak mendukung IPv6 secara penuh (parser fokus pada IPv4)
2. Model Isolation Forest bersifat unsupervised — tidak ada ground truth label
3. Distribusi ke MikroTik memerlukan koneksi API yang stabil
4. Waktu respons deteksi bergantung pada kecepatan analisis Python (~1-3 detik)
5. Belum ada mekanisme alert via email/Telegram (dapat ditambahkan sebagai pengembangan)
