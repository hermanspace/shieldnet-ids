-- =============================================================================
-- Schema inisialisasi database TimescaleDB untuk Sistem Deteksi Intrusi
-- File ini dieksekusi otomatis saat container TimescaleDB pertama kali berjalan
-- =============================================================================

-- Aktifkan ekstensi TimescaleDB untuk dukungan data time-series
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- =============================================================================
-- Tabel syslogs: Menyimpan semua data syslog yang diterima dari router MikroTik
-- =============================================================================
CREATE TABLE IF NOT EXISTS syslogs (
    time         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    node_id      TEXT NOT NULL,         -- ID/nama router pengirim syslog
    node_ip      TEXT NOT NULL,         -- IP address router pengirim
    source_ip    TEXT NOT NULL,         -- IP yang melakukan akses mencurigakan
    source_port  INTEGER,               -- Port asal koneksi
    dest_port    INTEGER,               -- Port tujuan koneksi
    event_type   TEXT,                  -- Tipe event: login_fail, port_scan, dll
    protocol     TEXT,                  -- Protokol: TCP, UDP, ICMP
    raw_message  TEXT NOT NULL          -- Pesan syslog mentah dari MikroTik
);

-- Jadikan tabel syslogs sebagai hypertable untuk optimasi time-series
SELECT create_hypertable('syslogs', 'time', if_not_exists => TRUE);

-- Indeks tambahan untuk mempercepat query berdasarkan IP sumber
CREATE INDEX IF NOT EXISTS idx_syslogs_source_ip ON syslogs (source_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_syslogs_node_id ON syslogs (node_id, time DESC);

-- =============================================================================
-- Tabel intrusion_results: Menyimpan hasil analisis Isolation Forest
-- =============================================================================
CREATE TABLE IF NOT EXISTS intrusion_results (
    time           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip      TEXT NOT NULL,
    anomaly_score  FLOAT NOT NULL,       -- Skor anomali dari Isolation Forest (negatif = anomali)
    is_intrusion   BOOLEAN NOT NULL,     -- True jika terdeteksi sebagai intrusi
    confidence     FLOAT,                -- Tingkat keyakinan deteksi (0.0 - 1.0)
    action_taken   TEXT,                 -- block / monitor / allow
    distributed    BOOLEAN DEFAULT FALSE,-- Sudah didistribusikan ke semua node?
    distributed_to TEXT[]                -- Daftar node yang sudah menerima pemblokiran
);

-- Jadikan tabel intrusion_results sebagai hypertable
SELECT create_hypertable('intrusion_results', 'time', if_not_exists => TRUE);

-- Indeks untuk query berdasarkan IP dan status intrusi
CREATE INDEX IF NOT EXISTS idx_intrusions_source_ip ON intrusion_results (source_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_intrusions_is_intrusion ON intrusion_results (is_intrusion, time DESC);

-- =============================================================================
-- Tabel mikrotik_nodes: Daftar semua node MikroTik yang terdaftar dalam sistem
-- =============================================================================
CREATE TABLE IF NOT EXISTS mikrotik_nodes (
    id          SERIAL PRIMARY KEY,
    node_id     TEXT UNIQUE NOT NULL,    -- Nama unik identifikasi node
    ip_address  TEXT NOT NULL,           -- IP untuk koneksi MikroTik API
    api_port    INTEGER DEFAULT 8728,    -- Port API MikroTik (default 8728)
    username    TEXT NOT NULL,           -- Username login MikroTik
    password    TEXT NOT NULL,           -- Password login MikroTik
    location    TEXT,                    -- Lokasi fisik node (opsional)
    is_active   BOOLEAN DEFAULT TRUE,    -- Node aktif atau tidak
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- Tabel users: Manajemen user yang dapat mengakses dashboard web
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,    -- Username untuk login dashboard
    password    TEXT NOT NULL,           -- Password terenkripsi bcrypt
    role        TEXT NOT NULL DEFAULT 'viewer', -- Role: admin / operator / viewer
    full_name   TEXT,                    -- Nama lengkap pengguna
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ              -- Waktu terakhir login
);

-- =============================================================================
-- Tabel access_list: Whitelist dan blacklist manual (bypass machine learning)
-- =============================================================================
CREATE TABLE IF NOT EXISTS access_list (
    id          SERIAL PRIMARY KEY,
    ip_address  TEXT NOT NULL,           -- IP address yang diatur
    list_type   TEXT NOT NULL,           -- 'whitelist' atau 'blacklist'
    reason      TEXT,                    -- Alasan penambahan ke list
    added_by    TEXT NOT NULL,           -- Username yang menambahkan
    is_active   BOOLEAN DEFAULT TRUE,    -- Aturan aktif atau tidak
    expires_at  TIMESTAMPTZ,             -- Waktu kadaluarsa (null = permanen)
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Indeks untuk query cepat berdasarkan IP dan tipe list
CREATE INDEX IF NOT EXISTS idx_access_list_ip ON access_list (ip_address, list_type);
CREATE INDEX IF NOT EXISTS idx_access_list_active ON access_list (is_active, list_type);

-- =============================================================================
-- Tabel app_settings: override konfigurasi Decision Engine dari web interface.
-- Hanya berisi parameter yang SENGAJA diubah operator melalui UI; parameter
-- yang tidak ada di tabel ini memakai nilai bawaan dari environment (.env).
-- Python Analyst membaca tabel ini secara berkala (cache 10 detik).
-- =============================================================================
CREATE TABLE IF NOT EXISTS app_settings (
    key         TEXT PRIMARY KEY,        -- Nama parameter, sama dengan nama env var
    value       TEXT NOT NULL,           -- Nilai override (disimpan sebagai teks)
    updated_by  TEXT,                    -- Username yang terakhir mengubah
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- Seed data: User-user default untuk web interface IDS
-- Semua password di-hash menggunakan bcrypt cost 10
-- Hash diverifikasi sesuai dengan password yang tercantum di komentar
-- =============================================================================

-- User admin: akses penuh ke semua fitur termasuk manajemen user
-- Password: admin123
INSERT INTO users (username, password, role, full_name, is_active)
VALUES (
    'admin',
    '$2a$10$WR/tN.om5dYEfv1eVU1JmerBGdwBb0Tbdu79eWrqjrW.naGTdJG5m',
    'admin',
    'Administrator',
    TRUE
) ON CONFLICT (username) DO UPDATE
    SET password  = EXCLUDED.password,
        role      = EXCLUDED.role,
        full_name = EXCLUDED.full_name,
        is_active = EXCLUDED.is_active;

-- User operator: kelola node & access list, tidak bisa kelola user
-- Password: operator123
INSERT INTO users (username, password, role, full_name, is_active)
VALUES (
    'operator',
    '$2a$10$b/yB6msud/fn2EsWRDkapun1rwdkDa8cOUgoxrNGKi1fb.3LmK6qW',
    'operator',
    'Operator Jaringan',
    TRUE
) ON CONFLICT (username) DO NOTHING;

-- User viewer: hanya bisa melihat dashboard, syslog, dan hasil deteksi
-- Password: viewer123
INSERT INTO users (username, password, role, full_name, is_active)
VALUES (
    'viewer',
    '$2a$10$Rjam8.N0K8dxCzXTtG8Xf.TO3TUIT4yTWCYtzmqHKcEHSDerw5pGK',
    'viewer',
    'Viewer Monitoring',
    TRUE
) ON CONFLICT (username) DO NOTHING;

-- =============================================================================
-- Seed data: Node MikroTik demo (untuk keperluan pengujian tesis)
-- =============================================================================
INSERT INTO mikrotik_nodes (node_id, ip_address, api_port, username, password, location, is_active)
VALUES
    ('router-01', '192.168.1.1', 8728, 'admin', 'admin', 'Gedung A - Lantai 1', TRUE),
    ('router-02', '192.168.1.2', 8728, 'admin', 'admin', 'Gedung A - Lantai 2', TRUE)
ON CONFLICT (node_id) DO NOTHING;

-- Konfirmasi inisialisasi berhasil dengan daftar kredensial
DO $$
BEGIN
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Schema database IDS berhasil diinisialisasi';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Kredensial Web Interface (http://localhost:8080):';
    RAISE NOTICE '  admin    / admin123    (role: admin)';
    RAISE NOTICE '  operator / operator123 (role: operator)';
    RAISE NOTICE '  viewer   / viewer123   (role: viewer)';
    RAISE NOTICE '--------------------------------------------';
    RAISE NOTICE 'Kredensial Grafana (http://localhost:3000):';
    RAISE NOTICE '  admin / admin123';
    RAISE NOTICE '============================================';
END $$;
