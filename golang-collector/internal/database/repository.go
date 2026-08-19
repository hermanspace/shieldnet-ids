// repository.go menyediakan semua fungsi query database yang dibutuhkan sistem.
// Setiap fungsi mencerminkan satu operasi data spesifik agar mudah dipahami
// dan diuji secara terpisah.
package database

import (
	"context"
	"fmt"
	"time"
)

// Syslog merepresentasikan satu baris data syslog dari router MikroTik.
type Syslog struct {
	Time       time.Time
	NodeID     string
	NodeIP     string
	SourceIP   string
	SourcePort int
	DestPort   int
	EventType  string
	Protocol   string
	RawMessage string
}

// IntrusionResult merepresentasikan hasil analisis Isolation Forest untuk satu IP.
type IntrusionResult struct {
	Time          time.Time
	SourceIP      string
	AnomalyScore  float64
	IsIntrusion   bool
	Confidence    float64
	ActionTaken   string
	Distributed   bool
	DistributedTo []string
}

// MikrotikNode merepresentasikan satu router MikroTik yang terdaftar.
type MikrotikNode struct {
	ID        int
	NodeID    string
	IPAddress string
	APIPort   int
	Username  string
	Password  string
	Location  string
	IsActive  bool
	CreatedAt time.Time
}

// User merepresentasikan satu pengguna dashboard web.
type User struct {
	ID        int
	Username  string
	Password  string
	Role      string
	FullName  string
	IsActive  bool
	CreatedAt time.Time
	LastLogin *time.Time
}

// AccessListEntry merepresentasikan satu aturan whitelist atau blacklist.
type AccessListEntry struct {
	ID        int
	IPAddress string
	ListType  string
	Reason    string
	AddedBy   string
	IsActive  bool
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// InsertSyslog menyimpan satu record syslog baru ke database.
// Dipanggil setiap kali syslog baru diterima dari router MikroTik.
func InsertSyslog(s Syslog) error {
	query := `
		INSERT INTO syslogs (time, node_id, node_ip, source_ip, source_port, dest_port, event_type, protocol, raw_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := DB.Exec(context.Background(), query,
		s.Time, s.NodeID, s.NodeIP, s.SourceIP, s.SourcePort,
		s.DestPort, s.EventType, s.Protocol, s.RawMessage,
	)
	if err != nil {
		return fmt.Errorf("gagal menyimpan syslog: %w", err)
	}
	return nil
}

// GetRecentSyslogs mengambil syslog terbaru dengan dukungan filter dan pagination.
// Digunakan untuk menampilkan tabel syslog di halaman web.
func GetRecentSyslogs(nodeID, sourceIP, eventType string, from, to time.Time, limit, offset int) ([]Syslog, int, error) {
	// Hitung total data untuk pagination
	countQuery := `
		SELECT COUNT(*) FROM syslogs
		WHERE time BETWEEN $1 AND $2
		AND ($3 = '' OR node_id = $3)
		AND ($4 = '' OR source_ip = $4)
		AND ($5 = '' OR event_type = $5)
	`
	var total int
	err := DB.QueryRow(context.Background(), countQuery, from, to, nodeID, sourceIP, eventType).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung total syslog: %w", err)
	}

	// Ambil data dengan pagination
	query := `
		SELECT time, node_id, node_ip, source_ip, source_port, dest_port, event_type, protocol, raw_message
		FROM syslogs
		WHERE time BETWEEN $1 AND $2
		AND ($3 = '' OR node_id = $3)
		AND ($4 = '' OR source_ip = $4)
		AND ($5 = '' OR event_type = $5)
		ORDER BY time DESC
		LIMIT $6 OFFSET $7
	`
	rows, err := DB.Query(context.Background(), query, from, to, nodeID, sourceIP, eventType, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal mengambil data syslog: %w", err)
	}
	defer rows.Close()

	var syslogs []Syslog
	for rows.Next() {
		var s Syslog
		if err := rows.Scan(&s.Time, &s.NodeID, &s.NodeIP, &s.SourceIP,
			&s.SourcePort, &s.DestPort, &s.EventType, &s.Protocol, &s.RawMessage); err != nil {
			return nil, 0, err
		}
		syslogs = append(syslogs, s)
	}
	return syslogs, total, nil
}

// GetSyslogStats mengambil statistik syslog untuk halaman dashboard.
// Mengembalikan jumlah total syslog, intrusi, node aktif, dan IP diblokir hari ini.
func GetSyslogStats() (map[string]int, error) {
	stats := map[string]int{}

	queries := map[string]string{
		"total_syslogs":   `SELECT COUNT(*) FROM syslogs WHERE time > NOW() - INTERVAL '24 hours'`,
		"total_intrusions": `SELECT COUNT(*) FROM intrusion_results WHERE time > NOW() - INTERVAL '24 hours' AND is_intrusion = true`,
		"active_nodes":    `SELECT COUNT(*) FROM mikrotik_nodes WHERE is_active = true`,
		"blocked_ips":     `SELECT COUNT(DISTINCT ip_address) FROM access_list WHERE list_type = 'blacklist' AND is_active = true`,
	}

	for key, q := range queries {
		var count int
		if err := DB.QueryRow(context.Background(), q).Scan(&count); err != nil {
			stats[key] = 0
			continue
		}
		stats[key] = count
	}
	return stats, nil
}

// GetRecentIntrusions mengambil hasil deteksi intrusi terbaru untuk dashboard.
func GetRecentIntrusions(limit int) ([]IntrusionResult, error) {
	query := `
		SELECT time, source_ip, anomaly_score, is_intrusion, confidence, action_taken, distributed
		FROM intrusion_results
		WHERE is_intrusion = true
		ORDER BY time DESC
		LIMIT $1
	`
	rows, err := DB.Query(context.Background(), query, limit)
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil data intrusi: %w", err)
	}
	defer rows.Close()

	var results []IntrusionResult
	for rows.Next() {
		var r IntrusionResult
		if err := rows.Scan(&r.Time, &r.SourceIP, &r.AnomalyScore, &r.IsIntrusion,
			&r.Confidence, &r.ActionTaken, &r.Distributed); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// GetAllIntrusions mengambil semua hasil deteksi dengan pagination.
func GetAllIntrusions(limit, offset int) ([]IntrusionResult, int, error) {
	var total int
	countErr := DB.QueryRow(context.Background(), "SELECT COUNT(*) FROM intrusion_results").Scan(&total)
	if countErr != nil {
		return nil, 0, countErr
	}

	query := `
		SELECT time, source_ip, anomaly_score, is_intrusion, confidence, action_taken, distributed
		FROM intrusion_results
		ORDER BY time DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := DB.Query(context.Background(), query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal mengambil data intrusi: %w", err)
	}
	defer rows.Close()

	var results []IntrusionResult
	for rows.Next() {
		var r IntrusionResult
		if err := rows.Scan(&r.Time, &r.SourceIP, &r.AnomalyScore, &r.IsIntrusion,
			&r.Confidence, &r.ActionTaken, &r.Distributed); err != nil {
			return nil, 0, err
		}
		results = append(results, r)
	}
	return results, total, nil
}

// GetFilteredIntrusions mengambil hasil deteksi dengan filter opsional:
// search    — pencarian teks pada IP sumber (substring, case-insensitive)
// eventType — jenis serangan berdasarkan event_type syslog dalam jendela analisis
//             10 menit sebelum waktu hasil (login_fail, port_scan, syn_flood, dst.)
// action    — aksi keputusan sistem (allow / monitor / block)
// Filter kosong berarti tidak diterapkan. Hasil diurutkan dari yang terbaru.
func GetFilteredIntrusions(search, eventType, action string, limit, offset int) ([]IntrusionResult, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}

	if search != "" {
		args = append(args, "%"+search+"%")
		where += fmt.Sprintf(" AND ir.source_ip ILIKE $%d", len(args))
	}
	if action != "" {
		args = append(args, action)
		where += fmt.Sprintf(" AND ir.action_taken = $%d", len(args))
	}
	if eventType != "" {
		args = append(args, eventType)
		where += fmt.Sprintf(` AND EXISTS (
			SELECT 1 FROM syslogs s
			WHERE s.source_ip = ir.source_ip
			  AND s.time > ir.time - interval '10 minutes'
			  AND s.time <= ir.time
			  AND s.event_type = $%d
		)`, len(args))
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM intrusion_results ir " + where
	if err := DB.QueryRow(context.Background(), countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung data intrusi terfilter: %w", err)
	}

	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT ir.time, ir.source_ip, ir.anomaly_score, ir.is_intrusion,
		       ir.confidence, ir.action_taken, ir.distributed
		FROM intrusion_results ir
		%s
		ORDER BY ir.time DESC
		LIMIT $%d OFFSET $%d
	`, where, len(args)-1, len(args))

	rows, err := DB.Query(context.Background(), query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal mengambil data intrusi terfilter: %w", err)
	}
	defer rows.Close()

	var results []IntrusionResult
	for rows.Next() {
		var r IntrusionResult
		if err := rows.Scan(&r.Time, &r.SourceIP, &r.AnomalyScore, &r.IsIntrusion,
			&r.Confidence, &r.ActionTaken, &r.Distributed); err != nil {
			return nil, 0, err
		}
		results = append(results, r)
	}
	return results, total, nil
}

// IntrusionStats merangkum statistik keseluruhan hasil deteksi untuk ditampilkan di halaman intrusi.
type IntrusionStats struct {
	TotalAnalyzed  int
	TotalIntrusion int
	TotalBlocked   int
	TotalMonitor   int
	TotalNormal    int
	AvgScore       float64
	MinScore       float64
}

// GetIntrusionStats mengambil statistik agregat dari seluruh tabel intrusion_results.
func GetIntrusionStats() (IntrusionStats, error) {
	var s IntrusionStats
	query := `
		SELECT
			COUNT(*)                                              AS total_analyzed,
			COUNT(*) FILTER (WHERE is_intrusion = true)          AS total_intrusion,
			COUNT(*) FILTER (WHERE action_taken = 'block')       AS total_blocked,
			COUNT(*) FILTER (WHERE action_taken = 'monitor')     AS total_monitor,
			COUNT(*) FILTER (WHERE is_intrusion = false)         AS total_normal,
			COALESCE(AVG(anomaly_score), 0)                      AS avg_score,
			COALESCE(MIN(anomaly_score), 0)                      AS min_score
		FROM intrusion_results
	`
	err := DB.QueryRow(context.Background(), query).Scan(
		&s.TotalAnalyzed, &s.TotalIntrusion, &s.TotalBlocked,
		&s.TotalMonitor, &s.TotalNormal, &s.AvgScore, &s.MinScore,
	)
	return s, err
}

// InsertIntrusionResult menyimpan hasil analisis dari Python Analyst ke database.
// Waktu diisi NOW() oleh database — payload dari Python tidak membawa timestamp,
// sehingga r.Time selalu zero value dan tidak boleh dipakai langsung.
func InsertIntrusionResult(r IntrusionResult) error {
	query := `
		INSERT INTO intrusion_results (time, source_ip, anomaly_score, is_intrusion, confidence, action_taken)
		VALUES (NOW(), $1, $2, $3, $4, $5)
	`
	_, err := DB.Exec(context.Background(), query,
		r.SourceIP, r.AnomalyScore, r.IsIntrusion, r.Confidence, r.ActionTaken,
	)
	return err
}

// MarkIntrusionDistributed memperbarui status distribusi setelah access list dikirim ke semua node.
func MarkIntrusionDistributed(sourceIP string, nodeIDs []string) error {
	query := `
		UPDATE intrusion_results
		SET distributed = true, distributed_to = $2
		WHERE source_ip = $1 AND is_intrusion = true
		AND time = (SELECT MAX(time) FROM intrusion_results WHERE source_ip = $1)
	`
	_, err := DB.Exec(context.Background(), query, sourceIP, nodeIDs)
	return err
}

// GetAllNodes mengambil semua node MikroTik yang terdaftar.
func GetAllNodes() ([]MikrotikNode, error) {
	query := `SELECT id, node_id, ip_address, api_port, username, password, location, is_active, created_at FROM mikrotik_nodes ORDER BY id`
	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []MikrotikNode
	for rows.Next() {
		var n MikrotikNode
		if err := rows.Scan(&n.ID, &n.NodeID, &n.IPAddress, &n.APIPort,
			&n.Username, &n.Password, &n.Location, &n.IsActive, &n.CreatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetActiveNodes mengambil hanya node yang sedang aktif untuk distribusi access list.
func GetActiveNodes() ([]MikrotikNode, error) {
	query := `SELECT id, node_id, ip_address, api_port, username, password, location, is_active, created_at FROM mikrotik_nodes WHERE is_active = true`
	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []MikrotikNode
	for rows.Next() {
		var n MikrotikNode
		if err := rows.Scan(&n.ID, &n.NodeID, &n.IPAddress, &n.APIPort,
			&n.Username, &n.Password, &n.Location, &n.IsActive, &n.CreatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// InsertNode menambahkan node MikroTik baru ke database.
func InsertNode(n MikrotikNode) error {
	query := `
		INSERT INTO mikrotik_nodes (node_id, ip_address, api_port, username, password, location)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := DB.Exec(context.Background(), query,
		n.NodeID, n.IPAddress, n.APIPort, n.Username, n.Password, n.Location,
	)
	return err
}

// SetNodeActive mengaktifkan atau menonaktifkan sebuah node.
func SetNodeActive(nodeID string, active bool) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE mikrotik_nodes SET is_active = $1 WHERE node_id = $2",
		active, nodeID,
	)
	return err
}

// DeleteNode menghapus node dari database berdasarkan ID-nya.
func DeleteNode(id int) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM mikrotik_nodes WHERE id = $1", id)
	return err
}

// GetUserByUsername mencari user berdasarkan username untuk keperluan login.
func GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, password, role, full_name, is_active, created_at, last_login FROM users WHERE username = $1`
	var u User
	err := DB.QueryRow(context.Background(), query, username).Scan(
		&u.ID, &u.Username, &u.Password, &u.Role, &u.FullName, &u.IsActive, &u.CreatedAt, &u.LastLogin,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateLastLogin memperbarui waktu login terakhir user setelah berhasil masuk.
func UpdateLastLogin(username string) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET last_login = NOW() WHERE username = $1", username,
	)
	return err
}

// GetAllUsers mengambil semua user untuk halaman manajemen user.
func GetAllUsers() ([]User, error) {
	query := `SELECT id, username, password, role, full_name, is_active, created_at, last_login FROM users ORDER BY id`
	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Role,
			&u.FullName, &u.IsActive, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// InsertUser menambahkan user baru ke database dengan password yang sudah di-hash.
func InsertUser(u User) error {
	query := `INSERT INTO users (username, password, role, full_name) VALUES ($1, $2, $3, $4)`
	_, err := DB.Exec(context.Background(), query, u.Username, u.Password, u.Role, u.FullName)
	return err
}

// SetUserActive mengaktifkan atau menonaktifkan user.
func SetUserActive(id int, active bool) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET is_active = $1 WHERE id = $2", active, id,
	)
	return err
}

// DeleteUser menghapus user dari database.
func DeleteUser(id int) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM users WHERE id = $1", id)
	return err
}

// GetAccessList mengambil daftar whitelist atau blacklist berdasarkan tipe.
func GetAccessList(listType string) ([]AccessListEntry, error) {
	query := `
		SELECT id, ip_address, list_type, reason, added_by, is_active, expires_at, created_at
		FROM access_list
		WHERE list_type = $1
		ORDER BY created_at DESC
	`
	rows, err := DB.Query(context.Background(), query, listType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AccessListEntry
	for rows.Next() {
		var e AccessListEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.ListType, &e.Reason,
			&e.AddedBy, &e.IsActive, &e.ExpiresAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// IsIPWhitelisted mengecek apakah sebuah IP ada dalam whitelist aktif.
// Digunakan untuk bypass analisis ML pada IP yang sudah dipercaya.
func IsIPWhitelisted(ip string) (bool, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM access_list
		WHERE ip_address = $1 AND list_type = 'whitelist' AND is_active = true
		AND (expires_at IS NULL OR expires_at > NOW())
	`
	err := DB.QueryRow(context.Background(), query, ip).Scan(&count)
	return count > 0, err
}

// IsIPBlacklisted mengecek apakah sebuah IP ada dalam blacklist aktif.
// IP yang masuk blacklist langsung diblokir tanpa analisis ML.
func IsIPBlacklisted(ip string) (bool, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM access_list
		WHERE ip_address = $1 AND list_type = 'blacklist' AND is_active = true
		AND (expires_at IS NULL OR expires_at > NOW())
	`
	err := DB.QueryRow(context.Background(), query, ip).Scan(&count)
	return count > 0, err
}

// InsertAccessList menambahkan IP baru ke whitelist atau blacklist.
func InsertAccessList(e AccessListEntry) error {
	query := `
		INSERT INTO access_list (ip_address, list_type, reason, added_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := DB.Exec(context.Background(), query,
		e.IPAddress, e.ListType, e.Reason, e.AddedBy, e.ExpiresAt,
	)
	return err
}

// GetAccessListByID mengambil satu entry access list berdasarkan ID-nya.
// Digunakan sebelum penghapusan agar sistem tahu IP dan tipe list yang dihapus.
func GetAccessListByID(id int) (*AccessListEntry, error) {
	query := `
		SELECT id, ip_address, list_type, reason, added_by, is_active, expires_at, created_at
		FROM access_list WHERE id = $1
	`
	var e AccessListEntry
	var expiresAt *time.Time
	err := DB.QueryRow(context.Background(), query, id).Scan(
		&e.ID, &e.IPAddress, &e.ListType, &e.Reason,
		&e.AddedBy, &e.IsActive, &expiresAt, &e.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	e.ExpiresAt = expiresAt
	return &e, nil
}

// DeleteAccessList menghapus aturan dari whitelist atau blacklist berdasarkan ID.
func DeleteAccessList(id int) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM access_list WHERE id = $1", id)
	return err
}

// GetIntrusionsPerHour mengambil jumlah intrusi per jam untuk grafik di dashboard.
func GetIntrusionsPerHour(hours int) ([]map[string]interface{}, error) {
	query := `
		SELECT
			time_bucket('1 hour', time) AS hour,
			COUNT(*) AS count
		FROM intrusion_results
		WHERE time > NOW() - ($1 || ' hours')::INTERVAL
		AND is_intrusion = true
		GROUP BY hour
		ORDER BY hour
	`
	rows, err := DB.Query(context.Background(), query, fmt.Sprintf("%d", hours))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []map[string]interface{}
	for rows.Next() {
		var hour time.Time
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, err
		}
		data = append(data, map[string]interface{}{
			"hour":  hour.Format("15:04"),
			"count": count,
		})
	}
	return data, nil
}

// =============================================================================
// App Settings — override konfigurasi Decision Engine dari web interface.
// Parameter yang tidak memiliki baris di tabel ini memakai nilai bawaan .env.
// =============================================================================

// AppSetting merepresentasikan satu override konfigurasi yang dibuat dari UI.
type AppSetting struct {
	Key       string
	Value     string
	UpdatedBy string
	UpdatedAt time.Time
}

// EnsureSettingsTable membuat tabel app_settings jika belum ada.
// Dipanggil sekali saat startup agar instalasi lama (database sudah terlanjur
// diinisialisasi tanpa tabel ini) tetap bisa memakai fitur pengaturan UI.
func EnsureSettingsTable() error {
	_, err := DB.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS app_settings (
			key         TEXT PRIMARY KEY,
			value       TEXT NOT NULL,
			updated_by  TEXT,
			updated_at  TIMESTAMPTZ DEFAULT NOW()
		)
	`)
	return err
}

// GetAppSettings mengambil seluruh override konfigurasi sebagai map key → setting.
func GetAppSettings() (map[string]AppSetting, error) {
	rows, err := DB.Query(context.Background(),
		"SELECT key, value, COALESCE(updated_by, ''), updated_at FROM app_settings")
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil app_settings: %w", err)
	}
	defer rows.Close()

	settings := make(map[string]AppSetting)
	for rows.Next() {
		var s AppSetting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedBy, &s.UpdatedAt); err != nil {
			return nil, err
		}
		settings[s.Key] = s
	}
	return settings, nil
}

// UpsertAppSetting menyimpan atau memperbarui satu override konfigurasi.
func UpsertAppSetting(key, value, updatedBy string) error {
	_, err := DB.Exec(context.Background(), `
		INSERT INTO app_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = NOW()
	`, key, value, updatedBy)
	return err
}

// DeleteAppSetting menghapus satu override sehingga parameter kembali ke nilai .env.
func DeleteAppSetting(key string) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM app_settings WHERE key = $1", key)
	return err
}

// DeleteAllAppSettings menghapus seluruh override (reset total ke nilai .env).
func DeleteAllAppSettings() error {
	_, err := DB.Exec(context.Background(), "DELETE FROM app_settings")
	return err
}

// UpdateUserPassword mengganti password (hash bcrypt) seorang pengguna berdasarkan ID.
// Dipakai fitur reset password oleh admin dari halaman Manajemen User.
func UpdateUserPassword(id int, passwordHash string) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET password = $1 WHERE id = $2", passwordHash, id)
	return err
}

// UpdateUserPasswordByUsername mengganti password (hash bcrypt) berdasarkan username.
// Dipakai fitur ubah password mandiri oleh pengguna yang sedang login.
func UpdateUserPasswordByUsername(username, passwordHash string) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET password = $1 WHERE username = $2", passwordHash, username)
	return err
}
