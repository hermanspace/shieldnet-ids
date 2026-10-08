// intrusion.go menangani halaman hasil deteksi intrusi dan fitur override manual.
// Operator dapat memindahkan IP ke whitelist atau blacklist dari halaman ini.
package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
	"thesis-ids/golang-collector/internal/mikrotik"
)

// validEventTypes adalah jenis serangan yang dikenali parser dan bisa dijadikan filter.
// Nilai harus sama persis dengan hasil classifyEvent pada syslog parser.
var validEventTypes = map[string]string{
	"login_fail":     "Brute Force (login gagal)",
	"port_scan":      "Port Scanning",
	"brute_force":    "Brute Force (eksplisit)",
	"syn_flood":      "SYN Flood",
	"firewall_block": "Firewall Block / Drop",
	"access_denied":  "Access Denied",
	"general":        "Umum / Lainnya",
}

// Intrusions menampilkan semua hasil analisis Isolation Forest dengan pagination,
// statistik agregat, informasi metode deteksi, serta filter pencarian teks,
// jenis serangan, dan aksi keputusan.
func (h *Handlers) Intrusions(w http.ResponseWriter, r *http.Request) {
	page := parseIntParam(r.URL.Query().Get("page"), 1)
	pageSize := 50
	offset := (page - 1) * pageSize

	// Parameter filter dari query string
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	eventType := r.URL.Query().Get("event_type")
	action := r.URL.Query().Get("action")

	// Validasi nilai filter agar hanya nilai yang dikenal yang diteruskan ke query
	if _, ok := validEventTypes[eventType]; !ok {
		eventType = ""
	}
	if action != "allow" && action != "monitor" && action != "block" {
		action = ""
	}

	results, total, err := database.GetFilteredIntrusions(search, eventType, action, pageSize, offset)
	if err != nil {
		results = nil
		total = 0
	}

	stats, err := database.GetIntrusionStats()
	if err != nil {
		stats = database.IntrusionStats{}
	}

	totalPages := (total + pageSize - 1) / pageSize

	// Nilai efektif parameter Decision Engine (override UI atau bawaan .env)
	eff, _ := effectiveSettings()

	// String query untuk mempertahankan filter pada tautan pagination
	filterQuery := url.Values{}
	if search != "" {
		filterQuery.Set("q", search)
	}
	if eventType != "" {
		filterQuery.Set("event_type", eventType)
	}
	if action != "" {
		filterQuery.Set("action", action)
	}

	h.render(w, r, "intrusions.html", PageData{
		Title: "Hasil Deteksi Intrusi",
		Data: map[string]interface{}{
			"results":      results,
			"total":        total,
			"page":         page,
			"total_pages":  totalPages,
			"stats":        stats,
			"search":       search,
			"event_type":   eventType,
			"action":       action,
			"event_types":  validEventTypes,
			"filter_query": filterQuery.Encode(),
			"has_filter":   search != "" || eventType != "" || action != "",

			// Ambang aktif (override UI jika ada, selain itu .env) agar teks
			// panel informasi selalu sinkron dengan konfigurasi Python Analyst
			"anomaly_threshold": eff["ANOMALY_THRESHOLD"],
			"block_score":       eff["BLOCK_SCORE_THRESHOLD"],
			"block_confidence":  eff["BLOCK_CONFIDENCE_THRESHOLD"],
		},
	})
}

// OverrideIntrusion memungkinkan operator memindahkan IP ke whitelist atau blacklist secara manual.
// Ini adalah mekanisme koreksi terhadap hasil analisis machine learning yang dianggap salah.
func (h *Handlers) OverrideIntrusion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/intrusions", http.StatusFound)
		return
	}

	sourceIP := r.FormValue("source_ip")
	action := r.FormValue("action") // "whitelist" atau "blacklist"
	username := auth.GetLoggedInUser(r)

	if sourceIP == "" || (action != "whitelist" && action != "blacklist") {
		http.Redirect(w, r, "/intrusions", http.StatusFound)
		return
	}

	// Tambahkan IP ke access list sesuai pilihan operator
	entry := database.AccessListEntry{
		IPAddress: sourceIP,
		ListType:  action,
		Reason:    "Override manual dari halaman deteksi intrusi",
		AddedBy:   username,
	}
	database.InsertAccessList(entry)

	// Jika dipindah ke whitelist, hapus pemblokiran dari semua node MikroTik
	if action == "whitelist" {
		go mikrotik.RemoveBlock(sourceIP)
	}

	// Jika dipindah ke blacklist, langsung blokir di semua node
	if action == "blacklist" {
		go mikrotik.DistributeBlock(sourceIP)
	}

	http.Redirect(w, r, "/intrusions", http.StatusFound)
}

// parseIntParamStr mengurai parameter string menjadi integer.
func parseIntParamStr(s string, defaultVal int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return defaultVal
}

// featureInfo menjelaskan tiap fitur agar halaman detail mudah dipahami.
type featureInfo struct {
	Key       string
	Label     string
	Deskripsi string
	Indikator string
	Raw       float64
	Scaled    float64
	HasScaled bool
}

// featureCatalog adalah urutan & keterangan 9 fitur — harus sama dengan
// FEATURE_NAMES pada python-analyst/modules/preprocessor.py.
var featureCatalog = []featureInfo{
	{Key: "total_requests", Label: "Total aktivitas", Deskripsi: "Jumlah seluruh log dari IP ini dalam jendela analisis", Indikator: "Flood / DoS"},
	{Key: "unique_dest_ports", Label: "Port tujuan unik", Deskripsi: "Banyaknya port tujuan berbeda yang diakses", Indikator: "Port scanning"},
	{Key: "unique_src_ports", Label: "Port asal unik", Deskripsi: "Banyaknya port asal berbeda", Indikator: "Scanner otomatis"},
	{Key: "login_fails", Label: "Login gagal", Deskripsi: "Jumlah kegagalan autentikasi", Indikator: "Brute force"},
	{Key: "port_scans", Label: "Event port scan", Deskripsi: "Jumlah log terklasifikasi port_scan", Indikator: "Reconnaissance"},
	{Key: "brute_forces", Label: "Event brute force", Deskripsi: "Jumlah log terklasifikasi brute_force", Indikator: "Brute force"},
	{Key: "requests_per_minute", Label: "Aktivitas per menit", Deskripsi: "total_requests ÷ durasi (menit)", Indikator: "Serangan volumetrik"},
	{Key: "port_diversity_ratio", Label: "Rasio keragaman port", Deskripsi: "unique_dest_ports ÷ total_requests (0–1)", Indikator: "Port scan (→ 1,0)"},
	{Key: "fail_ratio", Label: "Rasio login gagal", Deskripsi: "login_fails ÷ total_requests (0–1)", Indikator: "Brute force (→ 1,0)"},
}

// IntrusionDetail menampilkan alur pengolahan satu hasil analisis secara utuh:
// Tahap 1 log mentah MikroTik → Tahap 2 data diolah (9 fitur mentah & ternormalisasi)
// → Tahap 3 skor anomali, keyakinan, dan keputusan (revisi penguji).
func (h *Handlers) IntrusionDetail(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	tStr := r.URL.Query().Get("t")
	at, err := time.Parse(time.RFC3339Nano, tStr)
	if ip == "" || err != nil {
		http.Redirect(w, r, "/intrusions", http.StatusFound)
		return
	}

	res, err := database.GetIntrusionDetail(ip, at)
	if err != nil {
		h.render(w, r, "intrusion_detail.html", PageData{
			Title: "Detail Analisis",
			Flash: "Hasil analisis tidak ditemukan untuk IP dan waktu tersebut.",
			Data:  map[string]interface{}{"found": false},
		})
		return
	}

	// Jendela analisis: log mentah IP ini pada [waktu hasil − window, waktu hasil]
	window := res.WindowMinutes
	if window <= 0 {
		window = 10 // bawaan ANALYSIS_WINDOW_MINUTES
	}
	from := res.Time.Add(-time.Duration(window) * time.Minute)
	rawLogs, totalRaw, err := database.GetRecentSyslogs("", ip, "", from, res.Time, 200, 0)
	if err != nil {
		rawLogs, totalRaw = nil, 0
	}

	// Susun tabel fitur: nilai mentah & ternormalisasi mengikuti katalog
	feats := make([]featureInfo, 0, len(featureCatalog))
	for _, f := range featureCatalog {
		fi := f
		if res.Features != nil {
			fi.Raw = res.Features[f.Key]
		}
		if res.FeaturesScaled != nil {
			if v, ok := res.FeaturesScaled[f.Key]; ok {
				fi.Scaled, fi.HasScaled = v, true
			}
		}
		feats = append(feats, fi)
	}

	eff, _ := effectiveSettings()
	h.render(w, r, "intrusion_detail.html", PageData{
		Title: "Detail Analisis — " + ip,
		Data: map[string]interface{}{
			"found":        true,
			"res":          res,
			"raw_logs":     rawLogs,
			"total_raw":    totalRaw,
			"window":       window,
			"from":         from,
			"features":     feats,
			"has_features": res.Features != nil && len(res.Features) > 0,

			"anomaly_threshold": eff["ANOMALY_THRESHOLD"],
			"block_score":       eff["BLOCK_SCORE_THRESHOLD"],
			"block_confidence":  eff["BLOCK_CONFIDENCE_THRESHOLD"],
		},
	})
}
