// intrusion.go menangani halaman hasil deteksi intrusi dan fitur override manual.
// Operator dapat memindahkan IP ke whitelist atau blacklist dari halaman ini.
package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

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
