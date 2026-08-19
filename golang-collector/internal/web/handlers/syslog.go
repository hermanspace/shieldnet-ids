// syslog.go menangani halaman tabel syslog real-time dengan fitur filter dan pagination.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"thesis-ids/golang-collector/internal/database"
)

// Syslogs menampilkan tabel semua syslog dengan dukungan filter dan pagination.
// Mendukung filter berdasarkan node, IP sumber, tipe event, dan rentang waktu.
func (h *Handlers) Syslogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Ambil parameter filter dari query string
	nodeID := q.Get("node_id")
	sourceIP := q.Get("source_ip")
	eventType := q.Get("event_type")

	// Parse parameter pagination, gunakan default jika tidak ada
	page := parseIntParam(q.Get("page"), 1)
	pageSize := 50
	offset := (page - 1) * pageSize

	// Parse rentang waktu, default: 24 jam terakhir
	from := parseTimeParam(q.Get("from"), time.Now().Add(-24*time.Hour))
	to := parseTimeParam(q.Get("to"), time.Now())

	syslogs, total, err := database.GetRecentSyslogs(nodeID, sourceIP, eventType, from, to, pageSize, offset)
	if err != nil {
		syslogs = nil
		total = 0
	}

	totalPages := (total + pageSize - 1) / pageSize

	h.render(w, r, "syslogs.html", PageData{
		Title: "Data Syslog",
		Data: map[string]interface{}{
			"syslogs":     syslogs,
			"total":       total,
			"page":        page,
			"total_pages": totalPages,
			"page_size":   pageSize,
			// Filter aktif untuk mempertahankan nilai di form
			"filter_node":       nodeID,
			"filter_source_ip":  sourceIP,
			"filter_event_type": eventType,
		},
	})
}

// parseIntParam mengurai string menjadi integer dengan nilai default jika parsing gagal.
func parseIntParam(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return defaultVal
	}
	return n
}

// parseTimeParam mengurai string waktu ISO 8601 dengan nilai default jika parsing gagal.
func parseTimeParam(s string, defaultVal time.Time) time.Time {
	if s == "" {
		return defaultVal
	}
	t, err := time.Parse("2006-01-02T15:04", s)
	if err != nil {
		return defaultVal
	}
	return t
}
