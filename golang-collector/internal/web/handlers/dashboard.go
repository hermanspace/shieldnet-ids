// dashboard.go menangani halaman utama yang menampilkan ringkasan statistik sistem IDS.
// Termasuk kartu statistik, grafik intrusi, dan tabel intrusi terbaru.
package handlers

import (
	"encoding/json"
	"net/http"

	"thesis-ids/golang-collector/internal/database"
)

// Dashboard menampilkan halaman ringkasan sistem dengan statistik real-time.
func (h *Handlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	// Ambil statistik utama dari database
	stats, err := database.GetSyslogStats()
	if err != nil {
		stats = map[string]int{} // Gunakan data kosong jika query gagal
	}

	// Ambil 10 intrusi terbaru untuk ditampilkan di tabel
	recentIntrusions, err := database.GetRecentIntrusions(10)
	if err != nil {
		recentIntrusions = nil
	}

	h.render(w, r, "dashboard.html", PageData{
		Title: "Dashboard",
		Data: map[string]interface{}{
			"stats":             stats,
			"recent_intrusions": recentIntrusions,
		},
	})
}

// APIStats mengembalikan data statistik terkini dalam format JSON untuk HTMX polling.
// Endpoint ini dipanggil setiap 30 detik oleh halaman dashboard.
func (h *Handlers) APIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := database.GetSyslogStats()
	if err != nil {
		http.Error(w, "Gagal ambil statistik", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// APIIntrusionsChart mengembalikan data intrusi per jam untuk grafik Chart.js.
// Format data disesuaikan dengan kebutuhan library Chart.js.
func (h *Handlers) APIIntrusionsChart(w http.ResponseWriter, r *http.Request) {
	data, err := database.GetIntrusionsPerHour(24)
	if err != nil {
		http.Error(w, "Gagal ambil data grafik", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
