// about.go menangani halaman "Tentang Sistem" — penjelasan lengkap cara kerja
// sistem, arsitektur, formula machine learning, dan parameter yang digunakan.
// Halaman ini dirancang sebagai bahan penjelasan saat presentasi/sidang tesis.
package handlers

import (
	"net/http"
	"os"
)

// envOr mengembalikan nilai environment variable, atau nilai default jika kosong.
// Digunakan agar angka yang tampil di halaman selalu sinkron dengan konfigurasi
// aktif layanan Python Analyst (dibagikan melalui file .env yang sama).
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// About menampilkan halaman penjelasan sistem untuk semua role yang login.
func (h *Handlers) About(w http.ResponseWriter, r *http.Request) {
	// Nilai efektif Decision Engine: override dari UI (app_settings) jika ada,
	// selain itu nilai bawaan .env — sama dengan yang dipakai Python Analyst.
	eff, _ := effectiveSettings()

	h.render(w, r, "about.html", PageData{
		Title: "Tentang Sistem",
		Data: map[string]interface{}{
			// Parameter model Isolation Forest (default sama dengan config.py)
			"n_estimators":  envOr("IF_N_ESTIMATORS", "100"),
			"contamination": envOr("IF_CONTAMINATION", "0.1"),
			"max_samples":   envOr("IF_MAX_SAMPLES", "256"),

			// Ambang keputusan Decision Engine (nilai efektif)
			"anomaly_threshold": eff["ANOMALY_THRESHOLD"],
			"block_score":       eff["BLOCK_SCORE_THRESHOLD"],
			"block_confidence":  eff["BLOCK_CONFIDENCE_THRESHOLD"],
			"confidence_full_n": eff["CONFIDENCE_FULL_SAMPLES"],
			"analysis_window":   envOr("ANALYSIS_WINDOW_MINUTES", "10"),
			"retrain_interval":  envOr("MODEL_RETRAIN_INTERVAL", "100"),
		},
	})
}
