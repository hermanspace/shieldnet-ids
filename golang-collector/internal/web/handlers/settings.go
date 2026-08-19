// settings.go menangani halaman pengaturan Decision Engine dari web interface.
// Nilai yang diubah disimpan sebagai override di tabel app_settings; parameter
// tanpa override tetap memakai nilai bawaan dari environment (.env).
// Python Analyst membaca tabel yang sama secara berkala sehingga perubahan
// berlaku tanpa perlu me-restart container.
package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
)

// SettingDef mendefinisikan satu parameter Decision Engine yang bisa diatur dari UI.
type SettingDef struct {
	Key         string  // Nama parameter (sama dengan nama env var)
	Label       string  // Label yang ditampilkan di UI
	Description string  // Penjelasan fungsi parameter
	Impact      string  // Dampak jika nilai dinaikkan/diturunkan
	Min         float64 // Batas bawah validasi
	Max         float64 // Batas atas validasi
	Step        string  // Step untuk input number HTML
	IsInt       bool    // true jika nilai harus bilangan bulat
}

// settingDefs adalah daftar parameter Decision Engine yang dapat diatur dari UI,
// berurutan sesuai alur keputusan: deteksi → keyakinan → blokir.
var settingDefs = []SettingDef{
	{
		Key:   "ANOMALY_THRESHOLD",
		Label: "Ambang Deteksi Anomali",
		Description: "Skor decision_function di bawah nilai ini dianggap intrusi. " +
			"Batas alami scikit-learn adalah 0 (negatif = anomali, sesuai kalibrasi contamination).",
		Impact: "Lebih rendah (mis. -0.15) = deteksi lebih ketat, risiko serangan lolos (FN) naik. " +
			"Lebih tinggi (mendekati 0 atau positif) = lebih sensitif, risiko alarm palsu (FP) naik.",
		Min: -1, Max: 1, Step: "0.01",
	},
	{
		Key:   "BLOCK_SCORE_THRESHOLD",
		Label: "Ambang Skor Blokir",
		Description: "Syarat pertama blokir otomatis: skor anomali harus LEBIH NEGATIF dari nilai ini. " +
			"Harus lebih kecil atau sama dengan Ambang Deteksi.",
		Impact: "Lebih rendah = hanya serangan paling ekstrem yang diblokir otomatis (konservatif). " +
			"Lebih tinggi = lebih banyak blokir otomatis, risiko memblokir trafik normal.",
		Min: -1, Max: 1, Step: "0.01",
	},
	{
		Key:   "BLOCK_CONFIDENCE_THRESHOLD",
		Label: "Ambang Keyakinan Blokir",
		Description: "Syarat kedua blokir otomatis: keyakinan gabungan (kepastian skor × kecukupan data) " +
			"harus mencapai nilai ini (0–1).",
		Impact: "Lebih tinggi = butuh bukti lebih kuat sebelum blokir (presisi naik). " +
			"Lebih rendah = blokir lebih agresif.",
		Min: 0, Max: 1, Step: "0.05",
	},
	{
		Key:   "CONFIDENCE_FULL_SAMPLES",
		Label: "Sampel untuk Keyakinan Penuh",
		Description: "Jumlah minimum aktivitas IP dalam jendela analisis agar faktor kecukupan data " +
			"bernilai penuh (1.0). Di bawah ini keyakinan dikurangi proporsional.",
		Impact: "Lebih tinggi = IP dengan sedikit log tidak akan pernah diblokir otomatis. " +
			"Lebih rendah = keputusan blokir bisa diambil dari bukti yang lebih sedikit.",
		Min: 1, Max: 1000, Step: "1", IsInt: true,
	},
}

// settingsEnvDefaults memetakan setiap parameter ke nilai bawaan .env
// (atau nilai bawaan program jika env var tidak diset).
func settingsEnvDefaults() map[string]string {
	return map[string]string{
		"ANOMALY_THRESHOLD":          envOr("ANOMALY_THRESHOLD", "-0.1"),
		"BLOCK_SCORE_THRESHOLD":      envOr("BLOCK_SCORE_THRESHOLD", "-0.3"),
		"BLOCK_CONFIDENCE_THRESHOLD": envOr("BLOCK_CONFIDENCE_THRESHOLD", "0.75"),
		"CONFIDENCE_FULL_SAMPLES":    envOr("CONFIDENCE_FULL_SAMPLES", "10"),
	}
}

// effectiveSettings mengembalikan nilai efektif seluruh parameter Decision Engine:
// override dari tabel app_settings jika ada, selain itu nilai bawaan .env.
// Dipakai juga oleh halaman /intrusions dan /about agar angka yang tampil
// selalu sama dengan yang dipakai Python Analyst.
func effectiveSettings() (map[string]string, map[string]database.AppSetting) {
	defaults := settingsEnvDefaults()
	overrides, err := database.GetAppSettings()
	if err != nil {
		overrides = map[string]database.AppSetting{}
	}

	effective := make(map[string]string, len(defaults))
	for key, def := range defaults {
		if ov, ok := overrides[key]; ok {
			effective[key] = ov.Value
		} else {
			effective[key] = def
		}
	}
	return effective, overrides
}

// settingRow adalah data satu baris parameter untuk template settings.html.
type settingRow struct {
	Def        SettingDef
	EnvDefault string
	Effective  string
	Override   *database.AppSetting // nil jika tidak ada override
}

// Settings menampilkan halaman pengaturan Decision Engine (khusus admin).
func (h *Handlers) Settings(w http.ResponseWriter, r *http.Request) {
	h.renderSettings(w, r, "")
}

// renderSettings merender halaman pengaturan dengan pesan flash opsional.
func (h *Handlers) renderSettings(w http.ResponseWriter, r *http.Request, flash string) {
	_, overrides := effectiveSettings()
	defaults := settingsEnvDefaults()

	rows := make([]settingRow, 0, len(settingDefs))
	for _, def := range settingDefs {
		row := settingRow{Def: def, EnvDefault: defaults[def.Key], Effective: defaults[def.Key]}
		if ov, ok := overrides[def.Key]; ok {
			ovCopy := ov
			row.Override = &ovCopy
			row.Effective = ov.Value
		}
		rows = append(rows, row)
	}

	h.render(w, r, "settings.html", PageData{
		Title: "Pengaturan Decision Engine",
		Flash: flash,
		Data: map[string]interface{}{
			"rows": rows,
		},
	})
}

// SaveSettings memvalidasi dan menyimpan override parameter dari form UI.
func (h *Handlers) SaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}

	username := auth.GetLoggedInUser(r)
	defaults := settingsEnvDefaults()

	// Kumpulkan dan validasi seluruh nilai terlebih dahulu — simpan hanya jika
	// semuanya valid, agar konfigurasi tidak tersimpan setengah jadi.
	parsed := map[string]float64{}
	for _, def := range settingDefs {
		raw := r.FormValue(def.Key)
		if raw == "" {
			h.renderSettings(w, r, fmt.Sprintf("Nilai %s tidak boleh kosong.", def.Label))
			return
		}
		val, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			h.renderSettings(w, r, fmt.Sprintf("Nilai %s bukan angka yang valid.", def.Label))
			return
		}
		if val < def.Min || val > def.Max {
			h.renderSettings(w, r, fmt.Sprintf("Nilai %s harus berada pada rentang %g sampai %g.",
				def.Label, def.Min, def.Max))
			return
		}
		if def.IsInt && val != float64(int(val)) {
			h.renderSettings(w, r, fmt.Sprintf("Nilai %s harus bilangan bulat.", def.Label))
			return
		}
		parsed[def.Key] = val
	}

	// Validasi antar-parameter: ambang blokir harus <= ambang deteksi,
	// karena blokir adalah subset dari deteksi.
	if parsed["BLOCK_SCORE_THRESHOLD"] > parsed["ANOMALY_THRESHOLD"] {
		h.renderSettings(w, r, "Ambang Skor Blokir harus lebih kecil atau sama dengan Ambang Deteksi Anomali "+
			"(blokir adalah kondisi yang lebih ketat daripada deteksi).")
		return
	}

	// Simpan sebagai override hanya jika berbeda dari nilai bawaan .env;
	// jika sama persis, hapus override agar status kembali "bawaan".
	for _, def := range settingDefs {
		var valStr string
		if def.IsInt {
			valStr = strconv.Itoa(int(parsed[def.Key]))
		} else {
			valStr = strconv.FormatFloat(parsed[def.Key], 'f', -1, 64)
		}

		if valStr == defaults[def.Key] {
			database.DeleteAppSetting(def.Key)
			continue
		}
		if err := database.UpsertAppSetting(def.Key, valStr, username); err != nil {
			h.renderSettings(w, r, fmt.Sprintf("Gagal menyimpan %s: %v", def.Label, err))
			return
		}
	}

	h.renderSettings(w, r, "Pengaturan berhasil disimpan. Python Analyst menerapkan nilai baru maksimal 10 detik ke depan tanpa restart.")
}

// ResetSettings menghapus seluruh override sehingga semua parameter kembali ke .env.
func (h *Handlers) ResetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}
	if err := database.DeleteAllAppSettings(); err != nil {
		h.renderSettings(w, r, fmt.Sprintf("Gagal mereset pengaturan: %v", err))
		return
	}
	h.renderSettings(w, r, "Seluruh pengaturan dikembalikan ke nilai bawaan .env.")
}
