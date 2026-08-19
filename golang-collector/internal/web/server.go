// server.go mendefinisikan HTTP server dan semua routing untuk web interface IDS.
// Menggunakan net/http standar Go tanpa framework tambahan agar sederhana.
package web

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"thesis-ids/golang-collector/config"
	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/web/handlers"
)

// Server merepresentasikan HTTP server aplikasi web IDS.
type Server struct {
	cfg     *config.Config
	tmplDir string
}

// NewServer membuat instance Server baru dan memverifikasi direktori template tersedia.
func NewServer(cfg *config.Config) (*Server, error) {
	templateDir := findTemplateDir()
	if templateDir == "" {
		return nil, fmt.Errorf("direktori template tidak ditemukan")
	}
	log.Printf("Template dikonfigurasi dari: %s", templateDir)
	return &Server{cfg: cfg, tmplDir: templateDir}, nil
}

// findTemplateDir mencari lokasi direktori template dari beberapa kemungkinan path.
// Mendukung lokasi saat pengembangan lokal maupun saat berjalan di dalam Docker container.
func findTemplateDir() string {
	candidates := []string{
		// Saat berjalan di Docker (setelah COPY ke /app)
		"/app/internal/web/templates",
		// Saat dijalankan langsung dari direktori golang-collector
		"internal/web/templates",
		// Saat dijalankan dari cmd/
		"../internal/web/templates",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return ""
}

// findStaticDir mencari lokasi direktori static files.
func findStaticDir() string {
	candidates := []string{
		"/app/static",
		"static",
		"../static",
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return "static"
}

// Start memulai HTTP server dan mendaftarkan semua route.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Inisialisasi semua handler dengan direktori template dan function map
	h := handlers.NewHandlers(s.tmplDir, templateFuncs())

	// Route publik (tidak perlu login)
	mux.HandleFunc("/login", h.Login)
	mux.HandleFunc("/logout", h.Logout)

	// Route yang memerlukan login (semua role)
	mux.HandleFunc("/", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		} else {
			http.NotFound(w, r)
		}
	}))
	mux.HandleFunc("/dashboard", auth.RequireLogin(h.Dashboard))
	mux.HandleFunc("/syslogs", auth.RequireLogin(h.Syslogs))
	mux.HandleFunc("/intrusions", auth.RequireLogin(h.Intrusions))
	mux.HandleFunc("/about", auth.RequireLogin(h.About))

	// Route yang memerlukan minimal role operator
	mux.HandleFunc("/nodes", auth.RequireOperator(h.Nodes))
	mux.HandleFunc("/nodes/add", auth.RequireOperator(h.AddNode))
	mux.HandleFunc("/nodes/toggle", auth.RequireOperator(h.ToggleNode))
	mux.HandleFunc("/nodes/delete", auth.RequireOperator(h.DeleteNode))
	mux.HandleFunc("/nodes/status", auth.RequireOperator(h.NodeStatus))

	mux.HandleFunc("/access-list", auth.RequireOperator(h.AccessList))
	mux.HandleFunc("/access-list/add", auth.RequireOperator(h.AddAccessList))
	mux.HandleFunc("/access-list/delete", auth.RequireOperator(h.DeleteAccessList))

	mux.HandleFunc("/intrusions/override", auth.RequireOperator(h.OverrideIntrusion))

	// Route khusus admin
	mux.HandleFunc("/settings", auth.RequireAdmin(h.Settings))
	mux.HandleFunc("/settings/save", auth.RequireAdmin(h.SaveSettings))
	mux.HandleFunc("/settings/reset", auth.RequireAdmin(h.ResetSettings))
	mux.HandleFunc("/users", auth.RequireAdmin(h.Users))
	mux.HandleFunc("/users/add", auth.RequireAdmin(h.AddUser))
	mux.HandleFunc("/users/toggle", auth.RequireAdmin(h.ToggleUser))
	mux.HandleFunc("/users/delete", auth.RequireAdmin(h.DeleteUser))

	// Endpoint API untuk HTMX polling
	mux.HandleFunc("/api/stats", auth.RequireLogin(h.APIStats))
	mux.HandleFunc("/api/intrusions/chart", auth.RequireLogin(h.APIIntrusionsChart))

	// Static files (CSS, JS)
	staticDir := findStaticDir()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	addr := fmt.Sprintf("0.0.0.0:%s", s.cfg.WebPort)
	log.Printf("Web server berjalan di http://%s", addr)
	return http.ListenAndServe(addr, mux)
}

// templateFuncs mendefinisikan fungsi-fungsi tambahan yang tersedia di template HTML.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatBool": func(b bool) string {
			if b {
				return "Ya"
			}
			return "Tidak"
		},
		"boolToStatus": func(b bool) string {
			if b {
				return "Aktif"
			}
			return "Nonaktif"
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		// mul mendukung dua tipe berbeda untuk kompatibilitas template
		"mul": func(a, b interface{}) float64 {
			var fa, fb float64
			switch v := a.(type) {
			case int:
				fa = float64(v)
			case float64:
				fa = v
			}
			switch v := b.(type) {
			case int:
				fb = float64(v)
			case float64:
				fb = v
			}
			return fa * fb
		},
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"gt": func(a, b int) bool { return a > b },
		"lt": func(a, b int) bool { return a < b },
		"ge": func(a, b int) bool { return a >= b },
		// scoreBarWidth mengubah skor anomali negatif menjadi lebar bar (0–100%)
		// Skor 0.0 → 0%, skor −0.8 atau lebih negatif → 100%
		"scoreBarWidth": func(score float64) int {
			if score >= 0 {
				return 0
			}
			w := int((-score / 0.8) * 100)
			if w > 100 {
				return 100
			}
			return w
		},
		// scoreColor mengembalikan kelas warna Tailwind berdasarkan skor anomali
		"scoreColor": func(score float64) string {
			switch {
			case score < -0.3:
				return "text-red-600 font-bold"
			case score < -0.1:
				return "text-orange-600 font-semibold"
			default:
				return "text-green-600"
			}
		},
		// scoreBgColor mengembalikan warna bar berdasarkan skor anomali
		"scoreBgColor": func(score float64) string {
			switch {
			case score < -0.3:
				return "bg-red-500"
			case score < -0.1:
				return "bg-orange-400"
			default:
				return "bg-yellow-300"
			}
		},
		// confColor mengembalikan kelas warna Tailwind berdasarkan nilai keyakinan
		"confColor": func(conf float64) string {
			switch {
			case conf >= 0.75:
				return "text-red-600"
			case conf >= 0.60:
				return "text-orange-500"
			default:
				return "text-gray-600"
			}
		},
		// confBgColor mengembalikan warna bar keyakinan
		"confBgColor": func(conf float64) string {
			switch {
			case conf >= 0.75:
				return "bg-red-400"
			case conf >= 0.60:
				return "bg-orange-400"
			default:
				return "bg-gray-400"
			}
		},
	}
}
