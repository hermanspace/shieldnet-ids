// middleware.go menyediakan middleware untuk memproteksi route yang memerlukan login.
// Setiap request ke halaman yang dilindungi akan dicek sessionnya terlebih dahulu.
package auth

import (
	"net/http"
)

// RequireLogin adalah middleware yang memastikan hanya pengguna yang sudah login
// yang dapat mengakses route yang dilindungi. Jika belum login, redirect ke halaman login.
func RequireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := GetLoggedInUser(r)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// RequireAdmin adalah middleware yang hanya mengizinkan user dengan role admin.
// Digunakan untuk melindungi halaman manajemen user.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := GetLoggedInUser(r)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		role := GetUserRole(r)
		if role != "admin" {
			http.Error(w, "Akses ditolak: hanya admin yang dapat mengakses halaman ini", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// RequireOperator adalah middleware yang mengizinkan admin dan operator.
// Digunakan untuk halaman manajemen node dan access list.
func RequireOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := GetLoggedInUser(r)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		role := GetUserRole(r)
		if role != "admin" && role != "operator" {
			http.Error(w, "Akses ditolak: hanya admin dan operator yang dapat mengakses halaman ini", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
