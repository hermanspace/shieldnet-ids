// user.go menangani halaman manajemen pengguna dashboard web dan proses login/logout.
// Hanya admin yang dapat mengakses halaman manajemen user sesuai sistem role.
package handlers

import (
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
)

// Users menampilkan semua pengguna yang terdaftar dalam sistem.
func (h *Handlers) Users(w http.ResponseWriter, r *http.Request) {
	users, err := database.GetAllUsers()
	if err != nil {
		users = nil
	}

	h.render(w, r, "users.html", PageData{
		Title: "Manajemen Pengguna",
		Data:  users,
	})
}

// AddUser memproses penambahan pengguna baru dengan password yang di-hash menggunakan bcrypt.
func (h *Handlers) AddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	role := r.FormValue("role")
	fullName := r.FormValue("full_name")

	if username == "" || password == "" {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	// Validasi role yang diizinkan
	if role != "admin" && role != "operator" && role != "viewer" {
		role = "viewer"
	}

	// Hash password sebelum disimpan ke database untuk keamanan
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Gagal memproses password", http.StatusInternalServerError)
		return
	}

	user := database.User{
		Username: username,
		Password: string(hashedPassword),
		Role:     role,
		FullName: fullName,
	}
	database.InsertUser(user)
	http.Redirect(w, r, "/users", http.StatusFound)
}

// ToggleUser mengaktifkan atau menonaktifkan akun pengguna.
func (h *Handlers) ToggleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	active := r.FormValue("active") == "true"
	database.SetUserActive(id, active)
	http.Redirect(w, r, "/users", http.StatusFound)
}

// DeleteUser menghapus pengguna dari database berdasarkan ID-nya.
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}

	database.DeleteUser(id)
	http.Redirect(w, r, "/users", http.StatusFound)
}

// Login menampilkan halaman login dan memproses autentikasi pengguna.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	// Jika sudah login, langsung ke dashboard
	if username := auth.GetLoggedInUser(r); username != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		h.render(w, r, "auth.html", PageData{Title: "Login"})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Cari user di database
	user, err := database.GetUserByUsername(username)
	if err != nil || !user.IsActive {
		h.render(w, r, "auth.html", PageData{
			Title: "Login",
			Flash: "Username atau password salah, atau akun tidak aktif",
		})
		return
	}

	// Verifikasi password menggunakan bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		h.render(w, r, "auth.html", PageData{
			Title: "Login",
			Flash: "Username atau password salah",
		})
		return
	}

	// Simpan session dan perbarui waktu login terakhir
	if err := auth.SetUserSession(w, r, username, user.Role); err != nil {
		http.Error(w, "Gagal membuat session", http.StatusInternalServerError)
		return
	}
	database.UpdateLastLogin(username)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// Logout menghapus session pengguna dan mengarahkan kembali ke halaman login.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}
