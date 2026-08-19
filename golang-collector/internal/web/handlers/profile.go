// profile.go menangani halaman profil pengguna yang sedang login,
// khususnya fitur ubah password mandiri (tersedia untuk semua role).
package handlers

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
)

// Profile menampilkan halaman profil berisi form ubah password.
func (h *Handlers) Profile(w http.ResponseWriter, r *http.Request) {
	h.renderProfile(w, r, "")
}

// renderProfile merender halaman profil dengan pesan flash opsional.
func (h *Handlers) renderProfile(w http.ResponseWriter, r *http.Request, flash string) {
	h.render(w, r, "profile.html", PageData{
		Title: "Profil & Ubah Password",
		Flash: flash,
	})
}

// ChangeOwnPassword memproses penggantian password oleh pengguna yang sedang
// login. Password lama wajib diverifikasi terlebih dahulu agar sesi yang
// dibajak tidak bisa mengambil alih akun secara permanen.
func (h *Handlers) ChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	username := auth.GetLoggedInUser(r)
	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	// Validasi input dasar
	if newPassword != confirm {
		h.renderProfile(w, r, "Konfirmasi password baru tidak sama.")
		return
	}
	if len(newPassword) < 8 {
		h.renderProfile(w, r, "Password baru minimal 8 karakter.")
		return
	}
	if newPassword == oldPassword {
		h.renderProfile(w, r, "Password baru harus berbeda dari password lama.")
		return
	}

	// Verifikasi password lama terhadap hash di database
	user, err := database.GetUserByUsername(username)
	if err != nil {
		h.renderProfile(w, r, "Gagal memuat data pengguna.")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		h.renderProfile(w, r, "Password lama salah.")
		return
	}

	// Simpan password baru
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		h.renderProfile(w, r, "Gagal memproses password baru.")
		return
	}
	if err := database.UpdateUserPasswordByUsername(username, string(hashed)); err != nil {
		h.renderProfile(w, r, "Gagal menyimpan password baru.")
		return
	}

	h.renderProfile(w, r, "Password berhasil diubah. Gunakan password baru pada login berikutnya.")
}
