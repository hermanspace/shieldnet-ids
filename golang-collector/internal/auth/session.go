// session.go mengelola session login pengguna menggunakan cookie terenkripsi.
// Setiap sesi menyimpan informasi pengguna yang login agar tidak perlu
// query database di setiap request.
package auth

import (
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	// SessionName adalah nama cookie session yang disimpan di browser
	SessionName = "ids-session"
	// SessionKeyUser adalah key untuk menyimpan username dalam session
	SessionKeyUser = "username"
	// SessionKeyRole adalah key untuk menyimpan role dalam session
	SessionKeyRole = "role"
)

// Store adalah penyimpanan session global yang digunakan di seluruh aplikasi.
var Store *sessions.CookieStore

// InitSessionStore menginisialisasi penyimpanan session dengan secret key.
// Secret key digunakan untuk menandatangani dan mengenkripsi cookie session.
func InitSessionStore(secret string) {
	Store = sessions.NewCookieStore([]byte(secret))
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // Session berlaku 7 hari
		HttpOnly: true,      // Cegah akses JavaScript ke cookie (keamanan XSS)
		Secure:   false,     // Set true jika menggunakan HTTPS di produksi
	}
}

// GetSession mengambil data session dari request HTTP.
func GetSession(r *http.Request) (*sessions.Session, error) {
	return Store.Get(r, SessionName)
}

// SetUserSession menyimpan informasi user ke dalam session setelah login berhasil.
func SetUserSession(w http.ResponseWriter, r *http.Request, username, role string) error {
	session, err := Store.Get(r, SessionName)
	if err != nil {
		return err
	}
	session.Values[SessionKeyUser] = username
	session.Values[SessionKeyRole] = role
	return session.Save(r, w)
}

// ClearSession menghapus data session saat user logout.
func ClearSession(w http.ResponseWriter, r *http.Request) error {
	session, err := Store.Get(r, SessionName)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1 // Perintahkan browser untuk hapus cookie
	return session.Save(r, w)
}

// GetLoggedInUser mengambil username dari session aktif.
// Mengembalikan string kosong jika tidak ada session aktif.
func GetLoggedInUser(r *http.Request) string {
	session, err := Store.Get(r, SessionName)
	if err != nil {
		return ""
	}
	username, _ := session.Values[SessionKeyUser].(string)
	return username
}

// GetUserRole mengambil role pengguna dari session aktif.
func GetUserRole(r *http.Request) string {
	session, err := Store.Get(r, SessionName)
	if err != nil {
		return ""
	}
	role, _ := session.Values[SessionKeyRole].(string)
	return role
}
