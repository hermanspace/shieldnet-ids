// handlers.go mendefinisikan struct Handlers utama yang menyimpan template
// dan menyediakan fungsi helper yang digunakan bersama oleh semua handler.
package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

	"thesis-ids/golang-collector/internal/auth"
)

// Handlers menyimpan direktori template dan function map untuk rendering.
type Handlers struct {
	tmplDir string
	funcs   template.FuncMap
}

// NewHandlers membuat instance Handlers baru.
func NewHandlers(tmplDir string, funcs template.FuncMap) *Handlers {
	return &Handlers{tmplDir: tmplDir, funcs: funcs}
}

// PageData adalah struct umum yang dikirim ke semua template sebagai data halaman.
// Menyertakan informasi pengguna yang login untuk ditampilkan di navbar.
type PageData struct {
	Title    string
	Username string
	Role     string
	Data     interface{} // Data spesifik tiap halaman
	Flash    string      // Pesan sukses/error sementara
}

// render merender template HTML dengan parsing per-request sehingga setiap halaman
// memiliki template set tersendiri — menghindari tabrakan definisi {{define "content"}}.
func (h *Handlers) render(w http.ResponseWriter, r *http.Request, templateName string, data PageData) {
	data.Username = auth.GetLoggedInUser(r)
	data.Role = auth.GetUserRole(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var tmpl *template.Template
	var err error
	var execName string

	if templateName == "auth.html" {
		// Halaman login menggunakan layout auth yang berdiri sendiri
		tmpl, err = template.New("").Funcs(h.funcs).ParseFiles(
			filepath.Join(h.tmplDir, "layout", "auth.html"),
		)
		execName = "auth.html"
	} else {
		// Halaman biasa: parse base layout + halaman spesifik dalam template set baru
		// ParseFiles pertama menjadi template utama, tapi kita eksekusi "base"
		tmpl, err = template.New("").Funcs(h.funcs).ParseFiles(
			filepath.Join(h.tmplDir, "layout", "base.html"),
			filepath.Join(h.tmplDir, templateName),
		)
		execName = "base"
	}

	if err != nil {
		http.Error(w, "Gagal memuat template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, execName, data); err != nil {
		http.Error(w, "Gagal merender halaman: "+err.Error(), http.StatusInternalServerError)
	}
}

// redirect melakukan HTTP redirect ke URL yang ditentukan.
func redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusFound)
}
