// access_list.go menangani halaman whitelist dan blacklist manual.
// IP di whitelist tidak akan diproses ML, IP di blacklist langsung diblokir.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
	"thesis-ids/golang-collector/internal/mikrotik"
)

// AccessList menampilkan halaman whitelist dan blacklist dalam tampilan tab.
func (h *Handlers) AccessList(w http.ResponseWriter, r *http.Request) {
	whitelist, err := database.GetAccessList("whitelist")
	if err != nil {
		whitelist = nil
	}

	blacklist, err := database.GetAccessList("blacklist")
	if err != nil {
		blacklist = nil
	}

	// Tentukan tab aktif dari query parameter (default: whitelist)
	activeTab := r.URL.Query().Get("tab")
	if activeTab != "blacklist" {
		activeTab = "whitelist"
	}

	h.render(w, r, "access_list.html", PageData{
		Title: "Whitelist & Blacklist",
		Data: map[string]interface{}{
			"whitelist":  whitelist,
			"blacklist":  blacklist,
			"active_tab": activeTab,
		},
	})
}

// AddAccessList memproses penambahan IP baru ke whitelist atau blacklist.
func (h *Handlers) AddAccessList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/access-list", http.StatusFound)
		return
	}

	ipAddress := r.FormValue("ip_address")
	listType := r.FormValue("list_type")
	reason := r.FormValue("reason")
	expiresStr := r.FormValue("expires_at")
	username := auth.GetLoggedInUser(r)

	if ipAddress == "" || (listType != "whitelist" && listType != "blacklist") {
		http.Redirect(w, r, "/access-list", http.StatusFound)
		return
	}

	// Parse waktu kadaluarsa jika diisi
	var expiresAt *time.Time
	if expiresStr != "" {
		t, err := time.Parse("2006-01-02T15:04", expiresStr)
		if err == nil {
			expiresAt = &t
		}
	}

	entry := database.AccessListEntry{
		IPAddress: ipAddress,
		ListType:  listType,
		Reason:    reason,
		AddedBy:   username,
		ExpiresAt: expiresAt,
	}
	database.InsertAccessList(entry)

	switch listType {
	case "blacklist":
		// Tambah ke blacklist → blokir IP di semua node MikroTik sekarang juga
		go mikrotik.DistributeBlock(ipAddress)
	case "whitelist":
		// Tambah ke whitelist → hapus blokir di semua node MikroTik jika sebelumnya diblokir
		go mikrotik.RemoveBlock(ipAddress)
	}

	http.Redirect(w, r, "/access-list?tab="+listType, http.StatusFound)
}

// DeleteAccessList menghapus aturan dari access list berdasarkan ID-nya.
// Jika entry yang dihapus adalah blacklist, IP dihapus dari ids-blocked di semua MikroTik.
func (h *Handlers) DeleteAccessList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/access-list", http.StatusFound)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/access-list", http.StatusFound)
		return
	}

	// Ambil data entry sebelum dihapus agar tahu IP dan tipe list-nya
	entry, err := database.GetAccessListByID(id)
	if err != nil {
		http.Redirect(w, r, "/access-list", http.StatusFound)
		return
	}

	database.DeleteAccessList(id)

	// Hapus blokir di semua MikroTik jika entry yang dihapus adalah blacklist
	if entry.ListType == "blacklist" {
		go mikrotik.RemoveBlock(entry.IPAddress)
	}

	http.Redirect(w, r, "/access-list?tab="+entry.ListType, http.StatusFound)
}
