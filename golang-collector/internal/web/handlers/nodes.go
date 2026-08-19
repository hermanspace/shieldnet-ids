// nodes.go menangani halaman manajemen node MikroTik.
// Operator dapat menambah, mengaktifkan/menonaktifkan, dan menghapus node dari sini.
package handlers

import (
	"net/http"
	"strconv"

	"thesis-ids/golang-collector/internal/database"
	"thesis-ids/golang-collector/internal/mikrotik"
)

// Nodes menampilkan semua node MikroTik yang terdaftar beserta statusnya.
func (h *Handlers) Nodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := database.GetAllNodes()
	if err != nil {
		nodes = nil
	}

	h.render(w, r, "nodes.html", PageData{
		Title: "Manajemen Node MikroTik",
		Data:  nodes,
	})
}

// AddNode memproses form penambahan node MikroTik baru.
// Hanya menerima request POST dari form di halaman nodes.
func (h *Handlers) AddNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/nodes", http.StatusFound)
		return
	}

	apiPort, _ := strconv.Atoi(r.FormValue("api_port"))
	if apiPort == 0 {
		apiPort = 8728
	}

	node := database.MikrotikNode{
		NodeID:    r.FormValue("node_id"),
		IPAddress: r.FormValue("ip_address"),
		APIPort:   apiPort,
		Username:  r.FormValue("username"),
		Password:  r.FormValue("password"),
		Location:  r.FormValue("location"),
	}

	if node.NodeID == "" || node.IPAddress == "" {
		http.Redirect(w, r, "/nodes", http.StatusFound)
		return
	}

	database.InsertNode(node)
	http.Redirect(w, r, "/nodes", http.StatusFound)
}

// ToggleNode mengaktifkan atau menonaktifkan sebuah node berdasarkan status saat ini.
func (h *Handlers) ToggleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/nodes", http.StatusFound)
		return
	}

	nodeID := r.FormValue("node_id")
	activeStr := r.FormValue("active")
	active := activeStr == "true"

	database.SetNodeActive(nodeID, active)
	http.Redirect(w, r, "/nodes", http.StatusFound)
}

// DeleteNode menghapus node dari database berdasarkan ID-nya.
func (h *Handlers) DeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/nodes", http.StatusFound)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/nodes", http.StatusFound)
		return
	}

	database.DeleteNode(id)
	http.Redirect(w, r, "/nodes", http.StatusFound)
}

// NodeStatus mengecek status koneksi API satu node dan mengembalikan hasilnya sebagai JSON.
// Digunakan oleh HTMX untuk menampilkan indikator online/offline per node.
func (h *Handlers) NodeStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id diperlukan", http.StatusBadRequest)
		return
	}

	nodes, err := database.GetAllNodes()
	if err != nil {
		http.Error(w, "Gagal ambil data node", http.StatusInternalServerError)
		return
	}

	// Cari node yang diminta dan cek statusnya
	for _, node := range nodes {
		if node.NodeID == nodeID {
			online := mikrotik.CheckNodeStatus(node)
			if online {
				w.Write([]byte(`<span class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded-full">Online</span>`))
			} else {
				w.Write([]byte(`<span class="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded-full">Offline</span>`))
			}
			return
		}
	}

	http.Error(w, "Node tidak ditemukan", http.StatusNotFound)
}
