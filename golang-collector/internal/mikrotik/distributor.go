// distributor.go bertanggung jawab mendistribusikan access list (daftar IP yang diblokir)
// ke semua node MikroTik yang aktif secara bersamaan.
// Ini adalah inti dari konsep "deteksi kolaboratif": satu node diserang,
// semua node langsung terlindungi.
package mikrotik

import (
	"fmt"
	"log"
	"sync"
	"time"

	"thesis-ids/golang-collector/internal/database"
)

const (
	// BlockListName adalah nama address-list di MikroTik untuk IP yang diblokir sistem IDS
	BlockListName = "ids-blocked"
	// BlockTimeout adalah durasi pemblokiran per IP (dalam detik, 0 = permanen)
	BlockTimeout = "1d" // 1 hari, sesuai rekomendasi tesis
)

// DistributionResult merepresentasikan hasil distribusi ke satu node.
type DistributionResult struct {
	NodeID  string
	Success bool
	Error   error
}

// DistributeBlock mendistribusikan pemblokiran satu IP ke semua node aktif secara paralel.
// Setiap node diproses dalam goroutine terpisah untuk efisiensi.
// Mengembalikan daftar node yang berhasil menerima pemblokiran.
func DistributeBlock(sourceIP string) ([]string, error) {
	// Ambil semua node aktif dari database
	nodes, err := database.GetActiveNodes()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil daftar node aktif: %w", err)
	}

	if len(nodes) == 0 {
		log.Printf("Tidak ada node aktif untuk menerima pemblokiran IP %s", sourceIP)
		return nil, nil
	}

	// Gunakan WaitGroup dan channel untuk memproses semua node secara paralel
	var wg sync.WaitGroup
	results := make(chan DistributionResult, len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go func(n database.MikrotikNode) {
			defer wg.Done()
			err := blockIPOnNode(sourceIP, n)
			results <- DistributionResult{
				NodeID:  n.NodeID,
				Success: err == nil,
				Error:   err,
			}
		}(node)
	}

	// Tutup channel setelah semua goroutine selesai
	go func() {
		wg.Wait()
		close(results)
	}()

	// Kumpulkan hasil distribusi
	var successNodes []string
	for result := range results {
		if result.Success {
			successNodes = append(successNodes, result.NodeID)
			log.Printf("[OK] IP %s berhasil diblokir di node %s", sourceIP, result.NodeID)
		} else {
			log.Printf("[GAGAL] Gagal blokir IP %s di node %s: %v", sourceIP, result.NodeID, result.Error)
		}
	}

	// Tandai distribusi selesai di database
	if len(successNodes) > 0 {
		if dbErr := database.MarkIntrusionDistributed(sourceIP, successNodes); dbErr != nil {
			log.Printf("Gagal update status distribusi di database: %v", dbErr)
		}
	}

	return successNodes, nil
}

// blockIPOnNode menambahkan satu IP ke address-list "ids-blocked" di satu node MikroTik.
// Menggunakan perintah RouterOS API: /ip/firewall/address-list/add
func blockIPOnNode(sourceIP string, node database.MikrotikNode) error {
	// Buka koneksi ke node
	client, err := NewClient(node.NodeID, node.IPAddress, node.APIPort, node.Username, node.Password)
	if err != nil {
		return err
	}
	defer client.Close()

	// Cek apakah IP sudah ada di address-list untuk menghindari duplikat
	reply, err := client.RunCommand(
		"/ip/firewall/address-list/print",
		"?list="+BlockListName,
		"?address="+sourceIP,
	)
	if err == nil && len(reply.Re) > 0 {
		// IP sudah ada, tidak perlu ditambahkan lagi
		return nil
	}

	// Tambahkan IP ke address-list dengan timeout otomatis
	_, err = client.RunCommand(
		"/ip/firewall/address-list/add",
		"=list="+BlockListName,
		"=address="+sourceIP,
		"=timeout="+BlockTimeout,
		"=comment=IDS-blocked-"+time.Now().Format("2006-01-02"),
	)
	if err != nil {
		return fmt.Errorf("gagal tambah IP ke address-list: %w", err)
	}

	return nil
}

// RemoveBlock menghapus pemblokiran satu IP dari semua node aktif.
// Dipanggil ketika IP dipindahkan ke whitelist oleh operator.
func RemoveBlock(sourceIP string) {
	nodes, err := database.GetActiveNodes()
	if err != nil {
		log.Printf("Gagal ambil node untuk hapus blokir: %v", err)
		return
	}

	for _, node := range nodes {
		go func(n database.MikrotikNode) {
			if err := removeIPFromNode(sourceIP, n); err != nil {
				log.Printf("Gagal hapus blokir IP %s dari node %s: %v", sourceIP, n.NodeID, err)
			}
		}(node)
	}
}

// removeIPFromNode menghapus satu IP dari address-list di satu node MikroTik.
func removeIPFromNode(sourceIP string, node database.MikrotikNode) error {
	client, err := NewClient(node.NodeID, node.IPAddress, node.APIPort, node.Username, node.Password)
	if err != nil {
		return err
	}
	defer client.Close()

	// Cari ID entry yang sesuai di address-list
	reply, err := client.RunCommand(
		"/ip/firewall/address-list/print",
		"?list="+BlockListName,
		"?address="+sourceIP,
	)
	if err != nil || len(reply.Re) == 0 {
		return nil // Entry tidak ditemukan, tidak perlu dihapus
	}

	// Hapus entry menggunakan ID-nya
	for _, re := range reply.Re {
		id := re.Map[".id"]
		if id != "" {
			client.RunCommand("/ip/firewall/address-list/remove", "=.id="+id)
		}
	}
	return nil
}

// CheckNodeStatus mengecek apakah sebuah node bisa dihubungi melalui API.
// Digunakan untuk menampilkan indikator status di halaman web.
func CheckNodeStatus(node database.MikrotikNode) bool {
	client, err := NewClient(node.NodeID, node.IPAddress, node.APIPort, node.Username, node.Password)
	if err != nil {
		return false
	}
	defer client.Close()
	return client.TestConnection()
}
