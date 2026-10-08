// resource.go membaca penggunaan sumber daya router (CPU, memori, uptime) melalui
// RouterOS API `/system/resource/print` dan menyimpannya secara berkala ke
// TimescaleDB. Ini menggantikan rancangan pemantauan SNMP pada Bab 3: metrik yang
// diambil setara dengan HOST-RESOURCES-MIB (hrProcessorLoad, hrStorageUsed) tanpa
// perlu membuka port SNMP tambahan di router.
package mikrotik

import (
	"log"
	"strconv"
	"strings"
	"time"

	"thesis-ids/golang-collector/internal/database"
)

// GetResource mengambil satu sampel sumber daya dari sebuah node.
func GetResource(node database.MikrotikNode) (*database.NodeResource, error) {
	client, err := NewClient(node.NodeID, node.IPAddress, node.APIPort, node.Username, node.Password)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	reply, err := client.RunCommand("/system/resource/print")
	if err != nil {
		return nil, err
	}
	if len(reply.Re) == 0 {
		return nil, nil
	}
	m := reply.Re[0].Map

	res := &database.NodeResource{
		Time:        time.Now(),
		NodeID:      node.NodeID,
		CPULoad:     atoi(m["cpu-load"]),
		FreeMemory:  atoi64(m["free-memory"]),
		TotalMemory: atoi64(m["total-memory"]),
		CPUCount:    atoi(m["cpu-count"]),
		Uptime:      m["uptime"],
		Version:     m["version"],
		BoardName:   m["board-name"],
	}
	return res, nil
}

// StartResourcePoller menjalankan pengambilan sampel sumber daya seluruh node aktif
// setiap interval (0 = nonaktif). Sampel disimpan ke tabel node_resources sehingga
// dapat dibandingkan sebelum/sesudah sistem diaktifkan (make measure) dan
// divisualisasikan di Grafana.
func StartResourcePoller(interval time.Duration) {
	if interval <= 0 {
		log.Println("Pemantauan sumber daya router nonaktif (RESOURCE_POLL_INTERVAL=0)")
		return
	}
	log.Printf("Pemantauan sumber daya router aktif, interval %s", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			pollAllNodes()
			<-ticker.C
		}
	}()
}

// pollAllNodes mengambil sampel dari setiap node aktif secara paralel.
func pollAllNodes() {
	nodes, err := database.GetActiveNodes()
	if err != nil || len(nodes) == 0 {
		return
	}
	done := make(chan struct{}, len(nodes))
	for _, node := range nodes {
		go func(n database.MikrotikNode) {
			defer func() { done <- struct{}{} }()
			res, err := GetResource(n)
			if err != nil {
				log.Printf("Sumber daya node %s tidak terbaca: %v", n.NodeID, err)
				return
			}
			if res == nil {
				return
			}
			if err := database.InsertNodeResource(*res); err != nil {
				log.Printf("Gagal menyimpan sumber daya node %s: %v", n.NodeID, err)
			}
		}(node)
	}
	for range nodes {
		<-done
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
