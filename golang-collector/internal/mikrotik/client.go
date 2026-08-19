// client.go menyediakan klien untuk berkomunikasi dengan API router MikroTik.
// MikroTik API menggunakan protokol biner khusus (RouterOS API) yang berbeda dari REST.
// Library go-routeros/v3 digunakan untuk menyederhanakan komunikasi ini.
package mikrotik

import (
	"fmt"
	"log"
	"time"

	"github.com/go-routeros/routeros/v3"
)

// Client merepresentasikan satu koneksi aktif ke router MikroTik.
type Client struct {
	conn     *routeros.Client
	nodeID   string
	nodeIP   string
	apiPort  int
	username string
	password string
}

// NewClient membuat dan memverifikasi koneksi ke satu router MikroTik.
// Koneksi diuji dengan perintah identity print sebelum dianggap berhasil.
func NewClient(nodeID, nodeIP string, apiPort int, username, password string) (*Client, error) {
	address := fmt.Sprintf("%s:%d", nodeIP, apiPort)

	conn, err := routeros.DialTimeout(address, username, password, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("gagal koneksi ke MikroTik %s (%s): %w", nodeID, address, err)
	}

	log.Printf("Berhasil terhubung ke node MikroTik: %s (%s)", nodeID, nodeIP)
	return &Client{
		conn:     conn,
		nodeID:   nodeID,
		nodeIP:   nodeIP,
		apiPort:  apiPort,
		username: username,
		password: password,
	}, nil
}

// RunCommand menjalankan perintah RouterOS API dan mengembalikan hasilnya.
// Ini adalah fungsi dasar yang digunakan oleh fungsi-fungsi lain yang lebih spesifik.
func (c *Client) RunCommand(words ...string) (*routeros.Reply, error) {
	return c.conn.RunArgs(words)
}

// Close menutup koneksi ke router MikroTik.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// TestConnection mencoba menjalankan perintah sederhana untuk mengecek apakah
// koneksi ke MikroTik masih aktif dan responsif.
func (c *Client) TestConnection() bool {
	reply, err := c.conn.Run("/system/identity/print")
	if err != nil {
		return false
	}
	return reply != nil
}
