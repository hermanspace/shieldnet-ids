// receiver.go bertugas mendengarkan dan menerima pesan syslog dari router MikroTik
// melalui protokol UDP. Setiap pesan yang diterima langsung diproses, disimpan
// ke database, dan dipublikasikan ke Redis untuk analisis lebih lanjut.
package syslog

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// MessageHandler adalah tipe fungsi yang dipanggil setiap kali syslog baru diterima.
// Memisahkan logika penerimaan dari logika pemrosesan agar lebih fleksibel.
type MessageHandler func(rawMessage, sourceIP string)

// Receiver mengelola listener UDP untuk menerima syslog dari router MikroTik.
type Receiver struct {
	port    string
	conn    *net.UDPConn
	handler MessageHandler
}

// NewReceiver membuat instance Receiver baru dengan port dan handler yang ditentukan.
func NewReceiver(port string, handler MessageHandler) *Receiver {
	return &Receiver{
		port:    port,
		handler: handler,
	}
}

// Start memulai listener UDP dan mulai menerima pesan syslog.
// Fungsi ini berjalan dalam goroutine terpisah dan tidak blocking.
func (r *Receiver) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%s", r.port))
	if err != nil {
		return fmt.Errorf("gagal resolve alamat UDP: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("gagal membuka port UDP %s: %w", r.port, err)
	}
	r.conn = conn

	log.Printf("Syslog receiver aktif di UDP port %s", r.port)

	// Jalankan loop penerima dalam goroutine agar tidak memblokir main thread
	go r.receiveLoop()
	return nil
}

// receiveLoop adalah loop utama yang terus mendengarkan pesan UDP masuk.
// Loop ini berjalan selamanya sampai koneksi ditutup.
func (r *Receiver) receiveLoop() {
	buffer := make([]byte, 8192) // Buffer 8KB sudah cukup untuk syslog standar

	for {
		// Set deadline baca agar tidak stuck selamanya
		_ = r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, remoteAddr, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			// Timeout adalah hal normal, lanjutkan loop
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Error lain mungkin karena koneksi ditutup
			log.Printf("Error membaca UDP: %v", err)
			return
		}

		// Ekstrak isi pesan dan bersihkan whitespace
		rawMessage := strings.TrimSpace(string(buffer[:n]))
		if rawMessage == "" {
			continue
		}

		// Ekstrak IP sumber dari alamat UDP pengirim
		sourceIP := remoteAddr.IP.String()

		// Panggil handler dalam goroutine terpisah agar loop tidak tertunda
		go r.handler(rawMessage, sourceIP)
	}
}

// Stop menutup koneksi UDP dan menghentikan loop penerima.
func (r *Receiver) Stop() {
	if r.conn != nil {
		r.conn.Close()
		log.Println("Syslog receiver dihentikan.")
	}
}
