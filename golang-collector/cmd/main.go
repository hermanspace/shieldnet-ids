// main.go adalah entry point aplikasi Golang Collector.
// Bertanggung jawab menginisialisasi semua komponen sistem secara berurutan
// dan menjalankan semua service secara bersamaan.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"thesis-ids/golang-collector/config"
	"thesis-ids/golang-collector/internal/auth"
	"thesis-ids/golang-collector/internal/database"
	"thesis-ids/golang-collector/internal/mikrotik"
	redisclient "thesis-ids/golang-collector/internal/redis"
	"thesis-ids/golang-collector/internal/syslog"
	"thesis-ids/golang-collector/internal/web"
)

func main() {
	log.Println("=== Sistem Deteksi Intrusi Kolaboratif ===")
	log.Println("Memulai inisialisasi sistem...")

	// Muat konfigurasi dari environment variable
	cfg := config.Load()

	// Inisialisasi koneksi database
	if err := database.Connect(cfg); err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}
	defer database.Close()

	// Pastikan tabel app_settings tersedia (untuk database lama yang
	// diinisialisasi sebelum fitur pengaturan Decision Engine ditambahkan)
	if err := database.EnsureSettingsTable(); err != nil {
		log.Printf("Peringatan: gagal menyiapkan tabel app_settings: %v", err)
	}

	// Inisialisasi session store untuk manajemen login
	auth.InitSessionStore(cfg.SessionSecret)

	// Inisialisasi Redis publisher untuk mengirim event syslog ke Python
	publisher, err := redisclient.NewPublisher(cfg)
	if err != nil {
		log.Printf("Peringatan: Gagal terhubung ke Redis publisher: %v", err)
		log.Println("Sistem tetap berjalan, analisis ML tidak tersedia sampai Redis aktif.")
		publisher = nil
	}
	if publisher != nil {
		defer publisher.Close()
	}

	// Inisialisasi Redis subscriber untuk menerima hasil analisis dari Python
	subscriber, err := redisclient.NewSubscriber(cfg, func(result redisclient.AnalysisResult) {
		handleAnalysisResult(result)
	})
	if err != nil {
		log.Printf("Peringatan: Gagal terhubung ke Redis subscriber: %v", err)
	} else {
		subscriber.Start()
		defer subscriber.Close()
	}

	// Inisialisasi dan mulai syslog receiver UDP
	syslogHandler := func(rawMessage, sourceIP string) {
		processSyslog(rawMessage, sourceIP, publisher)
	}
	receiver := syslog.NewReceiver(cfg.SyslogPort, syslogHandler)
	if err := receiver.Start(); err != nil {
		log.Fatalf("Gagal memulai syslog receiver: %v", err)
	}
	defer receiver.Stop()

	// Inisialisasi dan mulai web server
	server, err := web.NewServer(cfg)
	if err != nil {
		log.Fatalf("Gagal menginisialisasi web server: %v", err)
	}

	// Jalankan web server di goroutine terpisah
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Web server berhenti: %v", err)
		}
	}()

	log.Println("Sistem IDS berjalan. Tekan Ctrl+C untuk berhenti.")

	// Tunggu sinyal interrupt untuk shutdown graceful
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Menerima sinyal shutdown, menghentikan sistem...")
}

// processSyslog memproses satu pesan syslog yang diterima dari router MikroTik.
// Alur: parse → cek whitelist/blacklist → simpan ke DB → kirim ke Redis (jika perlu ML)
func processSyslog(rawMessage, sourceIP string, publisher *redisclient.Publisher) {
	// Parse pesan syslog mentah menjadi struct terstruktur
	parsed := syslog.Parse(rawMessage, inferNodeID(sourceIP), sourceIP)

	// Cek apakah IP ada di whitelist - jika ya, simpan saja tanpa analisis lebih lanjut
	isWhitelisted, err := database.IsIPWhitelisted(parsed.SourceIP)
	if err == nil && isWhitelisted {
		database.InsertSyslog(parsed)
		return
	}

	// Simpan syslog ke database terlebih dahulu
	if err := database.InsertSyslog(parsed); err != nil {
		log.Printf("Gagal simpan syslog dari %s: %v", parsed.SourceIP, err)
		return
	}

	// Cek apakah IP ada di blacklist - jika ya, langsung blokir tanpa analisis ML
	isBlacklisted, err := database.IsIPBlacklisted(parsed.SourceIP)
	if err == nil && isBlacklisted {
		log.Printf("IP %s ada di blacklist, langsung mendistribusikan pemblokiran", parsed.SourceIP)
		go mikrotik.DistributeBlock(parsed.SourceIP)
		return
	}

	// Kirim ke Python Analyst via Redis untuk analisis Isolation Forest
	if publisher != nil {
		if err := publisher.PublishSyslog(parsed.SourceIP, parsed.EventType, parsed.NodeID); err != nil {
			log.Printf("Gagal publikasi ke Redis: %v", err)
		}
	}
}

// handleAnalysisResult memproses hasil analisis yang diterima dari Python Analyst.
// Jika terdeteksi sebagai intrusi, distribusikan pemblokiran ke semua node MikroTik.
func handleAnalysisResult(result redisclient.AnalysisResult) {
	log.Printf("Hasil analisis: IP=%s, intrusi=%v, skor=%.4f, aksi=%s",
		result.SourceIP, result.IsIntrusion, result.AnomalyScore, result.Action)

	// Simpan hasil analisis ke database untuk riwayat dan tampilan dashboard
	dbResult := database.IntrusionResult{
		SourceIP:     result.SourceIP,
		AnomalyScore: result.AnomalyScore,
		IsIntrusion:  result.IsIntrusion,
		Confidence:   result.Confidence,
		ActionTaken:  result.Action,
	}
	if err := database.InsertIntrusionResult(dbResult); err != nil {
		log.Printf("Gagal simpan hasil analisis: %v", err)
	}

	// Jika terdeteksi sebagai intrusi dan aksi adalah block, distribusikan ke semua node
	if result.IsIntrusion && result.Action == "block" {
		log.Printf("Mendistribusikan pemblokiran IP %s ke semua node aktif...", result.SourceIP)
		go mikrotik.DistributeBlock(result.SourceIP)
	}
}

// inferNodeID mencoba menentukan node ID dari IP pengirim syslog.
// Dalam kondisi nyata, MikroTik mengirim hostname-nya di pesan syslog.
func inferNodeID(sourceIP string) string {
	nodes, err := database.GetAllNodes()
	if err != nil {
		return sourceIP
	}
	for _, node := range nodes {
		if node.IPAddress == sourceIP {
			return node.NodeID
		}
	}
	return "unknown-" + sourceIP
}
