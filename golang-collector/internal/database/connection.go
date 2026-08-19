// connection.go mengelola koneksi pool ke database TimescaleDB.
// Menggunakan pgxpool agar koneksi bisa dipakai bersama oleh banyak goroutine
// secara aman dan efisien.
package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thesis-ids/golang-collector/config"
)

// DB adalah pool koneksi global yang digunakan di seluruh aplikasi.
var DB *pgxpool.Pool

// Connect membuka koneksi pool ke TimescaleDB dan memverifikasi koneksi berhasil.
// Fungsi ini dipanggil sekali saat aplikasi pertama kali start.
func Connect(cfg *config.Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBUser, cfg.DBPassword,
	)

	// Konfigurasi pool koneksi untuk performa optimal
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("gagal parse konfigurasi database: %w", err)
	}

	// Maksimal 20 koneksi aktif secara bersamaan
	poolConfig.MaxConns = 20
	// Minimum 2 koneksi selalu siap pakai
	poolConfig.MinConns = 2
	// Koneksi idle akan ditutup setelah 5 menit
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	// Coba koneksi ke database dengan retry sederhana
	var pool *pgxpool.Pool
	for attempt := 1; attempt <= 5; attempt++ {
		pool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
		if err == nil {
			// Verifikasi koneksi aktif dengan ping
			if pingErr := pool.Ping(context.Background()); pingErr == nil {
				break
			}
		}
		log.Printf("Percobaan koneksi database ke-%d gagal, coba lagi dalam 3 detik...", attempt)
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("gagal terhubung ke database setelah 5 percobaan: %w", err)
	}

	DB = pool
	log.Println("Koneksi database berhasil.")
	return nil
}

// Close menutup semua koneksi dalam pool saat aplikasi berhenti.
func Close() {
	if DB != nil {
		DB.Close()
		log.Println("Koneksi database ditutup.")
	}
}
