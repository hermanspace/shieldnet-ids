// publisher.go bertugas mempublikasikan event syslog baru ke Redis Stream.
// Python Analyst akan mengkonsumsi event ini untuk melakukan analisis Isolation Forest.
// Menggunakan Redis Stream (bukan Pub/Sub) agar pesan tidak hilang jika Python sedang down.
package redis

import (
	"context"
	"fmt"
	"log"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"thesis-ids/golang-collector/config"
)

const (
	// SyslogStreamKey adalah nama stream Redis untuk mengirim notifikasi syslog baru
	SyslogStreamKey = "ids:syslog:stream"
)

// Publisher mengelola koneksi ke Redis untuk publikasi pesan.
type Publisher struct {
	client *goredis.Client
}

// NewPublisher membuat instance Publisher baru dan memverifikasi koneksi Redis.
func NewPublisher(cfg *config.Config) (*Publisher, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr: fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
	})

	// Verifikasi koneksi aktif
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("gagal terhubung ke Redis: %w", err)
	}

	log.Println("Publisher Redis berhasil terhubung.")
	return &Publisher{client: client}, nil
}

// PublishSyslog mengirim notifikasi syslog baru ke Redis Stream.
// Pesan berisi informasi yang cukup bagi Python untuk mengambil data historis dan menganalisis.
func (p *Publisher) PublishSyslog(sourceIP, eventType, nodeID string) error {
	ctx := context.Background()

	// Tambahkan pesan ke stream dengan field yang relevan
	err := p.client.XAdd(ctx, &goredis.XAddArgs{
		Stream: SyslogStreamKey,
		MaxLen: 10000, // Batasi stream agar tidak tumbuh tak terbatas
		Approx: true,
		Values: map[string]interface{}{
			"source_ip":  sourceIP,
			"event_type": eventType,
			"node_id":    nodeID,
			"timestamp":  time.Now().Unix(),
		},
	}).Err()

	if err != nil {
		return fmt.Errorf("gagal publikasi ke Redis Stream: %w", err)
	}
	return nil
}

// Close menutup koneksi Redis publisher.
func (p *Publisher) Close() error {
	return p.client.Close()
}
