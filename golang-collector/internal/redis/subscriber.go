// subscriber.go bertugas menerima hasil analisis Isolation Forest dari Python Analyst
// melalui Redis Pub/Sub, kemudian memproses hasilnya untuk distribusi access list.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"thesis-ids/golang-collector/config"
)

const (
	// AnalysisResultChannel adalah nama channel Pub/Sub untuk menerima hasil analisis
	AnalysisResultChannel = "ids:analysis:result"
)

// AnalysisResult merepresentasikan hasil analisis yang dikirim Python ke Golang.
type AnalysisResult struct {
	SourceIP     string  `json:"source_ip"`
	IsIntrusion  bool    `json:"is_intrusion"`
	AnomalyScore float64 `json:"anomaly_score"`
	Confidence   float64 `json:"confidence"`
	Action       string  `json:"action"` // "block", "monitor", atau "allow"
}

// ResultHandler adalah tipe fungsi yang dipanggil ketika hasil analisis diterima.
type ResultHandler func(result AnalysisResult)

// Subscriber mengelola koneksi Redis untuk menerima hasil analisis.
type Subscriber struct {
	client  *goredis.Client
	handler ResultHandler
}

// NewSubscriber membuat instance Subscriber baru.
func NewSubscriber(cfg *config.Config, handler ResultHandler) (*Subscriber, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr: fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("gagal terhubung ke Redis: %w", err)
	}

	return &Subscriber{client: client, handler: handler}, nil
}

// Start mulai berlangganan ke channel hasil analisis dan mendengarkan pesan.
// Berjalan dalam goroutine terpisah dan otomatis reconnect jika koneksi terputus.
func (s *Subscriber) Start() {
	go s.subscribeLoop()
}

// subscribeLoop mendengarkan pesan dari channel Redis Pub/Sub secara terus-menerus.
// Jika koneksi terputus, akan coba reconnect secara otomatis.
func (s *Subscriber) subscribeLoop() {
	for {
		if err := s.subscribe(); err != nil {
			log.Printf("Subscriber Redis error: %v. Mencoba reconnect dalam 5 detik...", err)
			time.Sleep(5 * time.Second)
		}
	}
}

// subscribe membuka subscription dan memproses pesan masuk.
func (s *Subscriber) subscribe() error {
	ctx := context.Background()
	pubsub := s.client.Subscribe(ctx, AnalysisResultChannel)
	defer pubsub.Close()

	log.Printf("Subscriber Redis aktif, mendengarkan channel '%s'", AnalysisResultChannel)

	for msg := range pubsub.Channel() {
		var result AnalysisResult
		if err := json.Unmarshal([]byte(msg.Payload), &result); err != nil {
			log.Printf("Gagal parse hasil analisis: %v", err)
			continue
		}
		// Panggil handler dalam goroutine terpisah agar tidak memblokir subscriber
		go s.handler(result)
	}

	return fmt.Errorf("channel subscriber ditutup")
}

// Close menutup koneksi Redis subscriber.
func (s *Subscriber) Close() error {
	return s.client.Close()
}
