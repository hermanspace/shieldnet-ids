// config.go bertugas memuat semua konfigurasi dari environment variable.
// Semua nilai default sudah disediakan agar sistem tetap berjalan
// meskipun sebagian environment variable tidak diset.
package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config menyimpan semua konfigurasi yang dibutuhkan aplikasi.
type Config struct {
	// Koneksi database
	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string

	// Koneksi Redis
	RedisHost string
	RedisPort string

	// Port syslog UDP
	SyslogPort string

	// Web server
	WebPort       string
	SessionSecret string

	// Parameter Isolation Forest
	IFNEstimators  int
	IFContamination float64
	IFMaxSamples   int

	// Parameter analisis
	AnalysisWindowMinutes int
	ModelRetrainInterval  int

	// MikroTik default
	MikrotikDefaultAPIPort int
	MikrotikDefaultUser    string
	MikrotikDefaultPass    string
}

// Load membaca konfigurasi dari file .env dan environment variable sistem.
// Urutan prioritas: environment variable sistem > file .env > nilai default.
func Load() *Config {
	// Coba muat file .env, abaikan error jika file tidak ada
	_ = godotenv.Load()

	return &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBName:     getEnv("DB_NAME", "ids_thesis"),
		DBUser:     getEnv("DB_USER", "ids_user"),
		DBPassword: getEnv("DB_PASSWORD", "ids_password"),

		RedisHost: getEnv("REDIS_HOST", "localhost"),
		RedisPort: getEnv("REDIS_PORT", "6379"),

		SyslogPort: getEnv("SYSLOG_UDP_PORT", "514"),

		WebPort:       getEnv("WEB_PORT", "8080"),
		SessionSecret: getEnv("SESSION_SECRET", "rahasia-default-ganti-di-produksi"),

		IFNEstimators:  getEnvInt("IF_N_ESTIMATORS", 100),
		IFContamination: getEnvFloat("IF_CONTAMINATION", 0.1),
		IFMaxSamples:   getEnvInt("IF_MAX_SAMPLES", 256),

		AnalysisWindowMinutes: getEnvInt("ANALYSIS_WINDOW_MINUTES", 10),
		ModelRetrainInterval:  getEnvInt("MODEL_RETRAIN_INTERVAL", 100),

		MikrotikDefaultAPIPort: getEnvInt("MIKROTIK_DEFAULT_API_PORT", 8728),
		MikrotikDefaultUser:    getEnv("MIKROTIK_DEFAULT_USERNAME", "admin"),
		MikrotikDefaultPass:    getEnv("MIKROTIK_DEFAULT_PASSWORD", "admin"),
	}
}

// getEnv mengambil nilai environment variable atau mengembalikan nilai default.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt mengambil nilai environment variable sebagai integer.
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvFloat mengambil nilai environment variable sebagai float64.
func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}
