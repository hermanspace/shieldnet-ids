// middleware.go menyediakan middleware HTTP umum seperti logging request.
// Middleware ini diterapkan ke semua route untuk keperluan monitoring dan debugging.
package web

import (
	"log"
	"net/http"
	"time"
)

// responseWriter adalah wrapper untuk http.ResponseWriter yang juga menyimpan status code.
// Dibutuhkan agar middleware logging bisa mencatat status code response.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware mencatat setiap request HTTP yang masuk beserta durasi prosesnya.
// Berguna untuk debugging dan monitoring performa.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Bungkus ResponseWriter untuk bisa membaca status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("[HTTP] %s %s %d %s", r.Method, r.URL.Path, wrapped.statusCode, duration)
	})
}
