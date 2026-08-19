# =============================================================================
# Dockerfile untuk Golang Collector
# Menggunakan multi-stage build: stage build dan stage runtime yang ringan
# =============================================================================

# Stage 1: Build binary dari source code
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install dependensi sistem yang diperlukan
RUN apk add --no-cache git

# Salin file modul terlebih dahulu untuk memanfaatkan cache Docker layer
COPY go.mod go.sum ./
RUN go mod download

# Salin seluruh source code
COPY . .

# Build binary dengan optimasi ukuran
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o ids-collector \
    ./cmd/main.go

# Stage 2: Runtime image yang ringan
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates untuk koneksi HTTPS dan tzdata untuk timezone
RUN apk add --no-cache ca-certificates tzdata

# Salin binary dari stage build
COPY --from=builder /build/ids-collector .

# Salin file statis dan template yang dibutuhkan saat runtime
COPY --from=builder /build/internal/web/templates ./internal/web/templates
COPY --from=builder /build/static ./static

# Expose port web server dan syslog UDP
EXPOSE 8080
EXPOSE 514/udp

# Jalankan binary
CMD ["./ids-collector"]
