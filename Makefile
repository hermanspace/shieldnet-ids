# =============================================================================
# Makefile untuk otomasi build dan operasi Sistem Deteksi Intrusi Kolaboratif
# =============================================================================

# Gunakan file .env jika tersedia
ifneq (,$(wildcard ./.env))
	include .env
	export
endif

.PHONY: build up down logs restart clean db-init test evaluate status help

## build: Build semua Docker image dari source code
build:
	@echo ">> Membangun semua Docker image..."
	docker compose build

## up: Jalankan semua service di background
up:
	@echo ">> Menjalankan semua service..."
	@if [ ! -f .env ]; then \
		echo ">> File .env tidak ditemukan, menyalin dari .env.example..."; \
		cp .env.example .env; \
	fi
	docker compose up -d
	@echo ">> Semua service berjalan."
	@echo ">> Web Interface : http://localhost:${WEB_PORT:-8080}"
	@echo ">> Grafana       : http://localhost:${GRAFANA_PORT:-3000}"
	@echo ">> Login default : admin / admin123"

## down: Hentikan semua service
down:
	@echo ">> Menghentikan semua service..."
	docker compose down

## logs: Lihat log semua service secara live
logs:
	docker compose logs -f

## restart: Restart semua service
restart:
	@echo ">> Merestart semua service..."
	docker compose restart

## clean: Hapus semua container, image, dan volume Docker
clean:
	@echo ">> PERINGATAN: Semua data akan dihapus!"
	@read -p "Lanjutkan? (y/N): " confirm && [ "$$confirm" = "y" ]
	docker compose down -v --rmi all --remove-orphans
	@echo ">> Selesai. Semua resource Docker telah dihapus."

## db-init: Inisialisasi ulang schema database secara manual
db-init:
	@echo ">> Menginisialisasi ulang schema database..."
	docker compose exec timescaledb psql \
		-U ${DB_USER:-ids_user} \
		-d ${DB_NAME:-ids_thesis} \
		-f /docker-entrypoint-initdb.d/init.sql
	@echo ">> Schema database berhasil diinisialisasi."

## test: Simulasi serangan untuk demo (trafik latar 15 IP + brute force, port scan, flood)
# Detail skenario: evaluation/simulate.py — fase trafik latar WAJIB agar model
# Isolation Forest terlatih (butuh minimal 10 IP unik) sebelum serangan dikirim.
test:
	@echo ">> Menjalankan simulasi serangan (2 fase, +-30 detik)..."
	@docker exec -i ids-python python3 - < evaluation/simulate.py

## evaluate: Evaluasi kuantitatif deteksi (confusion matrix, precision/recall/F1, waktu respons)
evaluate:
	@echo ">> Menjalankan evaluasi kuantitatif sistem deteksi..."
	@docker exec -i ids-python python3 - < evaluation/evaluate.py

## status: Cek status semua container yang berjalan
status:
	@echo ">> Status container:"
	docker compose ps
	@echo ""
	@echo ">> Penggunaan resource:"
	docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

## help: Tampilkan daftar semua command yang tersedia
help:
	@echo "Sistem Deteksi Intrusi Kolaboratif - Makefile Commands"
	@echo "======================================================="
	@grep -E '^## ' Makefile | sed 's/## //'
