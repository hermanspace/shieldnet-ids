# =============================================================================
# Dockerfile untuk Python Analyst
# Menggunakan image slim untuk ukuran yang lebih kecil
# =============================================================================

FROM python:3.11-slim

WORKDIR /app

# Install dependensi sistem yang diperlukan oleh psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Salin file requirements terlebih dahulu untuk memanfaatkan cache Docker layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Salin seluruh source code
COPY . .

# Buat direktori untuk menyimpan model yang sudah dilatih
RUN mkdir -p /app/models

# Jalankan entry point
CMD ["python", "main.py"]
