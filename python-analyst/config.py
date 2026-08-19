# config.py bertugas memuat semua konfigurasi dari environment variable.
# Semua nilai default sudah tersedia agar sistem tetap berjalan
# meskipun sebagian environment variable tidak diset.

import os
from dotenv import load_dotenv

# Muat file .env jika ada
load_dotenv()

# Konfigurasi database TimescaleDB
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "ids_thesis")
DB_USER = os.getenv("DB_USER", "ids_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "ids_password")

# Konfigurasi Redis
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Nama stream dan channel Redis
SYSLOG_STREAM_KEY = "ids:syslog:stream"
ANALYSIS_RESULT_CHANNEL = "ids:analysis:result"
CONSUMER_GROUP = "ids-python-analyst"
CONSUMER_NAME = "analyst-1"

# Parameter model Isolation Forest
IF_N_ESTIMATORS = int(os.getenv("IF_N_ESTIMATORS", "100"))
IF_CONTAMINATION = float(os.getenv("IF_CONTAMINATION", "0.1"))
IF_MAX_SAMPLES = int(os.getenv("IF_MAX_SAMPLES", "256"))

# Jendela waktu data historis untuk analisis (dalam menit)
ANALYSIS_WINDOW_MINUTES = int(os.getenv("ANALYSIS_WINDOW_MINUTES", "10"))

# Interval retraining model dalam jumlah syslog baru
MODEL_RETRAIN_INTERVAL = int(os.getenv("MODEL_RETRAIN_INTERVAL", "100"))

# Lokasi penyimpanan model yang sudah dilatih
MODEL_PATH = os.getenv("MODEL_PATH", "/app/models/isolation_forest.pkl")
SCALER_PATH = os.getenv("SCALER_PATH", "/app/models/scaler.pkl")

# Ambang batas skor anomali untuk klasifikasi intrusi
# Skor dari Isolation Forest: nilai lebih negatif = lebih anomali
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "-0.1"))

# Ambang untuk aksi blokir otomatis (dua syarat independen):
# 1. Skor anomali harus lebih negatif dari BLOCK_SCORE_THRESHOLD
# 2. Keyakinan gabungan harus mencapai BLOCK_CONFIDENCE_THRESHOLD
BLOCK_SCORE_THRESHOLD = float(os.getenv("BLOCK_SCORE_THRESHOLD", "-0.3"))
BLOCK_CONFIDENCE_THRESHOLD = float(os.getenv("BLOCK_CONFIDENCE_THRESHOLD", "0.75"))

# Jumlah minimum record dalam jendela analisis agar faktor kecukupan data
# pada perhitungan keyakinan bernilai penuh (1.0). Di bawah ini, keyakinan
# dikurangi proporsional agar IP dengan bukti sedikit tidak langsung diblokir.
CONFIDENCE_FULL_SAMPLES = int(os.getenv("CONFIDENCE_FULL_SAMPLES", "10"))
