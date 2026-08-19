#!/usr/bin/env python3
# =============================================================================
# main.py adalah entry point Python Analyst untuk Sistem Deteksi Intrusi.
# Bertanggung jawab mengorkestrasi semua komponen: consumer Redis, model
# Isolation Forest, database query, dan publisher hasil analisis.
# =============================================================================

import logging
import signal
import sys
from datetime import datetime

import config
from modules.consumer import SyslogConsumer
from modules.database import wait_for_db, fetch_syslogs_for_analysis, fetch_training_data, count_syslogs_since
from modules.model import IDSModel
from modules.preprocessor import extract_features
from modules.publisher import ResultPublisher

# Konfigurasi logging dengan format yang jelas dan informatif
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Variabel global untuk komponen utama sistem
ids_model = IDSModel()
publisher = ResultPublisher()
last_train_time = datetime.now()


def process_syslog_event(fields: dict):
    """
    fungsi yang dipanggil untuk setiap event syslog baru dari Redis Stream.
    alur: ambil data historis → ekstrak fitur → prediksi → publikasi hasil.
    juga menangani logika retrain model jika sudah waktunya.
    """
    source_ip = fields.get('source_ip', '')
    if not source_ip:
        return

    logger.debug(f"Memproses event dari IP: {source_ip}")

    # Ambil data historis syslog untuk IP ini sebagai konteks analisis
    records = fetch_syslogs_for_analysis(source_ip, config.ANALYSIS_WINDOW_MINUTES)

    if not records:
        logger.debug(f"Tidak ada data historis untuk IP {source_ip}, lewati analisis.")
        return

    # Ekstrak fitur dari data historis
    features = extract_features(records)
    if features is None:
        logger.warning(f"Gagal ekstrak fitur untuk IP {source_ip}.")
        return

    # Lakukan prediksi menggunakan model Isolation Forest
    is_intrusion, anomaly_score, confidence = ids_model.predict(features)
    action = ids_model.determine_action(is_intrusion, anomaly_score, confidence)

    # Log hasil untuk keperluan monitoring
    if is_intrusion:
        logger.warning(
            f"[INTRUSI] IP={source_ip} skor={anomaly_score:.4f} "
            f"keyakinan={confidence:.2%} aksi={action}"
        )
    else:
        logger.debug(f"[NORMAL] IP={source_ip} skor={anomaly_score:.4f}")

    # Publikasi hasil ke Redis agar Golang bisa mengambil tindakan
    publisher.publish_result(source_ip, is_intrusion, anomaly_score, confidence, action)

    # Cek apakah model perlu dilatih ulang berdasarkan jumlah data baru
    check_and_retrain()


def check_and_retrain():
    """
    memeriksa apakah sudah waktunya model dilatih ulang.
    retrain dilakukan setiap MODEL_RETRAIN_INTERVAL syslog baru masuk.
    """
    global last_train_time

    new_syslog_count = count_syslogs_since(last_train_time)
    if ids_model.retrain_if_needed(new_syslog_count):
        last_train_time = datetime.now()


def initial_training():
    """
    melakukan pelatihan awal model saat sistem pertama kali start.
    jika ada model tersimpan di disk, model akan dimuat.
    jika tidak, akan mencoba melatih dari data yang ada di database.
    """
    logger.info("Memeriksa model tersimpan...")

    # Coba muat model dari disk terlebih dahulu
    if ids_model.load():
        logger.info("Model dimuat dari disk, siap untuk analisis.")
        return

    # Jika tidak ada model tersimpan, latih dari data yang ada
    logger.info("Melatih model baru dari data historis...")
    training_data = fetch_training_data(hours=24)

    if len(training_data) >= 10:
        if ids_model.train(training_data):
            ids_model.save()
            logger.info("Pelatihan awal berhasil.")
        else:
            logger.warning("Pelatihan awal gagal, sistem akan latih saat ada data cukup.")
    else:
        logger.warning(
            f"Data pelatihan tidak cukup ({len(training_data)} sampel), "
            "model akan dilatih setelah data masuk."
        )


def handle_shutdown(signum, frame):
    """
    menangani sinyal shutdown (Ctrl+C atau SIGTERM) dengan graceful.
    menyimpan model terbaru sebelum keluar.
    """
    logger.info("Menerima sinyal shutdown, menyimpan model...")
    if ids_model.is_trained:
        ids_model.save()
    logger.info("Python Analyst berhenti.")
    sys.exit(0)


def main():
    logger.info("=== Python Analyst - Sistem Deteksi Intrusi ===")
    logger.info("Menginisialisasi komponen...")

    # Daftarkan handler untuk shutdown graceful
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Tunggu database siap sebelum memulai
    logger.info("Menunggu database siap...")
    if not wait_for_db():
        logger.error("Database tidak bisa dihubungi setelah beberapa percobaan. Keluar.")
        sys.exit(1)

    # Hubungkan ke Redis publisher
    logger.info("Menghubungkan ke Redis publisher...")
    if not publisher.connect():
        logger.error("Tidak bisa terhubung ke Redis publisher. Keluar.")
        sys.exit(1)

    # Lakukan pelatihan awal model
    initial_training()

    # Inisialisasi consumer dan mulai consume
    consumer = SyslogConsumer(callback=process_syslog_event)
    logger.info("Menghubungkan ke Redis stream...")
    if not consumer.connect():
        logger.error("Tidak bisa terhubung ke Redis stream. Keluar.")
        sys.exit(1)

    logger.info("Sistem Python Analyst siap. Menunggu event syslog...")

    # Mulai loop konsumsi (blocking)
    consumer.consume()


if __name__ == "__main__":
    main()
