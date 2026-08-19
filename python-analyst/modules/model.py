# model.py bertugas mengelola siklus hidup model Isolation Forest:
# pelatihan, penyimpanan, pemuatan, dan inferensi (prediksi).
# Isolation Forest dipilih karena cocok untuk deteksi anomali tanpa label (unsupervised).

import logging
import os
from typing import Optional, Tuple
from datetime import datetime

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config
from modules.preprocessor import FEATURE_NAMES, extract_features_from_aggregated
from modules import database
from modules import settings

logger = logging.getLogger(__name__)


class IDSModel:
    """
    kelas yang membungkus model Isolation Forest lengkap dengan scaler-nya.
    scaler digunakan untuk menormalisasi fitur sebelum masuk ke model,
    yang penting agar fitur dengan skala berbeda tidak mendominasi hasil.
    """

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained: bool = False
        self.last_trained: Optional[datetime] = None
        self.training_samples: int = 0

    def train(self, training_data: list) -> bool:
        """
        melatih model Isolation Forest menggunakan data historis dari database.
        model dilatih ulang setiap MODEL_RETRAIN_INTERVAL syslog baru masuk
        agar model selalu up-to-date dengan pola trafik terkini.
        """
        if len(training_data) < 10:
            logger.warning(f"Data pelatihan terlalu sedikit ({len(training_data)} sampel), minimal 10.")
            return False

        # Ekstrak fitur dari setiap baris data agregasi
        feature_matrix = []
        for row in training_data:
            features = extract_features_from_aggregated(row)
            if features is not None:
                feature_matrix.append(features)

        if len(feature_matrix) < 10:
            logger.warning("Fitur yang berhasil diekstrak terlalu sedikit.")
            return False

        X = np.array(feature_matrix)

        # Normalisasi fitur menggunakan StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Latih Isolation Forest dengan parameter dari konfigurasi
        self.model = IsolationForest(
            n_estimators=config.IF_N_ESTIMATORS,
            contamination=config.IF_CONTAMINATION,
            max_samples=min(config.IF_MAX_SAMPLES, len(X_scaled)),
            random_state=42,  # Untuk reproduksibilitas hasil
            n_jobs=-1          # Gunakan semua CPU core yang tersedia
        )
        self.model.fit(X_scaled)

        self.is_trained = True
        self.last_trained = datetime.now()
        self.training_samples = len(feature_matrix)

        logger.info(
            f"Model berhasil dilatih dengan {self.training_samples} sampel. "
            f"n_estimators={config.IF_N_ESTIMATORS}, contamination={config.IF_CONTAMINATION}"
        )
        return True

    def predict(self, features: np.ndarray) -> Tuple[bool, float, float]:
        """
        memprediksi apakah sebuah IP melakukan intrusi berdasarkan fitur-fiturnya.
        mengembalikan tuple (is_intrusion, anomaly_score, confidence).
        skor anomali dari Isolation Forest: nilai negatif = anomali, positif = normal.
        semakin negatif, semakin besar kemungkinan intrusi.
        """
        if not self.is_trained or self.model is None or self.scaler is None:
            # Model belum dilatih, kembalikan hasil tidak ada intrusi
            return False, 0.0, 0.0

        # Normalisasi fitur menggunakan scaler yang sama saat pelatihan
        features_scaled = self.scaler.transform(features.reshape(1, -1))

        # Dapatkan skor anomali (-1 = anomali, 1 = normal dari decision_function)
        anomaly_score = self.model.decision_function(features_scaled)[0]

        # Ambang efektif: override dari web UI (tabel app_settings) jika ada,
        # selain itu nilai bawaan .env — lihat modules/settings.py.
        threshold = settings.anomaly_threshold()

        # Tentukan apakah terdeteksi sebagai intrusi berdasarkan threshold.
        # Cast ke bool Python murni: hasil perbandingan numpy.float64 adalah
        # numpy.bool_ yang tidak bisa diserialisasi json.dumps oleh publisher.
        is_intrusion = bool(anomaly_score < threshold)

        # Keyakinan dihitung dari DUA faktor independen:
        # 1. Kepastian skor  : jarak skor dari threshold klasifikasi.
        #    Skor di zona abu-abu (dekat threshold) = kepastian rendah.
        # 2. Kecukupan data  : jumlah record yang mendasari analisis
        #    (fitur total_requests). Skor ekstrem dari 2-3 record saja
        #    belum layak dipercaya penuh — bukti terlalu sedikit.
        distance_from_threshold = abs(anomaly_score - threshold)
        score_certainty = min(0.5 + distance_from_threshold * 2, 1.0)

        total_requests = float(features[0])
        data_sufficiency = min(total_requests / settings.confidence_full_samples(), 1.0)

        confidence = score_certainty * data_sufficiency

        return is_intrusion, float(anomaly_score), float(confidence)

    def determine_action(self, is_intrusion: bool, anomaly_score: float, confidence: float) -> str:
        """
        menentukan aksi yang harus diambil berdasarkan hasil prediksi.
        ada tiga kemungkinan aksi: block (blokir), monitor (pantau), allow (izinkan).
        """
        if not is_intrusion:
            return "allow"

        # Blokir hanya jika DUA syarat independen terpenuhi:
        # - skor sangat anomali (melewati ambang blokir, bukan sekadar ambang deteksi)
        # - keyakinan tinggi (skor pasti DAN didukung data yang cukup)
        # IP dengan skor ekstrem tapi data sedikit akan berstatus monitor,
        # bukan langsung diblokir di seluruh node.
        # Ambang diambil dari modules/settings.py (override UI atau bawaan .env).
        if confidence >= settings.block_confidence_threshold() and anomaly_score < settings.block_score_threshold():
            return "block"

        # Monitor jika keyakinan sedang (perlu pengawasan lebih lanjut)
        return "monitor"

    def save(self) -> bool:
        """
        menyimpan model dan scaler ke disk menggunakan joblib.
        model disimpan agar tidak perlu latih ulang saat container restart.
        """
        try:
            os.makedirs(os.path.dirname(config.MODEL_PATH), exist_ok=True)
            joblib.dump(self.model, config.MODEL_PATH)
            joblib.dump(self.scaler, config.SCALER_PATH)
            logger.info(f"Model disimpan ke {config.MODEL_PATH}")
            return True
        except Exception as e:
            logger.error(f"Gagal menyimpan model: {e}")
            return False

    def load(self) -> bool:
        """
        memuat model dan scaler yang sudah tersimpan dari disk.
        dipanggil saat startup agar tidak perlu latih ulang dari nol.
        """
        try:
            if not os.path.exists(config.MODEL_PATH) or not os.path.exists(config.SCALER_PATH):
                logger.info("File model tidak ditemukan, akan dilatih dari data baru.")
                return False

            self.model = joblib.load(config.MODEL_PATH)
            self.scaler = joblib.load(config.SCALER_PATH)
            self.is_trained = True
            logger.info("Model berhasil dimuat dari disk.")
            return True
        except Exception as e:
            logger.error(f"Gagal memuat model: {e}")
            return False

    def retrain_if_needed(self, syslog_count_since_last_train: int) -> bool:
        """
        melatih ulang model jika sudah ada cukup data baru sejak pelatihan terakhir.
        jumlah syslog minimum sebelum retrain ditentukan oleh MODEL_RETRAIN_INTERVAL.
        """
        if syslog_count_since_last_train < config.MODEL_RETRAIN_INTERVAL:
            return False

        logger.info(f"Memulai retrain model ({syslog_count_since_last_train} syslog baru)...")
        training_data = database.fetch_training_data(hours=24)

        if self.train(training_data):
            self.save()
            return True
        return False
