# publisher.py bertugas mempublikasikan hasil analisis Isolation Forest ke Redis Pub/Sub.
# Golang Collector akan menerima hasil ini dan memutuskan apakah perlu
# mendistribusikan pemblokiran ke semua node MikroTik.

import json
import logging
import time
from typing import Optional

import redis

import config

logger = logging.getLogger(__name__)


class ResultPublisher:
    """
    kelas yang mengelola koneksi Redis untuk mempublikasikan hasil analisis.
    menggunakan Pub/Sub karena hasilnya harus langsung diproses Golang
    (bukan antrian yang bisa dibaca nanti seperti Stream).
    """

    def __init__(self):
        self.client: Optional[redis.Redis] = None

    def connect(self) -> bool:
        """
        membuka koneksi ke Redis dan memverifikasi koneksi aktif.
        dipanggil saat startup aplikasi.
        """
        for attempt in range(1, 6):
            try:
                self.client = redis.Redis(
                    host=config.REDIS_HOST,
                    port=config.REDIS_PORT,
                    decode_responses=True
                )
                self.client.ping()
                logger.info("Publisher Redis berhasil terhubung.")
                return True
            except Exception as e:
                logger.warning(f"Percobaan ke-{attempt} koneksi Redis gagal: {e}")
                time.sleep(3)
        return False

    def publish_result(self, source_ip: str, is_intrusion: bool,
                       anomaly_score: float, confidence: float, action: str) -> bool:
        """
        mempublikasikan hasil analisis satu IP ke channel Redis.
        format JSON yang dikirim harus sesuai dengan struct AnalysisResult di Golang.
        """
        if self.client is None:
            logger.error("Belum terhubung ke Redis.")
            return False

        result = {
            "source_ip": source_ip,
            "is_intrusion": is_intrusion,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "action": action,
        }

        try:
            message = json.dumps(result)
            recipients = self.client.publish(config.ANALYSIS_RESULT_CHANNEL, message)
            logger.debug(f"Hasil analisis {source_ip} dipublikasikan ke {recipients} subscriber.")
            return True
        except Exception as e:
            logger.error(f"Gagal publikasi hasil analisis untuk {source_ip}: {e}")
            return False
