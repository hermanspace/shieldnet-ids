# preprocessor.py bertugas mengekstrak fitur-fitur penting dari data syslog mentah.
# fitur yang diekstrak merepresentasikan pola perilaku satu IP dalam jendela waktu tertentu.
# fitur inilah yang menjadi input untuk model Isolation Forest.

import logging
from typing import List, Dict, Optional
from datetime import datetime

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Daftar nama fitur yang digunakan model, urutan HARUS konsisten
FEATURE_NAMES = [
    "total_requests",      # Total jumlah request dalam jendela waktu
    "unique_dest_ports",   # Jumlah port tujuan yang berbeda (indikator port scan)
    "unique_src_ports",    # Jumlah port asal yang berbeda
    "login_fails",         # Jumlah kegagalan login (indikator brute force)
    "port_scans",          # Jumlah event bertipe port_scan
    "brute_forces",        # Jumlah event bertipe brute_force
    "requests_per_minute", # Frekuensi request per menit (indikator flood)
    "port_diversity_ratio",# Rasio port unik terhadap total request (indikator scanning)
    "fail_ratio",          # Rasio kegagalan login terhadap total request
]


def extract_features(syslog_records: List[Dict]) -> Optional[np.ndarray]:
    """
    mengekstrak fitur-fitur penting dari daftar record syslog untuk satu IP.
    mengembalikan array numpy 1D berisi nilai-nilai fitur, atau None jika data kosong.
    fitur yang diekstrak dirancang untuk menangkap pola anomali umum seperti
    port scanning, brute force login, dan flood traffic.
    """
    if not syslog_records:
        return None

    try:
        df = pd.DataFrame(syslog_records)

        # Hitung total request dalam jendela waktu
        total_requests = len(df)

        # Hitung keberagaman port tujuan (tinggi = indikasi port scan)
        unique_dest_ports = df['dest_port'].nunique() if 'dest_port' in df.columns else 0
        unique_src_ports = df['source_port'].nunique() if 'source_port' in df.columns else 0

        # Hitung jumlah event keamanan spesifik
        login_fails = (df['event_type'] == 'login_fail').sum() if 'event_type' in df.columns else 0
        port_scans = (df['event_type'] == 'port_scan').sum() if 'event_type' in df.columns else 0
        brute_forces = (df['event_type'] == 'brute_force').sum() if 'event_type' in df.columns else 0

        # Hitung frekuensi request per menit
        requests_per_minute = _calculate_request_rate(df)

        # Hitung rasio keberagaman port (0-1, lebih tinggi = lebih mencurigakan)
        port_diversity_ratio = unique_dest_ports / total_requests if total_requests > 0 else 0.0

        # Hitung rasio kegagalan login
        fail_ratio = login_fails / total_requests if total_requests > 0 else 0.0

        features = np.array([
            total_requests,
            unique_dest_ports,
            unique_src_ports,
            login_fails,
            port_scans,
            brute_forces,
            requests_per_minute,
            port_diversity_ratio,
            fail_ratio,
        ], dtype=np.float64)

        return features

    except Exception as e:
        logger.error(f"Gagal ekstrak fitur: {e}")
        return None


def extract_features_from_aggregated(row: Dict) -> Optional[np.ndarray]:
    """
    mengekstrak fitur dari data yang sudah diagregasi per IP (hasil query database).
    digunakan untuk pelatihan model menggunakan data historis yang sudah di-GROUP BY.
    """
    try:
        total_requests = float(row.get('total_requests', 0))
        unique_dest_ports = float(row.get('unique_dest_ports', 0))
        unique_src_ports = float(row.get('unique_src_ports', 0))
        login_fails = float(row.get('login_fails', 0))
        port_scans = float(row.get('port_scans', 0))
        brute_forces = float(row.get('brute_forces', 0))
        duration_seconds = float(row.get('duration_seconds', 0) or 0)

        # Hitung requests per menit dari durasi
        if duration_seconds > 0:
            requests_per_minute = (total_requests / duration_seconds) * 60
        else:
            requests_per_minute = total_requests

        port_diversity_ratio = unique_dest_ports / total_requests if total_requests > 0 else 0.0
        fail_ratio = login_fails / total_requests if total_requests > 0 else 0.0

        return np.array([
            total_requests,
            unique_dest_ports,
            unique_src_ports,
            login_fails,
            port_scans,
            brute_forces,
            requests_per_minute,
            port_diversity_ratio,
            fail_ratio,
        ], dtype=np.float64)

    except Exception as e:
        logger.error(f"Gagal ekstrak fitur agregat: {e}")
        return None


def _calculate_request_rate(df: pd.DataFrame) -> float:
    """
    menghitung jumlah request per menit dari dataframe syslog.
    jika rentang waktu kurang dari 1 menit, gunakan total request sebagai rate.
    """
    if 'time' not in df.columns or len(df) < 2:
        return float(len(df))

    try:
        times = pd.to_datetime(df['time'])
        duration_minutes = (times.max() - times.min()).total_seconds() / 60
        if duration_minutes < 0.01:  # Kurang dari 0.6 detik
            return float(len(df))
        return len(df) / duration_minutes
    except Exception:
        return float(len(df))
