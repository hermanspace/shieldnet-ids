# settings.py menyediakan nilai efektif parameter Decision Engine.
#
# Prioritas nilai: override dari tabel app_settings (diubah lewat web UI)
# > nilai environment (.env) yang dimuat config.py > nilai bawaan program.
#
# Tabel app_settings dibaca dengan cache TTL 10 detik agar perubahan dari UI
# berlaku cepat tanpa membebani database pada setiap analisis. Jika database
# tidak bisa diakses, sistem otomatis kembali ke nilai .env sehingga proses
# analisis tidak pernah terhenti karena fitur pengaturan ini.

import logging
import time

import config
from modules import database

logger = logging.getLogger(__name__)

# Interval pembacaan ulang tabel app_settings (detik)
_CACHE_TTL_SECONDS = 10

# Nilai bawaan dari environment/.env — dipakai bila tidak ada override di DB
_ENV_DEFAULTS = {
    "ANOMALY_THRESHOLD": config.ANOMALY_THRESHOLD,
    "BLOCK_SCORE_THRESHOLD": config.BLOCK_SCORE_THRESHOLD,
    "BLOCK_CONFIDENCE_THRESHOLD": config.BLOCK_CONFIDENCE_THRESHOLD,
    "CONFIDENCE_FULL_SAMPLES": config.CONFIDENCE_FULL_SAMPLES,
}

_cache = {}          # key -> nilai float hasil override yang valid
_cache_loaded_at = 0.0
_last_logged = {}    # key -> nilai terakhir yang dicatat ke log (hindari spam)


def _refresh_cache():
    """Membaca ulang seluruh override dari tabel app_settings ke cache."""
    global _cache, _cache_loaded_at
    try:
        conn = database.get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT key, value FROM app_settings")
            rows = cur.fetchall()
        conn.close()

        fresh = {}
        for key, value in rows:
            if key not in _ENV_DEFAULTS:
                continue  # hanya parameter Decision Engine yang dikenal
            try:
                fresh[key] = float(value)
            except (TypeError, ValueError):
                logger.warning(f"Override {key}='{value}' bukan angka, diabaikan.")

        _cache = fresh
        _cache_loaded_at = time.time()

        # Catat ke log hanya saat nilai efektif berubah
        for key in _ENV_DEFAULTS:
            effective = _cache.get(key, _ENV_DEFAULTS[key])
            if _last_logged.get(key) != effective:
                source = "override UI" if key in _cache else "bawaan .env"
                logger.info(f"Decision Engine: {key} = {effective} ({source})")
                _last_logged[key] = effective
    except Exception as e:
        # Kegagalan baca DB tidak boleh menghentikan analisis — pakai cache lama
        logger.warning(f"Gagal membaca app_settings, memakai nilai sebelumnya/.env: {e}")
        _cache_loaded_at = time.time()


def _get(key: str) -> float:
    """Mengembalikan nilai efektif satu parameter (override UI atau .env)."""
    if time.time() - _cache_loaded_at > _CACHE_TTL_SECONDS:
        _refresh_cache()
    return _cache.get(key, _ENV_DEFAULTS[key])


def anomaly_threshold() -> float:
    return _get("ANOMALY_THRESHOLD")


def block_score_threshold() -> float:
    return _get("BLOCK_SCORE_THRESHOLD")


def block_confidence_threshold() -> float:
    return _get("BLOCK_CONFIDENCE_THRESHOLD")


def confidence_full_samples() -> float:
    # float agar pembagian data_sufficiency tidak pernah integer division
    return max(_get("CONFIDENCE_FULL_SAMPLES"), 1.0)
