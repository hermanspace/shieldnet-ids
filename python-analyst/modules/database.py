# database.py bertugas mengelola koneksi dan query ke TimescaleDB.
# Python Analyst membutuhkan data historis syslog untuk melatih dan
# menjalankan model Isolation Forest.

import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional

import psycopg2
import psycopg2.extras
import config

logger = logging.getLogger(__name__)


def get_connection():
    """
    membuat dan mengembalikan koneksi baru ke TimescaleDB.
    koneksi dibuat baru setiap kali dipanggil karena psycopg2 tidak thread-safe
    untuk berbagi koneksi antar thread.
    """
    return psycopg2.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        dbname=config.DB_NAME,
        user=config.DB_USER,
        password=config.DB_PASSWORD
    )


def wait_for_db(max_retries: int = 10) -> bool:
    """
    menunggu database siap dengan mekanisme retry.
    dipanggil saat startup untuk memastikan database sudah running
    sebelum sistem mulai memproses data.
    """
    for attempt in range(1, max_retries + 1):
        try:
            conn = get_connection()
            conn.close()
            logger.info("Koneksi database berhasil.")
            return True
        except Exception as e:
            logger.warning(f"Percobaan ke-{attempt} koneksi database gagal: {e}")
            time.sleep(3)
    return False


def fetch_syslogs_for_analysis(source_ip: str, window_minutes: int) -> List[Dict]:
    """
    mengambil data syslog historis untuk satu IP dalam jendela waktu tertentu.
    data ini digunakan sebagai konteks untuk analisis Isolation Forest,
    memungkinkan model melihat pola perilaku IP tersebut secara keseluruhan.
    """
    query = """
        SELECT
            time,
            source_ip,
            source_port,
            dest_port,
            event_type,
            protocol,
            node_id
        FROM syslogs
        WHERE source_ip = %s
          AND time > NOW() - INTERVAL '%s minutes'
        ORDER BY time DESC
        LIMIT 1000
    """
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, (source_ip, window_minutes))
            rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Gagal mengambil syslog untuk IP {source_ip}: {e}")
        return []


def fetch_training_data(hours: int = 24) -> List[Dict]:
    """
    mengambil data syslog dari 24 jam terakhir untuk keperluan pelatihan model.
    data pelatihan mencakup semua IP agar model bisa membedakan
    pola normal dari pola anomali secara komprehensif.
    """
    query = """
        SELECT
            source_ip,
            COUNT(*) as total_requests,
            COUNT(DISTINCT dest_port) as unique_dest_ports,
            COUNT(DISTINCT source_port) as unique_src_ports,
            COUNT(CASE WHEN event_type = 'login_fail' THEN 1 END) as login_fails,
            COUNT(CASE WHEN event_type = 'port_scan' THEN 1 END) as port_scans,
            COUNT(CASE WHEN event_type = 'brute_force' THEN 1 END) as brute_forces,
            MIN(time) as first_seen,
            MAX(time) as last_seen,
            EXTRACT(EPOCH FROM (MAX(time) - MIN(time))) as duration_seconds
        FROM syslogs
        WHERE time > NOW() - INTERVAL '%s hours'
        GROUP BY source_ip
        HAVING COUNT(*) >= 2
    """
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query % hours)
            rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Gagal mengambil data pelatihan: {e}")
        return []


def count_syslogs_since(since: datetime) -> int:
    """
    menghitung jumlah syslog baru sejak waktu tertentu.
    digunakan untuk menentukan kapan model perlu dilatih ulang
    berdasarkan parameter MODEL_RETRAIN_INTERVAL.
    """
    query = "SELECT COUNT(*) FROM syslogs WHERE time > %s"
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(query, (since,))
            count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Gagal menghitung syslog: {e}")
        return 0
