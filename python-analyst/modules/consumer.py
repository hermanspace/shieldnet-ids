# consumer.py bertugas mengkonsumsi event syslog baru dari Redis Stream.
# menggunakan Consumer Group agar pesan tidak diproses dua kali
# jika ada beberapa instance Python Analyst berjalan.

import json
import logging
import time
from typing import Optional, Callable

import redis

import config

logger = logging.getLogger(__name__)

# Tipe fungsi callback yang dipanggil untuk setiap event syslog baru
MessageCallback = Callable[[dict], None]


class SyslogConsumer:
    """
    kelas yang mengelola konsumsi event dari Redis Stream menggunakan Consumer Group.
    Consumer Group memastikan setiap event hanya diproses satu kali meskipun
    ada beberapa instance consumer yang berjalan.
    """

    def __init__(self, callback: MessageCallback):
        self.client: Optional[redis.Redis] = None
        self.callback = callback

    def connect(self) -> bool:
        """
        membuka koneksi ke Redis dan membuat consumer group jika belum ada.
        consumer group dibutuhkan agar stream bisa dibaca oleh banyak consumer.
        """
        for attempt in range(1, 6):
            try:
                self.client = redis.Redis(
                    host=config.REDIS_HOST,
                    port=config.REDIS_PORT,
                    decode_responses=True
                )
                self.client.ping()
                self._ensure_consumer_group()
                logger.info("Consumer Redis berhasil terhubung.")
                return True
            except Exception as e:
                logger.warning(f"Percobaan ke-{attempt} koneksi Redis gagal: {e}")
                time.sleep(3)
        return False

    def _ensure_consumer_group(self):
        """
        membuat consumer group jika belum ada.
        '0' artinya mulai baca dari awal stream, '$' artinya hanya pesan baru.
        """
        try:
            self.client.xgroup_create(
                config.SYSLOG_STREAM_KEY,
                config.CONSUMER_GROUP,
                id='0',         # Baca dari awal untuk tidak melewatkan pesan yang ada
                mkstream=True   # Buat stream jika belum ada
            )
            logger.info(f"Consumer group '{config.CONSUMER_GROUP}' berhasil dibuat.")
        except redis.exceptions.ResponseError as e:
            # Error BUSYGROUP berarti group sudah ada, ini normal
            if "BUSYGROUP" not in str(e):
                logger.error(f"Error membuat consumer group: {e}")

    def consume(self):
        """
        loop utama yang terus membaca pesan dari Redis Stream.
        setiap pesan yang berhasil diproses akan di-acknowledge (ACK)
        agar tidak diproses ulang.
        """
        if self.client is None:
            logger.error("Belum terhubung ke Redis.")
            return

        logger.info("Mulai mengkonsumsi event dari Redis Stream...")

        while True:
            try:
                # Baca maksimal 10 pesan sekaligus, timeout 2 detik jika stream kosong
                messages = self.client.xreadgroup(
                    groupname=config.CONSUMER_GROUP,
                    consumername=config.CONSUMER_NAME,
                    streams={config.SYSLOG_STREAM_KEY: '>'},
                    count=10,
                    block=2000  # Tunggu 2 detik sebelum retry jika tidak ada pesan
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for message_id, fields in stream_messages:
                        try:
                            # Proses pesan melalui callback
                            self.callback(fields)
                            # Acknowledge pesan setelah berhasil diproses
                            self.client.xack(
                                config.SYSLOG_STREAM_KEY,
                                config.CONSUMER_GROUP,
                                message_id
                            )
                        except Exception as e:
                            logger.error(f"Gagal memproses pesan {message_id}: {e}")

            except redis.exceptions.ConnectionError:
                logger.warning("Koneksi Redis terputus, mencoba reconnect...")
                time.sleep(5)
                self.connect()
            except Exception as e:
                logger.error(f"Error pada consumer loop: {e}")
                time.sleep(1)
