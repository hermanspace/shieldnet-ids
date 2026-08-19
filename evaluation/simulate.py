#!/usr/bin/env python3
# =============================================================================
# simulate.py — Simulasi serangan untuk demo sistem (dipanggil oleh `make test`).
#
# Mengirim syslog dummy berformat MikroTik asli ke Golang Collector (UDP 514)
# dalam TIGA fase yang dirancang agar deteksi konsisten muncul saat demo:
#
#   FASE 1 — Baseline normal 30 IP unik yang JINAK & KONSISTEN.
#            Isolation Forest mengisolasi anomali relatif terhadap sebaran
#            data "normal". Baseline dibuat bervolume rendah (3-8 request),
#            sedikit port (1-2), dan TANPA login gagal — sehingga pola
#            serangan benar-benar menonjol sebagai outlier. Volume besar
#            (~155 pesan) memicu pelatihan model (butuh >= 10 IP unik).
#
#   FASE 2 — Tiga skenario serangan (brute force, port scan, flood).
#            Setelah fase ini, model dilatih ulang otomatis sehingga data
#            serangan ikut masuk sebagai ~10% anomali — proporsi yang cocok
#            dengan parameter contamination=0.1.
#
#   FASE 3 — Pengiriman ulang singkat tiap IP serangan untuk MEMICU
#            analisis ulang dengan model terkini (yang sudah mengenal pola
#            serangan). Vonis terakhir inilah yang tampil di dashboard.
#
# Semua parameter model (contamination 0.1, threshold -0.1) TIDAK diubah —
# demo bekerja pada konfigurasi default sistem.
#
# Cara pakai (dari host, direktori thesis-ids):
#   make test
# =============================================================================

import socket
import time

DST = ("golang-collector", 514)


def fw_msg(src_ip: str, src_port: int, dst_port: int, node: str = "router-01") -> str:
    """Pesan log firewall MikroTik (pasangan IP:port memakai panah '->')."""
    return (
        f"<134>Jan  1 12:00:00 {node} firewall: in:ether1 out:bridge, "
        f"proto TCP (SYN), {src_ip}:{src_port}->10.0.0.1:{dst_port}, len 60"
    )


def login_fail_msg(src_ip: str, node: str = "router-01") -> str:
    """Pesan login gagal MikroTik (topic system) — terklasifikasi login_fail."""
    return (
        f"<134>Jan  1 12:00:00 {node} system,error,critical "
        f"login failure for user admin from {src_ip} via ssh"
    )


def send(sock: socket.socket, msgs: list, delay: float):
    for m in msgs:
        sock.sendto(m.encode(), DST)
        time.sleep(delay)


# IP penyerang (dipakai di Fase 2 dan Fase 3)
IP_BRUTE = "10.10.10.99"
IP_SCAN = "172.16.0.50"
IP_FLOOD = "203.0.113.77"


def attack_messages() -> dict:
    """Bangun pesan tiap skenario serangan (dipakai ulang di Fase 2 & 3)."""
    return {
        "brute": [login_fail_msg(IP_BRUTE) for _ in range(20)],
        "scan": [fw_msg(IP_SCAN, 30000 + i, 20 + i * 3) for i in range(25)],
        "flood": [fw_msg(IP_FLOOD, 40000 + i, 80) for i in range(35)],
    }


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # =========================================================================
    # FASE 1 — Baseline normal jinak: 30 IP unik, volume rendah, tanpa fail
    # =========================================================================
    ports = [80, 443, 53]
    background = []
    for i in range(30):
        ip = f"192.168.1.{10 + i}"
        n_req = 3 + (i % 6)                       # 3..8 request (variasi ringan)
        port = ports[i % len(ports)]
        for k in range(n_req):
            background.append(fw_msg(ip, 50000 + i * 20 + k, port))

    print(f">> [Fase 1] Baseline normal    : {len(background)} pesan dari 30 IP unik (jinak)")
    print(">>          (melatih model — baseline sengaja jinak agar serangan menonjol)")
    send(sock, background, delay=0.02)
    print(">>          Menunggu model selesai dilatih (15 detik)...")
    time.sleep(15)

    # =========================================================================
    # FASE 2 — Skenario serangan (gelombang pertama)
    # =========================================================================
    atk = attack_messages()
    print(f">> [Fase 2] Brute force SSH    : {len(atk['brute'])} pesan dari {IP_BRUTE}")
    send(sock, atk["brute"], delay=0.08)
    print(f">> [Fase 2] Port scanning      : {len(atk['scan'])} pesan dari {IP_SCAN}")
    send(sock, atk["scan"], delay=0.04)
    print(f">> [Fase 2] Flood/DoS          : {len(atk['flood'])} pesan dari {IP_FLOOD}")
    send(sock, atk["flood"], delay=0.01)

    # Beri waktu model dilatih ulang otomatis dengan data serangan masuk
    print(">>          Menunggu model beradaptasi (retrain otomatis, 15 detik)...")
    time.sleep(15)

    # =========================================================================
    # FASE 3 — Picu analisis ulang dengan model terkini
    # Kirim ulang beberapa pesan tiap IP serangan agar sistem menganalisis
    # kembali memakai model yang sudah mengenal pola serangan.
    # =========================================================================
    print(">> [Fase 3] Analisis ulang serangan dengan model terkini...")
    retrigger = (
        [login_fail_msg(IP_BRUTE) for _ in range(4)]
        + [fw_msg(IP_SCAN, 31000 + i, 200 + i * 3) for i in range(4)]
        + [fw_msg(IP_FLOOD, 41000 + i, 80) for i in range(4)]
    )
    send(sock, retrigger, delay=0.15)

    sock.close()

    total = len(background) + sum(len(v) for v in atk.values()) + len(retrigger)
    print(f"""
>> Simulasi selesai — total {total} pesan terkirim.
>> Tunggu +-10-15 detik lalu periksa hasil deteksi:
>>   - Web      : http://localhost:8080/intrusions
>>              (IP serangan: {IP_BRUTE}, {IP_SCAN}, {IP_FLOOD})
>>   - Log      : docker logs ids-python --tail 30   (cari baris [INTRUSI])
>>   - Grafana  : http://localhost:3000/d/ids-intrusions
""")


if __name__ == "__main__":
    main()
