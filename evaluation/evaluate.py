#!/usr/bin/env python3
# =============================================================================
# evaluate.py — Evaluasi kuantitatif Sistem Deteksi Intrusi ShieldNet.
#
# Skrip ini mengirim skenario trafik BERLABEL (ground truth diketahui),
# menunggu seluruh hasil analisis masuk ke tabel intrusion_results, lalu
# menghitung metrik evaluasi standar machine learning:
#
#   - Confusion matrix (TP / FP / TN / FN)
#   - Accuracy, Precision, Recall, F1-score, False Positive Rate
#   - Waktu respons deteksi (syslog pertama -> deteksi intrusi pertama)
#   - Efektivitas aksi (berapa IP serangan yang berujung aksi "block")
#
# Cara pakai (dari host, direktori thesis-ids, semua container harus running):
#   make evaluate
# atau langsung:
#   docker exec -i ids-python python3 - < evaluation/evaluate.py
#
# Alur 5 fase (agar deteksi mencerminkan kemampuan sistem, bukan artefak
# pelatihan setengah-jalan):
#   1. Trafik latar 30 IP beragam        -> melatih baseline "normal"
#   2. Skenario uji berlabel             -> serangan ikut masuk data latih
#   3. Jeda retrain otomatis             -> model beradaptasi dengan data lengkap
#   4. Analisis ulang semua IP           -> vonis akhir dari model final yang sama
#   5. Hitung metrik
#
# Catatan metodologis:
# - IP uji memakai blok TEST-NET (RFC 5737) agar tidak bentrok data nyata:
#   192.0.2.0/24 untuk trafik latar (pelatihan), 198.51.100.0/24 untuk uji.
# - Baseline (Fase 1) sengaja dibuat BERAGAM. Baseline seragam membuat serangan
#   port scan / flood tidak menonjol sebagai outlier sehingga lolos deteksi.
# - Beri jeda minimal ANALYSIS_WINDOW_MINUTES (default 10 menit) antar-run,
#   karena jendela analisis akan mencampur syslog run sebelumnya. Skrip
#   memberi peringatan otomatis jika residu run sebelumnya terdeteksi.
# =============================================================================

import json
import os
import socket
import sys
import time

import psycopg2
import psycopg2.extras

# ---------------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------------
COLLECTOR_ADDR = (
    os.getenv("EVAL_COLLECTOR_HOST", "golang-collector"),
    int(os.getenv("EVAL_COLLECTOR_PORT", "514")),
)
ANALYSIS_WINDOW_MINUTES = int(os.getenv("ANALYSIS_WINDOW_MINUTES", "10"))
POLL_TIMEOUT_SECONDS = 90   # Batas tunggu hasil analisis
POLL_INTERVAL_SECONDS = 3   # Interval polling tabel intrusion_results

DB_PARAMS = dict(
    host=os.getenv("DB_HOST", "timescaledb"),
    port=int(os.getenv("DB_PORT", "5432")),
    dbname=os.getenv("DB_NAME", "ids_thesis"),
    user=os.getenv("DB_USER", "ids_user"),
    password=os.getenv("DB_PASSWORD", "ids_password"),
)


# ---------------------------------------------------------------------------
# Pembangkit pesan syslog berformat MikroTik asli
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Definisi skenario
# ---------------------------------------------------------------------------
def build_training_traffic() -> list:
    """
    Trafik latar jinak dari 30 IP unik dengan perilaku BERAGAM.

    Keberagaman ini penting untuk validitas evaluasi: Isolation Forest
    mengisolasi anomali relatif terhadap sebaran data "normal". Bila seluruh
    IP normal berperilaku identik (volume & port sama), sebaran terlalu sempit
    sehingga serangan seperti port scan / flood tidak menonjol sebagai outlier
    dan lolos deteksi. Variasi jumlah request (3-8) dan port tujuan
    (80/443/53) membentuk baseline realistis. Volume (~165 pesan) melewati
    MODEL_RETRAIN_INTERVAL (default 100) sehingga model terlatih.
    """
    ports = [80, 443, 53]
    msgs = []
    for j in range(30):
        ip = f"192.0.2.{10 + j}"
        n_req = 3 + (j % 6)                        # 3..8 request per IP (beragam)
        port = ports[j % len(ports)]
        for k in range(n_req):
            msgs.append(fw_msg(ip, 52000 + j * 20 + k, port))
    return msgs


def build_scenarios() -> list:
    """
    Skenario uji berlabel. label=0 berarti trafik normal (jinak),
    label=1 berarti serangan yang seharusnya terdeteksi sebagai intrusi.
    """
    scenarios = []

    # Catatan: tiap IP uji dibuat BERAGAM (intensitas berbeda), tidak ada dua
    # yang identik. Isolation Forest tidak dapat mengisolasi titik yang punya
    # "kembaran" persis — dua IP serangan identik akan saling menemani sehingga
    # skor anomalinya mendekati nol dan lolos deteksi.

    # --- label 0: trafik normal (5 IP, volume & port bervariasi wajar) ---
    normal_specs = [(3, 80), (4, 443), (5, 80), (4, 53), (6, 443)]
    for j, (n_req, port) in enumerate(normal_specs):
        ip = f"198.51.100.{10 + j}"
        scenarios.append(dict(
            ip=ip, label=0, name="normal-web",
            msgs=[fw_msg(ip, 51000 + j * 20 + k, port) for k in range(n_req)],
            delay=0.1,
        ))

    # --- label 1: brute force SSH (2 IP, jumlah login gagal berbeda) ---
    for ip, n_fail in (("198.51.100.101", 20), ("198.51.100.102", 28)):
        scenarios.append(dict(
            ip=ip, label=1, name="brute-force-ssh",
            msgs=[login_fail_msg(ip) for _ in range(n_fail)],
            delay=0.05,
        ))

    # --- label 1: port scanning (2 IP, jumlah port berbeda) ---
    for ip, n_port in (("198.51.100.111", 25), ("198.51.100.112", 33)):
        scenarios.append(dict(
            ip=ip, label=1, name="port-scan",
            msgs=[fw_msg(ip, 30000 + k, 100 + k * 7) for k in range(n_port)],
            delay=0.03,
        ))

    # --- label 1: flood (1 IP, banyak request cepat ke satu port) ---
    ip = "198.51.100.121"
    scenarios.append(dict(
        ip=ip, label=1, name="syn-flood",
        msgs=[fw_msg(ip, 40000 + k, 80) for k in range(40)],
        delay=0.01,
    ))

    return scenarios


def build_retrigger(scenario: dict) -> list:
    """
    Beberapa pesan tambahan per IP uji untuk MEMICU analisis ulang setelah
    model beradaptasi (retrain). Vonis dari analisis ulang inilah yang dinilai,
    sehingga setiap IP dievaluasi terhadap model final yang sama — bukan model
    setengah-terlatih di awal. Pesan menambah konteks pada jendela analisis
    tanpa mengubah karakter perilaku (normal tetap normal, serangan tetap
    serangan) karena syslog fase sebelumnya masih berada dalam jendela 10 menit.
    """
    ip, name = scenario["ip"], scenario["name"]
    if name == "brute-force-ssh":
        return [login_fail_msg(ip) for _ in range(5)]
    if name == "port-scan":
        return [fw_msg(ip, 33000 + k, 500 + k * 5) for k in range(5)]
    if name == "syn-flood":
        return [fw_msg(ip, 45000 + k, 80) for k in range(5)]
    # normal-web
    return [fw_msg(ip, 51500 + k, 80) for k in range(5)]


# ---------------------------------------------------------------------------
# Utilitas database dan pengiriman
# ---------------------------------------------------------------------------
def db_query(query: str, params=None):
    conn = psycopg2.connect(**DB_PARAMS)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params or ())
            return cur.fetchall()
    finally:
        conn.close()


def db_now():
    """Ambil waktu server database agar bebas dari selisih jam antar-container."""
    return db_query("SELECT NOW() AS now")[0]["now"]


def send_messages(sock: socket.socket, msgs: list, delay: float):
    for m in msgs:
        sock.sendto(m.encode(), COLLECTOR_ADDR)
        time.sleep(delay)


def check_residue(test_ips: list) -> int:
    """Cek apakah masih ada syslog IP uji di dalam jendela analisis (residu run lama)."""
    rows = db_query(
        """
        SELECT COUNT(*) AS n FROM syslogs
        WHERE source_ip = ANY(%s)
          AND time > NOW() - (%s || ' minutes')::INTERVAL
        """,
        (test_ips, str(ANALYSIS_WINDOW_MINUTES)),
    )
    return rows[0]["n"]


def wait_for_results(test_ips: list, run_start) -> None:
    """
    Tunggu hingga jumlah hasil analisis untuk IP uji stabil
    (tidak bertambah pada dua polling berturut-turut) atau timeout.
    """
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    prev_count, stable = -1, 0
    while time.time() < deadline:
        rows = db_query(
            "SELECT COUNT(*) AS n FROM intrusion_results WHERE time >= %s AND source_ip = ANY(%s)",
            (run_start, test_ips),
        )
        count = rows[0]["n"]
        distinct = db_query(
            "SELECT COUNT(DISTINCT source_ip) AS n FROM intrusion_results WHERE time >= %s AND source_ip = ANY(%s)",
            (run_start, test_ips),
        )[0]["n"]
        print(f"   ... {count} hasil analisis masuk ({distinct}/{len(test_ips)} IP)")
        if distinct == len(test_ips) and count == prev_count:
            stable += 1
            if stable >= 2:
                return
        else:
            stable = 0
        prev_count = count
        time.sleep(POLL_INTERVAL_SECONDS)
    print("   PERINGATAN: timeout menunggu hasil — evaluasi lanjut dengan data yang ada.")


# ---------------------------------------------------------------------------
# Perhitungan metrik
# ---------------------------------------------------------------------------
def evaluate(scenarios: list, run_start) -> dict:
    test_ips = [s["ip"] for s in scenarios]

    # Vonis akhir per IP = hasil analisis TERAKHIR (paling banyak konteks data)
    finals = {r["source_ip"]: r for r in db_query(
        """
        SELECT DISTINCT ON (source_ip)
               source_ip, time, anomaly_score, is_intrusion, confidence, action_taken
        FROM intrusion_results
        WHERE time >= %s AND source_ip = ANY(%s)
        ORDER BY source_ip, time DESC
        """,
        (run_start, test_ips),
    )}

    # Apakah IP pernah mendapat aksi "block" pada run ini
    ever_blocked = {r["source_ip"] for r in db_query(
        """
        SELECT DISTINCT source_ip FROM intrusion_results
        WHERE time >= %s AND source_ip = ANY(%s) AND action_taken = 'block'
        """,
        (run_start, test_ips),
    )}

    # Waktu respons: syslog pertama -> deteksi intrusi pertama, per IP
    latencies = {r["source_ip"]: r for r in db_query(
        """
        SELECT r.source_ip,
               EXTRACT(EPOCH FROM (
                   MIN(r.time) FILTER (WHERE r.is_intrusion) - MIN(s.first_log)
               )) AS delay_seconds
        FROM intrusion_results r
        JOIN LATERAL (
            SELECT MIN(time) AS first_log FROM syslogs
            WHERE source_ip = r.source_ip AND time >= %s
        ) s ON TRUE
        WHERE r.time >= %s AND r.source_ip = ANY(%s)
        GROUP BY r.source_ip
        """,
        (run_start, run_start, test_ips),
    )}

    # Susun confusion matrix dari vonis akhir vs ground truth
    tp = fp = tn = fn = 0
    per_ip = []
    for s in scenarios:
        r = finals.get(s["ip"])
        predicted = bool(r["is_intrusion"]) if r else False
        actual = s["label"] == 1
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1

        lat = latencies.get(s["ip"], {}).get("delay_seconds")
        per_ip.append(dict(
            ip=s["ip"], scenario=s["name"], label=s["label"],
            predicted=int(predicted),
            anomaly_score=float(r["anomaly_score"]) if r else None,
            confidence=float(r["confidence"]) if r else None,
            final_action=r["action_taken"] if r else "(tidak ada hasil)",
            ever_blocked=s["ip"] in ever_blocked,
            detect_delay_s=float(lat) if lat is not None else None,
        ))

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    attack_ips = [p for p in per_ip if p["label"] == 1]
    blocked_attacks = sum(1 for p in attack_ips if p["ever_blocked"])
    delays = [p["detect_delay_s"] for p in attack_ips if p["detect_delay_s"] is not None]

    return dict(
        per_ip=per_ip,
        confusion_matrix=dict(TP=tp, FP=fp, TN=tn, FN=fn),
        metrics=dict(
            accuracy=round(accuracy, 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
        ),
        blocking=dict(
            attack_ips=len(attack_ips),
            blocked=blocked_attacks,
        ),
        response_time_seconds=dict(
            avg=round(sum(delays) / len(delays), 2) if delays else None,
            max=round(max(delays), 2) if delays else None,
            min=round(min(delays), 2) if delays else None,
        ),
    )


def print_report(result: dict):
    print()
    print("=" * 76)
    print("HASIL EVALUASI KUANTITATIF — ShieldNet IDS")
    print("=" * 76)

    print(f"\n{'IP':<18} {'Skenario':<17} {'Label':<7} {'Prediksi':<9} "
          f"{'Skor':<8} {'Conf':<6} {'Aksi Akhir':<11} {'Delay(s)'}")
    print("-" * 76)
    for p in result["per_ip"]:
        label = "SERANG" if p["label"] else "NORMAL"
        pred = "INTRUSI" if p["predicted"] else "normal"
        score = f"{p['anomaly_score']:.3f}" if p["anomaly_score"] is not None else "-"
        conf = f"{p['confidence']:.2f}" if p["confidence"] is not None else "-"
        delay = f"{p['detect_delay_s']:.1f}" if p["detect_delay_s"] is not None else "-"
        print(f"{p['ip']:<18} {p['scenario']:<17} {label:<7} {pred:<9} "
              f"{score:<8} {conf:<6} {p['final_action']:<11} {delay}")

    cm = result["confusion_matrix"]
    m = result["metrics"]
    print("\nConfusion Matrix (vonis akhir per IP):")
    print(f"                     Prediksi INTRUSI   Prediksi NORMAL")
    print(f"  Aktual SERANGAN    TP = {cm['TP']:<14} FN = {cm['FN']}")
    print(f"  Aktual NORMAL      FP = {cm['FP']:<14} TN = {cm['TN']}")

    print("\nMetrik Evaluasi:")
    print(f"  Accuracy            : {m['accuracy']:.2%}")
    print(f"  Precision           : {m['precision']:.2%}")
    print(f"  Recall (Detection)  : {m['recall']:.2%}")
    print(f"  F1-Score            : {m['f1_score']:.4f}")
    print(f"  False Positive Rate : {m['false_positive_rate']:.2%}")

    b = result["blocking"]
    rt = result["response_time_seconds"]
    print(f"\nEfektivitas Aksi : {b['blocked']}/{b['attack_ips']} IP serangan berujung aksi 'block'")
    if rt["avg"] is not None:
        print(f"Waktu Respons    : rata-rata {rt['avg']}s | min {rt['min']}s | maks {rt['max']}s")
        print("                   (syslog pertama -> deteksi intrusi pertama)")

    print("\n--- JSON (untuk lampiran/olah data tesis) ---")
    print(json.dumps(result, indent=2, default=str))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=== Evaluasi Kuantitatif ShieldNet IDS ===")

    scenarios = build_scenarios()
    test_ips = [s["ip"] for s in scenarios]

    # Peringatan residu: syslog run sebelumnya masih di dalam jendela analisis
    residue = check_residue(test_ips)
    if residue > 0:
        print(f"PERINGATAN: {residue} syslog IP uji masih berada dalam jendela "
              f"analisis {ANALYSIS_WINDOW_MINUTES} menit (residu run sebelumnya).")
        print("Hasil bisa terkontaminasi — disarankan menunggu lalu jalankan ulang.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Fase 1: trafik latar beragam untuk melatih model dengan baseline normal
    training = build_training_traffic()
    print(f"\n[1/5] Mengirim {len(training)} pesan trafik latar dari 30 IP beragam...")
    send_messages(sock, training, delay=0.02)
    print("      Menunggu model selesai dilatih...")
    time.sleep(15)

    # Fase 2: kirim skenario uji berlabel. run_start diambil tepat sebelum ini
    # agar seluruh analisis serangan tercakup dan waktu respons terukur sejak
    # syslog serangan pertama.
    run_start = db_now()
    total_msgs = sum(len(s["msgs"]) for s in scenarios)
    print(f"\n[2/5] Mengirim {len(scenarios)} skenario uji berlabel ({total_msgs} pesan)...")
    for s in scenarios:
        print(f"      {s['name']:<17} {s['ip']:<18} ({len(s['msgs'])} pesan, label="
              f"{'SERANGAN' if s['label'] else 'NORMAL'})")
        send_messages(sock, s["msgs"], s["delay"])

    # Fase 3: beri waktu model beradaptasi, lalu analisis ulang tiap IP agar
    # vonis akhir mencerminkan model yang sudah matang (bukan setengah-terlatih).
    print("\n[3/5] Menunggu model beradaptasi lalu analisis ulang...")
    time.sleep(15)
    for s in scenarios:
        send_messages(sock, build_retrigger(s), delay=0.05)
    sock.close()

    # Fase 4: tunggu seluruh hasil analisis
    print(f"\n[4/5] Menunggu hasil analisis (timeout {POLL_TIMEOUT_SECONDS}s)...")
    time.sleep(5)
    wait_for_results(test_ips, run_start)

    # Fase 5: hitung dan tampilkan metrik
    print("\n[5/5] Menghitung metrik evaluasi...")
    result = evaluate(scenarios, run_start)

    # Deteksi model belum terlatih: semua hasil skor 0 dan confidence 0
    scored = [p for p in result["per_ip"] if p["anomaly_score"] is not None]
    if scored and all(p["anomaly_score"] == 0.0 and p["confidence"] == 0.0 for p in scored):
        print("PERINGATAN: seluruh skor bernilai 0 — model kemungkinan belum terlatih.")
        print("Pastikan data cukup (>= 10 IP unik) lalu jalankan ulang evaluasi.")

    print_report(result)


if __name__ == "__main__":
    main()
