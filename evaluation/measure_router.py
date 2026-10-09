#!/usr/bin/env python3
"""
measure_router.py — Pengukuran beban router MikroTik (CPU & memori) sebelum/sesudah
sistem diaktifkan, berbasis sampel yang dikumpulkan Golang Collector ke tabel
node_resources melalui RouterOS API `/system/resource/print` (RESOURCE_POLL_INTERVAL).

Acuan metrik: ISO/IEC 25023 (resource utilization) dan HOST-RESOURCES-MIB RFC 2790
(hrProcessorLoad ≈ cpu-load, hrStorageUsed ≈ total-memory − free-memory).

Pemakaian (dari host, lihat Makefile):
  make measure LABEL=sebelum DURATION=300     # rekam fase "sebelum" selama 300 detik
  make measure LABEL=sesudah DURATION=300     # rekam fase "sesudah" (sistem aktif / simulasi)
  make measure-compare A=sebelum B=sesudah    # tabel perbandingan + selisih

Prosedur sebelum/sesudah yang disarankan:
  1. "sebelum": matikan remote logging di tiap router
       /system logging disable [find action=remote]   (poller API tetap jalan)
  2. "sesudah": aktifkan kembali lalu jalankan `make test` di terminal lain
       /system logging enable [find action=remote]
  Pastikan beban trafik pada kedua fase sebanding dan NTP aktif.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DB_PARAMS = dict(
    host=os.getenv("DB_HOST", "timescaledb"),
    port=int(os.getenv("DB_PORT", "5432")),
    dbname=os.getenv("DB_NAME", "ids_thesis"),
    user=os.getenv("DB_USER", "ids_user"),
    password=os.getenv("DB_PASSWORD", "ids_password"),
)

SUMMARY_SQL = """
SELECT node_id,
       COUNT(*)                                   AS n,
       ROUND(AVG(cpu_load)::numeric, 2)           AS cpu_mean,
       ROUND(STDDEV_SAMP(cpu_load)::numeric, 2)   AS cpu_sd,
       MAX(cpu_load)                              AS cpu_max,
       ROUND(AVG(100.0*(total_memory-free_memory)/NULLIF(total_memory,0))::numeric, 2) AS mem_mean,
       ROUND(MAX(100.0*(total_memory-free_memory)/NULLIF(total_memory,0))::numeric, 2) AS mem_max,
       ROUND((MAX(total_memory)/1048576.0)::numeric, 0) AS mem_total_mb,
       MAX(board_name) AS board, MAX(version) AS version
FROM node_resources
WHERE time >= %s AND time < %s
GROUP BY node_id ORDER BY node_id
"""


def connect():
    return psycopg2.connect(**DB_PARAMS)


def ensure_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS measurement_runs (
            id SERIAL PRIMARY KEY,
            label TEXT NOT NULL,
            started_at TIMESTAMPTZ NOT NULL,
            ended_at TIMESTAMPTZ NOT NULL,
            summary JSONB
        )""")


def summarize(cur, start, end):
    cur.execute(SUMMARY_SQL, (start, end))
    return [dict(r) for r in cur.fetchall()]


def record(label, duration):
    conn = connect()
    with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_table(cur)
        cur.execute("SELECT COUNT(*) AS c FROM node_resources WHERE time > NOW() - interval '2 minutes'")
        if cur.fetchone()["c"] == 0:
            print(">> PERINGATAN: belum ada sampel node_resources 2 menit terakhir. "
                  "Pastikan RESOURCE_POLL_INTERVAL>0, node aktif, dan API 8728 dapat dihubungi.")
    start = datetime.now(timezone.utc)
    print(f">> Merekam fase '{label}' selama {duration} detik (mulai {start:%H:%M:%S} UTC)...")
    for remaining in range(duration, 0, -30):
        time.sleep(min(30, remaining))
        print(f"   ... {max(remaining-30,0)} detik tersisa", flush=True)
    end = datetime.now(timezone.utc)
    with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        rows = summarize(cur, start, end)
        cur.execute("INSERT INTO measurement_runs (label, started_at, ended_at, summary) VALUES (%s,%s,%s,%s)",
                    (label, start, end, json.dumps(rows, default=str)))
    print_table(label, rows)
    conn.close()


def print_table(label, rows):
    print(f"\n>> Ringkasan fase '{label}':")
    print(f"   {'Node':<14}{'Sampel':>7}{'CPU μ%':>9}{'CPU σ':>8}{'CPU maks':>10}{'RAM μ%':>9}{'RAM maks':>10}{'RAM MB':>8}  Perangkat / RouterOS")
    for r in rows:
        print(f"   {r['node_id']:<14}{r['n']:>7}{float(r['cpu_mean'] or 0):>9.2f}{float(r['cpu_sd'] or 0):>8.2f}{r['cpu_max'] or 0:>10}"
              f"{float(r['mem_mean'] or 0):>9.2f}{float(r['mem_max'] or 0):>10.2f}{float(r['mem_total_mb'] or 0):>8.0f}  {r['board']} / {r['version']}")
    if not rows:
        print("   (tidak ada sampel pada jendela ini)")


def compare(a, b):
    conn = connect()
    with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        ensure_table(cur)
        runs = {}
        for label in (a, b):
            cur.execute("SELECT * FROM measurement_runs WHERE label=%s ORDER BY id DESC LIMIT 1", (label,))
            row = cur.fetchone()
            if not row:
                sys.exit(f"Fase '{label}' belum direkam. Jalankan: make measure LABEL={label} DURATION=300")
            runs[label] = {r["node_id"]: r for r in row["summary"]}
            sa = row["started_at"].astimezone(timezone.utc)
            ea = row["ended_at"].astimezone(timezone.utc)
            print(f">> Fase '{label}': {sa:%Y-%m-%d %H:%M} – {ea:%H:%M} UTC ({len(row['summary'])} node)")
    conn.close()
    nodes = sorted(set(runs[a]) | set(runs[b]))
    print(f"\n>> Perbandingan beban router: '{a}' → '{b}'  (ISO/IEC 25023 resource utilization; metrik ≈ RFC 2790 HOST-RESOURCES-MIB)")
    print(f"   {'Node':<14}{'CPU μ% A':>10}{'CPU μ% B':>10}{'Δ CPU':>8}{'CPU maks A':>12}{'CPU maks B':>12}{'RAM μ% A':>10}{'RAM μ% B':>10}{'Δ RAM':>8}")
    for n in nodes:
        ra, rb = runs[a].get(n, {}), runs[b].get(n, {})
        ca, cb = float(ra.get("cpu_mean") or 0), float(rb.get("cpu_mean") or 0)
        ma, mb = float(ra.get("mem_mean") or 0), float(rb.get("mem_mean") or 0)
        print(f"   {n:<14}{ca:>10.2f}{cb:>10.2f}{cb-ca:>+8.2f}{ra.get('cpu_max',0) or 0:>12}{rb.get('cpu_max',0) or 0:>12}{ma:>10.2f}{mb:>10.2f}{mb-ma:>+8.2f}")
    print("\n   Δ ≈ 0 berarti sistem (remote syslog + address-list) tidak menambah beban router secara berarti (mendukung H3).")


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "compare":
        compare(args[1], args[2] if len(args) > 2 else "sesudah")
    elif len(args) >= 1:
        record(args[0], int(args[1]) if len(args) > 1 else 300)
    else:
        print(__doc__)
