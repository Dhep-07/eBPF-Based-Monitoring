#!/usr/bin/env bash
# Usage: ./stress_and_measure.sh [db_path] [stress_seconds]
# Needs: sudo, stress-ng, sqlite3 CLI; optional: gpu_burn (or gpu-burn) for GPU load.
set -u
DB="${1:-/dev/shm/run.db}"
DUR="${2:-30}"
export WIN_MS="${WIN_MS:-100}" SYS_MS="${SYS_MS:-1000}" MAX_DB_MB="${MAX_DB_MB:-256}"

[ -x ./monitor ] || { echo "Build first: make"; exit 1; }
command -v stress-ng >/dev/null || { echo "Install stress-ng (sudo apt install stress-ng)"; exit 1; }

echo "== Clearing old DB =="
sudo rm -f "$DB" "$DB-wal" "$DB-shm"

echo "== Starting monitor (WIN_MS=$WIN_MS SYS_MS=$SYS_MS cap=${MAX_DB_MB}MB) =="
sudo -E ./monitor "$DB" --system-only &
sleep 3

echo "== Phase 1: idle baseline (10s) =="
sleep 10

echo "== Phase 2: stress for ${DUR}s (CPU + RAM + disk + GPU) =="
stress-ng --cpu 0 --vm 2 --vm-bytes 40% --hdd 2 --hdd-bytes 1g \
          --timeout "${DUR}s" --temp-path /tmp >/dev/null 2>&1 &
SPID=$!
GPUBURN=$(command -v gpu_burn || command -v gpu-burn || true)
GPID=""
if [ -n "$GPUBURN" ]; then
    "$GPUBURN" "$DUR" >/dev/null 2>&1 &
    GPID=$!
else
    echo "   (no gpu_burn found - GPU phase skipped)"
fi
# Wait only for the stress jobs, never for the monitor
wait $SPID
[ -n "$GPID" ] && wait $GPID

echo "== Phase 3: idle cooldown (10s) =="
sleep 10

echo "== Stopping monitor =="
sudo pkill -INT -x monitor
sleep 3

echo
echo "================ DB REPORT ================"
ls -l "$DB" | awk '{printf "DB file size: %.2f MB\n", $5/1048576}'
sqlite3 "$DB" <<'SQL'
.headers on
.mode column
SELECT 'window_metrics' AS tbl, COUNT(*) AS rows FROM window_metrics
UNION ALL SELECT 'system_metrics', COUNT(*) FROM system_metrics
UNION ALL SELECT 'gpu_metrics', COUNT(*) FROM gpu_metrics
UNION ALL SELECT 'collectives', COUNT(*) FROM collectives;

SELECT 'peak values' AS what,
  ROUND(MAX(cpu_util_pct),1) AS cpu_pct_max,
  MAX(cpu_temp_mc)/1000.0     AS cpu_temp_c_max,
  (MAX(mem_total_kb)-MIN(mem_avail_kb))/1024 AS ram_used_mb_peak
FROM system_metrics;

SELECT 'gpu peaks' AS what, gpu_index,
  MAX(util_gpu_pct) AS util_max, MAX(temp_c) AS temp_c_max,
  MAX(power_mw)/1000.0 AS power_w_max, MAX(mem_used_bytes)/1048576 AS mem_mb_max
FROM gpu_metrics GROUP BY gpu_index;

SELECT 'disk peak' AS what,
  ROUND(MAX(sys_disk_wr_bytes*1e9/dt_ns)/1048576,1) AS wr_MBps_max,
  ROUND(MAX(sys_disk_rd_bytes*1e9/dt_ns)/1048576,1) AS rd_MBps_max,
  ROUND(MAX(sys_net_xmit_bytes*1e9/dt_ns)/1048576,1) AS net_tx_MBps_max
FROM window_metrics;

SELECT 'ringbuf drops' AS what, MAX(ringbuf_drops) AS drops FROM window_metrics;
SELECT key, val FROM run_meta WHERE key='sqlite_step_errors';
SQL