#!/usr/bin/env bash
# Run on BOTH nodes (start rank 0 first, or within a few seconds of each other).
# Usage: ./run_node.sh <node_rank 0|1> <schedule.csv> <out_root> [first_ep] [last_ep]
# Must be run INSIDE the monitored scope shell:  systemd-run --user --scope bash
# Start `sudo ./monitor` separately with the cgroup inode of that scope.
set -euo pipefail
NODE_RANK=${1:?node rank}; SCHED=${2:?schedule}; OUT=${3:?out root}
FIRST=${4:-1}; LAST=${5:-999999}

MASTER_ADDR=10.10.49.63; MASTER_PORT=29500
VENV=~/nccl-eye-venv; REPO=~/Downloads/eBPF-Based-Monitoring
FAULT_HOOK=${FAULT_HOOK:-$REPO/faults/inject.sh}   # to be written after calibration design
MARKER=/dev/shm/nccl_eye_fault_marker
source "$VENV/bin/activate"

export NCCL_SOCKET_IFNAME=eno1 NCCL_IB_DISABLE=1 NCCL_DEBUG=WARN
export GLOO_SOCKET_IFNAME=eno1
mkdir -p "$OUT"; cp -n "$SCHED" "$OUT/schedule.csv" || true
{ date -Is; uname -r; python -c "import torch;print(torch.__version__, torch.cuda.nccl.version())"
  nvidia-smi --query-gpu=driver_version,name --format=csv,noheader
  chronyc tracking | head -n 8; } > "$OUT/run_meta_node${NODE_RANK}.txt" 2>&1

n=0
tail -n +2 "$SCHED" | while IFS=, read -r EP CLS FRANK; do
  n=$((n+1)); [ "$n" -lt "$FIRST" ] && continue; [ "$n" -gt "$LAST" ] && break
  EPDIR="$OUT/$EP"; mkdir -p "$EPDIR"
  echo none > "$MARKER"
  sleep 20   # cool-down + let both nodes settle between episodes

  # fault injection (only on the faulty node), in a background window mid-run
  if [ "$CLS" != "none" ] && [ "$FRANK" = "$NODE_RANK" ] && [ -x "$FAULT_HOOK" ]; then
    ( sleep 25; echo "$CLS" > "$MARKER"; "$FAULT_HOOK" start "$CLS" ;
      sleep 60; "$FAULT_HOOK" stop "$CLS"; echo none > "$MARKER" ) &
    INJ=$!
  else INJ=""; fi

  torchrun --nnodes=2 --nproc_per_node=1 --node_rank="$NODE_RANK" \
    --master_addr="$MASTER_ADDR" --master_port="$MASTER_PORT" \
    "$REPO/harness.py" --episode "$EP" --out-dir "$EPDIR" --steps 600 --warmup 30 \
    ${DATA_FILE:+--data-file "$DATA_FILE"} || echo "episode $EP failed" >> "$OUT/failures.txt"

  [ -n "$INJ" ] && { wait "$INJ" || true; }
  echo none > "$MARKER"
done
