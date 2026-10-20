#!/usr/bin/env bash
# NCCL-Eye fault injector. Run on the faulty node (needs sudo for tc/drop_caches).
# Usage: inject.sh start|stop <cpu|net|disk|mem>
# Install at ~/Downloads/eBPF-Based-Monitoring/faults/inject.sh (chmod +x).
set -uo pipefail

IFACE=${IFACE:-eno1}
PEER_IP=${PEER_IP:-}              # REQUIRED for net: the OTHER node's IP (10.10.49.63 or .149)
CPU_CORES=${CPU_CORES:-2,3}       # pin stressors to cores used by harness; pick via `lscpu -e`
CPU_LOAD=${CPU_LOAD:-100}
MEM_VM_BYTES=${MEM_VM_BYTES:-4G}
DISK_FILE=${DISK_FILE:-/var/tmp/nccl_eye_disk_stress.bin}
DISK_SIZE_GB=${DISK_SIZE_GB:-24}  # > 16 GB RAM
DELAY=${DELAY:-2ms}; LOSS=${LOSS:-0.05%}
DEADMAN_SEC=${DEADMAN_SEC:-150}
PIDDIR=/dev/shm/nccl_eye_fault_pids
mkdir -p "$PIDDIR"

ACTION=${1:?start|stop}; CLS=${2:?class}

net_start() {
  [ -n "$PEER_IP" ] || { echo "set PEER_IP"; exit 2; }
  sudo tc qdisc del dev "$IFACE" root 2>/dev/null
  # prio qdisc: band 3 gets netem; filters send ONLY traffic to the peer on the NCCL/torch
  # ports (dynamic high ports) -- SSH(22) and NTP(123) are matched first and kept clean.
  sudo tc qdisc add dev "$IFACE" root handle 1: prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
  sudo tc qdisc add dev "$IFACE" parent 1:3 handle 30: netem delay "$DELAY" loss "$LOSS"
  sudo tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip dport 22 0xffff flowid 1:1
  sudo tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip sport 22 0xffff flowid 1:1
  sudo tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip dport 123 0xffff flowid 1:1
  sudo tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip sport 123 0xffff flowid 1:1
  sudo tc filter add dev "$IFACE" parent 1: protocol ip prio 2 u32 match ip dst "$PEER_IP"/32 flowid 1:3
  # independent dead-man timer: removes qdisc even if this script/session dies
  sudo systemd-run --quiet --unit=nccl-eye-tc-deadman --on-active="${DEADMAN_SEC}s" \
    /sbin/tc qdisc del dev "$IFACE" root 2>/dev/null
}
net_stop() {
  sudo tc qdisc del dev "$IFACE" root 2>/dev/null
  sudo systemctl stop nccl-eye-tc-deadman.timer 2>/dev/null
}

start() {
  case "$CLS" in
    cpu)  nohup taskset -c "$CPU_CORES" stress-ng --cpu "$(echo "$CPU_CORES" | tr ',' '\n' | wc -l)" \
            --cpu-load "$CPU_LOAD" --timeout 120s >/dev/null 2>&1 & echo $! > "$PIDDIR/cpu" ;;
    mem)  nohup stress-ng --vm 2 --vm-bytes "$MEM_VM_BYTES" --vm-method all --timeout 120s \
            >/dev/null 2>&1 & echo $! > "$PIDDIR/mem" ;;
    disk) [ -f "$DISK_FILE" ] || fallocate -l "${DISK_SIZE_GB}G" "$DISK_FILE"
          ( while true; do
              sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
              dd if="$DISK_FILE" of=/dev/null bs=4M count=512 iflag=direct 2>/dev/null
              dd if=/dev/zero of="$DISK_FILE.w" bs=4M count=256 oflag=direct 2>/dev/null
            done ) >/dev/null 2>&1 & echo $! > "$PIDDIR/disk" ;;
    net)  net_start ;;
    *) echo "unknown class $CLS"; exit 2 ;;
  esac
}
stop() {
  case "$CLS" in
    net) net_stop ;;
    *) if [ -f "$PIDDIR/$CLS" ]; then
         pid=$(cat "$PIDDIR/$CLS"); pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null
         rm -f "$PIDDIR/$CLS"
       fi
       pkill -f "stress-ng" 2>/dev/null; rm -f "$DISK_FILE.w" ;;
  esac
}
case "$ACTION" in start) start ;; stop) stop ;; *) exit 2 ;; esac
