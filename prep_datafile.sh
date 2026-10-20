#!/usr/bin/env bash
# Create the 24 GB data file with REAL (non-zero, incompressible) data.
# Run once per node. Usage: ./prep_datafile.sh   (env: DISK_FILE, DISK_SIZE_GB)
set -euo pipefail
DISK_FILE=${DISK_FILE:-/var/tmp/nccl_eye_disk_stress.bin}
DISK_SIZE_GB=${DISK_SIZE_GB:-24}
want=$((DISK_SIZE_GB * 1024 * 1024 * 1024))

if [ -f "$DISK_FILE" ] && [ "$(stat -c %s "$DISK_FILE")" -eq "$want" ]; then
  echo "OK: $DISK_FILE already exists with correct size."; exit 0
fi

dir=$(dirname "$DISK_FILE")
avail=$(df --output=avail -B1 "$dir" | tail -n1)
if [ "$avail" -lt $((want + 2*1024*1024*1024)) ]; then
  echo "ERROR: not enough free space in $dir (need ~$((DISK_SIZE_GB+2)) GB)." >&2; exit 1
fi

echo "Writing ${DISK_SIZE_GB} GB to $DISK_FILE (takes a few minutes)..."
rm -f "$DISK_FILE"
# fast pseudo-random stream via AES-CTR (urandom is too slow for 24 GB)
openssl enc -aes-128-ctr -nosalt -pass pass:nccl-eye < /dev/zero 2>/dev/null \
  | dd of="$DISK_FILE" bs=4M count=$((DISK_SIZE_GB * 256)) iflag=fullblock status=progress
sync
size=$(stat -c %s "$DISK_FILE")
[ "$size" -eq "$want" ] || { echo "ERROR: size $size != $want" >&2; exit 1; }
echo "DONE: $(ls -lh "$DISK_FILE")"