# NCCL-Eye experiment run guide

Layout on BOTH nodes (`~/Downloads/eBPF-Based-Monitoring`):
`harness.py  make_schedule.py  run_node.sh  analyze_calibration.py  faults/inject.sh`

## 0. One-time
```bash
mkdir -p ~/Downloads/eBPF-Based-Monitoring/faults
cp inject.sh ~/Downloads/eBPF-Based-Monitoring/faults/ && chmod +x run_node.sh faults/inject.sh
lscpu -e                      # choose CPU_CORES for the cpu fault (cores the harness uses)
chronyc tracking              # Device 2 must NOT also follow Device 1
```
Net fault needs the peer IP: Device 1 uses `PEER_IP=10.10.49.149`, Device 2 uses `PEER_IP=10.10.49.63`.
Export it before launching: `export PEER_IP=...` (and `CPU_CORES=...`).

## 1. Smoke test (no faults, 3 episodes)
```bash
python make_schedule.py --seed 1 --controls 3 --per-class 0 > smoke.csv
# Terminal A (each node): scope shell
systemd-run --user --scope bash
stat -c %i /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)     # -> inode
# Terminal B (each node): sudo ./monitor /dev/shm/smoke.db <inode> eno1
# Terminal A: ./run_node.sh <0|1> smoke.csv ~/runs/smoke       # start rank 0 first
```
Check: iters CSVs exist, step_ms stable, no `failures.txt`, monitor shows victim counters > 0.
Tune `--matmul-reps` so compute ~ all-reduce time.

## 2. Calibration (separate seed from evaluation!)
```bash
python make_schedule.py --seed 7 --controls 10 --per-class 6 > calib.csv   # copy SAME file to both nodes
./run_node.sh <0|1> calib.csv ~/runs/calib
python analyze_calibration.py ~/runs/calib --thresh 10
```
Keep only classes marked YES (>=10-15% slowdown). Adjust DELAY/LOSS, CPU_LOAD, MEM_VM_BYTES, DISK_SIZE_GB and repeat.

## 3. Evaluation
```bash
python make_schedule.py --seed 2026 --controls 60 --per-class 30 --classes <kept> > eval.csv
./run_node.sh <0|1> eval.csv ~/runs/eval     # run with a fresh monitor DB per batch
```
Run in batches (`first_ep last_ep` args); check GPU temp CSVs for thermal drift between batches.

## Safety
- net fault: SSH(22)/NTP(123) are kept clean via tc filters; dead-man timer removes qdisc after 150 s.
  If stuck: `sudo tc qdisc del dev eno1 root`.
- disk fault needs ~24 GB free in /var/tmp; delete `nccl_eye_disk_stress.bin*` afterwards.
- In the harness `--data-file` should point at that same file (`DATA_FILE=/var/tmp/nccl_eye_disk_stress.bin`) so the disk stressor actually slows the harness reads.
