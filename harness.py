#!/usr/bin/env python3
"""NCCL-Eye benchmark harness.

Per step: host-side prep (CPU, optional disk read) -> GPU compute -> 4 MB
all-reduce -> torch.cuda.synchronize(). Per-iteration CSV per rank, CUDA-event
timing, in-band fault marker, discarded warm-up, GPU temperature log.

Launch (both nodes) via run_node.sh, which wraps torchrun.
"""
import argparse, csv, os, subprocess, threading, time
import numpy as np
import torch
import torch.distributed as dist

MARKER_FILE = "/dev/shm/nccl_eye_fault_marker"  # fault controller writes a label here


def read_marker():
    try:
        with open(MARKER_FILE) as f:
            return f.read().strip() or "none"
    except FileNotFoundError:
        return "none"


def gpu_temp_logger(path, stop, period=1.0):
    with open(path, "w") as f:
        f.write("mono_ns,temp_c,sm_clock_mhz,power_w\n")
        while not stop.is_set():
            try:
                out = subprocess.check_output(
                    ["nvidia-smi", "--query-gpu=temperature.gpu,clocks.sm,power.draw",
                     "--format=csv,noheader,nounits"], text=True).strip()
                t, c, p = [x.strip() for x in out.split(",")]
                f.write(f"{time.monotonic_ns()},{t},{c},{p}\n"); f.flush()
            except Exception:
                pass
            stop.wait(period)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", type=int, default=300)
    ap.add_argument("--warmup", type=int, default=30)
    ap.add_argument("--elems", type=int, default=1 << 20)  # 1M fp32 = 4 MiB
    ap.add_argument("--matmul-n", type=int, default=2048)
    ap.add_argument("--matmul-reps", type=int, default=8)
    ap.add_argument("--cpu-prep-ms", type=float, default=5.0,
                    help="host-side busy work per step so CPU faults matter")
    ap.add_argument("--data-file", default="",
                    help="optional large on-disk file; random 4 MiB reads per step")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--episode", default="ep0")
    args = ap.parse_args()

    rank = int(os.environ["RANK"]); world = int(os.environ["WORLD_SIZE"])
    local = int(os.environ.get("LOCAL_RANK", 0))
    torch.cuda.set_device(local)
    dist.init_process_group("nccl", device_id=torch.device("cuda", local))
    os.makedirs(args.out_dir, exist_ok=True)

    stop = threading.Event()
    th = threading.Thread(target=gpu_temp_logger,
                          args=(f"{args.out_dir}/gputemp_rank{rank}.csv", stop), daemon=True)
    th.start()

    dev = torch.device("cuda", local)
    a = torch.randn(args.matmul_n, args.matmul_n, device=dev)
    b = torch.randn(args.matmul_n, args.matmul_n, device=dev)
    buf = torch.ones(args.elems, device=dev)
    host = np.random.rand(1 << 16).astype(np.float64)

    fd = None; fsize = 0; chunk = 4 << 20
    if args.data_file:
        fd = os.open(args.data_file, os.O_RDONLY); fsize = os.fstat(fd).st_size
    rng = np.random.default_rng(1234 + rank)

    ev = [torch.cuda.Event(enable_timing=True) for _ in range(4)]
    path = f"{args.out_dir}/iters_rank{rank}.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["episode", "rank", "step", "is_warmup", "fault_marker",
                    "mono_start_ns", "real_start_ns", "prep_ms", "compute_ms",
                    "allreduce_ms", "sync_wait_ms", "step_ms"])
        dist.barrier(); torch.cuda.synchronize()
        for step in range(args.steps):
            marker = read_marker()
            m0, r0 = time.monotonic_ns(), time.time_ns()
            # --- host prep (CPU / disk sensitive)
            tp = time.perf_counter()
            if fd is not None:
                off = int(rng.integers(0, max(1, fsize - chunk)))
                os.pread(fd, chunk, off)
            end = tp + args.cpu_prep_ms / 1e3
            while time.perf_counter() < end:
                host = np.sqrt(host * 1.0001 + 1.0)
            prep_ms = (time.perf_counter() - tp) * 1e3
            # --- GPU compute + all-reduce, timed with CUDA events
            ev[0].record()
            c = a
            for _ in range(args.matmul_reps):
                c = torch.matmul(c, b); c = c / c.norm() * 100.0
            ev[1].record()
            dist.all_reduce(buf)
            ev[2].record()
            ts = time.perf_counter()
            torch.cuda.synchronize()          # real sync each step
            sync_ms = (time.perf_counter() - ts) * 1e3
            ev[3].record(); torch.cuda.synchronize()
            comp_ms = ev[0].elapsed_time(ev[1]); ar_ms = ev[1].elapsed_time(ev[2])
            step_ms = (time.monotonic_ns() - m0) / 1e6
            w.writerow([args.episode, rank, step, int(step < args.warmup), marker,
                        m0, r0, f"{prep_ms:.3f}", f"{comp_ms:.3f}", f"{ar_ms:.3f}",
                        f"{sync_ms:.3f}", f"{step_ms:.3f}"])
        f.flush()
    dist.barrier()
    stop.set()
    dist.destroy_process_group()


if __name__ == "__main__":
    main()
