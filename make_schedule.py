#!/usr/bin/env python3
"""Generate a randomized, reproducible episode schedule.

Usage: make_schedule.py --seed 42 --controls 60 --per-class 30 \
           --classes cpu,net,disk,mem --faulty-rank 1 > schedule.csv
Both nodes must use the SAME schedule.csv (copy it, or fix the seed).
Calibration and evaluation should use different seeds and separate files.
"""
import argparse, csv, random, sys

ap = argparse.ArgumentParser()
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--controls", type=int, default=60)
ap.add_argument("--per-class", type=int, default=30)
ap.add_argument("--classes", default="cpu,net,disk,mem")
ap.add_argument("--faulty-rank", default="alternate", help="0, 1, or alternate")
args = ap.parse_args()

rnd = random.Random(args.seed)
eps = [("none", -1)] * args.controls
for cls in args.classes.split(","):
    for i in range(args.per_class):
        r = i % 2 if args.faulty_rank == "alternate" else int(args.faulty_rank)
        eps.append((cls, r))
rnd.shuffle(eps)
w = csv.writer(sys.stdout, lineterminator="\n")
w.writerow(["episode", "fault_class", "faulty_rank"])
for i, (c, r) in enumerate(eps):
    w.writerow([f"ep{i:04d}", c, r])
