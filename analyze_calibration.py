#!/usr/bin/env python3
"""Calibration summary: which fault classes slow iterations by >= threshold?

Usage: analyze_calibration.py <out_root> [--thresh 10]
Reads <out_root>/schedule.csv and <out_root>/epXXXX/iters_rank*.csv.
Compares step_ms inside the fault window (marker == class) vs the same episode's
pre-fault baseline (marker == none, post-warm-up), using the median across the job
(max over ranks, since a collective step is gated by the slowest rank).
"""
import argparse, csv, glob, os, statistics as st
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("root"); ap.add_argument("--thresh", type=float, default=10.0)
a = ap.parse_args()

sched = {r["episode"]: r for r in csv.DictReader(open(f"{a.root}/schedule.csv"))}
res = defaultdict(list)
for ep, row in sched.items():
    per_rank = {}
    for p in glob.glob(f"{a.root}/{ep}/iters_rank*.csv"):
        rs = list(csv.DictReader(open(p)))
        per_rank[p] = [r for r in rs if r["is_warmup"] == "0"]
    if not per_rank: continue
    steps = defaultdict(float)
    marks = {}
    for rs in per_rank.values():
        for r in rs:
            s = int(r["step"]); steps[s] = max(steps[s], float(r["step_ms"]))
            marks[s] = marks.get(s) if marks.get(s, "none") != "none" else r["fault_marker"]
    base = [steps[s] for s in steps if marks.get(s, "none") == "none"]
    flt = [steps[s] for s in steps if marks.get(s, "none") != "none"]
    if row["fault_class"] == "none":
        if len(base) > 10: res["none"].append(0.0)   # control: no window
        continue
    if len(base) < 10 or len(flt) < 10: continue
    res[row["fault_class"]].append(100 * (st.median(flt) / st.median(base) - 1))

print(f"{'class':8} {'n':>3} {'median %slow':>13} {'min':>7} {'max':>7}  keep(>={a.thresh}%)")
for c, v in sorted(res.items()):
    if c == "none": continue
    m = st.median(v)
    print(f"{c:8} {len(v):>3} {m:>13.1f} {min(v):>7.1f} {max(v):>7.1f}  {'YES' if m >= a.thresh else 'no'}")
