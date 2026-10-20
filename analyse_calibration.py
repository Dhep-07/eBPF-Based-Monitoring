#!/usr/bin/env python3
"""Calibration summary v2: which fault classes slow iterations by >= threshold?

Usage: analyze_calibration.py <out_root> [--thresh 10] [--trim 20]

For each episode (needs BOTH ranks' CSVs in <out_root>/epXXXX/):
  * step_ms per step = max over ranks (a collective step is gated by the slowest rank)
  * fault window = steps where the FAULTY rank's fault_marker == class, trimmed by
    --trim steps at each edge (ramp-up / recovery)
  * baseline = post-warm-up steps BEFORE the fault window only
  * slowdown % = median(window) / median(baseline) - 1
Controls (fault_class none) use a matched window (median start time and duration of
the faulty episodes) so the control row measures natural noise / false slowdown.
Skipped episodes are listed with the reason.
"""
import argparse, csv, glob, os, re, statistics as st
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("root")
ap.add_argument("--thresh", type=float, default=10.0)
ap.add_argument("--trim", type=int, default=20)
a = ap.parse_args()

sched = {r["episode"].strip(): r for r in csv.DictReader(open(f"{a.root}/schedule.csv"))}
skipped = []


def load_episode(ep):
    per = {}
    for p in glob.glob(f"{a.root}/{ep}/iters_rank*.csv"):
        rk = int(re.search(r"iters_rank(\d+)\.csv", p).group(1))
        per[rk] = [r for r in csv.DictReader(open(p)) if r["is_warmup"] == "0"]
    return per


episodes = {}
for ep, row in sched.items():
    per = load_episode(ep)
    if len(per) < 2:
        skipped.append((ep, f"only {len(per)} rank file(s)")); continue
    steps = defaultdict(float)
    for rows in per.values():
        for r in rows:
            s = int(r["step"]); steps[s] = max(steps[s], float(r["step_ms"]))
    cls = row["fault_class"].strip()
    ref = int(row["faulty_rank"]) if cls != "none" else 0
    if ref not in per or not per[ref]:
        skipped.append((ep, "reference rank file missing/empty")); continue
    t0 = int(per[ref][0]["mono_start_ns"])
    t = {int(r["step"]): (int(r["mono_start_ns"]) - t0) / 1e9 for r in per[ref]}
    mark = {int(r["step"]): r["fault_marker"] for r in per[ref]}
    episodes[ep] = dict(cls=cls, steps=steps, t=t, mark=mark)

res = defaultdict(list)
starts, durs = [], []
# pass 1: faulty episodes
for ep, d in episodes.items():
    if d["cls"] == "none": continue
    idx = sorted(s for s, m in d["mark"].items() if m == d["cls"])
    if len(idx) < 2 * a.trim + 10:
        skipped.append((ep, f"only {len(idx)} marked steps for {d['cls']}")); continue
    win = idx[a.trim:-a.trim]
    pre = [s for s in d["steps"] if s < idx[0]]
    if len(pre) < 10:
        skipped.append((ep, f"only {len(pre)} pre-fault steps")); continue
    res[d["cls"]].append(100 * (st.median(d["steps"][s] for s in win) /
                                st.median(d["steps"][s] for s in pre) - 1))
    starts.append(d["t"][idx[0]]); durs.append(d["t"][idx[-1]] - d["t"][idx[0]])

# pass 2: controls with matched window
if starts:
    off, dur = st.median(starts), st.median(durs)
    tt = a.trim * 0.07  # trim in seconds (~70 ms/step)
    for ep, d in episodes.items():
        if d["cls"] != "none": continue
        win = [s for s in d["steps"] if off + tt <= d["t"].get(s, -1) <= off + dur - tt]
        pre = [s for s in d["steps"] if d["t"].get(s, 1e9) < off]
        if len(win) < 10 or len(pre) < 10:
            skipped.append((ep, "control: window/baseline too short")); continue
        res["none"].append(100 * (st.median(d["steps"][s] for s in win) /
                                  st.median(d["steps"][s] for s in pre) - 1))

print(f"{'class':8} {'n':>3} {'median %slow':>13} {'min':>7} {'max':>7}  keep(>={a.thresh}%)")
for c in sorted(res):
    v = res[c]; m = st.median(v)
    keep = "(control)" if c == "none" else ("YES" if m >= a.thresh else "no")
    print(f"{c:8} {len(v):>3} {m:>13.1f} {min(v):>7.1f} {max(v):>7.1f}  {keep}")
if skipped:
    print(f"\nSkipped {len(skipped)} episode(s):")
    for ep, why in skipped[:20]: print(f"  {ep}: {why}")
if not res:
    print("\nNo results. Check that schedule.csv and both ranks' CSVs are in the root folder.")