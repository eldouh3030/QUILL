#!/usr/bin/env python3
"""Mean and 95% confidence half-width over the seeds of results/streams-runs.csv -> stdout CSV."""
import csv, statistics as st, sys
T = {1: 12.706, 2: 4.303, 4: 2.776, 9: 2.262, 19: 2.093, 29: 2.045}
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else "results/streams-runs.csv")))
key = ["workload", "signature", "payload", "n", "m", "k", "loss", "burst"]
num = [c for c in rows[0] if c not in key]
groups = {}
for r in rows:
    groups.setdefault(tuple(r[c] for c in key), []).append(r)
ci_cols = ["air_bytes_per_packet", "overhead_per_packet", "verified_of_delivered", "nr_delay_mean_s", "urgent_nr_delay_s", "cpu_duty_pct", "total_mJ_per_h"]
w = csv.writer(sys.stdout, lineterminator="\n")
w.writerow(key + num + ["seeds"] + [c + "_ci95" for c in ci_cols])
for g, rs in groups.items():
    mean = {c: st.mean(float(r[c]) for r in rs) for c in num}
    t = T.get(len(rs) - 1, 2.0)
    ci = {c: (t * st.stdev(float(r[c]) for r in rs) / len(rs) ** 0.5 if len(rs) > 1 else 0.0) for c in ci_cols}
    w.writerow(list(g) + [f"{mean[c]:.4f}" for c in num] + [len(rs)] + [f"{ci[c]:.4f}" for c in ci_cols])
