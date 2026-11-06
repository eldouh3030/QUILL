#!/usr/bin/env python3
"""Merge the emulator result files into results/mcu-all.csv.
Rows measured in mcu-protocol.csv (current frame format) replace older rows of the same function."""
import csv, sys
R = "results/"
order = ["mcu-emulated.csv", "mcu-components.csv", "mcu-extra.csv", "mcu-pqm4.csv", "mcu-protocol.csv"]
cols = ["function", "payload_bytes", "sig", "n", "m", "k", "reps", "instructions", "cycles", "ms_at_64MHz",
        "ms_at_120MHz", "stack_bytes", "heap_bytes", "cycles_sd", "cycles_min", "cycles_max"]
rows = {f: list(csv.DictReader(open(R + f))) for f in order}
newer = {r["function"] for r in rows["mcu-protocol.csv"]}
out = csv.DictWriter(open(R + "mcu-all.csv", "w", newline=""), cols, extrasaction="ignore", lineterminator="\n")
out.writeheader()
for f in order:
    for r in rows[f]:
        if f != "mcu-protocol.csv" and r["function"] in newer:
            continue
        out.writerow({c: r.get(c, "") for c in cols})
