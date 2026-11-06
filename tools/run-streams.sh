#!/bin/sh
# Real-data streams for every signature on a clean and a lossy channel.
# Parameters (n, m, k) for the lossy channel come from `sim optimise` (target 0.99).
# The lossy channel is run with SEEDS different seeds; tools/summarise-streams.py gives mean and 95% CI.
B=${BIN:-./build}; M=${MCU:-results/mcu-all.csv}; SEEDS=${SEEDS:-20}
echo "workload,signature,payload,n,m,k,loss,burst,packets,urgent,batches,air_bytes_per_packet,overhead_per_packet,verified_of_delivered,nr_delay_mean_s,nr_delay_p95_s,nr_delay_max_s,urgent_nr_delay_s,cpu_duty_pct,cpu_mJ_per_h,radio_mJ_per_h,total_mJ_per_h"
run() {   # workload data sig n m k
  $B/stream $1 $2 $3 $4 0 $4 0 1 $M 1
  s=1; while [ $s -le $SEEDS ]; do $B/stream $1 $2 $3 $4 $5 $6 0.05 4 $M $s; s=$((s+1)); done
}
#            sig  n  m  k   (lossy)
for cfg in "0 32 17 18" "1 32 17 18" "3 32 13 22" "4 32 20 22" "5 32 15 16"; do set -- $cfg; run vitals data/vitals.csv $1 $2 $3 $4; done
for cfg in "0 64 22 44" "1 64 20 42" "3 64 20 49" "4 64 19 48" "5 64 20 42"; do set -- $cfg; run ecg data/100.dat $1 $2 $3 $4; done
