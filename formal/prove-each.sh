#!/bin/sh
# Proves each lemma of pqs.spthy separately, together with the two helper lemmas,
# and appends the verdicts to prove-each.log. Usage: sh prove-each.sh [lemma ...]
export LANG=C.UTF-8 LC_ALL=C.UTF-8
LIST=${*:-$(grep -o "^lemma [a-z_]*" pqs.spthy | awk '{print $2}')}
for L in $LIST; do
  start=$(date +%s)
  timeout ${LIMIT:-1500} tamarin-prover --derivcheck-timeout=0 --prove=dev_state_origin --prove=chain_key_index --prove=$L pqs.spthy +RTS -M2500m -RTS > out-$L.txt 2>&1
  rc=$?; end=$(date +%s)
  echo "$L rc=$rc $((end-start))s :: $(grep -E "^  $L \(" out-$L.txt | head -1)" >> prove-each.log
done
