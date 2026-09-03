#!/usr/bin/env bash
# sweep_run.sh -- run real_corpus_sweep.sh as N background shards over one corpus.
#
#   sweep_run.sh [CORPUS=/tmp/nzre_corpus] [SHARDS=8] [RESULTS=/tmp/nzre_sweep/results.tsv]
#
# Each shard appends to the same results file (one line per fixture x method), so the
# run is resumable: rerun the same command and only missing pairs are done. Progress:
#   wc -l /tmp/nzre_sweep/results.tsv ; tests/sweep_report.py /tmp/nzre_sweep/results.tsv
# Extra environment is passed through (NZ_METHODS, NZ_DIR_MODE, NZ_TIMEOUT, NZ_MAX_FIXTURE).
# Do NOT rebuild bin/nz_recon while shards run (it invents failures).
set -uo pipefail
CORPUS=${1:-/tmp/nzre_corpus}
SHARDS=${2:-8}
RESULTS=${3:-/tmp/nzre_sweep/results.tsv}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$(dirname "$RESULTS")"
[[ -d $CORPUS ]] || { echo "corpus missing: $CORPUS" >&2; exit 1; }
for i in $(seq 0 $((SHARDS-1))); do
  NZ_REAL_CORPUS="$CORPUS" NZ_RESULTS_TSV="$RESULTS" NZ_SHARD="$i/$SHARDS" \
    nohup bash "$SCRIPT_DIR/real_corpus_sweep.sh" > "$(dirname "$RESULTS")/shard$i.log" 2>&1 &
  echo "shard $i/$SHARDS pid $!"
done
echo "results: $RESULTS   logs: $(dirname "$RESULTS")/shard*.log"
