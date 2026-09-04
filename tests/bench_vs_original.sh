#!/bin/bash
# Decode-speed benchmark against the original binary (the wiki's Performance page).
#
#   tests/bench_vs_original.sh build  <corpus_root> <workdir>   # ~140 MB mixed tar from a sample collection
#   tests/bench_vs_original.sh compress <workdir>               # the original compresses it in 6 codecs (-p1)
#   tests/bench_vs_original.sh run <workdir> [results.txt]      # `t` wall time, original vs bin/nz_recon
#
# Needs the original at ../linux32/nz or $NZ_LEGACY_ORACLE. The tar is ~205 real
# files (text, documents, images, executables, audio, music, fonts, 3-D) picked
# deterministically by size band from the collection's category folders.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
NZ=${NZ_LEGACY_ORACLE:-$here/../linux32/nz}
OURS=${OURS:-$here/bin/nz_recon}
cmd=${1:-}; shift || true
case "$cmd" in
  build)
    C=${1:?corpus root}; W=${2:?workdir}; mkdir -p "$W/src"; cd "$W"; rm -rf src; mkdir -p src
    pick() { find "$C/$1" -type f -size +$2 -size -$3 2>/dev/null | sort | awk -v k=$4 'NR%k==1' | head -$5; }
    { pick text 100k 3M 7 60; pick document 200k 4M 5 40; pick image 200k 4M 9 40; pick executable 200k 6M 1 25;
      pick audio 500k 6M 3 15; pick music 100k 2M 5 15; pick font 50k 2M 3 10; pick other 100k 3M 3 15; pick poly 200k 4M 3 10; } > list.txt
    i=0; while read -r f; do i=$((i+1)); cp "$f" "src/$(printf %04d $i)_$(basename "$f" | tr -c 'A-Za-z0-9._-\n' '_')"; done < list.txt
    tar cf mix.tar -C src .; ls -la mix.tar ;;
  compress)
    W=${1:?workdir}; cd "$W"
    for c in o O c d D f; do s=$(date +%s.%N); "$NZ" a -y -c$c -p1 mix_$c.nz mix.tar >/dev/null 2>&1; e=$(date +%s.%N)
      echo "a -c$c $(echo "$e - $s" | bc -l | cut -c1-6) s $(stat -c %s mix_$c.nz) bytes"; done ;;
  run)
    W=${1:?workdir}; out=${2:-$W/bench_results.txt}; : > "$out"
    for c in o O c d D f; do for who in orig ours; do bin=$NZ; [ $who = ours ] && bin=$OURS
      s=$(date +%s.%N); "$bin" t "$W/mix_$c.nz" >/dev/null 2>&1; e=$(date +%s.%N)
      echo "-c$c $who $(echo "$e - $s" | bc -l | cut -c1-6) s" | tee -a "$out"; done; done ;;
  *) sed -n 2,8p "$0"; exit 1 ;;
esac
