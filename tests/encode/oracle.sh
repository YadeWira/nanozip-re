#!/usr/bin/env bash
# oracle.sh -- the encode phase's yardstick: `a` of the original against `a` of this port on the
# same inputs, same switches, same working directory, compared BYTE FOR BYTE; then each archive
# decoded by the other binary (the original must read ours, we must read the original's).
#
# A case is a line "name|switches|files..." (files relative to the case's source tree). The source
# tree is built by build_sources() below: small, deterministic, with the shapes the container
# cares about (an empty file, a subdirectory, a file given twice, distinct mtimes and modes).
#
# usage: tests/encode/oracle.sh [workdir] [case-name-filter]
#   NZ_ORIG (default ../linux32/nz), NZ_RECON (default bin/nz_recon)
set -u
W=${1:-/tmp/nzre_encode_oracle}; FILTER=${2:-}
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz_recon}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W"; mkdir -p "$W"

build_sources() {  # $1 = directory
  local d=$1; mkdir -p "$d/sub/deep"
  python3 - "$d" <<'PY'
import os, random, sys
d = sys.argv[1]; random.seed(20260905)
open(f'{d}/a.txt','w').write(('the quick brown fox jumps over the lazy dog\n' * 700))
open(f'{d}/b.bin','wb').write(bytes(random.randrange(256) for _ in range(30000)))
open(f'{d}/empty','w').write('')
open(f'{d}/tiny','w').write('x')
open(f'{d}/sub/c.dat','wb').write(bytes((i * 7) % 251 for i in range(12000)))
open(f'{d}/sub/deep/d.log','w').write('log line\n' * 300)
os.chmod(f'{d}/a.txt', 0o644); os.chmod(f'{d}/b.bin', 0o600); os.chmod(f'{d}/sub/c.dat', 0o755)
for i, f in enumerate(['a.txt','b.bin','empty','tiny','sub/c.dat','sub/deep/d.log']):
    t = 1000000000 + i * 86400 * 37
    os.utime(f'{d}/{f}', (t, t))
PY
}

# name|switches|files (relative to the source tree)
CASES=(
  "cn_one|-cn|a.txt"
  "cn_three|-cn|a.txt b.bin empty"
  "cn_order|-cn|empty b.bin a.txt"
  "cn_tree|-cn -r|sub"
  "cn_all|-cn -r|a.txt b.bin empty tiny sub"
  "cn_hn|-cn -hn|a.txt b.bin"
  "cn_hc|-cn -hc|a.txt b.bin empty"
  "cn_hC|-cn -hC|a.txt b.bin empty"
  "cn_twice|-cn|a.txt a.txt"
  "cf_one|-cf|a.txt"
  "cF_one|-cF|a.txt"
  "cd_one|-cd|a.txt"
  "cD_one|-cD|a.txt"
  "co_one|-co|a.txt"
  "cO_one|-cO|a.txt"
  "cc_one|-cc|a.txt"
)

same=0; xok=0; total=0; fails=""
for spec in "${CASES[@]}"; do
  name=${spec%%|*}; rest=${spec#*|}; sw=${rest%%|*}; files=${rest#*|}
  [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]] && continue
  total=$((total+1)); c="$W/$name"; mkdir -p "$c"
  for who in orig ours; do
    bin=$ORIG; [ $who = ours ] && bin=$OURS
    build_sources "$c/$who"
    ( cd "$c/$who" && env -i PATH=/usr/bin:/bin "$bin" a -y $sw ../$who.nz $files > "../$who.out" 2>&1 )
  done
  if cmp -s "$c/orig.nz" "$c/ours.nz"; then same=$((same+1)); verdict="IDENTICAL"
  else
    verdict="DIFF $(cmp "$c/orig.nz" "$c/ours.nz" 2>&1 | grep -oE 'byte [0-9]+' | head -1) sizes $(stat -c%s "$c/orig.nz" 2>/dev/null)/$(stat -c%s "$c/ours.nz" 2>/dev/null)"
  fi
  # cross-decode: the original reads ours, we read the original's; both against the source tree
  cross=""
  for pair in "orig:ours" "ours:orig"; do
    reader=${pair%%:*}; arch=${pair#*:}; bin=$ORIG; [ $reader = ours ] && bin=$OURS
    rm -rf "$c/x_$reader"; mkdir -p "$c/x_$reader"
    ( cd "$c/x_$reader" && env -i PATH=/usr/bin:/bin "$bin" x -y "../$arch.nz" > out.txt 2>&1 )
    ok=1
    for f in $files; do
      if [ -d "$c/orig/$f" ]; then diff -rq "$c/orig/$f" "$c/x_$reader/$f" >/dev/null 2>&1 || ok=0
      else cmp -s "$c/orig/$f" "$c/x_$reader/$f" || ok=0; fi
    done
    [ $ok = 1 ] && cross="$cross $reader-reads-$arch:ok" || cross="$cross $reader-reads-$arch:FAIL"
  done
  [[ "$cross" != *FAIL* ]] && xok=$((xok+1))
  printf "%-10s %-38s %s\n" "$name" "$verdict" "$cross"
  [ "$verdict" != IDENTICAL ] && fails="$fails $name"
done
echo "oracle: $same/$total archives byte-identical, $xok/$total cross-decode both ways$([ -n "$fails" ] && echo " -- differing:$fails")"
