#!/usr/bin/env bash
# env_switches.sh -- the environment switches this port adds, checked against the
# behaviour they promise (the original has none of these; see README).
#
#   NZ_SAFE=1        on a damaged archive write only entries whose checksum verifies
#   NZ_STRICT_EXIT=1 exit 2 on a damaged archive instead of the original's 0
#   NZ_THREADS=n     cap the worker threads of a parallel container
#   NZ_RECON         (test harness only) pin a frozen binary
#
# usage: tests/env_switches.sh [workdir]
set -u
W=${1:-/tmp/nzre_env_switches}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
OURS=${NZ_RECON:-$HERE/bin/nz_recon}
[ -x "$OURS" ] || { echo "FAIL: no $OURS"; exit 1; }
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }

rm -rf "$W"; mkdir -p "$W/src"
head -c 400000 /dev/urandom | base64 | head -c 400000 > "$W/src/a.txt"
head -c 200000 /dev/urandom > "$W/src/b.bin"
( cd "$W/src" && env -i PATH=/usr/bin:/bin "$ORIG" a -co -p4 ../ok.nz a.txt b.bin >/dev/null 2>&1 )
[ -f "$W/ok.nz" ] || { echo "FAIL: the original did not build the fixture"; exit 1; }
# one flipped byte at 60 % of the payload
python3 - "$W/ok.nz" "$W/bad.nz" <<'PY'
import sys
b=bytearray(open(sys.argv[1],'rb').read()); b[int(len(b)*0.6)] ^= 0xff
open(sys.argv[2],'wb').write(b)
PY

pass=0; fail=0
check() { # name expected_exit expected_grep dir env...
  local name=$1 want=$2 pat=$3; shift 3
  local d="$W/$name"; rm -rf "$d"; mkdir -p "$d"
  local out; out=$(cd "$d" && env -i PATH=/usr/bin:/bin "$@" "$OURS" x -y "$W/bad.nz" 2>&1); local rc=$?
  local ok=1
  [ "$rc" = "$want" ] || { echo "FAIL $name: exit $rc, want $want"; ok=0; }
  if [ -n "$pat" ] && ! printf '%s' "$out" | tr '\r' '\n' | grep -q "$pat"; then
    echo "FAIL $name: output does not match /$pat/"; ok=0
  fi
  if [ $ok = 1 ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
}
# the original always exits 0 on a damaged archive, and so do we by default
check default 0 "Archive corrupted"
check strict_exit 2 "Archive corrupted" NZ_STRICT_EXIT=1
check safe 2 "" NZ_SAFE=1
# NZ_THREADS must not change the outcome, only the worker count
for t in 1 2 8; do check "threads_$t" 0 "Archive corrupted" NZ_THREADS=$t; done
# and an intact archive decodes the same whatever the thread count
for t in 1 4; do
  d="$W/intact_$t"; rm -rf "$d"; mkdir -p "$d"
  ( cd "$d" && env -i PATH=/usr/bin:/bin NZ_THREADS=$t "$OURS" x -y "$W/ok.nz" >/dev/null 2>&1 )
  if diff -r "$W/src" "$d" >/dev/null 2>&1; then pass=$((pass+1)); else echo "FAIL intact_$t: tree differs"; fail=$((fail+1)); fi
done
echo "env_switches: $pass passed, $fail failed"
[ $fail -eq 0 ]
