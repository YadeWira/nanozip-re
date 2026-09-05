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
# the shapes the container rules were measured on
os.makedirs(f'{d}/my.dir', exist_ok=True)
open(f'{d}/my.dir/f','w').write('dotted dir\n'); open(f'{d}/.hidden','w').write('h\n')
open(f'{d}/A.TXT','w').write('upper ' * 30); open(f'{d}/c.Txt','w').write('mixed\n'); open(f'{d}/x._','w').write('underscore\n')
open(f'{d}/r98304.bin','wb').write(bytes(98304)); open(f'{d}/r98303.bin','wb').write(bytes(98303))
open(f'{d}/blk1.bin','wb').write(bytes(random.randrange(256) for _ in range(65536)))
open(f'{d}/blk2.bin','wb').write(bytes(random.randrange(256) for _ in range(65536)))
open(f'{d}/blk3.bin','wb').write(bytes(random.randrange(256) for _ in range(65536)))
open(f'{d}/one.bin','wb').write(b'\x42')
open(f'{d}/big.bin','wb').write(bytes(random.randrange(256) for _ in range(1000000)))
os.chmod(f'{d}/my.dir/f', 0o600); os.chmod(f'{d}/.hidden', 0o600)
for f in ['my.dir/f','.hidden','A.TXT','c.Txt','x._','r98304.bin','r98303.bin','blk1.bin','blk2.bin','blk3.bin','one.bin','big.bin']:
    os.utime(f'{d}/{f}', (1200000000, 1200000000))
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
  "cn_sn|-cn -sn|tiny a.txt sub/c.dat b.bin empty"
  "cn_sa|-cn -sa|A.TXT b.bin a.txt c.Txt x._ empty"
  "cn_ss|-cn -ss|a.txt b.bin tiny empty sub/c.dat"
  "cn_case|-cn|A.TXT c.Txt x._ a.txt b.bin"
  "cn_dots|-cn -r|my.dir .hidden a.txt"
  "cn_dotdir|-cn -r|."
  "cn_star|-cn|*.txt"
  "cn_nt|-cn -nt|a.txt b.bin empty"
  "cn_np|-cn -np|a.txt b.bin empty"
  "cn_nm|-cn -nm|a.txt b.bin empty"
  "cn_fo|-cn -fo|a.txt b.bin empty"
  "cn_sp|-cn -sp -r|sub a.txt"
  "cn_x|-cn -r -xb.bin|a.txt b.bin sub"
  "cn_round|-cn -sn|r98303.bin"
  "cn_round2|-cn -sn|r98304.bin"
  "cn_bound|-cn -sn|blk1.bin blk2.bin blk3.bin one.bin"
  "cn_bound2|-cn -sn|one.bin blk1.bin blk2.bin blk3.bin"
  "cn_big|-cn|big.bin a.txt"
  "cn_600|-cn|my.dir/f .hidden"
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
  # cross-decode: the original reads ours, we read the original's; each tree must
  # equal what the ORIGINAL extracts from its OWN archive (so globs, `.`, -sp and -x
  # need no path arithmetic here).
  cross=""
  rm -rf "$c/x_ref"; mkdir -p "$c/x_ref"
  ( cd "$c/x_ref" && env -i PATH=/usr/bin:/bin "$ORIG" x -y "../orig.nz" > out.txt 2>&1 ); rm -f "$c/x_ref/out.txt"
  for pair in "orig:ours" "ours:orig"; do
    reader=${pair%%:*}; arch=${pair#*:}; bin=$ORIG; [ $reader = ours ] && bin=$OURS
    rm -rf "$c/x_$reader"; mkdir -p "$c/x_$reader"
    ( cd "$c/x_$reader" && env -i PATH=/usr/bin:/bin "$bin" x -y "../$arch.nz" > out.txt 2>&1 ); rm -f "$c/x_$reader/out.txt"
    if diff -r "$c/x_ref" "$c/x_$reader" >/dev/null 2>&1; then cross="$cross $reader-reads-$arch:ok"; else cross="$cross $reader-reads-$arch:FAIL"; fi
  done
  [[ "$cross" != *FAIL* ]] && xok=$((xok+1))
  printf "%-10s %-38s %s\n" "$name" "$verdict" "$cross"
  [ "$verdict" != IDENTICAL ] && fails="$fails $name"
done
echo "oracle: $same/$total archives byte-identical, $xok/$total cross-decode both ways$([ -n "$fails" ] && echo " -- differing:$fails")"
