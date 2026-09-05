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
# parallel (-pN) shapes: files straddling worker boundaries, a file exactly on one
open(f'{d}/p12.bin','wb').write(bytes(random.randrange(256) for _ in range(1200000)))
open(f'{d}/p6.bin','wb').write(bytes(random.randrange(256) for _ in range(600000)))
open(f'{d}/p3.dat','wb').write(bytes(random.randrange(256) for _ in range(300000)))
open(f'{d}/p2.txt','w').write('parallel text line\n' * 5000)
# an executable and a text+random mix for the compressing codecs
import shutil; shutil.copy('/usr/bin/ls', f'{d}/exe.bin')
open(f'{d}/mix.bin','wb').write((('lorem ipsum dolor sit amet ' * 40 + '\n') * 900).encode() + bytes(random.randrange(256) for _ in range(700000)))
os.chmod(f'{d}/my.dir/f', 0o600); os.chmod(f'{d}/.hidden', 0o600)
open(f'{d}/unread.bin','wb').write(bytes(5000)); os.utime(f'{d}/unread.bin', (1200000000, 1200000000)); os.chmod(f'{d}/unread.bin', 0)
for f in ['my.dir/f','.hidden','A.TXT','c.Txt','x._','r98304.bin','r98303.bin','blk1.bin','blk2.bin','blk3.bin','one.bin','big.bin','p12.bin','p6.bin','p3.dat','p2.txt','exe.bin','mix.bin']:
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
  "cn_x2|-cn -sn -r -x*.dat|sub a.txt"
  "cn_x3|-cn -sn -p2 -t1 -xb.bin|p12.bin b.bin a.txt"
  "cn_x4|-cn -sn -xb.bin -r|."
  "cn_xonly|-cn -xa.txt|a.txt"
  "cn_unread|-cn -sn|a.txt unread.bin b.bin"
  "cn_unread2|-cn -sn|b.bin unread.bin"
  "cn_round|-cn -sn|r98303.bin"
  "cn_round2|-cn -sn|r98304.bin"
  "cn_bound|-cn -sn|blk1.bin blk2.bin blk3.bin one.bin"
  "cn_bound2|-cn -sn|one.bin blk1.bin blk2.bin blk3.bin"
  "cn_big|-cn|big.bin a.txt"
  "cn_600|-cn|my.dir/f .hidden"
  # parallel store: -pN with -t1 (the original's default thread count makes the stream
  # emission order nondeterministic, so only -t1 can be an oracle)
  "cn_p2|-cn -p2 -t1|p12.bin b.bin a.txt"
  "cn_p3|-cn -p3 -t1|p12.bin p6.bin p3.dat p2.txt"
  "cn_p4|-cn -p4 -t1|p12.bin p6.bin p3.dat p2.txt b.bin a.txt tiny"
  "cn_p2_empty|-cn -p2 -t1 -sn|p6.bin empty"
  "cn_p2_empty2|-cn -p2 -t1 -sn|empty p6.bin"
  "cn_p3_hn|-cn -p3 -t1 -hn|p12.bin p6.bin a.txt"
  "cn_p2_hc|-cn -p2 -t1 -hc|p12.bin p6.bin a.txt"
  "cn_p2_nt|-cn -p2 -t1 -nt -np|p12.bin p6.bin"
  "cn_p2_tree|-cn -p2 -t1 -r|sub p6.bin"
  "cn_p8|-cn -p8 -t1|p12.bin a.txt"
  "cn_p1|-cn -p1 -t1|p12.bin a.txt"
  "cn_p2_one|-cn -p2 -t1|tiny"
  "cn_p3_one|-cn -p3 -t1|tiny"
  "cn_p4_two|-cn -p4 -t1 -sn|tiny one.bin"
  "cn_p2_et|-cn -p2 -t1 -sn|empty tiny"
  "cn_p2_te|-cn -p2 -t1 -sn|tiny empty"
  "cn_p3_hn_one|-cn -p3 -t1 -hn|tiny"
  # lzpf (-cf/-cF): under -t1 -- the original's reader runs ahead of its compressor on
  # other thread counts and the metadata lands wherever the race left it
  "cf_one|-cf -t1|a.txt"
  "cF_one|-cF -t1|a.txt"
  "cf_three|-cf -t1|a.txt b.bin empty"
  "cF_three|-cF -t1|a.txt b.bin empty"
  "cf_tree|-cf -t1 -r|sub"
  "cf_big|-cf -t1|big.bin a.txt"
  "cF_big|-cF -t1|big.bin a.txt"
  "cf_p12|-cf -t1|p12.bin p6.bin p2.txt"
  "cf_sn|-cf -t1 -sn|tiny a.txt sub/c.dat b.bin empty"
  "cf_hn|-cf -t1 -hn|a.txt b.bin"
  "cf_hc|-cf -t1 -hc|a.txt b.bin empty"
  "cf_bound|-cf -t1 -sn|blk1.bin blk2.bin blk3.bin one.bin"
  "cf_round|-cf -t1 -sn|r98304.bin r98303.bin tiny"
  "cf_p2|-cf -p2 -t1|p12.bin b.bin a.txt"
  "cF_p2|-cF -p2 -t1|p12.bin b.bin a.txt"
  "cf_p3|-cf -p3 -t1|p12.bin p6.bin p3.dat p2.txt"
  "cf_p2_one|-cf -p2 -t1|tiny"
  "cf_x|-cf -t1 -r -xb.bin|a.txt b.bin sub"
  "cf_dotdir|-cf -t1 -r|."
  "cf_exe|-cf -t1|exe.bin"
  "cF_exe|-cF -t1|exe.bin"
  "cf_mix|-cf -t1|mix.bin"
  "cf_default|-cf|a.txt b.bin"
  "cd_one|-cd|a.txt"
  "cD_one|-cD|a.txt"
  "co_one|-co|a.txt"
  "cO_one|-cO|a.txt"
  "cc_one|-cc|a.txt"
)

same=0; xok=0; cok=0; total=0; fails=""; cfails=""
norm_console() {
  sed -E 's/^(Intel|AMD|unknown).*//; s/Linux(32|64)/LinuxNN/; s/Archive: .*/Archive: X/; s/in [0-9.]+s, [0-9]+ [KMG]?B\/s/in T, R/; s/IO-(in|out): [0-9.]+s, [0-9]+ [KMG]?B\/s/IO-\1: T, R/g; s/ IO-out: T, R//' "$1"
}
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
  # console of `a`: byte-compared after removing what only timing decides (rates,
  # seconds, the IO-out figure that appears when a write took a millisecond) and
  # the host line of the banner.
  if diff -q <(norm_console "$c/orig.out") <(norm_console "$c/ours.out") >/dev/null; then cok=$((cok+1)); con="console:same"; else con="console:DIFF"; cfails="$cfails $name"; fi
  printf "%-10s %-38s %s %s\n" "$name" "$verdict" "$cross" "$con"
  [ "$verdict" != IDENTICAL ] && fails="$fails $name"
done
echo "oracle: $same/$total archives byte-identical, $xok/$total cross-decode both ways, $cok/$total consoles identical$([ -n "$fails" ] && echo " -- differing:$fails")$([ -n "$cfails" ] && echo " -- console:$cfails")"
