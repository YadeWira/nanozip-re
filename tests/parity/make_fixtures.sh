#!/usr/bin/env bash
# make_fixtures.sh -- build the archives the parity harnesses need, with the ORIGINAL.
#
# The harnesses compare our console and our damaged-archive behaviour against the
# original's, so their fixtures have to come from the original itself; shipping
# them as binaries would only hide which `nz` made them. One multi-file archive
# per codec (m_<tag>.nz) and one parallel single-file archive per codec
# (pf_<tag>.nz), from a mixed 2.5 MB input.
#
# usage: tests/parity/make_fixtures.sh <outdir>
set -u
OUT=${1:?usage: make_fixtures.sh <outdir>}
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
# The 32-bit original cannot open anything under /tmp/claude-*; keep to /tmp/nzre_*.
case "$OUT" in /tmp/claude-*) echo "FATAL: the original cannot read $OUT"; exit 1;; esac

rm -rf "$OUT"; mkdir -p "$OUT/src/sub"
# text, base64, binary and a couple of tiny files: enough to exercise the text
# transforms, the LZ paths and the metadata records.
head -c 900000 /dev/urandom | base64 | head -c 900000 > "$OUT/src/b_mid.txt"
head -c 400000 /dev/urandom                          > "$OUT/src/sub/c.bin"
head -c 200000 /dev/urandom                          > "$OUT/src/sub/d.dat"
head -c 100000 /dev/urandom | base64 | head -c 100000 > "$OUT/src/e_small.txt"
printf 'hello\n'                                     > "$OUT/src/f_tiny.txt"
: > "$OUT/src/g_empty"
head -c 900000 /dev/urandom | base64 | head -c 900000 > "$OUT/src/a_big.bin"

for spec in n:-cn c:-cc d:-cd Du:-cD f:-cf Fu:-cF o:-co Ou:-cO; do
  tag=${spec%%:*}; opt=${spec#*:}
  ( cd "$OUT/src" && env -i PATH=/usr/bin:/bin "$ORIG" a "$opt" -r "../m_$tag.nz" \
      a_big.bin b_mid.txt sub e_small.txt f_tiny.txt g_empty >/dev/null 2>&1 )
  ( cd "$OUT/src" && cat a_big.bin b_mid.txt sub/c.bin sub/d.dat e_small.txt > mixed.bin
    env -i PATH=/usr/bin:/bin "$ORIG" a "$opt" -p4 "../pf_$tag.nz" mixed.bin >/dev/null 2>&1
    rm -f mixed.bin )
done
n=$(ls "$OUT"/*.nz 2>/dev/null | wc -l)
echo "make_fixtures: $n archives in $OUT"
[ "$n" -ge 16 ]
