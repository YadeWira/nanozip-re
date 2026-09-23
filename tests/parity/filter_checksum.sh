#!/usr/bin/env bash
# filter_checksum.sh -- a file filter decides what is WRITTEN, not what is CHECKED.
#
# The original judges every entry's checksum whatever the filter says: with the
# stored checksum of the middle entry damaged, `x bad.nz a.txt` writes a.txt alone
# and still prints b.txt's "Checksum mismatch" line, and so does a filter naming
# only the entry after it. This builds that archive with the original and compares
# `x` and `t` under four filters: the files written, and the checksum/footer lines
# with what only timing decides removed (the normalisation of tests/encode/oracle.sh).
#
# usage: tests/parity/filter_checksum.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_filter_checksum}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W"; mkdir -p "$W/src"; cd "$W" || exit 1

python3 -c "
for n in ('a.txt', 'b.txt', 'c.txt'):
    open('src/' + n, 'wb').write(b''.join(
        ('%s line %06d varied content %d\n' % (n, j, (j * 7919) % 1000)).encode() for j in range(60000)))
"
( cd src && "$ORIG" a -cf -t1 ../t.nz a.txt b.txt c.txt </dev/null >/dev/null 2>&1 )

# Flip one bit of b.txt's stored checksum (the listing prints it; the archive
# stores it little-endian): the decode completes and only b.txt mismatches.
CK=$("$ORIG" l t.nz 2>/dev/null | tr '\r\b' '\n\n' | awk '$NF=="b.txt"{print $1}')
python3 -c "
import sys
pat = int('$CK', 16).to_bytes(4, 'little')
d = bytearray(open('t.nz', 'rb').read())
i = d.rfind(pat)
if i < 0: sys.exit('stored checksum not found')
d[i] ^= 1
open('bad.nz', 'wb').write(d)
" || exit 1

norm() {
  sed -E 's/^(Intel|AMD|unknown).*//; s/Linux(32|64)/LinuxNN/; s/in [0-9.]+s, [0-9]+ [KMG]?B\/s/in T, R/; s/IO-(in|out): [0-9.]+s, [0-9]+ [KMG]?B\/s/IO-\1: T, R/g; s/ IO-out: T, R//' "$1" |
    tr '\r\b' '\n\n' | grep -oE 'Checksum mismatch.*|.*corrupt.*|(Decompressed|Tested).*|.*rror.*'
}
ok=0; bad=0
for cmd in x t; do
  for sel in "" a.txt b.txt c.txt; do
    for who in orig ours; do
      bin=$ORIG; [ $who = ours ] && bin=$OURS
      rm -rf "x_$who"; mkdir "x_$who"
      ( cd "x_$who" && env -i PATH=/usr/bin:/bin "$bin" $cmd -y ../bad.nz $sel </dev/null > ../$who.out 2>&1 )
    done
    if diff -r x_orig x_ours >/dev/null && diff <(norm orig.out) <(norm ours.out) >/dev/null; then
      ok=$((ok+1))
    else
      bad=$((bad+1)); echo "DIFF: $cmd filter=[$sel]"; diff <(norm orig.out) <(norm ours.out) | head -4
    fi
  done
done
echo "filter_checksum: $ok/$((ok+bad)) identical (files written + checksum/footer lines)"
[ "$bad" -eq 0 ]
