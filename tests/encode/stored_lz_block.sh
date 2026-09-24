#!/usr/bin/env bash
# stored_lz_block.sh -- a -co block the LZ engine cannot shrink, against the original.
#
# When the engine's encode gives nothing back, the original writes the block
# STORED (decr_param 1, param6 0, no size18) and cold-starts the model. The
# decoder puts those bytes into the window through the engine's own store
# (FUN_0809e4e0), in the 32 KB chunks DecodeBlock writes -- not through the
# window feed. The two leave the ring cursor in different places unless the
# block ends on a 32 KB boundary, and every stored block this port had been
# tested on was a whole 1 MB -m4m block, so it never showed: v0.17.2-pre fails
# to decode the original's archive of these two files (578205-byte stored
# block), and its compressor refused to write them at all.
#
# Two real files from the corpus (copied, never touched in place). Per method:
# our `a -t1 -m4m` against the original's byte for byte, and each binary's `t`
# of the other's archive. The -co case must contain a stored LZ block or the
# test refuses to count it -- a fixture that stops producing one proves nothing.
#
# usage: tests/encode/stored_lz_block.sh [workdir]   (NZ_ORIG, NZ_RECON, NZ_CORPUS)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
CORPUS=${NZ_CORPUS:-/mnt/OSR_D3/fileFormatSamples/fileFormatSamples}
W=${1:-/tmp/nzre_stored_lz}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
A=$CORPUS/document/rocketeBook/March_Upcountry.rb
B=$CORPUS/document/starOfficePresentation/STAR.SDD
[ -f "$A" ] && [ -f "$B" ] || { echo "SKIP: corpus files not found under $CORPUS"; exit 0; }
case "$W" in /tmp/claude-*) echo "FATAL: the original cannot read $W"; exit 1;; esac
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1
cp "$A" March_Upcountry.rb; cp "$B" STAR.SDD

tst() { env -i PATH=/usr/bin:/bin "$1" t "$2" </dev/null 2>&1 | tr '\r\b' '\n\n' | grep -aq '^Decompressed' && echo ok || echo FAIL; }
stored() { NZOPT_TRACE_TDO=1 "$OURS" t "$1" </dev/null 2>&1 | tr '\r\b' '\n\n' | grep -ac 'decr_param=1 param6=0'; }

pass=0; fail=0
for m in co cO cc; do
    rm -f o_$m.nz r_$m.nz
    env -i PATH=/usr/bin:/bin "$ORIG" a -$m -t1 -m4m o_$m.nz March_Upcountry.rb STAR.SDD </dev/null >/dev/null 2>&1
    env -i PATH=/usr/bin:/bin "$OURS" a -$m -t1 -m4m r_$m.nz March_Upcountry.rb STAR.SDD </dev/null >/dev/null 2>&1
    if [ ! -f r_$m.nz ]; then echo "FAIL -$m: nothing written"; fail=$((fail+1)); continue; fi
    s=$(stored o_$m.nz)
    if [ "$m" = co ] && [ "$s" -lt 1 ]; then
        echo "FAIL -$m: the original's archive has no stored LZ block -- the fixture no longer tests it"
        fail=$((fail+1)); continue
    fi
    same=$(cmp -s o_$m.nz r_$m.nz && echo identical || echo "DIFFERS ($(stat -c %s o_$m.nz) vs $(stat -c %s r_$m.nz))")
    to=$(tst "$ORIG" r_$m.nz); tr_=$(tst "$OURS" o_$m.nz)
    if [ "$same" = identical ] && [ "$to" = ok ] && [ "$tr_" = ok ]; then pass=$((pass+1)); r=ok; else fail=$((fail+1)); r=FAIL; fi
    echo "$r -$m: stored LZ blocks=$s, archive $same, original reads ours: $to, we read the original's: $tr_"
done
echo "stored_lz_block: $pass/$((pass+fail)) ok"
[ "$fail" -eq 0 ]
