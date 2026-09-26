#!/usr/bin/env bash
# lzpf_ring_laps.sh -- -cf/-cF archives whose window ring wraps more than once.
#
# The lzpf window is a ring: when fewer than 32 KB are left the cursor goes back
# to 0 (FUN_080b6bb0), and the tail from the cursor to 32 KB past the capacity
# is zeroed only on the FIRST wrap after the reset (the flag at +0x1005c, set by
# FUN_080b6c60). From the second
# lap on, the bytes past the cursor are the previous lap's, and a stale hash
# entry can match into them. Up to v0.17.4-pre this reader zeroed them on every
# lap and decoded such a match as zeros: 15 of these 30 archives failed, and
# v0.17.4-pre's self-check refused `a -cF -r` of a folder of many files at the
# default thread count (16 workers make the -cF windows 64 KB).
#
# The original compresses a folder of many real files with -cf and -cF, at
# budgets from -m1m to -m256m (windows from 64 KB, -cF under -m64m, up to the
# whole input, so most but not all of them wrap more than once), single
# container and -p2/-p8;
# ours must test clean and extract every file identical to the input. The
# folder is NZ_LAPS_DIR (default: the 127 mixed files of the wide sweep); the
# test is skipped (exit 77) without it or without the original.
# About twenty seconds.
# usage: tests/lzpf_ring_laps.sh [workdir]   (NZ_RECON, NZ_ORIG as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OURS=${NZ_RECON:-$HERE/bin/nz-re}
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
SRC=${NZ_LAPS_DIR:-/mnt/IA_LAB/agentes/NZ-RE/imgsweep/in}
W=${1:-/tmp/nzre_ring_laps}
[ -x "$ORIG" ] || { echo "lzpf_ring_laps: no original at $ORIG, skipped"; exit 77; }
[ -d "$SRC" ] || { echo "lzpf_ring_laps: no input folder $SRC, skipped"; exit 77; }
rm -rf "$W"; mkdir -p "$W" || exit 1
nfiles=$(find "$SRC" -type f | wc -l)
cd "$(dirname "$SRC")" || exit 1
base=$(basename "$SRC")

pass=0; fail=0
for c in cf cF; do for m in 1m 4m 16m 64m 256m; do for p in 1 2 8; do
    a=$W/$c-$m-p$p.nz
    env -i PATH=/usr/bin:/bin "$ORIG" a -$c -t1 -m$m -p$p -r "$a" "$base" </dev/null >/dev/null 2>&1
    t=$("$OURS" t "$a" </dev/null 2>&1 | tr '\r\b' '\n\n')
    rm -rf "$W/x"; mkdir "$W/x"
    ( cd "$W/x" && "$OURS" x -y "$a" </dev/null >/dev/null 2>&1 )
    got=$(find "$W/x/$base" -type f 2>/dev/null | wc -l)
    if ! echo "$t" | grep -aq '^Decompressed [0-9 ]* bytes'; then
        fail=$((fail+1)); echo "FAIL -$c -m$m -p$p: t did not run: $(echo "$t" | tail -1)"
    elif echo "$t" | grep -aqE 'Checksum mismatch|Archive corr|Error'; then
        fail=$((fail+1)); echo "FAIL -$c -m$m -p$p: t reports $(echo "$t" | grep -acE 'Checksum mismatch|Archive corr|Error') bad lines"
    elif [ "$got" -ne "$nfiles" ] || ! diff -rq "$base" "$W/x/$base" >/dev/null 2>&1; then
        fail=$((fail+1)); echo "FAIL -$c -m$m -p$p: x gives $got of $nfiles files, $(diff -rq "$base" "$W/x/$base" 2>&1 | wc -l) differ"
    else
        pass=$((pass+1))
    fi
done; done; done
rm -rf "$W/x"
echo "lzpf_ring_laps: $pass/$((pass+fail)) ok"
[ "$fail" -eq 0 ]
