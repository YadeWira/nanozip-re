#!/usr/bin/env bash
# parallel_readback.sh -- `a` above the automatic-split size, with threads, against the original.
#
# From 8 MB of input the compressor splits into one worker per thread on its own, so a
# plain `a` of a big file on any multi-core machine writes a parallel container. Every
# other encode check runs `-t1` (quirk 58), which never splits, and none of them had a
# `-pN` case for the optimum/CM family. Two defects lived there, v0.15.0/v0.15.1 to
# v0.17.0-pre: the last worker's header was written with the two-byte codec record of
# the store era (-co/-cO need three bytes, -cc four), so neither program could read the
# archive (the original on Windows hangs on it); and -cO/-cc were split at all, where
# the original keeps one compressor. A third came out of the -p16 case: CM_Init chose
# its first hash slot before clearing the table, so a second CM object in the same
# process started from the previous one's leftovers -- `a -cc -p16` wrote an
# unreadable stream and `t -t1` refused the original's own -p12 archive.
#
# Checks, per codec: `a -t4` of a 20 MB input is read by the original and extracts to
# the input, and asks for as many compressors as the original's own `a -t4`; `a -t1 -p3`
# and `a -t1 -p16` are byte-identical to the original's -- for -cc on that input, for
# -co/-cO on 12 MB of base64 text (on word-salad text and structured binary their
# single-stream archives already differ, quirk 72 and the LZ engine's known residuals,
# so a byte comparison there would say nothing about -pN); and `t -t1` reads the
# original's -cc -p12 and -p16 archives. About 8 minutes.
#
# usage: tests/encode/parallel_readback.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_parallel_readback}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
# The 32-bit original cannot open anything under /tmp/claude-*; keep to /tmp/nzre_*.
case "$W" in /tmp/claude-*) echo "FATAL: the original cannot read $W"; exit 1;; esac
rm -rf "$W"; mkdir -p "$W/x"; cd "$W" || exit 1

# 20 MB: text made of repeated sentences, with runs of structured binary between them
python3 - <<'PY'
import random
random.seed(20260923)
words = [''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(2, 9)))
         for _ in range(4000)]
sentences = [(' '.join(random.choice(words) for _ in range(random.randint(4, 14))) + '.\n').encode()
             for _ in range(30000)]
out, size, k = [], 0, 0
while size < 20 * 2**20:
    chunk = b''.join(random.choices(sentences, k=3000))
    out.append(chunk); size += len(chunk); k += 1
    if k % 4 == 0:
        b = bytes(((i * (k + 7)) ^ (i >> 5) ^ random.randrange(8)) & 0xff for i in range(60000))
        out.append(b); size += len(b)
open('in.bin', 'wb').write(b''.join(out)[:20 * 2**20])
import base64
random.seed(11)
open('b64.bin', 'wb').write(base64.encodebytes(bytes(random.getrandbits(8) for _ in range(9 * 2**20)))[:12 * 2**20])
PY

run() { env -i PATH=/usr/bin:/bin "$@" </dev/null 2>&1 | tr '\r\b' '\n\n'; }
bad_lines() { grep -a -m1 -iE 'corrupt|error|mismatch|incompatible'; }
ok=0; bad=0; fails=""
pass() { ok=$((ok+1)); }
fail() { bad=$((bad+1)); fails="$fails
  $1"; }

for c in cn cf cF cd cD co cO cc; do
  rm -f r.nz o.nz
  nr=$(run "$OURS" a -$c -t4 r.nz in.bin | grep -a -c '^Compressor #')
  no=$(run "$ORIG" a -$c -t4 o.nz in.bin | grep -a -c '^Compressor #')
  if [ ! -s r.nz ]; then fail "-$c -t4: no archive"; continue; fi
  t=$(run "$ORIG" t r.nz | bad_lines)
  rm -rf x/*; ( cd x && run "$ORIG" x -y ../r.nz >/dev/null )
  if [ -z "$t" ] && cmp -s x/in.bin in.bin && [ "$nr" = "$no" ]; then pass
  else fail "-$c -t4: original t=[${t:-OK}] extract=$(cmp -s x/in.bin in.bin && echo match || echo DIFFERS) compressors ours=$nr original=$no"; fi
done
for spec in co:b64.bin cO:b64.bin cc:in.bin; do
  c=${spec%%:*}; f=${spec#*:}
  for p in 3 16; do
    rm -f r.nz o.nz
    run "$OURS" a -$c -t1 -p$p r.nz $f >/dev/null; run "$ORIG" a -$c -t1 -p$p o.nz $f >/dev/null
    if cmp -s r.nz o.nz; then pass; else fail "-$c -t1 -p$p ($f): not the original's bytes"; fi
  done
done
for p in 12 16; do
  rm -f o.nz; run "$ORIG" a -cc -t1 -p$p o.nz in.bin >/dev/null
  t=$(run "$OURS" t -t1 o.nz | bad_lines)
  if [ -z "$t" ]; then pass; else fail "t -t1 of the original's -cc -p$p: $t"; fi
done
rm -rf x in.bin b64.bin r.nz o.nz
echo "parallel_readback: $ok/$((ok+bad)) ok$fails"
[ "$bad" -eq 0 ]
