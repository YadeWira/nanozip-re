#!/usr/bin/env bash
# large_window.sh -- `a -cd` across the 128 MB window, against the original.
#
# The -cd window is the byte-float nearest the input size, and from 132 087 808
# bytes (126 MB - 32 KB) it rounds to 128 MB. A window of 128 MB or more gives the
# original's match finder a second table (FUN_0805c260 allocates it above
# 0x7ffffff; FUN_0805c530 probes it), which changes the archive from its first
# chunk and the console's memory figure by 4 MB. No other test reaches that size:
# the port wrote the original's bytes one byte below it and different ones at it.
#
# Per size: our `a -cd -t1` archive against the original's, byte for byte, and the
# compressor's `[N MB]` line. About 20 s and 700 MB of disk.
#
# usage: tests/encode/large_window.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_large_window}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
# The 32-bit original cannot open anything under /tmp/claude-*; keep to /tmp/nzre_*.
case "$W" in /tmp/claude-*) echo "FATAL: the original cannot read $W"; exit 1;; esac
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1

# text made of 20 000 random sentences drawn with repetition: matches at every
# distance, including the long ones the second table is there for
python3 - <<'PY'
import random
random.seed(20260923)
words = [''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(2, 9)))
         for _ in range(3000)]
sentences = [(' '.join(random.choice(words) for _ in range(random.randint(4, 14))) + '.\n').encode()
             for _ in range(20000)]
out, size = [], 0
while size < 132087808:
    for s in random.choices(sentences, k=100000):
        out.append(s); size += len(s)
open('big.txt', 'wb').write(b''.join(out)[:132087808])
PY

mem() { env -i PATH=/usr/bin:/bin "$1" a -cd -t1 "$2" "$3" </dev/null 2>&1 | tr '\r\b' '\n\n' | grep -a -o 'nz_lzhd \[[0-9]* MB\]' | head -1; }
ok=0; bad=0; fails=""
for n in 132087807 132087808; do
  head -c $n big.txt > in.bin
  rm -f o.nz r.nz
  mo=$(mem "$ORIG" o.nz in.bin)
  mr=$(mem "$OURS" r.nz in.bin)
  if cmp -s o.nz r.nz && [ -n "$mo" ] && [ "$mo" = "$mr" ]; then ok=$((ok+1))
  else bad=$((bad+1)); fails="$fails $n(archive=$(cmp -s o.nz r.nz && echo same || echo differs),console='$mo'/'$mr')"; fi
done
rm -f in.bin o.nz r.nz big.txt
echo "large_window: $ok/$((ok+bad)) identical to the original (archive + memory line)$fails"
[ "$bad" -eq 0 ]
