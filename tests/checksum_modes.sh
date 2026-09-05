#!/usr/bin/env bash
# checksum_modes.sh -- every checksum mode of the original, across every codec and
# both container shapes, listed, tested and extracted with both binaries.
#
# `-h<n,c,C,f>` picks none, crc16, crc32 or fletcher16 (the default). The mode
# lands in the archive as a zero-payload record (type 5/6/7, or the type-20/21/22
# extension in a parallel container) and decides both the per-file trailer width
# and whether extraction verifies anything at all -- so an archive per mode per
# codec is the only way to know the decoder reads all four.
#
# usage: tests/checksum_modes.sh [workdir]
set -u
W=${1:-/tmp/nzre_cksum}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
OURS=${NZ_RECON:-$HERE/bin/nz_recon}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W" && mkdir -p "$W/src/sub"
# One input of every shape the codecs care about: text, binary, tiny, empty.
python3 - "$W/src" <<'PY'
import os, random, sys
d = sys.argv[1]; random.seed(4242)
open(f'{d}/a.txt','w').write(('the quick brown fox jumps over the lazy dog\n' * 6000))
open(f'{d}/b.bin','wb').write(bytes(random.randrange(256) for _ in range(300000)))
open(f'{d}/sub/c.dat','wb').write(bytes((i*7) % 251 for i in range(120000)))
open(f'{d}/tiny.txt','w').write('x')
open(f'{d}/empty','w').write('')
PY
msgs() {
  tr '\r' '\n' |
    sed -E -e 's/(NanoZip [0-9.]+ alpha\/)(Linux|Win)(32|64)/\1<P>/' \
           -e 's/^[A-Za-z].*MHz\|.*MB$/<HOST>/' \
           -e 's/[0-9]+([.,][0-9]+)?s,.*//' |
    grep -v $'\010' | grep -vE '^ *$' |
    awk '/^Compressor #/ { b[++n] = $0; next }
         { flush() ; print }
         END { flush() }
         function flush(   i, j, t) {
           for (i = 2; i <= n; i++) { t = b[i]; for (j = i - 1; j >= 1 && b[j] > t; j--) b[j+1] = b[j]; b[j+1] = t }
           for (i = 1; i <= n; i++) print b[i]
           n = 0
         }'
}

ok=0; bad=0; fails=""
for codec in cn cf cF cd cD co cO cc; do
  for h in "" -hn -hc -hC -hf; do
    for par in "" -p4; do
      tag="${codec}${h:+_${h#-}}${par:+_p4}"
      a="$W/$tag.nz"
      ( cd "$W/src" && env -i PATH=/usr/bin:/bin "$ORIG" a -y -$codec $h $par "$a" a.txt b.bin sub/c.dat tiny.txt empty >/dev/null 2>&1 )
      [ -s "$a" ] || { bad=$((bad+1)); fails="$fails $tag(no-archive)"; continue; }
      for cmd in l t; do
        # Same normalisation the console matrices use: the banner's platform word,
        # the host line, timings and the status-line rewrites (every one of which
        # carries a backspace) are inherent, and so is the order of the parallel
        # `Compressor` lines (quirk 43), so only the messages are compared.
        o=$(env -i PATH=/usr/bin:/bin "$ORIG" $cmd "$a" 2>&1 | msgs)
        u=$(env -i PATH=/usr/bin:/bin "$OURS" $cmd "$a" 2>&1 | msgs)
        if [ "$o" = "$u" ]; then ok=$((ok+1)); else bad=$((bad+1)); fails="$fails $tag($cmd)"; fi
      done
      rm -rf "$W/xo_$tag" "$W/xu_$tag"; mkdir -p "$W/xo_$tag" "$W/xu_$tag"
      ( cd "$W/xo_$tag" && env -i PATH=/usr/bin:/bin "$ORIG" x -y "$a" >/dev/null 2>&1 )
      ( cd "$W/xu_$tag" && env -i PATH=/usr/bin:/bin "$OURS" x -y "$a" >/dev/null 2>&1 )
      if diff -r "$W/xo_$tag" "$W/xu_$tag" >/dev/null 2>&1; then ok=$((ok+1)); else bad=$((bad+1)); fails="$fails $tag(x)"; fi
    done
  done
done
echo "checksum_modes: $ok checks passed, $bad failed$fails"
[ $bad -eq 0 ]
