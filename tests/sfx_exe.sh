#!/usr/bin/env bash
# sfx_exe.sh -- self-extracting archives (.exe made by the original's `w32c`).
#
# The original builds an SFX on Linux too: a Windows PE stub (nz_w32c.sfx) with a
# normal archive appended, so `l`/`t`/`x` on the .exe must behave exactly as on the
# .nz inside it (quirk 20). This builds one .exe per codec with the ORIGINAL and
# compares our listing, test and extraction against it.
#
# usage: tests/sfx_exe.sh [workdir]        (needs ../linux32/nz next to the checkout)
set -u
W=${1:-/tmp/nzre_sfx_exe}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
OURS=${NZ_RECON:-$HERE/bin/nz_recon}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
[ -x "$OURS" ] || { echo "FAIL: no $OURS"; exit 1; }

rm -rf "$W"; mkdir -p "$W/src"
# Three files of different shapes: text, a 6-byte one, binary.
head -c 600000 /dev/urandom | base64 | head -c 600000 > "$W/src/b_mid.txt"
printf 'hello\n' > "$W/src/f_tiny.txt"
head -c 200000 /dev/urandom > "$W/src/d.dat"

pass=0; fail=0
strip_noise() { tr '\r' '\n' | grep -v "MHz\|Linux32\|Linux64\|Win32\|Win64\|IO-in\|IO-out\| in [0-9]"; }
for spec in n:-cn c:-cc d:-cd Du:-cD f:-cf Fu:-cF o:-co Ou:-cO; do
  tag=${spec%%:*}; opt=${spec#*:}
  ( cd "$W/src" && env -i PATH=/usr/bin:/bin "$ORIG" w32c "$opt" "../sx_$tag.exe" b_mid.txt f_tiny.txt d.dat >/dev/null 2>&1 )
  [ -f "$W/sx_$tag.exe" ] || { echo "FAIL $tag: the original did not build the .exe"; fail=$((fail+1)); continue; }
  for cmd in l t; do
    a=$(cd "$W" && env -i PATH=/usr/bin:/bin "$ORIG" $cmd "sx_$tag.exe" 2>/dev/null | strip_noise)
    b=$(cd "$W" && env -i PATH=/usr/bin:/bin "$OURS" $cmd "sx_$tag.exe" 2>/dev/null | strip_noise)
    # `t` differs only in how many progress figures fit in a second (quirk: timing).
    if [ "$cmd" = l ] && [ "$a" != "$b" ]; then echo "FAIL $tag: $cmd output differs"; fail=$((fail+1)); continue; fi
    if [ "$cmd" = t ] && [ "$(echo "$a" | grep -c Decompressed)" != "$(echo "$b" | grep -c Decompressed)" ]; then
      echo "FAIL $tag: $cmd footer differs"; fail=$((fail+1)); continue
    fi
  done
  rm -rf "$W/x_$tag"; mkdir -p "$W/x_$tag"
  ( cd "$W/x_$tag" && env -i PATH=/usr/bin:/bin "$OURS" x -y "../sx_$tag.exe" >/dev/null 2>&1 )
  if diff -r "$W/src" "$W/x_$tag" >/dev/null 2>&1; then pass=$((pass+1)); else
    echo "FAIL $tag: extracted tree differs"; diff -rq "$W/src" "$W/x_$tag" | head -3; fail=$((fail+1))
  fi
done
echo "sfx_exe: $pass/8 codecs byte-exact, $fail failures"
[ $fail -eq 0 ]
