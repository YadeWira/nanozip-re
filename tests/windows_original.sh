#!/usr/bin/env bash
# windows_original.sh -- archives made by the WINDOWS original, and our Windows
# build's console against it.
#
# The Windows binaries of NanoZip 0.09a are a separate download; this script
# takes them from $NZ_WIN_ORIG (a directory holding nz.exe) and runs them through
# `wine`, which is enough because the decoder never touches the Windows API for
# anything the format depends on. Two things only Windows exercises:
#
#   * a Windows-made archive stores FILE ATTRIBUTES (record type 3): one nibble
#     per entry, `8 | READONLY | HIDDEN<<1 | SYSTEM<<2`, absent when every file
#     is plain. The Linux original maps them to a mode (0400 read-only, 0600
#     otherwise) and lists them under `perm`; a Windows build names the column
#     `attr.` and prints "R", "H", "S", "A" in fixed positions, blank for an
#     archive that carries POSIX modes instead (quirk 48).
#   * the thread count: the original reports the CPU's physical cores, from the
#     CPU itself and not from the OS.
#
# usage: tests/windows_original.sh [workdir]
#   NZ_WIN_ORIG=dir   the Windows original (default /tmp/nzre_orig_dl/win32)
set -u
W=${1:-/tmp/nzre_win_orig}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ORIG32=${NZ_ORIG:-$HERE/../linux32/nz}
OURS=${NZ_RECON:-$HERE/bin/nz_recon}
WIN_ORIG=${NZ_WIN_ORIG:-/tmp/nzre_orig_dl/win32}/nz.exe
command -v wine >/dev/null 2>&1 || { echo "SKIP: no wine"; exit 0; }
[ -f "$WIN_ORIG" ] || { echo "SKIP: no Windows original at $WIN_ORIG"; exit 0; }
[ -x "$ORIG32" ] || { echo "SKIP: no Linux original at $ORIG32"; exit 0; }
export WINEDEBUG=-all

rm -rf "$W"; mkdir -p "$W/src"
head -c 200000 /dev/urandom | base64 | head -c 200000 > "$W/src/t.txt"
head -c 100000 /dev/urandom > "$W/src/b.bin"
printf 'tiny\n' > "$W/src/s.txt"
mkdir -p "$W/src/sub"; printf 'in a subdir\n' > "$W/src/sub/c.txt"
# every attribute combination, so the type-3 nibbles are all exercised
for i in 1 2 3 4 5; do printf "a$i\n" > "$W/src/a$i.txt"; done
( cd "$W/src" && timeout 120 wine cmd /c "attrib +R a2.txt" >/dev/null 2>&1
                 timeout 120 wine cmd /c "attrib +H a3.txt" >/dev/null 2>&1
                 timeout 120 wine cmd /c "attrib +S a4.txt" >/dev/null 2>&1
                 timeout 120 wine cmd /c "attrib +H a5.txt" >/dev/null 2>&1
                 timeout 120 wine cmd /c "attrib +S a5.txt" >/dev/null 2>&1 )
# Verify the attributes actually took: under load a wine call can come back
# without having applied one, and then the archives carry attributes the
# comparison did not expect.
attrs=$( cd "$W/src" && timeout 120 wine cmd /c "attrib a*.txt" 2>/dev/null | tr -d '\r' )
for want in "R.*a2.txt" "H.*a3.txt" "S.*a4.txt" "H.*a5.txt"; do
  printf '%s\n' "$attrs" | grep -qE "$want" || { echo "SKIP: wine did not apply the attributes ($want)"; exit 0; }
done

pass=0; fail=0
for spec in n:-cn c:-cc d:-cd Du:-cD f:-cf Fu:-cF o:-co Ou:-cO; do
  tag=${spec%%:*}; opt=${spec#*:}
  ( cd "$W/src" && timeout 900 wine "$WIN_ORIG" a "$opt" -r "../w_$tag.nz" \
      t.txt b.bin s.txt sub a1.txt a2.txt a3.txt a4.txt a5.txt >/dev/null 2>&1 )
  [ -f "$W/w_$tag.nz" ] || { echo "FAIL $tag: the Windows original did not build the archive"; fail=$((fail+1)); continue; }
  # the Linux original's extraction is the reference (contents and modes)
  for who in orig ours; do
    bin=$ORIG32; [ $who = ours ] && bin=$OURS
    d="$W/x_${tag}_$who"; rm -rf "$d"; mkdir -p "$d"
    ( cd "$d" && env -i PATH=/usr/bin:/bin "$bin" x -y "$W/w_$tag.nz" >/dev/null 2>&1 )
  done
  state() { ( cd "$1" && find . -type f -printf '%P %m\n' 2>/dev/null | sort ); }
  if diff <(state "$W/x_${tag}_orig") <(state "$W/x_${tag}_ours") >/dev/null &&
     diff -r "$W/x_${tag}_orig" "$W/x_${tag}_ours" >/dev/null; then
    pass=$((pass+1))
  else
    echo "FAIL $tag: extraction differs from the Linux original's"
    diff <(state "$W/x_${tag}_orig") <(state "$W/x_${tag}_ours") | head -4 | sed 's/^/    /'
    fail=$((fail+1))
  fi
  # and the listing, on Linux
  a=$(env -i PATH=/usr/bin:/bin "$ORIG32" l "$W/w_$tag.nz" 2>/dev/null | tr '\r' '\n' | grep -v "MHz\|Linux3\|Linux6")
  b=$(env -i PATH=/usr/bin:/bin "$OURS"   l "$W/w_$tag.nz" 2>/dev/null | tr '\r' '\n' | grep -v "MHz\|Linux3\|Linux6")
  if [ "$a" = "$b" ]; then pass=$((pass+1)); else
    echo "FAIL $tag: listing differs"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; fail=$((fail+1))
  fi
done

# The console of OUR Windows build against the Windows original, if one is built.
for exe in "$W/../nzre_win/nz_recon_i686.exe" "$HERE/bin/nz_recon.exe"; do
  [ -f "$exe" ] || continue
  for tag in n c f o; do
    for cmd in l t; do
      a=$(timeout 600 wine "$WIN_ORIG" $cmd "$W/w_$tag.nz" 2>/dev/null | tr -d '\r' | grep -v "MHz\|Win32\|Win64\|IO-\| in [0-9]")
      b=$(timeout 600 wine "$exe"      $cmd "$W/w_$tag.nz" 2>/dev/null | tr -d '\r' | grep -v "MHz\|Win32\|Win64\|IO-\| in [0-9]")
      if [ "$a" = "$b" ]; then pass=$((pass+1)); else
        echo "FAIL windows console $cmd $tag"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; fail=$((fail+1))
      fi
    done
  done
  break
done
echo "windows_original: $pass checks passed, $fail failed"
[ $fail -eq 0 ]
