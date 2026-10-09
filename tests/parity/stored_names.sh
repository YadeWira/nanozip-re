#!/usr/bin/env bash
# stored_names.sh -- the name `a` stores for each way of typing a path.
#
# Both originals drop the FRONT of the path they were given: a drive ("C:"),
# then any run of "/", "./" and "../"; a "./" or "../" further in is kept, and
# `dir/` takes what `dir/*` takes. Up to v0.17.6-pre this port kept "../" (and
# "./" before a "..") and, on Windows, the drive: `a x.nz C:\data\f` stored
# `C:/data/f` and `a x.nz ..\d1\f` stored `../d1/f`, entries that every
# extractor of ours then refused as unsafe (reported by xman). Names are
# compared on the listing of a -cn archive made by each binary; with wine and
# the Windows original (NZ_WIN_ORIG) and a Windows build of ours (NZ_WIN_OURS)
# the backslash and drive forms are compared too.
# usage: tests/parity/stored_names.sh [workdir]   (NZ_RECON, NZ_ORIG as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
OURS=${NZ_RECON:-$HERE/bin/nz-re}
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
W=${1:-/tmp/nzre_stored_names}
[ -x "$ORIG" ] || { echo "stored_names: no original at $ORIG, skipped"; exit 77; }
rm -rf "$W"; mkdir -p "$W/d1/sub" "$W/w/q/r/.x" "$W/w/q/r/..y" "$W/w/q/r/...d" || exit 1
echo hola > "$W/d1/f.txt"; echo x > "$W/d1/sub/g.txt"
echo 1 > "$W/w/q/r/.x/a.txt"; echo 2 > "$W/w/q/r/..y/b.txt"; echo 3 > "$W/w/q/r/...d/h.txt"
cd "$W/w/q/r" || exit 1
names() {   # binary, then the switches and the path (last)
          local b=$1; shift; local arg=${!#}
          rm -f "$W/o.nz"; "$b" a -cn "${@:1:$#-1}" "$W/o.nz" "$arg" </dev/null >/dev/null 2>&1
          "$b" l "$W/o.nz" 2>/dev/null | tr '\r' '\n' | grep -a ' B ' | awk '{print $NF}' | LC_ALL=C sort | tr '\n' ' '; }
pass=0; fail=0
check() {   # switches..., path
    local a b
    a=$(names "$ORIG" "$@"); b=$(names "$OURS" "$@")
    if [ -n "$a" ] && [ "$a" = "$b" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL a $*: original [$a] ours [$b]"; fi
}
for arg in ../../../d1/f.txt ./../../../d1/f.txt .././../../d1/f.txt ../../../d1/./f.txt \
           ../../../d1/sub/../f.txt ../../..//d1/f.txt ./...d/h.txt ...d/h.txt "$W//d1/f.txt" \
           "$W/./d1/f.txt" "/..$W/d1/f.txt" '../../../d1/*.txt' .x/a.txt ./.x/a.txt ./..y/b.txt \
           .//.x/a.txt ../../../d1/ ; do
    check "$arg"
done
for arg in ../../../d1/. ../../../d1 ../../../d1/sub/.. ../../../d1/ .x/. . ./ ..; do check -r "$arg"; done
# what the original extracts from such a name, we extract too (a ".." inside the
# extraction directory is resolved, not refused)
rm -f "$W/o.nz"; "$ORIG" a -cn -r "$W/o.nz" ../../../d1/sub/.. ../../../d1/./f.txt </dev/null >/dev/null 2>&1
for b in "$ORIG" "$OURS"; do
    rm -rf "$W/x_$(basename "$b")"; mkdir "$W/x_$(basename "$b")"
    (cd "$W/x_$(basename "$b")" && "$b" x -y "$W/o.nz" </dev/null >/dev/null 2>&1)
done
if diff -r "$W/x_$(basename "$ORIG")" "$W/x_$(basename "$OURS")" >/dev/null && [ -f "$W/x_$(basename "$OURS")/d1/f.txt" ]; then
    pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL x of names with an inner ..: the trees differ"; fi

WO=${NZ_WIN_ORIG:-}; WR=${NZ_WIN_OURS:-}
if command -v wine >/dev/null && [ -n "$WO" ] && [ -n "$WR" ] && [ -f "$WO" ] && [ -f "$WR" ]; then
    cd "$W/w" || exit 1
    wn() { WINEDEBUG=-all wine "$1" a -cn -r o.nz "$2" </dev/null >/dev/null 2>&1
           WINEDEBUG=-all wine "$1" l o.nz 2>/dev/null | tr '\r' '\n' | grep -a ' B ' | awk '{print $NF}' | LC_ALL=C sort | tr '\n' ' '; rm -f o.nz; }
    zw=$(printf 'Z:%s' "$W" | tr '/' '\\')
    for arg in "$zw\\d1\\f.txt" "$zw\\d1" "Z:$W/d1/f.txt" "$(printf '%s' "$W" | tr '/' '\\')\\d1\\f.txt" \
               '..\d1\f.txt' 'Z:..\d1\f.txt' '..\d1' '..\d1\.' "$zw\\d1\\." '..\d1\'; do
        a=$(wn "$WO" "$arg"); b=$(wn "$WR" "$arg")
        if [ -n "$a" ] && [ "$a" = "$b" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL win a -r $arg: original [$a] ours [$b]"; fi
    done
else
    echo "stored_names: no wine / NZ_WIN_ORIG / NZ_WIN_OURS, Windows forms not compared"
fi
echo "stored_names: $pass/$((pass+fail)) ok"
[ "$fail" -eq 0 ]
