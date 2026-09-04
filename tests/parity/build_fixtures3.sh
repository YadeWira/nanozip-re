#!/bin/bash
# build_fixtures3.sh -- archives for CLI parity round 3 (shapes the earlier matrices never built).
# Trees under $FX/src/<name>/, archives $FX/<name>.nz made by the ORIGINAL. Usage: build_fixtures3.sh [FX=/tmp/nzre_fx3]
set -u
FX=${1:-/tmp/nzre_fx3}
HERE=$(cd "$(dirname "$0")/../.." && pwd); ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
case $FX in /tmp/nzre_*) ;; *) echo "FX must be under /tmp/nzre_*"; exit 1;; esac
[[ $(id -u) -eq 0 ]] && { echo "do not run as root"; exit 1; }
rm -rf "$FX"; mkdir -p "$FX/src"; cd "$FX/src"
# --- trees
mkdir -p empties && : > empties/a && : > empties/b.txt && : > empties/c.bin
mkdir -p dirs_only/one/two/three dirs_only/four
mkdir -p mixed/d && : > mixed/empty.txt && printf 'hello\n' > mixed/full.txt
mkdir -p dup/a dup/b && printf 'AAA\n' > dup/a/x.txt && printf 'BBBBBB\n' > dup/b/x.txt && printf 'ccc\n' > dup/a/y.txt
mkdir -p links/d && printf 'target\n' > links/target.txt && ln -s target.txt links/to_file && ln -s d links/to_dir && ln -s nowhere links/dangling && printf 'in d\n' > links/d/f.txt
mkdir -p names/hos names/sub && printf 'x\n' > names/hos/tile.txt && printf 'sp\n' > "names/with space.txt" && printf 'u\n' > "names/ñandú_中文.txt" \
  && printf 'b\n' > 'names/back\slash.txt' && printf 'w\n' > 'names/star*q?colon:.txt' \
  && printf '40\n' > "names/$(printf 'a%.0s' $(seq 1 30)).txt40" && printf '41\n' > "names/$(printf 'b%.0s' $(seq 1 31)).txt41" \
  && printf 'long\n' > "names/$(printf 'c%.0s' $(seq 1 251)).txt"
# deep path > 4096 chars: 360 levels of 12 chars
( cd names && p=sub; for i in $(seq 1 360); do p="$p/d$(printf '%010d' $i)"; done; mkdir -p "$p" && printf 'deep\n' > "$p/deep.txt" ) 2>/dev/null
mkdir -p modes && printf 's\n' > modes/setuid && chmod 4755 modes/setuid && printf 'r\n' > modes/ro && chmod 0444 modes/ro \
  && printf 'x\n' > modes/all && chmod 0777 modes/all && printf 'z\n' > modes/none && chmod 0000 modes/none
mkdir -p mtimes && for t in "@0:epoch" "@-86400:y1969" "2100-01-01 00:00:00:y2100" "2038-01-20 00:00:00:y2038" "1990-06-15 12:34:56:y1990"; do
  d=${t%:*}; n=${t##*:}; printf '%s\n' "$n" > "mtimes/$n"; touch -d "$d" "mtimes/$n" 2>/dev/null; done
echo "trees built"
# --- archives (original binary, -y)
# original syntax: a [switches] <archive> <patterns...> -- the archive comes BEFORE the file patterns
a() { local name=$1; shift; local sw=(); while [[ $# -gt 0 && $1 == -* ]]; do sw+=("$1"); shift; done
      (cd "$FX/src" && env -i PATH=/usr/bin:/bin "$ORIG" a -y "${sw[@]}" "$FX/$name.nz" "$@" 2>&1 | tr '\r' '\n' | grep -i "cannot\|warning\|error\|Compressed\|No files" | sed "s/^ */  $name: /"); }
# The original takes FILE PATTERNS, not directories: "dup" alone is "No files found"; -r 'dup/*' recurses.
a empties -cn -r 'empties/*'; a dirs_only -cn -r 'dirs_only/*'; a mixed -cn -r 'mixed/*'; a dup -cn -r 'dup/*'; a links -cn -r 'links/*'
a names -cn -r 'names/*'; a names_co -co -r 'names/*'; a names_hn -cn -hn -nt -np -r 'names/*'
a modes -cn -r 'modes/*'; a modes_fo -cn -fo -r 'modes/*'; a mtimes -cn -r 'mtimes/*'
a three -cn -r 'dup/*' 'mixed/*'   # 3+ files for the prompt harness (Always retroactive?)
# --- hostile paths: patch the stored name in the -hn (no checksum) store archive, same length
python3 - "$FX" <<'PY'
import sys; FX=sys.argv[1]; b=open(f'{FX}/names_hn.nz','rb').read()
for tag,new in (('dotdot',b'../../ab.txt'),('abs',b'/tmp/nzre_fx')):
    assert b.count(b'names/hos/tile.txt')==1, b.count(b'names/hos/tile.txt')
    # keep total length: replace the 18-byte name with a 18-byte hostile one
    repl={'dotdot':b'../../../abcd.txt1'[:18].ljust(18,b'x'), 'abs':b'/tmp/nzre_fx3/hst1'}[tag]
    assert len(repl)==18
    open(f'{FX}/hostile_{tag}.nz','wb').write(b.replace(b'names/hos/tile.txt',repl))
    print('hostile', tag, repl)
PY
for h in hostile_dotdot hostile_abs; do echo "== l $h (original)"; env -i PATH=/usr/bin:/bin "$ORIG" l "$FX/$h.nz" 2>/dev/null | tr '\r' '\n' | grep -i "abcd\|hst1\|Total\|corrupt"; done
ls -la "$FX"/*.nz | awk '{print $5, $9}'
