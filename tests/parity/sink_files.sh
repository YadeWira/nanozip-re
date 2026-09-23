#!/usr/bin/env bash
# sink_files.sh -- how extraction handles FILES, on every path that writes through
# the streaming sink (psink) and on the buffered one, against the original.
#
# None of the other suites could see these, because they run with a huge
# descriptor limit, no -sp/-forceout collisions, no damaged checksum on an empty
# file and a disk that never fills:
#   fd      2000 files extracted under `ulimit -n 256` (the original opens one file
#           at a time; a writer that keeps every file open until the end wrote 253
#           and printed "Cannot write" for the rest)
#   forceout  -forceout maps every entry to one name: the last entry wins, whole,
#           with its own mode and timestamp
#   sp      -sp: an empty entry and a real one with the same base name, in the
#           order the archive keeps them
#   ck0     an empty entry's stored checksum damaged: the mismatch line in `x`,
#           none in `t`
#   full    two outputs are symlinks to /dev/full: "Out of disk space!" once, and
#           every other file still written
# Compared: the files written (name, size, mode, mtime, content) and the
# checksum/disk/cannot lines. Parallel containers are left out of `forceout`:
# there the original's own result changes from run to run (the last worker to
# finish wins).
#
# usage: tests/parity/sink_files.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_sink_files}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W"; mkdir -p "$W/many" "$W/mix/p1" "$W/mix/p2" "$W/mix/p3"; cd "$W" || exit 1

python3 -c "
import os
for i in range(2000): open('many/f%04d.txt' % i, 'w').write(('file %d\n' % i) * 20)
# e*.txt empty, f*.txt of different sizes, modes and dates; p*/b.txt collide under -sp
sizes = {'f1.txt': 70000, 'f2.txt': 150000, 'f3.txt': 90000, 'f4.txt': 130000, 'f5.txt': 200000}
for n, sz in sizes.items(): open('mix/' + n, 'wb').write(bytes((j * 7 + len(n)) % 251 for j in range(sz)))
for n in ('e0.txt', 'e1.txt'): open('mix/' + n, 'wb').close()
open('mix/p1/b.txt', 'wb').close()
open('mix/p2/b.txt', 'w').write('the real one\n' * 3000)
open('mix/p3/b.txt', 'wb').close()
for k, (n, m) in enumerate([('f1.txt', 0o640), ('f2.txt', 0o600), ('f3.txt', 0o755), ('f4.txt', 0o604), ('f5.txt', 0o644), ('e0.txt', 0o644), ('e1.txt', 0o600)]):
    os.chmod('mix/' + n, m); os.utime('mix/' + n, (946684800 + k * 86400 * 30,) * 2)
"
# single container (-t1) and parallel (-p4) archives of each writer family
for c in cf co cc cd; do
  ( cd many && "$ORIG" a -$c -t1 ../many_$c.nz . </dev/null >/dev/null 2>&1 )
  ( cd many && "$ORIG" a -$c -p4 -t1 ../many_${c}p4.nz . </dev/null >/dev/null 2>&1 )
  ( cd mix && "$ORIG" a -$c -t1 -r ../mix_$c.nz . </dev/null >/dev/null 2>&1 )
done

# ck0: flip one bit of e0.txt's stored checksum (ffffffff, stored little-endian)
python3 -c "
for c in ('cf', 'co', 'cc', 'cd'):
    d = bytearray(open('mix_%s.nz' % c, 'rb').read())
    i = d.find(b'\xff\xff\xff\xff')
    if i < 0: raise SystemExit('no empty checksum in mix_' + c)
    d[i + 1] ^= 0x11
    open('ck0_%s.nz' % c, 'wb').write(d)
"

files() { ( cd "$1" && find . -type f -printf '%p %s %m %TY-%Tm-%Td_%TH:%TM\n' | sort; find . -type f | sort | xargs -r md5sum ); }
lines() { tr '\r\b' '\n\n' < "$1" | grep -oE 'Checksum mismatch.*|Out of disk space!|Cannot write.*' | sort | uniq -c; }
ok=0; bad=0
run() {   # run <tag> <archive> <prep> <cmd...>
  local tag=$1 arc=$2 prep=$3; shift 3
  for who in orig ours; do
    local bin=$ORIG; [ $who = ours ] && bin=$OURS
    rm -rf "x_$who"; mkdir "x_$who"
    ( cd "x_$who" && eval "$prep" && env -i PATH=/usr/bin:/bin "$bin" "$@" "../$arc" </dev/null > ../$who.out 2>&1 )
    find "x_$who" -type l -delete
  done
  if diff <(files x_orig) <(files x_ours) >/dev/null && diff <(lines orig.out) <(lines ours.out) >/dev/null; then
    ok=$((ok+1))
  else
    bad=$((bad+1)); echo "DIFF: $tag"
    diff <(files x_orig) <(files x_ours) | head -3; diff <(lines orig.out) <(lines ours.out) | head -3
  fi
}
for c in cf co cc cd; do
  run "fd -$c"       many_$c.nz   'ulimit -n 256' x -y
  run "fd -$c -p4"   many_${c}p4.nz 'ulimit -n 256' x -y
  run "forceout -$c" mix_$c.nz    ':' x -y -forceout
  run "sp -$c"       mix_$c.nz    ':' x -y -sp
  run "ck0 x -$c"    ck0_$c.nz    ':' x -y
  run "ck0 t -$c"    ck0_$c.nz    ':' t
  run "full -$c"     mix_$c.nz    'ln -s /dev/full f3.txt; ln -s /dev/full f4.txt' x -y
done
echo "sink_files: $ok/$((ok+bad)) identical (files written + checksum/disk/cannot lines)"
[ "$bad" -eq 0 ]
