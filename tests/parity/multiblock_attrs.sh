#!/usr/bin/env bash
# multiblock_attrs.sh -- attribute records of a MULTI-BLOCK archive, against the original.
#
# With -t1 a file of about a megabyte or more gets a block of its own, and each
# block carries its own table and attribute records: its type-4 permission record
# is OMITTED when every file of the block is 0600, and its checksum record may sit
# between two of its data records. Reading the records as one run per archive
# refused such an archive outright (a 300 KB file and a 1.5 MB one, -cf: "Archive
# corrupted") or gave every file mode 0664 and a date in 1997 (-cd).
#
# The original's lister, unlike its extractor, does NOT align the modes to their
# blocks (quirk 76), so `l` and `x` are both compared: the files written (name,
# size, mode, mtime, content) and the listing.
#
# usage: tests/parity/multiblock_attrs.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_multiblock_attrs}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1

# shape <name> <mode...>: one 1.1 MB file per mode, each its own block
shape() {
  local name=$1; shift; mkdir -p "src_$name"; local k=0
  for m in "$@"; do
    python3 -c "
import os, sys
n, m, k = sys.argv[1], int(sys.argv[2], 8), int(sys.argv[3])
data = bytes(((j * 131 + k * 17) ^ (j >> 7)) % 251 for j in range(1150000))
open(n, 'wb').write(data); os.chmod(n, m); os.utime(n, (946684800 + k * 86400 * 40,) * 2)
" "src_$name/f$k.bin" "$m" "$k"
    k=$((k+1))
  done
}
shape last0600   0664 0600
shape first0600  0600 0664
shape mid0600    0664 0600 0644
shape two0600    0600 0600 0664
shape all0600    0600 0600 0600
shape mixed      0755 0600 0640
# small files sharing a block, then blocks of one large file each
mkdir -p src_smallbig && python3 -c "
import os
for n, m in (('a.txt', 0o644), ('b.txt', 0o600), ('c.txt', 0o664)):
    open('src_smallbig/' + n, 'w').write(n * 400); os.chmod('src_smallbig/' + n, m)
" && cp -p src_mid0600/f1.bin src_smallbig/z1.bin && cp -p src_mid0600/f2.bin src_smallbig/z2.bin

# with -nt the archive stores no dates, so a file's mtime is the moment it was
# extracted -- compared, it only says whether the two runs fell in the same minute
files() { local fmt='%p %s %m %TY-%Tm-%Td_%TH:%TM\n'; [ "${2:-}" = -nt ] && fmt='%p %s %m\n'
          ( cd "$1" && find . -type f -printf "$fmt" | sort; find . -type f | sort | xargs -r md5sum ); }
listing() { "$1" l "$2" 2>/dev/null | tr '\r\b' '\n\n' | grep -vE '^(NanoZip|Intel|AMD|unknown)' | sed 's/ *$//' | grep -v '^$'; }
ok=0; bad=0
for sh in last0600 first0600 mid0600 two0600 all0600 mixed smallbig; do
  for c in cn cf cd co cc; do
    for sw in "" -np -nt; do
      arc="${sh}_${c}${sw}.nz"
      ( cd "src_$sh" && "$ORIG" a -$c -t1 $sw "../$arc" . </dev/null >/dev/null 2>&1 )
      for who in orig ours; do
        bin=$ORIG; [ $who = ours ] && bin=$OURS
        rm -rf "x_$who"; mkdir "x_$who"
        ( cd "x_$who" && env -i PATH=/usr/bin:/bin "$bin" x -y "../$arc" </dev/null >/dev/null 2>&1 )
      done
      if diff <(files x_orig "$sw") <(files x_ours "$sw") >/dev/null && diff <(listing "$ORIG" "$arc") <(listing "$OURS" "$arc") >/dev/null; then
        ok=$((ok+1))
      else
        bad=$((bad+1)); echo "DIFF: $arc"
        diff <(files x_orig "$sw") <(files x_ours "$sw") | head -2; diff <(listing "$ORIG" "$arc") <(listing "$OURS" "$arc") | head -2
      fi
    done
  done
done
echo "multiblock_attrs: $ok/$((ok+bad)) identical (files written + listing)"
[ "$bad" -eq 0 ]
