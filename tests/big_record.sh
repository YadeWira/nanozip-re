#!/bin/sh
# A record whose payload is 256 MB or more has a tag of 2^32 or more, because the
# tag is (size << 4) | type. Narrowing that tag to 32 bits made the header walk
# read a 256 MB data record as type 0 size 0 and then parse the payload as
# records; every archive holding more than 256 MB in one record was refused with
# "Data corrupted while reading headers!". Reported by a user on a 4.5 GB archive
# of one video file.
#
# The test needs the original binary to build the fixture and about 1.2 GB of
# scratch, so it is not part of the default suite run. Both sides of the boundary
# are checked, and every codec, since the walk is shared.
#
#   tests/big_record.sh [workdir]
set -e
BIN=${BIN:-bin/nz_recon}
ORIG=${ORIG:-../linux32/nz}
W=${1:-/tmp/nzre_bigrec}
[ -x "$BIN" ] || { echo "no $BIN -- build first"; exit 1; }
[ -x "$ORIG" ] || { echo "skip: the original ($ORIG) is needed to build the fixture"; exit 0; }
rm -rf "$W"; mkdir -p "$W"

# incompressible, so the archive keeps the size the record needs
openssl enc -aes-256-ctr -pass pass:nzre-big-record -nosalt </dev/zero 2>/dev/null \
  | head -c 268435456 > "$W/over.bin"
head -c 268435455 "$W/over.bin" > "$W/under.bin"

ok=0; bad=0
for side in under over; do
  for c in cn cf cF cd cD; do
    a="$W/$side-$c.nz"
    "$ORIG" a -$c -t1 -y "$a" "$W/$side.bin" >/dev/null 2>&1
    if "$BIN" t "$a" 2>&1 | tr '\r' '\n' | grep -q "Decompressed"; then
      ok=$((ok+1))
    else
      bad=$((bad+1)); echo "FAIL $side -$c"
    fi
    rm -f "$a"
  done
done
rm -rf "$W"
echo "big_record: $ok ok, $bad bad"
[ "$bad" = 0 ]
