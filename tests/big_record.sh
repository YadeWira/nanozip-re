#!/bin/sh
# A record whose payload is 256 MB or more has a tag of 2^32 or more, because the
# tag is (size << 4) | type. Narrowing that tag to 32 bits made the header walk
# read a 256 MB data record as type 0 size 0 and then parse the payload as
# records; every archive holding more than 256 MB in one record was refused with
# "Data corrupted while reading headers!". Reported by a user on a 4.5 GB archive
# of one video file.
#
# Measured blast radius: only the store writes a record that big. The compressing
# codecs cut a record per block, so their records stay near the block size however
# large the archive gets -- verified by feeding the 0.12.0 binary a 300 MB archive
# of each codec, where only -cn failed. Both sides of the boundary are still
# checked across five codecs, since the walk is shared and a future codec could
# write one large record.
#
# On a 32-BIT build this test is limited to what size_t can address: an archive
# above 4 GB cannot be parsed at all, because the reader maps it whole. That is a
# separate, structural gap -- the original streams instead of mapping.
#
# The test needs the original binary to build the fixture and about 1.2 GB of
# scratch, so it is not part of the default suite run.
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
