#!/bin/sh
# An archive this build cannot hold in one piece must be REPORTED, not guessed at,
# and walking a hostile one must not cost unbounded memory.
#
# The reader maps (or reads) the whole archive and indexes it with size_t, so a
# 32-bit build cannot address one above 4 GB: the length wrapped, the header walk
# read a fraction of the file as if it were all of it, and a sound archive came
# back as "Archive corrupted. Error decoding (code 25600)" -- which is how a
# user's 4.5 GB archive of one video file first surfaced, reproduced byte for byte
# with a 4.4 GB -co archive. Below 4 GB but past a 32-bit address space, mmap
# fails and the read-it-in fallback threw std::length_error straight past main:
# the process died with a C++ terminate message instead of reporting anything.
# Both now print the original's own "Out of memory!".
#
# The third case is a file of zeros: a record tag of 0x00 reads as type 0 size 0,
# so the walk advances one byte per record and used to collect one table entry per
# byte -- on a 4.3 GB file that is tens of GB and the OOM killer takes the process
# before it can call the archive corrupt.
#
# The original streams the archive and has none of these limits; ours will when
# the reader streams too. Until then this test pins the honest reports.
#
#   tests/huge_archive.sh [workdir]
#
# The fixtures are SPARSE, so the disk cost is nil however large they look.
# BIN32=<a 32-bit build> adds the two cases only a 32-bit build can reach.
set -e
BIN=${BIN:-bin/nz-re}
W=${1:-/tmp/nzre_huge}
[ -x "$BIN" ] || { echo "no $BIN -- build first"; exit 1; }
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
SEED=${SEED:-$HOME/.cache/nzre_tools/release_verify_pkg/arc/bmp_c.nz}
[ -f "$SEED" ] || { echo "skip: no seed archive at $SEED"; exit 0; }
rm -rf "$W"; mkdir -p "$W"

ok=0; bad=0
check() {   # check <label> <expected-substring> <command...>
    label=$1; want=$2; shift 2
    got=$("$@" 2>&1 | tr '\r' '\n' | grep -vE '^[[:space:]]*$' | tail -3 || true)
    if printf '%s' "$got" | grep -aq "$want"; then ok=$((ok+1)); else
        bad=$((bad+1)); echo "FAIL $label: wanted '$want', got:"; printf '%s\n' "$got" | sed 's/^/    /'
    fi
}

# A real archive's first bytes, then a sparse tail: past size_t either way, and
# the guard measures the length before reading a byte of it.
head -c 4096 "$SEED" > "$W/over4g.nz"; truncate -s 4300000000 "$W/over4g.nz"
head -c 4096 "$SEED" > "$W/over2g.nz"; truncate -s 3000000000 "$W/over2g.nz"

if [ -n "$BIN32" ] && [ -x "$BIN32" ]; then
    BIN32=$(cd "$(dirname "$BIN32")" && pwd)/$(basename "$BIN32")
    check "32-bit past size_t"      "Out of memory!" "$BIN32" t "$W/over4g.nz"
    check "32-bit past its address space" "Out of memory!" "$BIN32" t "$W/over2g.nz"
else
    echo "note: no BIN32, skipping the two 32-bit cases"
fi

# A 64-bit build addresses it, so the archive is merely bad, not unreadable: the
# report must come from the header walk, and the walk must stay within its budget.
check "64-bit walks 4.3 GB of zeros" "corrupted while reading headers" "$BIN" t "$W/over4g.nz"

# An archive whose ENTRY produces more than 4 GB. Three post-filter sites bounded
# their expansion by (uint32)total - (uint32)produced, and that subtraction wraps
# once an entry passes 4 GB: the wrapped cap came out SMALLER than the block being
# expanded, the block-RLE refuses a capacity under its own input, and a sound
# archive was called corrupt (code 100) at the first block past the wrap. Nothing
# smaller reaches it -- the whole 3037-file sweep never produced a 4 GB entry --
# so the case is opt-in and wants a real archive:
#
#   NZ_BIG_OUT=/path/to/one.nz tests/huge_archive.sh
#
# The fixture used to find it was the 4 617 294 329-byte -cO archive of a 4600 MB
# MPG sent in by the reporter; testing it takes about 38 minutes and 17 GB of RAM.
if [ -n "$NZ_BIG_OUT" ] && [ -f "$NZ_BIG_OUT" ]; then
    check "64-bit decodes an entry over 4 GB" "Decompressed" "$BIN" t "$NZ_BIG_OUT"
else
    echo "note: no NZ_BIG_OUT, skipping the over-4-GB-output case"
fi

# param15 offsets are LZ-ring positions. A -co archive whose worker stream wraps its
# 8 MB ring with a gap (EnsureHeadroom abandoning the ring's tail when a 32 KB chunk
# does not fit) and then carries a param15 block reproduced a wrong source 18 522
# bytes late -- status 105 -- while the offsets were resolved against a flat copy of
# the stream. The smallest input that showed it is 180 MB of tiled corpus material
# (`mkmix.sh` in the agent workspace, first 180 000 000 bytes, `-co` by the original),
# too large to ship; opt in with the archive:
#
#   NZ_P15_REPRO=/path/to/s_180000000.nz tests/huge_archive.sh
if [ -n "$NZ_P15_REPRO" ] && [ -f "$NZ_P15_REPRO" ]; then
    check "param15 across a ring gap" "Decompressed" "$BIN" t "$NZ_P15_REPRO"
else
    echo "note: no NZ_P15_REPRO, skipping the param15 ring-gap case"
fi

rm -rf "$W"
echo "huge_archive: $ok ok, $bad bad"
[ "$bad" = 0 ]
