// Internal constant-table accessors for the `-cO` (nz_optimum2) LZ/CM engine.
// See nz_optimum2_lz_tables.cpp for what these tables are and how they were
// captured; see nz_optimum2_lz.h for the public decoder API.
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace nzr {
namespace optimum2 {

// The "large" subengine's full per-instance memory (0x1083000 bytes -- the
// real object is ~17MB, dominated by the order-2 "Context P" bit-history
// table (16MB) and the LZP-predictor hash table (256KB)), in its
// as-freshly-constructed (never decoded a bit yet) state. Dumped live via GDB
// at the very first instruction of FUN_080a5d90 against a real -cO archive,
// then RLE-compressed (the real cold state is >99.7% long runs of a handful
// of repeated byte values -- 48651 runs across 17313792 bytes -- so a trivial
// (byte, varint run-length) encoding shrinks it to ~97KB before base64,
// versus needing to embed the raw 17MB/23MB-base64 blob the naive "port -co's
// approach verbatim" plan would have required). Callers copy the decoded
// result into a fresh mutable buffer at NzOptimum2LzDecoder construction time.
const std::vector<std::uint8_t>& Optimum2ColdState();

// DAT_081732c0: the literal-mixer's / dispatch-bit's second SSE/APM stage
// seed table, indexed by (mixed_probability >> 4) i.e. 0..255. Captured via
// GDB (256 x uint16, little-endian) -- NOT independently confirmed identical
// to nz_cm.cpp's kModelLutLookup (unlike every other DAT_ table this engine
// uses, which WERE confirmed byte-identical to already-ported constants --
// see nz_optimum2_lz.cpp's header comment) -- embedded as its own captured
// constant since the values themselves are what matters for a byte-exact
// port, not their relationship to another table.
const std::uint16_t* Optimum2Dat081732c0();

}  // namespace optimum2
}  // namespace nzr
