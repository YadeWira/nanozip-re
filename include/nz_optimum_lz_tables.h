// Internal constant-table accessors for the `-co` (nz_optimum1) LZ/CM engine.
// See nz_optimum_lz_tables.cpp for what these tables are and how they were
// captured; see nz_optimum_lz.h for the public decoder API.
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace nzr {
namespace optimum {

// The "compact" subengine's full 0x3f700-byte per-instance memory, in its
// as-freshly-constructed (never decoded a bit yet) state. Callers copy this
// into a fresh mutable buffer at NzOptimumLzDecoder construction time.
const std::vector<std::uint8_t>& OptimumColdState();

// DAT_08172380: 256-byte lookup, indexed by the running 8-bit literal/match
// decision history byte.
const std::uint8_t* OptimumDat08172380();

// DAT_081724d0: 16-byte lookup, indexed by min(length_class, 15).
const std::uint8_t* OptimumDat081724d0();

}  // namespace optimum
}  // namespace nzr
