// nz_optimum_seg.h -- the block SEGMENTER of the `-co`/`-cO`/`-cc` compressor.
//
// Before FUN_0808da10 analyses a block, FUN_0808d0b0 decides how long that
// block is: it reads up to 1 MB into an internal buffer and asks FUN_0808c740
// where to cut. The cut is chosen by an order-1 entropy model over an 8-bit
// rolling context -- the split position that minimises the cost of the two
// halves, taken only when it beats the unsplit cost by more than a
// thirty-second plus 1 KB. That is why a 68 KB HTML file becomes two blocks
// while a 148 KB one stays whole.
//
// Decompiles: FUN_0808c500 (the object), FUN_0808c580 (reset), FUN_0808c5d0
// (prime + cost), FUN_0808c740 (the walk), FUN_0808c410 (the two cost tables)
// in ~/.cache/nzre_tools/encode/decomp/param21_segmenter.c and the disassembly
// at 0x0808c410.
#pragma once
#include <cstdint>
#include <vector>

namespace nzr::opt_enc {

// FUN_0808c500's object. `counts` is the 0x80800-byte table the original keeps:
// per-context totals for each half, then a 256x256 cell count for each half.
struct CoSegmenter {
    std::vector<std::uint32_t> counts;    // +0x04, 0x20200 entries
    std::vector<std::uint32_t> snapshot;  // +0x08, the copy Prime leaves behind
    std::int64_t cost = 0;                // +0x0c, the whole sample's cost
    std::int64_t prev_cost = 0;           // +0x14, what the previous Prime left
    std::uint32_t ctx = 0;                // +0x1c, the rolling context

    CoSegmenter();
    void Reset();                                                   // FUN_0808c580
    void Prime(const std::uint8_t* buf, std::uint32_t n);           // FUN_0808c5d0
    // FUN_0808c740: where to cut `buf` (n bytes, already primed), never below
    // `lower + 2`. Returns n when no split pays. CONSUMES the primed counts, so
    // one Split per Prime.
    std::uint32_t Split(const std::uint8_t* buf, std::uint32_t n, std::uint32_t lower);
};

// The block length FUN_0808d0b0 hands the block driver for the next `n` bytes
// of input, capped at `block_size`: one fresh segmenter over what it buffered.
// (The audio/image detector's forced lengths and the multi-round path only
// matter for inputs above 1 MB or with a detected region; neither is written.)
std::uint32_t CoBlockLength(const std::uint8_t* buf, std::uint32_t n, std::uint32_t block_size);

}  // namespace nzr::opt_enc
