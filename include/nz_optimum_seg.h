// nz_optimum_seg.h -- the block SEGMENTER of the `-co`/`-cO`/`-cc` compressor.
//
// Before FUN_0808da10 analyses a block, FUN_0808d0b0 decides how long that
// block is: it reads from the stream into a 1 MB buffer until that buffer holds
// 0xff000 bytes (or the stream ends) and asks FUN_0808c740 where to cut. The cut is chosen by an order-1 entropy model over an 8-bit
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
#include <functional>

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
    // FUN_0808d040: fold the right half back into the left one, so that another
    // Prime/Split round measures everything gathered so far as its left side.
    // Used only when a block grew past the buffer and the driver went back for
    // more input; it does NOT touch the rolling context.
    void Fold();
    void Prime(const std::uint8_t* buf, std::uint32_t n);           // FUN_0808c5d0
    // FUN_0808c740: where to cut `buf` (n bytes, already primed), never below
    // `lower + 2`. Returns n when no split pays. CONSUMES the primed counts, so
    // one Split per Prime.
    std::uint32_t Split(const std::uint8_t* buf, std::uint32_t n, std::uint32_t lower);
};

// One fresh segmenter over `n` bytes, capped at `block_size`: what
// FUN_0808d0b0 does for a buffer that is filled in one go. Kept for the tests;
// the encoder goes through CoBlockFeeder below, which is the whole function.
std::uint32_t CoBlockLength(const std::uint8_t* buf, std::uint32_t n, std::uint32_t block_size);

// FUN_0808d0b0 itself: the 1 MB staging buffer that decides where the blocks
// fall. It is NOT a function of one piece of input -- the driver reads from the
// stream until it holds 0xff000 bytes (or the stream ends) and only then cuts,
// and whatever the split leaves over is pushed BACK into the buffer and starts
// the next block. A 1.1 MB file therefore becomes blocks of 691274 / 313809 /
// 89687 / 5230 where cutting each 1 MB piece on its own gives six blocks, none
// of them the original's after the first.
//
// The block is assembled in a buffer that lives as long as the stream and is
// never cleared, which is why the passes downstream may read past the block's
// last byte: what they find there is the tail the split pushed back (and, past
// that, the previous block's bytes). `Data()` hands out that buffer, `Len()`
// the block inside it, and the slack after `Len()` is readable up to
// `block_size + 0x2000`.
struct CoBlockFeeder {
    // The reference's read loop runs the audio/image detector and FORCES a
    // detected region into its own block (`param_1[0]`/`param_1[1]` in
    // FUN_0808d0b0), which is why a 64 KB .wav comes out as ONE block there and
    // the entropy split is never even called for it. The caller installs this to
    // answer "does a span start here, and how long is it"; 0 means no.
    std::function<std::uint32_t(const std::uint8_t*, std::uint32_t)> span_probe;
    // What the reader has handed over and the buffer has not taken yet.
    void Feed(const std::uint8_t* p, std::size_t n);
    // Cuts the next block. False means "nothing to code": either the stream has
    // to advance first (`final` false) or it is over.
    bool Next(std::uint32_t block_size, bool final);
    // What the staging buffer holds: the reader's next call asks for exactly
    // what is left of the 1 MB, which is what decides where a file's metadata
    // records fall between the blocks.
    std::size_t Held() const { return ring.size() + (pending.size() - pend_off); }
    const std::uint8_t* Data() const { return dst.data(); }
    std::uint32_t Len() const { return blk_len; }

    std::vector<std::uint8_t> ring;      // param_1[2]/[3], capacity 0x100000
    std::vector<std::uint8_t> pending;   // the reader's bytes the ring could not take
    std::size_t pend_off = 0;
    std::vector<std::uint8_t> dst;       // the block buffer, param_3
    CoSegmenter seg;
    std::uint32_t total = 0;             // uVar6, what the block holds so far
    std::uint32_t budget = 0;            // param_4, what is left of block_size
    std::uint32_t blk_len = 0;
    bool started = false;                // a block is half-gathered across calls
};

}  // namespace nzr::opt_enc
