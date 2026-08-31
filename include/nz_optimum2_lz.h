// Native linux32 `-cO` (nz_optimum2, method_p0==6) LZ/CM engine.
//
// Reverse-engineered from `work/linux32/nz`'s FUN_080a5d90 (the "large"
// subengine, selected the same way the sibling `-co` port's FUN_0809e600
// is -- see nz_optimum_lz.h). Full architecture doc, GDB scripts, golden
// vectors and exact real addresses:
//   work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md (session 5,
//   plus this port's own additional findings recorded in nz_optimum2_lz.cpp's
//   header comment -- the doc's session 5 left the literal-mixer's exact
//   per-context bit-indexing/seed arithmetic mapped to table roles/bases but
//   NOT reduced to explicit closed-form pseudocode; that reduction is this
//   port's own contribution, done via a fresh Ghidra decompile + disassembly
//   cross-check, not by re-deriving from the doc's summary alone).
//
// Shape: BACKBONE (range coder, rep0-3 array, literal-vs-match dispatch bit,
// rep-slot select, match length, match distance, bulk ring-buffer copy) is a
// byte-identical-formula scale-up of the sibling nz_optimum_lz.cpp engine
// (FUN_0809e600 / `-co`) -- confirmed by direct comparison of a fresh full
// decompile of FUN_080a5d90 against the already-shipped `-co` port: same
// length-clamp idiom, same 0xc0-byte per-slot distance table stride, same
// rep-offset semantics, two of its small lookup tables byte-identical to
// `-co`'s own (DAT_08173140==DAT_08172380, DAT_08173290==DAT_081724d0 --
// reused directly from nz_optimum_lz_tables.cpp, not re-embedded).
//
// What's materially different from `-co` is the LITERAL-BYTE CODER: an
// 8-input context-mixing bit-tree (vs `-co`'s 4-input) that reuses
// src/nz_cm.cpp's own modele[]/kDivideLookup/kLzModelLNext math verbatim for
// several of its 8 contexts, PLUS a rolling 3-byte-hash LZP-style secondary
// predictor with no analog in `-co` at all: a hash of the 3 bytes before the
// current position (`hash = (byte[pos-3]*0xc5 + word16(byte[pos-2..pos-1]))
// mod 65536` -- a 16-bit hash, NOT the ~18-bit/256K-entry table the
// architecture doc's session 5f guessed from decompile-reading alone; this
// port's own disassembly-level read found the hash is truncated to `ushort`
// before use, so the table only needs 65536 entries x 4 bytes = 256KB, not
// ~1MB) looked up in a "most recent output position this exact 3-byte
// context was seen" table, re-validated by direct byte comparison (2-3 bytes
// before both positions) before its "byte that followed" is folded into the
// packed matchmask/predicted-byte context several of the 8 mixer inputs key
// on. The dispatch bit also gets a SECOND chained APM/SSE refinement stage
// (vs `-co`'s one).
//
// The engine's per-block output flows through the same kind of persistent
// circular ring/dictionary window as `-co` (capacity from the same
// NzOptimumLzWindowSizeFromP1 formula in nz_optimum_lz.h/.cpp -- reused
// directly, not re-derived) that PERSISTS, together with every adaptive
// probability table (and the ~17MB per-instance "large" object -- see
// nz_optimum2_lz_tables.h for how its ~0x1083000-byte cold state is
// captured/embedded), across every sequential decr_param==1 block decoded by
// the same container/stream -- so callers must keep ONE
// NzOptimum2LzDecoder instance alive for an entire stream's sequence of
// blocks, not construct a fresh one per block.
//
// Scope of this port: SINGLE-CONTAINER only (archive header flag 0x06, one
// stream_tag's worth of blocks). Parallel-container `-cO` (flag 0x0f) and
// decr_param==0 (BWT) blocks are explicitly OUT OF SCOPE for this port (they
// continue to decline cleanly to the bridge), matching this project's own
// incremental-shipping precedent for `-co` (ship one shape byte-exact,
// extend later).
//
// STATUS: WIRED into sfx_archive.cpp / TryDecodeLegacyOptimum for
// method_p0==6u (checksum-gated exactly like the sibling -co path). Passes
// both golden vectors byte-exact (tests/test_optimum2_lz.cpp): aaa200_cO
// (trivial cold-start: one literal + one rep0 match) and hientropy_cO
// (repetitive text framing a 200000-byte random segment, 218000 bytes total
// -- exercises long literal runs with fully-trained mixer weights, rep-slot
// reuse, and all three distance-tier footer-bit schedules including tier3).
//
// This engine went through TWO debugging rounds. Round 1 found 3 bugs (see
// nz_optimum2_lz.cpp's header comment): a units->bytes conversion slip in
// the dispatch-bit's 2nd APM stage, a missing counter-based addressing
// scheme in rep-slot selection, and a wrong base address in the length
// decoder's "extra bits" loop -- these got aaa200_cO passing but
// hientropy_cO still diverged partway through an extended literal run.
// Round 2 (fresh GDB ground-truth comparison, bit-by-bit rather than
// byte-by-byte) found 2 MORE bugs, both exactly matching the "right on
// cold/first update, wrong once the model has adapted" shape: (1) the
// literal-mixer's Context 1 nibble-packed tree update used the wrong
// operand (the 0-255 STATE byte instead of the 0-15 NIBBLE index) in its
// delta formula, corrupting the packed table in a way invisible until a
// later read pulled a wrong nibble back out; (2) the distance decoder's
// tier3 (slot>6) footer-bit table used a base address 0x80 bytes off
// (confusing a scratch-counter field's own address with the actual
// cell-address base), invisible until the first real slot>6 match (only
// reachable with a large repetitive fixture, not aaa200_cO's trivial single
// match). Both were found by tracing bit-for-bit against live GDB state
// (matching weight/context values exactly except one, or matching slot but
// not the reconstructed distance) rather than reasoning from the decompile
// alone -- see nz_optimum2_lz.cpp's header comment and the fix sites' own
// comments for the exact ground-truth evidence.
//
// See work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md for the
// prior sessions' RE notes this port built on.
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace nzr {
namespace optimum2 {

// Persistent per-stream decode state. Construct ONE instance per container
// stream (not per block) and feed it every decr_param==1 block belonging to
// that stream, in order. `window_capacity` uses the exact same
// nzr::optimum::NzOptimumLzWindowSizeFromP1(method_p1) formula the sibling
// `-co` engine uses (confirmed shared -- both are the same `nz_cm`-family
// dispatcher's subengine, differing only in which vtable/parameters the
// container selected).
class NzOptimum2LzDecoder {
public:
    explicit NzOptimum2LzDecoder(std::uint32_t window_capacity);

    // Decode one block. `in`/`in_len` is this block's compressed payload
    // (the range-coder bitstream, starting at its very first byte -- no
    // extra header inside this call). Produces exactly `out_size` bytes into
    // `out` (caller-owned, >= out_size bytes) on success. Returns false on
    // ANY detected inconsistency (malformed bitstream, a match referencing
    // outside the valid window, a length that doesn't fit remaining space,
    // truncated input, ...) -- never partially trusts or partially emits
    // output on failure.
    bool DecodeBlock(const std::uint8_t* in, std::uint32_t in_len,
                      std::uint8_t* out, std::uint32_t out_size);

    // Feed already-known output bytes into the window WITHOUT decoding, so a
    // later block's matches can reference them. Needed because in the original
    // the window is the shared accumulated-block buffer, advanced by every
    // block that writes into it (reference: `mem->data += size`), not just by
    // LZ blocks -- a decr_param==0 (BWT) block's post-param14/15 output lands
    // there too. This port's ring is otherwise only ever written by
    // DecodeBlock, so without this a later LZ match that reaches back into a
    // BWT block's output reads stale ring bytes and the block fails.
    //
    // Note the window carries each block's PRE-post-filter bytes: call this
    // before param2/param1/text-transform/dece run. Audio (decr_param==2)
    // blocks must NOT be fed -- the reference returns before touching the
    // window for those.
    void FeedWindow(const std::uint8_t* data, std::uint32_t len);


private:
    struct Ring {
        std::uint32_t capacity = 0;
        std::vector<std::uint8_t> storage;  // capacity + 512 bytes; logical
                                             // position p in [-256, capacity+256)
                                             // maps to storage[p + 256].
        std::uint32_t cursor = 0;           // next logical write position, 0..capacity
        bool scrolled_once = false;

        std::uint8_t* Base() { return storage.data() + 256; }
        const std::uint8_t* Base() const { return storage.data() + 256; }

        std::uint32_t EnsureHeadroom(std::uint32_t needed);
    };

    Ring ring_;
    std::vector<std::uint8_t> mem_;  // the "large" subengine's ~0x1083000-byte state
};

}  // namespace optimum2
}  // namespace nzr
