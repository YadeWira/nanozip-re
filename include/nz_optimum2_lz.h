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
// Scope: single-container (flag 0x06) AND parallel-container (flag 0x0f)
// archives, decr_param==0 (BWT) blocks included -- all native since 2026-09.
// (The note that once limited this to single containers is historical.)
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
#include <functional>
#include <memory>
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
// One parse decision of the large LZ engine -- the same shape the sibling
// `-co` engine's OptimumDecision has (slot group 0 = a new distance, 1..4 =
// rep0..rep3), kept as its own type so the two engines stay independent.
struct Optimum2Decision {
    std::uint8_t is_literal = 0;
    std::uint8_t byte = 0;
    std::uint8_t sg = 0;
    std::uint32_t len = 0;
    std::uint32_t dist = 0;
};

class NzOptimum2LzDecoder {
public:
    explicit NzOptimum2LzDecoder(std::uint32_t window_capacity);

    // The encoder's side of the same block loop: codes `dec` with the models in
    // their current state (which advances exactly as a decode would) and
    // range-codes the result into `payload`. The window receives the block's
    // bytes as in a decode.
    bool EncodeBlock(const Optimum2Decision* dec, std::size_t ndec, std::uint32_t out_size,
                     std::vector<std::uint8_t>& payload);
    // Decode-side: keep the decisions of the last DecodeBlock (for the recode check).
    void RecordDecisions(bool on) { record_ = on; }
    const std::vector<Optimum2Decision>& LastDecisions() const { return decisions_; }

    // The -cO optimal parser (FUN_08083e90, the DAT_08183620 == 0 / -t1 path --
    // the structural twin of the `-co` engine's FUN_0806f8e0, differing in its
    // table addresses, a 0x1040-node horizon instead of 0x120, a 0x200-byte
    // immediate-match threshold instead of 0x20, a match-finder chain depth of
    // 0x100 instead of 0x10, and a literal priced from the 8-input mixer with no
    // price cache at all). Turns one block's bytes into the decision list the
    // original would pick, using the models in their CURRENT state. Feed the
    // result to EncodeBlock to get the payload.
    bool ParseBlock(const std::uint8_t* data, std::uint32_t size,
                    std::vector<Optimum2Decision>& out);

    // Parse AND code one block in the original's interleaved order: the parser
    // hands the coder one flush of decisions at a time and the coder advances the
    // models before the next flush is parsed, so prices track the model as it
    // adapts inside the block. This is the real encoder entry point.
    bool EncodeBlockParsed(const std::uint8_t* data, std::uint32_t size,
                           std::vector<std::uint8_t>& payload,
                           std::vector<Optimum2Decision>* out_decisions);

    // Build the match finder NOW, before any block is parsed -- see the `-co`
    // sibling: a plain decode never builds one, so an encoder whose first block
    // is a BWT block would otherwise feed the window without feeding the hash.
    void EnableParser();

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

private:
    // The block loop, written once and instantiated over the bit source: a
    // decoding IO reads each bit from the range decoder, an encoding one codes
    // the bit it was handed. Everything between the bit calls -- every model
    // read, update and symbol assembly -- is therefore literally the same code
    // in both directions. See nz_optimum_lz.cpp for the sibling that does this.
    template <class IO>
    bool RunBlock(IO& io, const Optimum2Decision* dec, std::size_t ndec,
                  std::uint8_t* out, std::uint32_t out_size);

    struct ParserState;
    std::shared_ptr<ParserState> parser_;
    // when set, RunBlock pulls the next decision from here instead of a list
    std::function<bool(Optimum2Decision&)> feed_;
    // installed by the encoding pass; called at the top of every chunk
    std::function<void(std::uint32_t, std::uint32_t, std::uint32_t, bool)> chunk_begin_;
    // Stage one chunk for the parser at the window position the coder reads it
    // from: the engine splits a block into chunks of at most 0x8000 and the
    // original parses once per chunk, so the two must step together.
    void BeginChunk(std::uint32_t off, std::uint32_t len, std::uint32_t ring_pos, bool reset_reps);
    bool ChunkExhausted() const;
    // The window feed also pushes what it appended into the match finder, which is
    // how a later block's matches can start inside a stored or filtered block.
    void FeedFinder(std::uint32_t cursor_before, std::uint32_t len);
    bool ParseNextFlush(std::vector<Optimum2Decision>& out);
    void BeginParse(const std::uint8_t* data, std::uint32_t size);
public:

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

    // Cold-start the adaptive model again, keeping the window (see the -co sibling).
    void ResetModel();

    // What the encoder driver needs to read off the window, the same five the
    // `-co` sibling exposes: how far the ring is filled, whether it has ever
    // scrolled, whether a model reset is still waiting for its first feed (which
    // is what gates param15), and the long-range index param15 searches.
    std::uint32_t WindowFill() const { return ring_.cursor; }
    bool WindowScrolled() const { return ring_.scrolled_once; }
    bool WindowResetPending() const { return window_reset_pending_; }
    // The match-finder tree, which the reference also uses as param14's two
    // hash tables (quirk 72): 3 MB shared between the two passes, cleared by
    // neither. Lent to the param14 encoder so it starts where the reference's
    // does.
    std::uint32_t* ParserArena();
    std::size_t ParserArenaWords() const;
    const std::uint32_t* LongRangeTable() const;
    std::uint32_t LongRangeMask() const;

    // The ring's capacity. param15's absolute offsets are ring positions, so the
    // post-filter needs it to map one back to the accumulated stream.
    std::uint32_t WindowCapacity() const;
    // The ring's bytes, position 0 first, capacity + 256 bytes of slack behind
    // it. param15 names its sources as RING positions (the encoder's long-range
    // index speaks in them, 256-aligned), and the ring is the only buffer whose
    // positions follow the original's cursor -- a flat accumulation of the same
    // bytes does not, because EnsureHeadroom abandons up to 32 KB at the ring's
    // end whenever a chunk does not fit before it.
    const std::uint8_t* WindowBase() const;


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
    // The match finder's tree is sized from the archive's BLOCK size (the `-co`
    // sibling's note applies verbatim).
    std::uint32_t blocksize_ = 0x100000u;
    std::vector<Optimum2Decision> decisions_;
    bool record_ = false;
    bool window_reset_pending_ = false;   // 1 after a model reset, 0 after a feed
    std::vector<std::uint8_t> mem_;  // the "large" subengine's ~0x1083000-byte state
};

}  // namespace optimum2
}  // namespace nzr
