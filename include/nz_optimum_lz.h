// Native linux32 `-co` (nz_optimum1, method_p0==5) LZ/CM engine.
//
// Reverse-engineered from `work/linux32/nz`'s FUN_0809e600 ("compact" subengine,
// selected by the `nz_cm`-family dispatcher FUN_080aa850's mode==1 cold-start path
// whenever the per-block flag byte at obj+0x8b5ca is nonzero -- confirmed via GDB
// to be the ONLY path any real `-co` archive fixture takes, 48B through 15MB,
// across 4 independent RE sessions). Full architecture doc, GDB scripts, golden
// vectors and exact real addresses:
//   work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md
//
// Shape: a classic 32-bit binary range decoder (identical formula shape to
// nz_cm.cpp's ArithmeticDecoder, but NOT the same object -- this engine keeps its
// own state) drives, per output byte position:
//   - one range-coded "is-literal" dispatch bit (context keyed by a 4-bit
//     "matchmask" -- do the last 1..4 output bytes match what continuing a
//     rep0-distance copy would produce -- and the byte currently sitting at the
//     rep0-distance offset);
//   - if literal: a full byte via a 4-input context-mixing bit-tree (contexts:
//     order-1 on the previous byte, order-1 on the byte two positions back, and
//     two adaptive bit-tree walks seeded from the dispatch bit's own context);
//   - if match: a rep0-3 slot selector (cheap bit = "brand new distance", LZMA's
//     OPPOSITE polarity), then a length (Elias-gamma-shaped, implicit leading
//     bit + adaptive/raw extra bits), then -- only for a brand-new distance -- a
//     5-bit distance-slot plus slot-dependent footer bits (small direct table for
//     slot<3, a 4-bit "align" table for slot 3-5, plus further adaptive bits for
//     slot>=6), then a bulk ring-buffer copy.
//
// The engine's per-block output flows through a real, possibly-smaller-than-
// output CIRCULAR ring/dictionary window (capacity determined once per archive
// stream from the container's `method_p1` byte -- see
// NzOptimumLzWindowSizeFromP1 below, empirically confirmed against 20+ real
// archives spanning both the "linear" and "exponential" regimes of that byte's
// mantissa+exponent encoding) that PERSISTS, together with every adaptive
// probability table, across every sequential decr_param==1 block decoded by the
// same container/stream (only the range coder and the 4 rep-offsets reset at the
// start of each block) -- so callers must keep ONE NzOptimumLzDecoder instance
// alive for an entire stream's sequence of blocks, not construct a fresh one per
// block.
//
// Scope of this port: both the SINGLE-CONTAINER case (archive header flag
// 0x05) and the PARALLEL-CONTAINER case (flag 0x0f, >8MB, used by the
// multi-threaded encoder) are wired up. Confirmed empirically: a parallel
// stream's type-0 chunk record holds the exact same "sequence of block
// records" body the single-container path decodes after its own leading
// stream_tag varint (no extra stream_tag inside the chunk), and each
// parallel stream gets a FRESH NzOptimumLzDecoder (same "each encoder
// thread owned its own subengine instance" pattern already established for
// -cd/-cD's parallel branch), all sharing the one archive-wide window
// capacity derived from method_p1. See sfx_archive.cpp's
// DecodeOptimumBlockSequence (the extracted, reusable block-record decode
// loop) and the -co parallel branch inside TryParseLegacyCnArchive that
// calls it per stream, for both engines (method_p0==5 -co and method_p0==6 -cO).
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace nzr {
namespace optimum {

// Derive the -co/-cO/-cc shared window/dictionary-size value from the
// container's `method_p1` byte. This is the exact same "mantissa (4 bits) +
// exponent (4 bits)" encoding sfx_archive.cpp's existing `cm_window_size`
// computation already implements for `-cc` (method 0x4b, p0==7); this session
// confirmed empirically (live GDB against 20+ freshly-generated `-co` archives,
// sizes 70000..5000000 bytes, spanning both the linear s==0 regime and the
// exponential s>=1 regime) that `-co` derives its ring capacity from the exact
// same byte using the exact same formula:
//   xp1 = method_p1 + 1
//   m   = xp1 & 0xf
//   s   = xp1 >> 4
//   if (s) m = (m + 16) << (s - 1)
//   window_size = m << 16
std::uint32_t NzOptimumLzWindowSizeFromP1(std::uint8_t method_p1);

// Persistent per-stream decode state. Construct ONE instance per container
// stream (not per block) and feed it every decr_param==1 block belonging to
// that stream, in order.
class NzOptimumLzDecoder {
public:
    explicit NzOptimumLzDecoder(std::uint32_t window_capacity);

    // Decode one block. `in`/`in_len` is this block's compressed payload
    // (the range-coder bitstream, starting at its very first byte -- no extra
    // header inside this call). Produces exactly `out_size` bytes into `out`
    // (caller-owned, >= out_size bytes) on success. Returns false on ANY
    // detected inconsistency (malformed bitstream, a match referencing outside
    // the valid window, a length that doesn't fit remaining space, truncated
    // input, ...) -- never partially trusts or partially emits output on
    // failure (this function does not touch `out` at all before it is certain
    // of success, except through the internal ring, which is discarded/rolled
    // back on failure).
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

    // Cold-start the adaptive model again, keeping the window. The original
    // does this after a STORED LZ block (decr_param=1, param6=0): the next LZ
    // block of the stream decodes from a cold model. Measured on a 130 MB
    // `-co -p16` archive whose one stream with a stored block between two LZ
    // blocks decoded garbage from byte 0 with a byte-exact ring.
    void ResetModel();

    // The ring's capacity. param15's absolute offsets are ring positions, so the
    // post-filter needs it to map one back to the accumulated stream.
    std::uint32_t WindowCapacity() const;


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

        // FUN_080bd380: ensure >= `needed` bytes of headroom before `cursor`
        // runs into the ring's capacity; if not, wrap `cursor` back to 0 and
        // refresh the 256-byte "prefix mirror" (positions [-256,0), mirroring
        // the ring's current tail [capacity-256,capacity)) so short backward
        // context reads just after a wrap still see correct recent history.
        // Returns the (possibly just-reset) cursor.
        std::uint32_t EnsureHeadroom(std::uint32_t needed);
    };

    Ring ring_;
    std::vector<std::uint8_t> mem_;  // the "compact" subengine's 0x3f700-byte state
};

}  // namespace optimum
}  // namespace nzr
