// nz_lzpf_encoder.h -- the original's lzpf compressor (-cf variant A, -cF
// variant B), ported from linux32/nz: FUN_0805a790 (block driver),
// FUN_0805a190 (the LZ parser), FUN_08059cb0 (block header), FUN_0805cbe0 /
// FUN_0805c980 / FUN_08074b10 / FUN_080757d0 (the Huffman "arith" side stream).
// Decompiles: ~/.cache/nzre_tools/encode/decomp/lzpf_encoder_*.c.
//
// Everything here reproduces the original's decisions byte for byte: the
// greedy LZP-style parse over a shared hash table (the decoder rebuilds the
// same table, so a different candidate would not merely compress worse, it
// would not decode), the literal/raw/side fallbacks, and the Huffman code
// lengths with the original's length limiting and tie-breaking.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace nzr::lzpf_enc {

// The audio probe (FUN_08080e50's 0x28-byte struct at ctx+0x487c0): what the
// format detector decided and the running audio span.
struct AudioProbe {
    std::uint8_t signed_ = 0;   // +0
    std::uint8_t le = 0;        // +1 little-endian (only meaningful above 8 bits)
    std::uint8_t width = 0;     // +2 bytes per sample
    std::uint8_t chans = 0;     // +3 0 mono, 1 L/R, 2 side/mid
    std::uint16_t prefix = 0;   // +4 header bytes / alignment carry copied verbatim
    std::uint8_t hdr = 0;       // +6 a RIFF/AIFF header was recognised
    std::uint32_t code = 0;     // +8 the detector's candidate code
    std::uint32_t conf = 0;     // +0xc its confidence
    std::uint32_t lz_cost = 0;  // +0x10
    std::uint32_t pf_cost = 0;  // +0x14
    std::uint8_t b18 = 0;       // +0x18
    std::uint32_t bytes_done = 0;   // +0x1c bytes processed since the header
    std::uint32_t audio_end = 0;    // +0x20 where the header says the audio ends
    std::uint8_t b24 = 0;       // +0x24
};

// One predictor plane of the prefilter object (0x1c10 bytes each in the original;
// the decoder's LpcPredictor seen from the encoder's side).
struct LpcPlane {
    std::uint32_t order = 8, taps = 8, shift = 13;
    std::int32_t pred = 0;
    std::int16_t hist[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    std::int16_t sign_hist[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    std::int16_t factors[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    void Configure(std::uint32_t o) { order = o; taps = o >= 8u ? 8u : 4u; Reset(); }
    void Reset() { pred = 0; shift = 13u; for (int k = 0; k < 8; ++k) { hist[k] = 0; sign_hist[k] = 0; factors[k] = 0; } }
    void Forward(std::int32_t* v, std::uint32_t n);   // FUN_08053220: samples -> residuals
    void StepForward(std::int32_t& v, bool adapt);
};

// The prefilter object (FUN_080b1600(obj, order01, 0, 1, 0)): six planes, planes 0
// and 1 of order01 (4 for -cf, 8 for -cF), the rest 8; one stage; no LMS.
struct AudioModel {
    LpcPlane plane[6];
    void Configure(std::uint32_t order01) { plane[0].Configure(order01); plane[1].Configure(order01); for (int i = 2; i < 6; ++i) plane[i].Configure(8u); }
    void ResetAll() { for (auto& p : plane) p.Reset(); }   // FUN_080b1950
};

// FUN_080899d0's 0x28-byte struct: what the image detector found.
struct ImageProbe {
    std::uint32_t width = 0, height = 0, prefix = 0, nch = 1, bps = 1, w5 = 0;
};
bool ImageDetect(ImageProbe& pr, const std::uint8_t* block, std::uint32_t len);

// The image model object (FUN_080b5f50 layout, the fields the lzpf flavour --
// flags 0 -- touches) plus the one piece of the original's STACK the block
// encoder depends on: FUN_08089a80's 65536-entry match table is an
// uninitialised local that doubles as the residual planes, so the previous
// block's residuals (and the previous gate's positions) are what the next
// block's gate reads. Zero on the thread's first call; kept here across blocks
// and NOT touched by Reset() (FUN_080b6170 does not know about the stack).
struct ImageEncModel {
    std::vector<std::int16_t> ring1;   // obj+4: one short per sample, index & 0x7fff (0x8003 shorts)
    std::uint32_t r1 = 0;              // obj+0x52914
    std::uint32_t width = 1;           // obj+0x5291a (u16)
    std::uint32_t height = 0;          // obj+0x5291c (u16)
    std::uint32_t rows_done = 0;       // obj+0x5291e (u16)
    std::uint32_t col = 0;             // obj+0x52918 (u16): pixels of the row a block ended inside
    std::uint8_t align = 0, nch = 1, grp = 1, bps = 1, endian = 0;   // obj+0x52921/22/23/24/25
    std::vector<std::uint32_t> stack_tbl;
    ImageEncModel() : ring1(0x8003u, 0), stack_tbl(65543u, 0) {}
    void Reset() {                      // FUN_080b6170
        width = 1; col = 0; rows_done = 0; height = 0; align = 0; grp = 1; nch = 1; bps = 1; endian = 0;
        r1 = 0; std::fill(ring1.begin(), ring1.end(), 0);
    }
};

// FUN_08089a80 for the lzpf configuration (flags 0). Appends the block's bytes
// to `out`; returns their count, or 0 when the image model declines (the caller
// then stores a literal). `pr` is this block's detect (width 0 = none: a
// continuation block); `align` is the output address of the block payload & 3.
std::size_t ImageEncodeBlock(ImageEncModel& m, const ImageProbe& pr, const std::uint8_t* block,
                             std::uint32_t len, std::vector<std::uint8_t>& out, std::uintptr_t align);

std::uint32_t AudioCost(const std::int32_t* v, std::uint32_t n);
void AudioUnpack(const std::uint8_t* src, std::uint32_t nbytes, std::int32_t* out, const AudioProbe& pr);
void AudioProbeBlock(AudioProbe& pr, const std::uint8_t* block, std::uint32_t len);
bool AudioDecide(AudioProbe& pr, const std::uint8_t* block, std::uint32_t len, std::uint32_t avail);
std::uint32_t ResidualCostBits(const std::int32_t* v, std::uint32_t n, std::uint8_t* bytes);
std::uint32_t MaskBits(std::uint32_t k);
// The bit writer of FUN_080b1f20 / FUN_080b2030: MSB-first, 32-bit big-endian
// words; `cur == end` stops writing (the caller then sees the overflow).
struct BitWriter {
    std::uint8_t* base = nullptr;
    std::uint8_t* end = nullptr;
    std::uint8_t* cur = nullptr;
    std::uint32_t bitbuf = 0;
    std::uint32_t nbits = 0;

    void Put(std::uint32_t value, std::uint32_t n) {                    // FUN_080b1f20
        const std::uint32_t total = nbits + n;
        if (total < 0x21u) {
            nbits = total;
            bitbuf = (bitbuf << (n & 31u)) | value;
            return;
        }
        if (cur == end) return;
        const std::uint32_t room = 32u - nbits;
        const std::uint32_t keep = n - room;
        nbits = keep;
        const std::uint32_t word = (bitbuf << (room & 31u)) | (value >> (keep & 31u));
        std::uint8_t* next = cur + 4;
        bitbuf = value;
        if (end < next) { cur = end; return; }
        cur[0] = static_cast<std::uint8_t>(word >> 24u); cur[1] = static_cast<std::uint8_t>(word >> 16u);
        cur[2] = static_cast<std::uint8_t>(word >> 8u);  cur[3] = static_cast<std::uint8_t>(word);
        cur = next;
    }
    void PutBisect(std::uint32_t value, std::uint32_t hi) {            // FUN_080c0680
        std::uint32_t lo = 0;
        for (;;) {
            std::uint32_t mid = (hi + lo) >> 1u;
            if (mid <= lo) return;
            for (;;) {
                const bool up = value < mid;
                Put(up ? 1u : 0u, 1u);
                if (!up) { lo = mid; break; }
                hi = mid;
                mid = (hi + lo) >> 1u;
                if (mid <= lo) return;
            }
        }
    }
    void Flush() {                                                       // FUN_080b2030
        while (nbits != 0u) {
            if (nbits < 8u) {
                const std::uint32_t k = nbits; nbits = 0;
                if (end <= cur) continue;
                *cur++ = static_cast<std::uint8_t>(bitbuf << ((8u - k) & 31u));
            } else {
                nbits -= 8u;
                if (end <= cur) continue;
                *cur++ = static_cast<std::uint8_t>(bitbuf >> (nbits & 31u));
            }
        }
    }
};

std::size_t EncodeArithAt(const std::uint8_t* src, std::size_t n, std::uint8_t* out, std::size_t limit, std::uintptr_t align);
void ResidualEncode(const std::int32_t* v, std::uint32_t n, std::uint8_t* bytes, BitWriter& w);
std::size_t AudioEncodeBlock(AudioModel& m, const std::uint8_t* src, std::uint32_t len, AudioProbe& pr, std::vector<std::uint8_t>& out, std::uintptr_t align);

// The codec state the block driver keeps across blocks: the window (4 bytes of
// left padding, the capacity, 32 KB of slack the wrap memset reaches), the hash
// table(s) and the "last long match" offset the next block's head may resume.
struct State {
    bool variant_b = false;
    std::size_t capacity = 0;
    std::vector<std::uint8_t> window_alloc;   // capacity + 0x9004 (FUN_080b6a00)
    std::uint8_t* window = nullptr;           // the base; data starts at cursor 4
    std::size_t cursor = 4;                   // FUN_080b6bb0's +0x10058
    bool dirty = true;                        // +0x1005c: something was written since the last wrap
    std::vector<std::int32_t> hash;           // A: 0x2000 + 0x80000 entries; B: 0x1000000
    std::vector<std::uint8_t> hash_bytes_b;   // B only: the 0x8000-byte predicted-literal table (13 bits used)
    std::int32_t last_long = 0;               // +0x487e8: offset (source - position) of the last long match, 0 = none
    std::uint64_t exe_pos = 4;                // +0x10060: running position for the exe filter
    std::uint64_t literal_bytes = 0;          // +0x487dc (param_1[0x121f7]) -- bytes stored outside prefilter blocks
    std::uint64_t audio_pending = 0;          // +0x487e0 (param_1[0x121f8])
    AudioProbe probe;                         // the analysis job's copy (job+0x8060)
    AudioProbe probe_ctx;                     // the codec's copy (ctx+0x487c0), the one the encoder edits
    AudioModel audio;                         // +0x10080 (ctx + 0x4020)
    ImageEncModel image;                      // +0x12200 (the image model object)

    void Init(bool variant_b, std::size_t capacity);
    // FUN_080b6bb0: when fewer than 32 KB remain, zero [cursor, capacity + 32 KB) and rewind.
    void Wrap();
    // FUN_080b6cf0 / FUN_080b6d90: the dense / sparse hash backfill after a
    // literal or prefilter block of `len` bytes ending at the cursor.
    void BackfillDense(std::size_t len);
    void BackfillSparse(std::size_t len);
};

// FUN_0805a190: the LZ parse of `len` bytes at window + pos (already copied
// there). Appends the opcode bytecode to `out` and returns its length.
std::size_t LzParse(State& st, std::size_t pos, std::size_t len, std::vector<std::uint8_t>& out);

// FUN_08059cb0: the block header varint. flags = the low bits (0/1 literal,
// 2 raw bytecode, 3 bytecode + side stream, 4 prefilter), size 0x8000 -> 0.
void WriteBlockHeader(std::vector<std::uint8_t>& out, std::uint32_t size, std::uint32_t flags, std::uint32_t image);

// FUN_080757d0: the Huffman side stream of `n` bytecode bytes. Returns the
// bytes written to `out` (appended), or 0 when it would not fit in `limit`.
std::size_t EncodeArith(const std::uint8_t* src, std::size_t n, std::size_t limit, std::vector<std::uint8_t>& out);

// FUN_0805cbe0: the code lengths (max_len-limited) for a 256-entry histogram;
// lengths[256] out, returns the number of symbols with a nonzero count.
std::size_t BuildCodeLengths(const std::uint32_t* hist, std::uint32_t max_len, std::uint8_t* lengths, std::uint8_t* codes);

// One block of the stream (FUN_0805a790) without the audio/image/exe paths:
// appends the block's records to `out`. `remaining` = bytes of the input left
// including this block (the original's param_4).
void EncodeBlock(State& st, const std::uint8_t* block, std::size_t len, std::size_t remaining, std::vector<std::uint8_t>& out, std::uintptr_t align, bool first_in_chunk);

// FUN_08059dd0: the block's randomness score (0..~255).
std::uint32_t Score(const std::uint8_t* p, std::uint32_t len);

}  // namespace nzr::lzpf_enc
