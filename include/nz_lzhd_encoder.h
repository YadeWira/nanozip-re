// nz_lzhd_encoder.h -- the original's `-cd` (nz_lzhd) compressor: the LZ
// object FUN_0805ed90 (window FUN_080bd240, match finder FUN_0805c260, chunk
// encoder FUN_0805f640, sparse hash append FUN_0805e190), the token-to-column
// coder FUN_0808aff0 / FUN_0808ab90 / FUN_0808b6b0 and the chunk writer
// FUN_0805d690, driven per 32 KB chunk by the piece compressor FUN_08064bb0.
// Decompiles: ~/.cache/nzre_tools/encode/decomp/lzhd_encoder*.c, lzhd_core.c.
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <algorithm>
#include "nz_lzpf_encoder.h"

namespace nzr::lzhd_enc {

// FUN_0805c4b0: the finder table's byte count for the Compressor line; the text
// object's size (FUN_080b88b0) for the same line.
std::uint64_t FinderTableBytes(std::uint32_t window);
constexpr std::uint64_t kTextObjectBytes = 0;   // TODO from FUN_080b88b0

// FUN_080b1d50: the bounded varint (the byte count follows `limit`).
void PutVar(std::vector<std::uint8_t>& out, std::uint32_t limit, std::uint32_t value);

// FUN_080bd240 / FUN_080bd380 / FUN_080bd480: the ring window with a 0x100-byte
// prefix that receives the tail on a wrap, 0x8000 + 0x100 of slack after it.
struct Window {
    std::uint32_t size = 0;
    std::vector<std::uint8_t> mem;
    std::uint8_t* base = nullptr;
    std::uint32_t pos = 0, end = 0;
    bool wrapped = false;
    void Init(std::uint32_t sz);
    void Slide(std::uint32_t n);                       // FUN_080bd380
    void Append(const std::uint8_t* s, std::uint32_t n); // FUN_080bd480
};

// FUN_0805c260: buckets of four entries `(pos << shift) | tag`.
struct Finder {
    std::uint32_t win = 0, bmask = 0, mask2 = 0;
    std::uint32_t shift = 0;
    std::uint8_t tagmask = 0;
    std::vector<std::uint32_t> table;
    void Init(std::uint32_t window);
    void Clear();
};

// The token buffer object (FUN_080c1120): tokens as {lit_run, sel, raw_len},
// the three field columns, the extra-bits stream and the coded columns.
struct TokenBuf {
    std::vector<std::uint32_t> tok;    // 3 per token
    std::uint32_t trailing_lit = 0;    // FUN_080c13f0: the (N+1)th lit_run
    std::vector<std::uint8_t> col_lit, col_len, col_off;
    std::vector<std::uint8_t> bits;
    std::vector<std::uint8_t> out_lit, out_len, out_off;
    void Reset() { tok.clear(); trailing_lit = 0; }
};

// ---- the -cD (nz_lzhds, big object FUN_08061760) extras --------------------
// FUN_08059b20: the long-range matcher, a 256-byte rolling hash (K = 0x104070b)
// whose table holds `(pos >> 8) | (hash & 0xffc00000)` for positions that are
// multiples of 256; the running hash itself persists across chunks (obj+0x5a9c).
struct HdsLrHash {
    std::vector<std::uint32_t> table;
    std::uint32_t mask = 0, hash = 0;
    void Init(std::uint32_t window);
    void Clear() { std::fill(table.begin(), table.end(), 0u); hash = 0; }
};
// FUN_0805c680: the hash-chain finder (head by ((v >> 19) ^ v) & hmask, chain by
// position & cmask, entries tag | position); `depth` is the adaptive chain budget
// that survives across chunks (obj+0x5824).
struct HdsFinder {
    std::uint32_t win = 0, mask = 0, tag = 0, hmask = 0, cmask = 0, depth = 0;
    std::vector<std::uint32_t> head, chain;
    void Init(std::uint32_t window, std::uint32_t per);
    void Clear() { std::fill(head.begin(), head.end(), 0u); std::fill(chain.begin(), chain.end(), 0u); depth = 0; }
};
// FUN_080b1f20 / FUN_080b2030: the MSB-first bit writer behind the Exp-Golomb
// run codes ("ratebits"), 32-bit words stored big-endian, 255 bytes of room.
struct HdsBitWriter {
    std::uint8_t buf[0x100 + 8];
    std::uint32_t cur = 0, acc = 0, nbits = 0;   // cur: byte offset; end = 0xff
    void Reset() { cur = 0; acc = 0; nbits = 0; }
    void Put(std::uint32_t v, std::uint32_t n);
    void Flush();
    void PutEG(std::uint32_t v);                 // FUN_080c09f0
};
struct Hds {
    HdsLrHash lr;
    HdsFinder finder;
    std::vector<std::uint8_t> ctx;               // obj+0x20: 256 contexts x (32 ranks + 32-byte presence bitmap)
    std::uint32_t ctx_index = 0;                 // obj+4
    // obj+0x4a00: the distance-selection block, reset per chunk (FUN_080bf3f0)
    std::uint8_t hist[0x80 * 0x11];
    std::uint32_t counters[17];
    std::uint32_t rowctr = 0;
    std::uint32_t lastpos[256];                  // positions in the window (the original keeps pointers)
    std::uint8_t row[17];
    std::uint32_t e4 = 0, e8 = 0, ec = 0, f0 = 0, f4 = 0x11;
    std::int32_t f8 = 0;
    // obj+0x5700: the ring of the last 256 rank codes and its sum (FUN_0805d330)
    std::uint8_t ring[256];
    std::uint32_t ring_idx = 0, ring_sum = 0x800;
    HdsBitWriter rate;
    std::vector<std::uint8_t> ratebits;          // the chunk's field: what FUN_080bf4b0 appends
    void Init(std::uint32_t window);
    void ResetCtx();                              // FUN_080beea0 (vtable slot 4)
    void ResetSelection(std::uint32_t pos);       // FUN_080bf3f0
};

struct State {
    std::unique_ptr<Hds> hds;          // -cD only
    Window win;
    Finder finder;
    std::uint32_t cont = 0;            // obj+0xb6c: where the last match continues
    TokenBuf tb;
    std::vector<std::uint8_t> lits;    // the literal stream of the current chunk
    std::vector<std::uint8_t> tmp;
    lzpf_enc::AudioProbe probe_ctx;    // ctx+0x387a8: the format probe
    lzpf_enc::AudioModel audio;        // ctx+0x40: the -cd prefilter model (8 taps, 3 stages)
    lzpf_enc::ImageEncModel image;     // ctx+0x38800 (profile 0x10/0x10/2)
    std::uint64_t exe_pos = 4;         // ctx[0]: the exe filter's position base
    void Init(std::uint32_t window, bool lzhds = false);
};

// -cD: FUN_08061d00 (mode 0 of FUN_08066fb0), FUN_0805da50, FUN_0805e6a0, and the
// memory figure FUN_0805d3d0 prints as "nz_lzhds [N MB]".
std::uint32_t HdsEncodeChunk(State& st, std::uint32_t n);
void HdsAppend(State& st, std::uint32_t n);
std::uint32_t HdsEstimate(State& st, const std::uint8_t* p, std::uint32_t n);
std::uint64_t HdsMemoryBytes(std::uint32_t window, unsigned threads);

// FUN_0805f640 after the window append: parse `n` bytes at the window cursor into
// tokens (State::tb) and literals (State::lits); returns the literal count.
std::uint32_t LzEncodeChunk(State& st, std::uint32_t n);
// FUN_0805e190: a chunk that bypasses the parser still feeds sparse hash entries.
void SparseAppend(State& st, std::uint32_t n);
// FUN_0808aff0 + FUN_0808ab90 + FUN_0808b6b0: tokens -> coded columns -> bytes.
void WriteColumns(State& st, std::vector<std::uint8_t>& out);
// FUN_0805d690: one LZ/literal chunk: header varints, columns, literal stream
// (arith when it pays), the text parameter byte and the block-RLE side bytes.
void WriteChunk(State& st, const std::uint8_t* lits, std::uint32_t lit_size, std::uint32_t out_size,
                std::uint32_t flags, std::uint8_t text_param, const std::vector<std::uint8_t>& rle_side,
                std::vector<std::uint8_t>& out);
// FUN_08064bb0: compress one reader piece (<= 1 MB) into `out`.
void CompressPiece(State& st, const std::uint8_t* src, std::uint32_t n, std::vector<std::uint8_t>& out);

}  // namespace nzr::lzhd_enc
