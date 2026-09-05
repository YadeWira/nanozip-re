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
void EncodeBlock(State& st, const std::uint8_t* block, std::size_t len, std::size_t remaining, std::vector<std::uint8_t>& out, std::uintptr_t align);

// FUN_08059dd0: the block's randomness score (0..~255).
std::uint32_t Score(const std::uint8_t* p, std::uint32_t len);

}  // namespace nzr::lzpf_enc
