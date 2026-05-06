#pragma once

#include <cstdint>

namespace nzr::lzpf {

// MSB-first big-endian bit reader.
//
// Mirrors the legacy NanoZip in-memory bit reader at FUN_080b1fb0
// (see work/reports/decomp_lzpf/FUN_080b1fb0_FUN_080b1fb0.c).
//
// Layout matches the legacy struct layout used by FUN_080a4ea0 / FUN_0809cd90 /
// FUN_0809cdc0:
//   +0x00 = start (input base, used by Finalize for byte-count)
//   +0x04 = end   (one-past-last byte of input)
//   +0x08 = cur   (current cursor; advances by 4 bytes per refill)
//   +0x0c = cache (32-bit big-endian word holding pending bits)
//   +0x10 = n_valid (number of unconsumed bits in cache)
struct BitReader {
    const std::uint8_t* start;
    const std::uint8_t* end;
    const std::uint8_t* cur;
    std::uint32_t cache;
    std::uint32_t n_valid;
};

// Mask of `n` low bits, with `Mask(0)` == 0 and `Mask(32)` == 0xffffffff.
// Backs the legacy DAT_081b42f0 lookup table referenced by every bit-reader call.
std::uint32_t Mask(unsigned n);

// Initialise a fresh reader pointing at [data, data+size). Caller owns the buffer.
void Init(BitReader& r, const std::uint8_t* data, std::size_t size);

// Read `req` bits (1..31) MSB-first from the stream. Behaviour past end-of-input
// matches the legacy code: returns garbage but never reads beyond `end`.
std::uint32_t ReadBits(BitReader& r, std::uint32_t req);

// Range-coder counter init: stores `total` and `total` again (consumed counter)
// at offsets 0 and 4 of the 12-byte struct, plus ceil(log2(total))+1 (or 1 if
// total == 0) at offset 8. Mirrors FUN_080c0630.
struct RangeCounter {
    std::uint32_t total;
    std::uint32_t remaining;
    std::uint32_t leading_bits;
};
void CounterInit(RangeCounter& c, std::uint32_t total);

// Range-coder bit-stream priming (FUN_0809cd90): reads 31 bits and stores them
// at the model's "code register" offset (model[0x240]). The caller passes the
// destination so this header is symmetric with the rest of the API.
void RangeCoderPrime(std::uint32_t& code_register, BitReader& r);

// Range-coder bit-stream finalise (FUN_0809cdc0): rewinds the cursor in `r` to
// the byte boundary corresponding to bits actually consumed. Equivalent to
// ((-31 - n_valid) + (cur - start)*8) >> 3 then bytes consumed = cur - start.
void RangeCoderFinalize(BitReader& r);

// Canonical Huffman table built by FUN_0809cbe0 from a per-symbol code-length
// array. The layout below mirrors the legacy 604-byte buffer exactly (offsets
// in comments) so existing decompiler offsets can be cross-referenced.
//
// Code lengths are bounded such that first_code[length] and base_index[length]
// fit in a byte; the table-reader (FUN_080a41d0) enforces this on the encoder
// side. We store as u8 for byte-for-byte compatibility with the legacy code.
struct HuffmanContext {
    std::uint8_t symbols[256];       // +0x000  sorted symbol values, longest length first
    std::uint8_t length_table[256];  // +0x100  length lookup keyed by top 9 bits of code reg
    std::uint8_t first_code[32];     // +0x200  first canonical code value per length (1..31)
    std::uint8_t base_index[32];     // +0x220  symbols[] base index per length
    std::uint32_t code_register;     // +0x240  31-bit code register (top bit = 0)
    std::uint8_t pad[24];            // +0x244  padding to match legacy 604-byte buffer
};

// Build the Huffman context from a `n_symbols`-entry array of per-symbol code
// lengths (zero length = symbol absent). Mirrors FUN_0809cbe0.
void BuildHuffman(HuffmanContext& ctx, const std::uint8_t* code_lengths,
                  std::size_t n_symbols);

// Decode `count` symbols from the bit stream into `dst`, using `ctx`. Mirrors
// the slow-path of FUN_0809cf40 (the fast-path optimisation for count >= 1024
// is intentionally deferred). Updates `ctx.code_register` and consumes from `br`.
void DecodeHuffmanBytes(HuffmanContext& ctx, BitReader& br,
                        std::uint8_t* dst, std::size_t count);

// Binary-search range decoder (FUN_080c06f0). Returns a value in [0, hi]
// using ceil(log2(hi+1)) bits of input via successive bisection. Used by the
// meta-Huffman code-length reader (FUN_080a41d0).
std::uint32_t ReadRangeBisect(BitReader& br, std::uint32_t hi);

// Decode `n_symbols` per-symbol Huffman code lengths from a bit stream.
//
// Mirrors FUN_080a41d0. The encoding is a two-pass scheme:
//   Pass 1 reads `max_len + 1` meta-Huffman code lengths via ReadRangeBisect
//          with running Kraft-sum validation.
//   Pass 2 builds the meta-Huffman from those lengths, primes the bit
//          stream, then decodes `n_symbols` length values into `dst[]` using
//          one of three relative-encoding modes (delta / literal / modular)
//          plus an RLE escape after three consecutive equal values.
//
// `max_len` is the maximum allowed code length value (e.g., 12 in observed
// NanoZip use). The meta-Huffman has `max_len + 1` symbols (lengths 0..max_len).
//
// On entry `br` should sit at the start of the encoded length stream. On
// exit `br` is finalized to the next byte boundary.
//
// Returns true on success. Does not currently fail (the legacy code has no
// failure path either; malformed input may produce garbage but won't crash).
bool ReadCodeLengthsHuffman(BitReader& br, std::uint8_t* dst,
                            std::size_t n_symbols, std::uint32_t max_len);

// Pass 1 only: reads the meta-Huffman code lengths (`max_len + 1` entries)
// into `meta_lengths_out[]`. Exposed separately so unit tests can validate
// pass 1 against gdb-captured ground truth before hooking up pass 2.
// `meta_lengths_out` must point to at least `max_len + 1` bytes.
// Returns the mode (0..3) read from the first 2 bits.
std::uint32_t ReadCodeLengthsPass1(BitReader& br,
                                    std::uint8_t* meta_lengths_out,
                                    std::uint32_t max_len);

// LZ77 bytecode dispatcher — variant A (= `nz_lzpf`, where `*ctx == 0`).
//
// Mirrors the inner loop in FUN_08097570 (lines 134-217 of the decompile).
// Reads `bytecode`/`bytecode_size` opcodes, writes up to `output_size` bytes
// into `dict + dict_cursor` (a sliding window of `dict_capacity` bytes).
//
// Opcodes:
//   <  0xf6 : literal (= the byte itself)
//   == 0xf6 : 1-byte repeat from previous LZ-destination offset
//   == 0xf7 : long match (read 6 more bytes; OR escape-literal if next < 0xf5)
//   == 0xf8 : short match (1- or 2-byte length suffix)
//   else    : medium match (length = ~opcode + 1)
//
// `hash_table` is an 8192-entry int32 array tracking the most recent
// window-relative offset for each 13-bit hash (must be zero-initialised on
// first call). `last_lz_dest` tracks the offset for opcode 0xf6
// (initialise to -1 on first call).
//
// Returns true on success; false on bytecode underflow or output overflow.
bool DecodeLz77VariantA(const std::uint8_t* bytecode, std::size_t bytecode_size,
                        std::uint8_t* dict, std::size_t dict_capacity,
                        std::size_t* dict_cursor, std::size_t output_size,
                        std::int32_t* hash_table,
                        std::int32_t* last_lz_dest);

// LZ77 bytecode dispatcher — variant B (= `nz_lzpf_large`, where `*ctx != 0`).
//
// Mirrors the `else` branch of FUN_08097570 (lines 219-313 of the decompile).
// Differences from variant A:
//   - Hash key uses 3 bytes from `out - 3` masked to 24 bits (vs 13 bits in A).
//     `hash_table` must therefore be a 16M-entry int32 array (= 64 MiB).
//   - A secondary 8 KiB byte buffer (`byte_buffer_8k`) is keyed by the
//     low 13 bits of the u16 at `out - 2` and stores the most recent literal
//     for each 2-byte context. Used by the new opcode 0xf5.
//   - Literal threshold is `< 0xf5` (vs `< 0xf6` in A), and 0xf5 means
//     "emit byte_buffer_8k[hash13(out-2)]".
//
// Both `hash_table` and `byte_buffer_8k` must be zero-initialised on first
// call and persist across blocks within the same substream chain.
bool DecodeLz77VariantB(const std::uint8_t* bytecode, std::size_t bytecode_size,
                        std::uint8_t* dict, std::size_t dict_capacity,
                        std::size_t* dict_cursor, std::size_t output_size,
                        std::int32_t* hash_table_24bit,
                        std::uint8_t* byte_buffer_8k,
                        std::int32_t* last_lz_dest);

// Top-level wrapper that decodes `output_count` arith-coded bytes. Mirrors
// FUN_080a4ea0:
//   1. Read 256 per-symbol code lengths via ReadCodeLengthsHuffman.
//   2. Build the outer Huffman from those lengths.
//   3. Prime the bit stream and decode `output_count` symbols.
//   4. Finalise the bit stream.
// Returns the number of input bytes consumed.
std::size_t DecodeArithBuffer(const std::uint8_t* input, std::size_t input_size,
                               std::uint8_t* output, std::size_t output_count,
                               std::uint32_t max_len);

}  // namespace nzr::lzpf
