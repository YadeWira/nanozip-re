// Native linux32 `-cd` (nz_lzhd) token pipeline — VALIDATED byte-exact pieces.
//
// These reimplement the linux32 `nz` 0.09a coroutine token-LZ decoder (NOT the
// older reference `DecLZ` in nz_lzhd.cpp, which is a different/wrong format for
// linux32 `-cd`). Each function below was reverse-engineered from the stripped
// binary and validated byte-exact against it via GDB capture+replay:
//
//   NzCdTokenAssemble  <-  FUN_080aa070  (token assembler; 5346/5346 fields exact)
//   NzCdReconstruct    <-  FUN_08099050  (LZMA-style token->bytes reconstruction)
//
// They are pure functions (no global state) so they can be unit-tested in
// isolation. They are NOT yet wired into the archive dispatcher — full native
// `-cd` additionally needs the block sub-stream framing, the param14 text
// transform (FUN_080a0ff0), and the tt08 dictionary expand. See
// work/reports/decomp_lzhd/ARCHITECTURE_cd.md for the complete map.
#pragma once
#include <cstdint>
#include <cstddef>

namespace nzr {
namespace cd {

// Reconstruct LZ output from 12-byte tokens {lit_run, sel, raw_len} + a literal
// byte stream. `sel >= 4` => new match, offset = sel-3; `sel < 4` => repeat-match
// index into a 4-entry MTF history. Returns bytes produced (== out_size for a
// well-formed token stream that exactly fills the block). `out` must hold at
// least out_size bytes.
//
// Mirrors FUN_08099050. Byte-exact vs the binary on the canonical single-token
// case (validated). NOTE: the legacy copies literals/matches word-wise (rounded
// up to 4 bytes) into a sliding window and restores a guard word; this flat port
// emits exact lengths, which matches the legacy for every token-produced byte.
std::uint32_t NzCdReconstruct(const std::uint32_t* tokens, std::uint32_t num_tokens,
                              const std::uint8_t* literals,
                              std::uint8_t* out, std::uint32_t out_size);

// Per-field model tables for the token assembler (from the decoder object). Each
// field decodes a column byte `b`: if `b < threshold` the value is `b`; else
// `idx = b - threshold`, `slot = slot_tbl[idx]`, `nbits = model[slot+1]`; if
// nbits==0 the value is `b`, else `value = (extra | ((idx - model[slot]) << nbits)
// + base) + threshold` with `base = (slot>>1==0)?0:(1<<(slot>>1))` and `extra` =
// `nbits` bits read MSB-first from the shared byte-swapped bitstream.
struct NzCdField {
    const std::uint8_t* slot_tbl;   // idx -> slot
    const std::uint8_t* model;      // slot -> {baseoff @[slot], nbits @[slot+1]}
    std::uint32_t       threshold;
};

// Assemble `num_tokens` 12-byte tokens (3 u32 each: lit_run, sel, raw_len) from
// three per-field column byte streams + a shared bitstream. Mirrors FUN_080aa070.
// `out_tokens` must hold num_tokens*3 u32. `bitstream`/`bitstream_len` are the
// extra-bits stream (MSB-first over byte-swapped 32-bit words; reads may overrun
// the logical end by up to 3 bytes, so the buffer must have >=3 trailing bytes).
void NzCdTokenAssemble(std::uint32_t num_tokens,
                       const std::uint8_t* col_lit,
                       const std::uint8_t* col_off,
                       const std::uint8_t* col_len,
                       const std::uint8_t* bitstream, std::size_t bitstream_len,
                       const NzCdField& field_lit,
                       const NzCdField& field_off,
                       const NzCdField& field_len,
                       std::uint32_t* out_tokens);

// param14 post-recon text transform (FUN_080a0ff0). Re-inserts word-boundary
// spaces into the LZ output using a fixed 256-entry character-class table (the
// output of FUN_080b7600, embedded). Returns bytes written to `dst` (0 if it
// would overflow `dst_cap`). `dst` must hold up to ~1.3x `src_len` + slack.
// Validated byte-exact against the binary (full 12 KB chunks and a 1 KB slice).
std::uint32_t NzCdParam14(const std::uint8_t* src, std::uint32_t src_len,
                          std::uint8_t* dst, std::uint32_t dst_cap);

// Per-column RLE run-expander (FUN_080acb90 + length coder FUN_08090070). After a
// column's arith decode, runs are expanded: literals pass through, and on a detected
// run of equal bytes the run length is read as `(1<<k) | ReadBits(k)` (k = detected
// run prefix) from the lzpf bit reader over `rle_bits` (the per-column size-region).
// `thr` = the run threshold (column header). Returns bytes written to `dst`.
// Validated byte-exact against the binary on 3 real columns (map.txt.nz). The byte
// history uses a rolling 4-byte window (`CONCAT31`): `win = (win << 8) | byte`.
std::uint32_t NzCdRleExpand(const std::uint8_t* src, std::uint32_t count,
                            std::uint8_t* dst, std::uint32_t dst_cap, std::uint32_t thr,
                            const std::uint8_t* rle_bits, std::size_t rle_bits_len);

// Decode ONE `-cd` LZ chunk from a raw block: parses the chunk header (bounded
// varints, FUN_080b1dc0), decodes the 3 token columns (arith + RLE), the token
// bitstream and literal stream, assembles tokens and reconstructs the chunk's LZ
// output window (the ~32 KB pre-param14/tt08 bytes). `*block_pos` is advanced past
// the consumed bytes. Returns the number of output bytes written to `out` (the
// chunk out_size), or 0 on malformed input. Uses the embedded deterministic
// model/slot tables (the output of FUN_080b7600-class init). Validated byte-exact
// against the binary on a real `-cd` block (map.txt.nz batch 0).
std::uint32_t NzCdDecodeLzChunk(const std::uint8_t* block, std::size_t block_len,
                                std::size_t* block_pos,
                                std::uint8_t* out, std::uint32_t out_cap);

// Decode a whole `-cd` LZ block (loop NzCdDecodeLzChunk over its 32 KB chunks)
// into `out`. Returns total bytes produced. Suitable for `-cd` blocks whose chunks
// are the pure-LZ form (no per-chunk CM/BWT/param14/tt08 post-filter); those are
// handled by the dispatcher around this. Validated byte-exact on the full
// map.txt.nz file (69689 bytes, 3 chunks). The recon sliding window spans chunks
// (matches reference into prior chunk output), so `out` must be the contiguous
// full-file buffer.
std::uint32_t NzCdDecodeBlock(const std::uint8_t* block, std::size_t block_len,
                              std::uint8_t* out, std::uint32_t out_cap);

}  // namespace cd
}  // namespace nzr
