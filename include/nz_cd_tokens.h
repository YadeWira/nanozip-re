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
// isolation. NzCdDecodeBlock wires them into the archive dispatcher
// (TryDecodeLegacyLzhd) and handles pure-LZ, block-RLE (&2), exe (&4) and text-
// pipeline (&8, line-RLE/CRLF) chunks across a 64 KB cross-chunk ring. Remaining
// `-cd` gaps that still bridge: tt08/reorder text bits, and CM/BWT sub-chunks. See
// work/reports/decomp_lzhd/ARCHITECTURE_cd.md for the complete map.
#pragma once
#include "lzpf_arith.h"
#include "nz_audio.h"
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

// Exe post-filter (chunk flag &4, FUN_080c0540). A BCJ-style x86 E8/E9 call/jmp
// address un-transform applied in place to a decoded window: each E8/E9 whose
// following 4-byte little-endian address has a high byte of 0x00/0xFF is converted
// back to absolute by subtracting the position (`(addr_offset + pos_base) & 0xffffff`)
// and sign-extending bit 24. After every E8/E9 the 4 address bytes are skipped.
// `pos_base` = 4 + the chunk's output offset. Validated byte-exact vs the binary.
void NzCdExeUnfilter(std::uint8_t* buf, std::uint32_t size, std::uint32_t pos_base);

// Text pipeline (chunk flag &8, FUN_080a3c90). A per-chunk param bitmask selects an
// ordered sequence of text transforms applied with double-buffering. Supported bits:
// 0x80 param14 (NzCdParam14), 0x20 line-RLE (FUN_080a2f20: newline-terminated runs +
// >0xE0 repeat-previous-line back-refs), 0x1 EOL->CRLF (FUN_080a19b0). Each stage is
// validated byte-exact vs the binary. Returns the transformed size, or 0 if `param`
// uses a not-yet-ported bit (e.g. 0x8 reorder / tt08 dict — those chunks still bridge).
// WIRED into DecodeChunk: applied to the chunk's compact recon slice; the 64 KB ring
// base then advances by this OUTPUT size so a following chunk's matches reach back into
// the (compact) text chunk through the ring wrap (validated on atoll/f18 end-to-end).
std::uint32_t NzCdTextPipeline(const std::uint8_t* src, std::uint32_t size,
                               std::uint8_t* out, std::uint32_t out_cap, std::uint32_t param);

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
                                std::uint8_t* out, std::uint32_t out_cap,
                                std::uint32_t ring_size = 0x10000u);

// Decode a whole `-cd` LZ block (loop DecodeChunk over its 32 KB chunks) into `out`.
// Returns total bytes produced. Handles pure-LZ, block-RLE (&2), exe (&4) and text-
// pipeline (&8, line-RLE/CRLF) chunks; chunks using a not-yet-ported post-filter
// (tt08/reorder/CM/BWT) make a chunk return 0 and the dispatcher bridges. The LZ
// window is a per-archive RING (FUN_08099050, obj+0x978) whose size the encoder sets
// to round(total_output / 0x10000) * 0x10000 (min 0x10000) so the COMPACT recon fits
// without wrapping; each chunk's COMPACT recon is written at the ring cursor and the
// cursor advances by the COMPACT recon size (matches resolve into prior chunks; the
// reset/wrap path is a safety fallback that real archives never hit). `out` is the
// linear full-file output (separate from the ring). Validated byte-exact on map.txt
// and source.cpp (7 chunks, 192 KB ring). ring_size defaults to 64 KB for the
// standalone single-stream path; the dispatcher passes the round() value.
std::uint32_t NzCdDecodeBlock(const std::uint8_t* block, std::size_t block_len,
                              std::uint8_t* out, std::uint32_t out_cap,
                              std::uint32_t ring_size = 0x10000u,
                              bool is_lzhds = false);

// Decode one -cd stream into `out` using a CALLER-OWNED ring window that PERSISTS
// across streams. Large files split their output into 1 MB streams whose LZ matches
// reference prior streams through this shared ring, so the dispatcher allocates the
// ring once (size = round(total_output/0x10000)*0x10000) and threads `*ring_pos`
// across calls. `out_pos_base` is this stream's file-absolute output offset (used by
// the &4 exe filter). Returns bytes written. NzCdDecodeBlock is the single-stream
// wrapper.
// `is_lzhds`/`lzhds_ctx_table`/`lzhds_ctx_index` select the `-cD` (nz_lzhds)
// literal model instead of `-cd`'s raw-copy literal handler (see nz_lzhds.h).
// `lzhds_ctx_table` must point at kLzhdsCtxTableSize (16 KB) bytes, initialized
// once via NzLzhdsInitCtxTable and threaded (along with `*lzhds_ctx_index`)
// across every NzCdDecodeStream call for the whole `-cD` archive/stream. Both
// are ignored when `is_lzhds` is false.
std::uint32_t NzCdDecodeStream(const std::uint8_t* block, std::size_t block_len,
                               std::uint8_t* out, std::uint32_t out_cap,
                               std::uint8_t* ring, std::uint32_t ring_size,
                               std::uint32_t* ring_pos, std::uint32_t out_pos_base,
                               bool is_lzhds = false,
                               std::uint8_t* lzhds_ctx_table = nullptr,
                               std::uint32_t* lzhds_ctx_index = nullptr,
                               // Prefilter sub-chunk state ((nibble & 0xc) == 0xc).
                               // Caller-owned so it persists across the stream's
                               // chunks; nullptr makes such a chunk decline.
                               nzr::lzpf::PrefilterContext* pf_ctx = nullptr,
                               nzr::lzpf::LmsObject* pf_lms1 = nullptr,
                               nzr::lzpf::LmsObject* pf_lms2 = nullptr,
                               // Image model for the 0xf sub-chunk (FUN_080a9ca0).
                               // Caller-owned, persists across the stream's chunks;
                               // nullptr makes such a chunk decline.
                               nzr::audio::NzImageModel* img = nullptr);

}  // namespace cd
}  // namespace nzr
