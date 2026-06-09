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

}  // namespace cd
}  // namespace nzr
