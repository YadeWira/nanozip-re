// Native linux32 `-cD` (nz_lzhds, method_p0==4) literal model. This is the ONLY
// difference vs `-cd` (nz_lzhd, method_p0==3): the token queue consumption + LZ
// copy are identical (same rep-cache MTF, same match-length classes -- see
// FUN_080982e0's rep-cache code, byte-identical logic to nz_cd_tokens.cpp's
// ReconstructRing except for match-length class thresholds, which differ:
// -cD uses 0x3ff/0x3fff/0x7fffff vs -cd's 0x4ff/0x63ff). The literal-run bytes
// are decoded through a per-context (order-1, keyed by the previously emitted
// byte value) MTF rank table + an adaptive order-N linear predictor, fed by a
// plain MSB-first bit-reader + Exp-Golomb/Elias-delta-style integer decoder
// (FUN_080b1fb0 / FUN_080c07d0 / FUN_080c0a20) -- NOT an arithmetic coder.
//
// Reverse-engineered from `linux32/nz` (FUN_080982e0 + 11 supporting functions;
// see work/reports/decomp_lzhd/decomp_cD_nz_lzhds.txt) and validated byte-exact
// against 3 real chunks of a 292 KB `-cD` fixture via GDB ground-truth capture
// (both the token/litstream/ratebits inputs AND the resulting COMPACT --
// pre-text-pipeline -- recon output and the persisted MTF-context index).
//
// IMPORTANT: the value this function produces is the chunk's COMPACT recon (the
// same "pre-text/BWT/exe post-filter" domain NzCdReconstruct/ReconstructRing
// produce for -cd) -- it legitimately contains raw control bytes (<0x20) that a
// subsequent text/word-dictionary pipeline (NzCdTextPipeline, flag &8) expands
// into the final human-readable text. Do not compare this function's output
// directly against final decompressed file bytes for text inputs; compare
// against the compact recon (or run the whole DecodeChunk pipeline).
#pragma once
#include <cstdint>
#include <cstddef>

namespace nzr {
namespace cd {

// Per-context record layout (0x40 = 64 bytes), N=256 contexts (one per possible
// previous-byte value), stride 0x40: obj+0x20+ctx*0x40 in the original binary.
//   [0x00..0x1f] MTF rank table (32 symbol slots; rank[i] = symbol currently at
//                MTF rank i).
//   [0x20..0x3f] presence bitmap (256 bits / 32 bytes; bit (sym&7) of byte
//                (sym>>3) is set iff `sym` currently occupies some rank slot).
constexpr std::size_t kLzhdsCtxRecordSize = 0x40u;
constexpr std::size_t kLzhdsCtxCount      = 256u;
constexpr std::size_t kLzhdsCtxTableSize  = kLzhdsCtxRecordSize * kLzhdsCtxCount;

// Initialize a freshly allocated ctx_table (kLzhdsCtxTableSize bytes) to the
// IDENTITY MTF state used at the start of a `-cD` stream: rank[i]=i for
// i in 0..31 (NOT all-zero -- GDB-verified: a fresh context's rank table holds
// the identity permutation, and its presence bitmap has bits 0..31 set to
// match), rest zero. Call ONCE per archive/-cD-stream before the first
// NzLzhdsReconstruct call; the table is mutated in place and threaded across
// every subsequent call for that stream (it is the ctx TABLE CONTENT that
// persists across chunks, per the architecture doc's "ctx persists across
// calls" finding -- rep-cache and the adaptive predictor do NOT persist, they
// reset every call, per FUN_080982e0's own top-of-function reset code).
void NzLzhdsInitCtxTable(std::uint8_t* ctx_table);

// Reconstruct one `-cD` chunk's COMPACT recon into a cross-chunk RING (the same
// ring abstraction nz_cd_tokens.cpp's ReconstructRing uses:
// `ring[RingReduce(base+pos, ring_size)]`, modular wrap, ring_size a multiple of
// 0x10000). Consumes:
//   - `tokens`/`num_tokens`: the SAME flat {lit_run, sel, raw_len} token array
//     NzCdTokenAssemble produces (12 bytes/token). May be shorter than strictly
//     needed for a well-formed chunk (an implicit trailing literal-run flush of
//     `out_size - bytes_produced_so_far` bytes, continuing the SAME model
//     state, covers any shortfall once tokens run out -- GDB-verified: real
//     `-cD` chunks legitimately exhaust their captured token window ~11 bytes
//     short of out_size and finish via literal decode alone).
//   - `litstream`/`litstream_len`: the SAME byte-at-a-time literal/MTF-rank
//     stream `-cd`'s decode_literals() already produces (arith-or-raw literal
//     column) -- NOT a separate stream.
//   - `ratebits`/`ratebits_len`: the `-cD`-only Exp-Golomb run-length control
//     stream (a brand-new, length-prefixed chunk field: one raw length byte
//     followed by that many raw bytes, positioned immediately after `bs` and
//     immediately before `literals` in the chunk layout).
//   - `ctx_table`/`ctx_index`: the PERSISTENT per-archive MTF-context state
//     (kLzhdsCtxTableSize bytes; init once via NzLzhdsInitCtxTable, then thread
//     across every call for the stream). `*ctx_index` is read at entry (which
//     context to start this call's first literal in) and written back at exit
//     (the context that would decode the NEXT byte, i.e. the value of the last
//     compact-recon byte produced by this call).
// The rep-distance cache and the adaptive predictor (order/stage/weights) are
// LOCAL to each call (reset every call, matching FUN_080982e0's own top-of-
// function reset via FUN_080bf140 -- NOT a bug, GDB-confirmed).
// Returns bytes produced (== out_size on success), or 0 on malformed/garbage
// input (a match referencing further back than `ring_size`) -- mirrors
// ReconstructRing's safety-refuse convention so a wrong decode never emits
// corrupted output; the caller's checksum gate is the final backstop regardless.
std::uint32_t NzLzhdsReconstruct(const std::uint32_t* tokens, std::uint32_t num_tokens,
                                 const std::uint8_t* litstream, std::size_t litstream_len,
                                 const std::uint8_t* ratebits, std::size_t ratebits_len,
                                 std::uint8_t* ring, std::uint32_t ring_size, std::uint32_t base,
                                 std::uint32_t out_size,
                                 std::uint8_t* ctx_table, std::uint32_t* ctx_index);

}  // namespace cd
}  // namespace nzr
