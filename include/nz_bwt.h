#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// NanoZip decr_param == 0 ("BWT") block decoding, ported from the community
// reference decoder (nzdec_v0 NZ.cpp: BwtUntransform / BwtDecodeInput /
// BwtUnpackInput).
//
// A non-CM block with decr_param == 0 carries Burrows-Wheeler-transformed data
// plus an inverse-BWT start position. Two shapes exist, selected by param6:
//
//   param6 == 0  the payload IS the BWT output, stored raw (the encoder found
//                it incompressible, e.g. random data). Only the inverse BWT
//                runs, and the block's output size equals its payload size.
//   param6 == 1  the BWT output is itself entropy-coded: 256 independent
//                per-leading-symbol buckets, each an arithmetic-coded
//                move-to-front rank stream plus an optional byte-wise RLE
//                expansion (BwtDecodeInput / BwtUnpackInput). size18 holds the
//                decoded size.
//
// Both then optionally run params 14/15 and the shared param2/param1/tt/dece
// post-filters, which live in nz_postfilter.cpp / nz_text_transform.cpp.

// Inverse Burrows-Wheeler transform, in place over `data[0..data_size)`.
// `bwt_pos` is the block header's bwt_start_pos. Returns false (leaving `data`
// untouched) when bwt_pos is out of range for this block, rather than reading
// out of bounds the way the reference does.
bool NzBwtUntransform(uint8_t* data, uint32_t data_size, uint32_t bwt_pos);
// Forward Burrows-Wheeler transform of `in` (n bytes) into `out` (n bytes), for
// the encoder: returns the bwt_start_pos the decoder needs. Rotation sort by
// prefix doubling; canonical output.
uint32_t NzBwtTransform(const uint8_t* in, uint32_t n, uint8_t* out);
// The BWT bucket encoder (FUN_0806c350): codes `bwt` (n bytes of BWT output)
// into the payload NzBwtDecodeInput reads. `cap` is the caller's room (the -co
// trial gate passes 0x600487). Returns the payload size, or 0 when the payload
// would not be below n (the original then stores the block).
uint32_t NzBwtEncodeInput(const uint8_t* bwt, uint32_t n, uint32_t cap, std::vector<uint8_t>& out,
                          unsigned threads = 1u);
// Threads used by the inverse BWT walk on large blocks (0 = hardware default).
void NzBwtSetThreadCount(unsigned n);

// Decodes the param6 == 1 entropy layer that wraps the BWT output (reference
// BwtDecodeInput). `payload`/`payload_size` are the block's raw payload,
// `out_size` its declared decoded size (the header's size18). On success writes
// exactly `out_size` bytes to `out` and returns true; on any malformed or
// inconsistent input returns false without producing output.
//
// This is the pre-image of the inverse BWT, not the final block output: the
// caller still runs NzBwtUntransform over the result.
bool NzBwtDecodeInput(const uint8_t* payload, uint32_t payload_size,
                      uint32_t out_size, uint8_t* out);

// param14 / param15: BWT-only follow-on transforms that run after the inverse
// BWT and before the shared param2/param1/text-transform/dece chain. Both are
// LZ77 passes over the block's bytes, driven by their own arithmetic-coded side
// stream (`model_data`), that locate matches by scanning for a two-byte escape
// tag: 0xfe 0xf1 for param14, 0xfe 0xf0 for param15.
//
// param14 codes its match offset relative to the current output position, with
// four repeat-offset slots. Ported from reference DecodeLZ_Param14
// (NZ_LZ.cpp:543).
//
// WARNING: this is NOT the same transform as NzCdParam14 in nz_cd_tokens.h
// (the -cd char-class space-insertion text transform). Same name in the
// original, completely different algorithm.
bool NzBwtParam14(const uint8_t* model_data, uint32_t model_len,
                  const uint8_t* in, uint32_t in_size,
                  uint8_t* out, uint32_t out_cap, uint32_t* out_size);

// param15 names its match source as an ABSOLUTE offset (4 raw big-endian
// one's-complement bytes taken from the byte stream) into the whole accumulated
// output stream, so a match can reach back into earlier blocks. The caller must
// therefore pass the base and length of everything decoded so far, with this
// block's own pre-param15 bytes sitting at its end, and `in` pointing at them.
// Ported from reference DecodeParam15 (NZ.cpp:843).
// `window_cap` is the LZ ring's capacity: param15's four raw offset bytes are a
// position in that ring, so on a stream whose accumulated window has grown past
// the capacity the real source sits one or more capacities further along. Pass 0
// to keep the literal (pre-2026-09-04) reading.
bool NzBwtParam15(const uint8_t* model_data, uint32_t model_len,
                  const uint8_t* in, uint32_t in_size,
                  const uint8_t* window_base, size_t window_len,
                  uint8_t* out, uint32_t out_cap, uint32_t* out_size,
                  uint32_t window_cap = 0u);

// ---------------------------------------------------------------------------
// The ENCODER of param14 (reference FUN_080bb3a0 -> FUN_080b9990, called from
// the -co block analysis after the two BWT-only passes' input is settled and
// before the forward BWT).
//
// It is an LZ77 pass over the block that names its matches with a two-byte
// escape tag in the BYTE stream (0xfe 0xf1 followed by a zero selector) and
// codes offset and length in an arithmetic side stream, with four
// repeat-offset slots. A literal 0xfe 0xf1 followed by a byte below 2 is
// escaped by inserting a selector of 1.
//
// A match is only taken when a rarity model agrees: `stats` counts, over the
// block, how often each hashed four-byte context occurs, and the sum of those
// counts across the candidate match must fall under a length-indexed
// threshold. Build it with NzBwtParam14Stats over the SAME bytes the reference
// feeds it (FUN_08054ad0, called on the block before param15 runs).
//
// Returns the filtered length, or 0 when the reference would decline (a block
// under 0x80 bytes, or a side stream that overflowed half its budget).
void NzBwtParam14Stats(const uint8_t* data, uint32_t n, std::vector<uint16_t>* stats);

// The param15 ENCODER (FUN_08083570): long matches against the LZ engine's ring
// through the long-range index its window feed keeps. Returns the coded size, or
// 0 when the pass does not pay (output + side stream must stay under n - 8).
uint32_t NzBwtParam15Encode(const uint8_t* in, uint32_t n,
                            const std::vector<uint16_t>& stats,
                            const uint32_t* lr_table, uint32_t lr_mask,
                            const uint8_t* ring, uint32_t ring_cap,
                            uint32_t ring_fill, bool ring_scrolled,
                            std::vector<uint8_t>* out, std::vector<uint8_t>* side,
                            uint32_t side_cap);
uint32_t NzBwtParam14Encode(const uint8_t* in, uint32_t n,
                            const std::vector<uint16_t>& stats,
                            std::vector<uint8_t>* out,
                            std::vector<uint8_t>* side,
                            uint32_t side_cap = 0x80000u);
