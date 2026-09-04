#pragma once
#include <cstddef>
#include <cstdint>

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
bool NzBwtParam15(const uint8_t* model_data, uint32_t model_len,
                  const uint8_t* in, uint32_t in_size,
                  const uint8_t* window_base, size_t window_len,
                  uint8_t* out, uint32_t out_cap, uint32_t* out_size);
