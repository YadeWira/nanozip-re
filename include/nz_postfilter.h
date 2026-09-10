#pragma once
#include <cstdint>
#include <vector>

// NanoZip CM/BWT post-filters (ported from nzdec_v0 NZ.cpp).
// param2 = BwtRleExpander::DecodeU32 (u32-wise RLE expansion driven by an
// arithmetic-coded run-length side stream).
//
// model_data/model_len : the param2 side stream (arith input).
// in/in_size           : the just-decoded payload (e.g. CM output).
// out                  : expanded output buffer (capacity *out_size on entry).
// *out_size            : in = buffer capacity, out = bytes actually produced
//                        (0 on error).
// Returns true on success.
bool NzBwtRleDecodeU32(const uint8_t* model_data, uint32_t model_len,
                       const uint8_t* in, uint32_t in_size,
                       uint8_t* out, uint32_t* out_size);

// The ENCODER of that transform, i.e. param2 of the -co family's compressor
// (FUN_0808ff20): collapses runs of six or more equal 32-bit words, the run
// lengths going into `*side` (cleared and grown to at most `side_cap`), and
// copies the sub-word tail verbatim. Returns the collapsed size, or 0 when the
// side stream did not fit. The caller applies it only when
// side + result < in_size - min(in_size >> 7, 2048).
uint32_t NzPostfilterParam2Encode(const uint8_t* in, uint32_t in_size,
                                  uint8_t* out, uint32_t out_cap,
                                  std::vector<uint8_t>* side, uint32_t side_cap);

// param1 = AddBytesFilter (NZ.cpp): a delta filter driven by a BitReader over the
// param1 side stream. Output size == in_size.
//   p1data/p1len : the param1 side stream (bit-coded).
//   in/in_size   : input buffer (the param2/CM output).
//   out          : output buffer (>= in_size bytes; must differ from in).
// Returns true on success (false if in_size <= 263, the filter's minimum).
bool NzAddBytesFilter(const uint8_t* p1data, uint32_t p1len,
                      const uint8_t* in, uint32_t in_size, uint8_t* out);
