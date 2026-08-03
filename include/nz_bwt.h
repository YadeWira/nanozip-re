#pragma once
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
//   param6 == 1  the BWT output is itself entropy-coded (a per-symbol-bucket
//                MTF + arithmetic layer, BwtDecodeInput). size18 holds the
//                decoded size. Not yet ported.
//
// Both then optionally run params 14/15 and the shared param2/param1/tt/dece
// post-filters, which live in nz_postfilter.cpp / nz_text_transform.cpp.

// Inverse Burrows-Wheeler transform, in place over `data[0..data_size)`.
// `bwt_pos` is the block header's bwt_start_pos. Returns false (leaving `data`
// untouched) when bwt_pos is out of range for this block, rather than reading
// out of bounds the way the reference does.
bool NzBwtUntransform(uint8_t* data, uint32_t data_size, uint32_t bwt_pos);
