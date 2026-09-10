#pragma once
#include <cstdint>
#include <vector>

namespace nzr {
namespace opt_enc {

// param1 of the -co family's compressor: the ENCODER whose output
// NzAddBytesFilter (src/nz_postfilter.cpp) undoes.
//
// Reference FUN_0806e7a0. It walks the block keeping three order-2.5 context
// models -- the raw bytes and the bytes delta-coded against two candidate
// offsets -- and whenever a delta model beats the raw one for long enough it
// places, measures and (if three independent cost tests agree) emits a region
// coded as `out[k] = data[k] - data[k - offset]`. The regions go into a
// bit-coded side stream read back by AddBytesFilter::DecodeOne.
//
//   data/n : the block.
//   out    : receives n filtered bytes (a copy of the block with the accepted
//            regions delta-coded in place).
//   side   : receives the bit stream (at most `cap` bytes; the reference uses
//            0x1000).
//
// Returns true when the reference would keep the filter, i.e. the side stream
// stayed under cap/2, at least one region was emitted, and -- for blocks over
// 0x3ff bytes -- the filtered block has fewer distinct order-2.5 contexts than
// the original.
bool NzOptimumParam1Encode(const std::uint8_t* data, std::uint32_t n,
                           std::vector<std::uint8_t>* out,
                           std::vector<std::uint8_t>* side,
                           std::uint32_t cap = 0x1000u);

}  // namespace opt_enc
}  // namespace nzr
