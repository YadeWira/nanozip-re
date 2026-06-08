#pragma once
#include <cstdint>

// tt16 text-transform = TextTransformNumber::Decode (NanoZip nzdec_v0
// NZ_TextTransforms.cpp). Reconstructs number runs from a compact CM-domain
// encoding, driven by the tt16 side stream (arith-coded).
//
// side/side_len : the tt16_data side stream (arith input).
// in/in_size    : the transform input (CM output).
// out/out_cap   : output buffer + capacity.
// Returns the number of bytes written (0 on error).
// Requires NzCmInitAll() to have run (uses kModelInterpolation/kModelLutLookup).
uint32_t NzTextTransformNumber(const uint8_t* side, uint32_t side_len,
                               const uint8_t* in, uint32_t in_size,
                               uint8_t* out, uint32_t out_cap);
