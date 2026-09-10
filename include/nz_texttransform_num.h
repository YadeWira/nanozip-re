#pragma once
#include <cstdint>
#include <vector>

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

// The FORWARD number pass (FUN_08058580), the `-co` family's encoder side of the
// transform above. Size-preserving: a decimal digit becomes '0', each character
// of a hexadecimal run '1' (lowercase) or '2' (uppercase), the rest is copied;
// the values go to `*side` (cleared first). The original's writer stops at half
// of `side_cap` and the pass declines -- returns 0 -- unless it wrote more than
// four bytes and stayed under that half. Requires NzCmInitAll() to have run.
uint32_t NzTextTransformNumberEncode(const uint8_t* in, uint32_t in_size,
                                     uint8_t* out, uint32_t out_cap,
                                     std::vector<uint8_t>* side, uint32_t side_cap);
