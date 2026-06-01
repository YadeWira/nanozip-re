#pragma once
#include <cstdint>

// Apply the NanoZip word-dictionary inverse transform (tt_flags & 0x08).
// in:         CM-decoded bytes (compressed dict stream, must end with 0x20)
// in_size:    size of CM-decoded data
// out:        output buffer (pre-allocated to allocated bytes)
// allocated:  capacity of out buffer
// Returns decoded size on success, 0 on error.
uint32_t NzTextTransformDict(const uint8_t* in, uint32_t in_size,
                             uint8_t* out, uint32_t allocated);
