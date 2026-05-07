#pragma once
#include <cstdint>

struct DecLZ;
using NzLzhdDecoder = DecLZ;

NzLzhdDecoder* NzLzhdCreate();
void NzLzhdDestroy(NzLzhdDecoder* dec);

// Decode one LZ block. dec state (model arrays, position history) persists
// across consecutive calls for multi-block archives.
// window_base = constant base of the full output buffer.
// out         = current write pointer (window_base + bytes_written_so_far).
// out_size    = number of bytes this block should produce.
void NzLzhdDecode(NzLzhdDecoder* dec,
                  const uint8_t* in,  uint32_t in_size,
                  uint8_t*       out, uint32_t out_size,
                  uint8_t*       window_base);
