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
//
// Returns false if the bitstream decodes a match offset/length that would
// read or write outside the valid window (a sign that this stream isn't
// actually in the format this decoder expects, e.g. real linux32/nz -co/-cO
// archives -- see the comment at the top of nz_lzhd.cpp). Callers MUST check
// the return value and decline (never trust partially-written `out`) instead
// of treating the buffer as valid output; this only guards against wild
// pointer arithmetic (SIGSEGV), it does NOT mean the decoded bytes are
// correct even when it returns true.
bool NzLzhdDecode(NzLzhdDecoder* dec,
                  const uint8_t* in,  uint32_t in_size,
                  uint8_t*       out, uint32_t out_size,
                  uint8_t*       window_base);
