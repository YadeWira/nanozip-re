#pragma once
#include <cstdint>

// dece post-filter: x86 CALL/JMP address un-relativiser, ported from the
// community reference decoder (nzdec_v0 NZ_x86.cpp, ExeFilter).
//
// It is the LAST step of the post-filter chain (reference DecodeFromStream:
// param2 -> param1 -> text transforms -> dece). The encoder rewrites the
// 32-bit displacement of every CALL (0xe8), JMP (0xe9) and Jcc (0x0f 0x8x)
// into an absolute-ish form that compresses far better, and drops the
// displacement bytes plus an optional "add esp, imm8" tail into side streams;
// this puts them back.
//
// Three input streams are involved:
//   `side`        the dece_data vector: two backwards varints at its tail give
//                 the counts, and the rest is an arithmetic-coded model stream.
//   the tail of `in`  raw bytes: `num_call` add-esp immediates followed by
//                 `num_call_offs` big-endian 32-bit call targets.
//   the front of `in`  the instruction bytes themselves.
//
// Output GROWS relative to input (each restored displacement adds 4 bytes, and
// an add-esp adds 3 more), so `out_cap` must be the room actually available.
//
// Returns false on any malformed or inconsistent input, leaving *out_size
// unset; the caller declines rather than emitting partial output. `in` and
// `out` must not overlap.
bool NzExeFilter(const uint8_t* side, uint32_t side_len,
                 const uint8_t* in, uint32_t in_size,
                 uint8_t* out, uint32_t out_cap, uint32_t* out_size);
