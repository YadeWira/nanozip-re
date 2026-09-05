// Native linux32 `-cd` text-pipeline bit 0x8 — word-dictionary text transform.
//
// The &8 handler (FUN_080a3c90) bit 0x8 = an optional 1:1 byte substitution
// (kReorderAscii, applied when the method is not CM) followed by the word/
// dictionary/IP/case expansion FUN_080a0a00. This reverses the encoder's text
// model: dictionary words (ultra-small / mid / big tables), recent-IP MTF list,
// and per-word case toggling. Ported near-verbatim from the community reference
// decoder nzdec_v0 (NZ_TextTransforms.cpp TransformText_1_Dictionary + extab.h /
// Tables.h), the same source the tt16 number transform was ported from.
#pragma once
#include <cstdint>

namespace nzr {
namespace cd {

// Apply the bit-0x8 transform to `in` (in_size bytes) -> `out` (capacity out_cap).
// `reorder_ascii` selects the kReorderAscii pre-pass (true for -cd / non-CM, i.e.
// decparams->type != 7 in the reference). Returns bytes written, or 0 on malformed
// input (the chunk then bridges). `out` must hold the expanded text (~<= 32 KB here)
// plus a few bytes of slack for the word-copy overruns.
std::uint32_t NzCdDict(const std::uint8_t* in, std::uint32_t in_size,
                       std::uint8_t* out, std::uint32_t out_cap, bool reorder_ascii);

}  // namespace cd
}  // namespace nzr

namespace nzr { namespace cd {
const unsigned char* NzCdCharacterTraits0();
std::uint32_t NzCdDictBucketIndex(unsigned char c_e60, unsigned char c_a60);
const std::uint16_t* NzCdDictBucketStarts();
struct NzCdDictRef { const std::uint16_t* big_initial; const std::uint32_t* big_lo; const std::uint32_t* big_hi; const std::uint16_t* mid_initial; const std::uint32_t* mid; const std::uint32_t* ultrasmall; };
void NzCdDictRefArrays(NzCdDictRef* r);
} }
