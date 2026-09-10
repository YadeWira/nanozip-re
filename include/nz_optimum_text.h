// nz_optimum_text.h -- the text detector of the `-co`/`-cO`/`-cc` compressor.
//
// `-co` and `-cd` share their text TRANSFORMS but not their detectors: `-cd`
// decides with FUN_08064bb0 over the plain histogram of FUN_08054dc0, while this
// family decides in FUN_0808da10's text section over the much richer object of
// FUN_08054b50, which deduplicates repeats, keeps a second score and a mean line
// length, and drives eight predicates instead of two. That difference is the
// whole reason `-co` reaches for the transform where `-cd` does not.
//
// Decompiles: ~/.cache/nzre_tools/encode/decomp/optimum_encoder_2.c (the driver),
// lzpf_audio_model.c (FUN_08054b30/b50/e60/e90/ee0/f10/f50/f80/fe0) and
// tt_encoder_missing.c (FUN_080550c0). Policy: docs/CO_TEXT_TRANSFORM.md.
#pragma once
#include <cstdint>
#include <vector>

namespace nzr::opt_enc {

// FUN_08054b50's stack object, laid out as the original's offsets.
struct CoTextObj {
    std::uint32_t hist[256];   // +0x000  byte counts
    std::uint32_t n;           // +0x400  the sample size
    std::uint32_t dedup;       // +0x404  positions the scan visited, from 1
    std::uint8_t  s9d;         // +0x408  sum(hist[traits & 0x9d]) * 100 / dedup
    std::uint8_t  s19;         // +0x409  sum(hist[traits & 0x19]) * 100 / dedup
    std::uint8_t  pad[2];      // +0x40a
    std::uint32_t meanline;    // +0x40c  sum of line-feed gaps over hist[10] + 1
};

// FUN_08054b50 over `n` bytes (the driver passes the block size >> 3). Reads a
// few bytes past `n`, as the original does, so `buf` must hold the whole block.
// Under 16 bytes the original leaves its stack object as it found it; this zeroes
// it, which reads as "not text".
void CoTextAnalyze(CoTextObj& o, const std::uint8_t* buf, std::uint32_t n);

// The eight predicates, in the order docs/CO_TEXT_TRANSFORM.md lists them.
bool CoIsText(const CoTextObj& o);        // FUN_08054e60
bool CoInsertLfFits(const CoTextObj& o);  // FUN_08054b30
bool CoHtmlFits(const CoTextObj& o);      // FUN_08054e90
bool CoEnoughDigits(const CoTextObj& o);  // FUN_08054ee0
bool CoMostlyDigits(const CoTextObj& o);  // FUN_08054f10
bool CoNumber1(const CoTextObj& o);       // FUN_08054f50
bool CoCrlfFits(const CoTextObj& o);      // FUN_08054f80
bool CoNumber2(const CoTextObj& o);       // FUN_08054fe0

// FUN_080550c0: the `-co`-only digit route. Counts nonzero integers below 256
// that are followed by a dot, and accepts when the count exceeds `n >> 8`.
bool CoDigitDotFits(const std::uint8_t* buf, std::uint32_t n);

// FUN_0808da10's text section: the transform bits the block asks for, or 0.
// `scratch` needs the block's own capacity (the chess and line-RLE detectors
// encode into it). `cm` is true only for `-cc`, whose CM object is non-null and
// which suppresses the digit route. `*number_route` reports whether the mask came
// from that route, which is what `-cc` suppresses.
std::uint32_t CoTextFlags(const std::uint8_t* buf, std::uint32_t n, std::uint8_t* scratch,
                          bool cm, bool* number_route);

// The aux stream's room, read out of the original's object under GDB at every
// -m from 2m to 64m: the side streams of insert-LF and the number pass may use
// half of it.
constexpr std::uint32_t kCoAuxStreamBytes = 4299161u;

// FUN_08052ec0: the entropy estimate the number step's trial compares. `before4`
// is the four bytes preceding `buf` (nullptr = zeros) and `after` the byte past
// its end, both of which the original reads.
std::uint32_t CoEntropyEstimate(const std::uint8_t* buf, std::uint32_t n);

// FUN_08059060 for this family: the whole chain in the original's order, with the
// dictionary's inverse ASCII reorder (`reorder_ascii`, true for -co/-cO) and
// the number step's second-half trial. `buf`/`tmp` are swapped as steps land.
// Returns the new size and the applied bits, or 0; the two side streams come
// back in `tt2` and `tt16`.
std::uint32_t CoTextPipeline(std::uint32_t bits, std::uint8_t*& buf, std::uint32_t n, std::uint8_t*& tmp,
                             std::uint32_t cap, std::uint8_t* applied, std::vector<std::uint8_t>* tt2,
                             std::vector<std::uint8_t>* tt16, bool reorder_ascii, bool cm);

// FUN_080b8910: the side streams as the block carries them -- a LEB128 length
// and the bytes, tt2 then tt16, each only when its bit applied. Appends to
// `out`, returns the bytes appended.
std::uint32_t CoSideStreamBytes(std::uint8_t applied, const std::vector<std::uint8_t>& tt2,
                                const std::vector<std::uint8_t>& tt16, std::vector<std::uint8_t>* out);

// FUN_0808f8e0: does the transform pay? Codes a sample of min(n >> 3, 128 KB)
// with the BWT bucket coder as it is and after the pipeline (plus the side
// streams), and accepts only when the transformed sample codes smaller by more
// than a thousandth. Returns true to apply.
bool CoTrialGate(const std::uint8_t* buf, std::uint32_t n, std::uint32_t mask, bool reorder_ascii, bool cm);

}  // namespace nzr::opt_enc
