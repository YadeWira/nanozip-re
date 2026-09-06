// Native linux32 `-co` (nz_optimum1) LZ/CM engine. See include/nz_optimum_lz.h
// for the architecture summary and RE provenance. This file is a careful,
// mostly line-by-line transcription of the real binary's FUN_0809e600 (Ghidra
// decompile captured in full, 860 raw lines, cross-checked against live
// disassembly + GDB register traces for every offset/formula below -- NOT a
// "clean reimplementation from understanding": several of this project's own
// prior RE sessions flagged the literal 4-context mixer's node-advance
// mechanism (DecodeLiteralByte below) as intricate and not independently
// re-derived from first principles, so it is transcribed verbatim, preserving
// the original decompile's variable names (uVar8/uVar10/uVar15/..., iVar9/
// iVar26/..., local_a4/local_ac/...) rather than renamed/refactored, precisely
// so it can be diffed against the source decompile by a future reader.
//
// Memory model: the real FUN_0809e600 addresses two completely separate chunks
// of memory via plain pointer arithmetic:
//   - `param_1` (the "compact" subengine's persistent 0x3f700-byte object) --
//     every `*(TYPE*)(param_1 + OFFSET)` access below becomes `Rd8/Wr8/Rd16/
//     Wr16/Rd32/Wr32(OFFSET)` against `mem_`. This uniformly covers BOTH the
//     genuinely-persistent adaptive-probability tables (mixer weights, the 4
//     literal contexts, the dispatch-bit table, all length/distance tables)
//     AND the transient "scratch pointer" fields the original code also stores
//     at fixed param_1-relative offsets (e.g. 0x3f6d4, 0x29674) purely to
//     avoid recomputing an address between a table read and its matching
//     update a few lines later -- there is no need to (and this port
//     deliberately does not try to) classify which offsets are "real state"
//     vs "scratch": mem_ persists for the object's whole lifetime exactly like
//     the original, so scratch fields simply get overwritten before their next
//     use, exactly as in the original.
//   - `&local_5c` (a small ring/window-cursor struct on the real stack,
//     swapped in from and back out to a per-container persistent descriptor at
//     param_1+0x40 via FUN_080bd350/FUN_080bd300) -- this becomes `ring_`
//     (Ring::Base()/cursor/capacity), which this port keeps as a genuinely
//     persistent member (one NzOptimumLzDecoder instance per container stream)
//     since a single container can have multiple sequential decr_param==1
//     blocks sharing one window.
#include "nz_env.h"
// NZOPT_* trace/dump switches on the -co core's per-bit path: compiled in only with -DNZOPT_DEBUG.
#ifdef NZOPT_DEBUG
#define O1_DBG_ENV(name) NZ_ENV(name)
#else
#define O1_DBG_ENV(name) static_cast<const char*>(nullptr)
#endif
#include "nz_optimum_lz.h"
#include "nz_optimum_lz_tables.h"
#include "nz_cm.h"  // kLzModelInterpolation (== the real DAT_08172900, confirmed
                     // byte-for-byte identical this project's own prior RE
                     // session; reused here rather than re-embedded)

#include <cstring>
#include <algorithm>
#include <utility>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>
#include <memory>

// DAT_08172900 == nz_cm.cpp's kLzModelInterpolation (confirmed byte-identical
// this project's own prior RE session: a standalone re-implementation of
// nz_cm.cpp's Build_kModelInterpolation()+LzCreateTables() was compiled and
// diffed byte-for-byte against a live GDB dump of the real DAT_08172900 -- zero
// differences). kLzModelInterpolation is a plain global (not namespaced) in
// nz_cm.cpp; declared here instead of duplicating/re-deriving it.
extern int16_t kLzModelInterpolation[256];

namespace nzr {
namespace optimum {

namespace {

constexpr std::size_t kMemSize = 0x3f700u;

inline std::uint8_t Rd8(const std::uint8_t* mem, int off) {
    return mem[off];
}
inline void Wr8(std::uint8_t* mem, int off, std::uint8_t v) {
    mem[off] = v;
}
inline std::uint16_t Rd16(const std::uint8_t* mem, int off) {
    std::uint16_t v;
    std::memcpy(&v, mem + off, 2);
    return v;
}
inline void Wr16(std::uint8_t* mem, int off, std::uint16_t v) {
    std::memcpy(mem + off, &v, 2);
}
inline std::int32_t Rd32(const std::uint8_t* mem, int off) {
    std::int32_t v;
    std::memcpy(&v, mem + off, 4);
    return v;
}
inline void Wr32(std::uint8_t* mem, int off, std::int32_t v) {
    std::memcpy(mem + off, &v, 4);
}

inline int Stretch(std::uint8_t state) {
    return kLzModelInterpolation[state];
}

// ---------------------------------------------------------------------------
// Binary range decoder. Every per-bit decode in the real function shares this
// exact shape: mid = lo + (prob) * ((hi-lo)>>12) [note: shift-BEFORE-multiply,
// confirmed via exhaustive grep of every decode site in the raw decompile --
// NOT lo + ((hi-lo)*prob)>>12 the way nz_cm.cpp's own ArithmeticDecoder does
// it; a materially different rounding behavior at the margins that must be
// preserved exactly], bit = (code <= mid), renormalize while (lo^hi) < 2^24.
// ---------------------------------------------------------------------------
struct RangeDecoder {
    std::uint32_t lo = 0, hi = 0xffffffffu, code = 0;
    const std::uint8_t* cur = nullptr;
    const std::uint8_t* end = nullptr;

    void Init(const std::uint8_t* in, std::uint32_t in_len) {
        cur = in;
        end = in + in_len;
        lo = 0;
        hi = 0xffffffffu;
        code = 0;
        for (int i = 0; i < 4; i++) code = (code << 8) | ReadByte();
    }

    std::uint32_t ReadByte() {
        if (cur < end) return *cur++;
        return 0;
    }

    void Renormalize() {
        while ((lo ^ hi) < 0x1000000u) {
            hi = (hi << 8) | 0xffu;
            lo = (lo << 8);
            code = (code << 8) | ReadByte();
        }
    }

    // prob: 12-bit probability (0..4095) that the bit is 0 (matches the real
    // "compare = lo + (range>>12)*prob; bit = code<=compare" polarity: bit==1
    // corresponds to code<=mid, i.e. the LOW sub-range).
    std::uint32_t DecodeBit(std::uint32_t prob) {
        std::uint32_t mid = ((hi - lo) >> 12) * prob + lo;
        std::uint32_t bit = (code <= mid) ? 1u : 0u;
        if (bit) hi = mid; else lo = mid + 1u;
        Renormalize();
        return bit;
    }

    // The length coder's raw/equiprobable overflow bits: fixed prob=0x800
    // (exactly 1/2), no adaptive state read or update at all.
    std::uint32_t DecodeRawBit() {
        std::uint32_t mid = ((hi - lo) >> 12) * 0x800u + lo;
        std::uint32_t bit = (code <= mid) ? 1u : 0u;
        if (bit) hi = mid; else lo = mid + 1u;
        Renormalize();
        return bit;
    }
};

// The block loop is one template over the bit source: decoding reads the bit
// from the range decoder (the intended value is ignored), encoding codes the
// intended bit and queues (probability << 2 | bit) the way FUN_0806f8e0 does
// for FUN_0806d8f0's bulk range coder. A raw bit is a bit at probability 0x800.
struct DecodeIO {
    RangeDecoder rc;
    std::uint32_t Bit(std::uint32_t prob, std::uint32_t) { return rc.DecodeBit(prob); }
    std::uint32_t RawBit(std::uint32_t) { return rc.DecodeRawBit(); }
    std::uint32_t Lo() const { return rc.lo; }
    std::uint32_t Hi() const { return rc.hi; }
    std::uint32_t Code() const { return rc.code; }
};
struct EncodeIO {
    std::vector<std::uint16_t>* q = nullptr;
    std::uint32_t Bit(std::uint32_t prob, std::uint32_t intended) {
        q->push_back(static_cast<std::uint16_t>((prob << 2) | (intended & 1u)));
        return intended & 1u;
    }
    std::uint32_t RawBit(std::uint32_t intended) { return Bit(0x800u, intended); }
    std::uint32_t Lo() const { return 0; }
    std::uint32_t Hi() const { return 0; }
    std::uint32_t Code() const { return 0; }
};
// FUN_0806d8f0 over the whole queue, then the single flush byte FUN_0806f8e0 writes.
void RangeEncodePairs(const std::vector<std::uint16_t>& q, std::vector<std::uint8_t>& out) {
    std::uint32_t lo = 0, hi = 0xffffffffu;
    for (std::uint16_t e : q) {
        const std::uint32_t prob = e >> 2, bit = e & 1u;
        const std::uint32_t mid = ((hi - lo) >> 12) * prob + lo;
        if (bit) hi = mid; else lo = mid + 1u;
        while ((hi ^ lo) < 0x1000000u) {
            out.push_back(static_cast<std::uint8_t>(hi >> 24));
            hi = (hi << 8) | 0xffu;
            lo <<= 8;
        }
    }
    out.push_back(static_cast<std::uint8_t>(hi >> 24));
}
inline std::uint32_t BitLenU(std::uint32_t v) { std::uint32_t n = 0; while (v) { ++n; v >>= 1; } return n; }

// Adaptive bit decode against a 16-bit direct-probability cell at mem+off
// (stored value is prob<<4): the real formula reads `(*(ushort*)(mem+off))>>4`,
// OPTIONALLY biases +1 if <0x800 (avoids a zero-width sub-range), decodes,
// then updates the cell via `cell += ((K-cell)+bit*0x10000)>>S` (16-bit
// arithmetic, so the `>>S` truncates the concatenated 32-bit value --
// replicated exactly via uint32_t math then truncating to uint16_t on store).
//
// Neither (K,S) nor the +1 bias is uniform across every table using this
// shape -- confirmed by disassembling every call site individually (NOT
// inferred/assumed) in the real binary:
//   rep-selector (0x3d980 unit table):        K=0x10,S=5, WITH bias
//   length unary/raw-count (0x396c0+bias):    K=0x10,S=5, WITH bias
//   length extra-bits (0x396c0+persisted..):  K=8,   S=4, NO bias
//   distance tier-1 (0x39f40+0xf80+slot*.60): K=8,   S=4, NO bias
//   distance tier-2/align (external table):   K=0x10,S=5, NO bias  <- same
//     (K,S) as the two "WITH bias" tables above but confirmed via direct
//     disassembly (0x080a01f5-0x080a0207 in a captured full disassembly) to
//     have NO cmp-$0x7ff/setbe bias step at all; the bias is genuinely an
//     independent per-call-site design choice, not derivable from (K,S).
//   distance tier-3 (0x39f40+0x380+(slot-6)*.60): K=0x20,S=6, NO bias
template <class IO>
std::uint32_t DecodeAdaptiveKSB(IO& io, std::uint8_t* mem, int off,
                                 std::uint32_t K, std::uint32_t S, bool bias, std::uint32_t intended) {
    std::uint32_t cell = Rd16(mem, off);
    std::uint32_t prob = cell >> 4;
    if (bias) prob = prob + ((prob < 0x800u) ? 1u : 0u);
    std::uint32_t bit = io.Bit(prob, intended);
    std::uint32_t upd = (std::uint32_t)((std::int32_t)((K - cell) + bit * 0x10000u) >> S) + cell;
    Wr16(mem, off, (std::uint16_t)upd);
    return bit;
}
template <class IO>
inline std::uint32_t DecodeAdaptiveKS(IO& io, std::uint8_t* mem, int off,
                                       std::uint32_t K, std::uint32_t S, std::uint32_t intended) {
    return DecodeAdaptiveKSB(io, mem, off, K, S, /*bias=*/false, intended);
}
template <class IO>
inline std::uint32_t DecodeAdaptive16(IO& io, std::uint8_t* mem, int off, std::uint32_t intended) {
    return DecodeAdaptiveKSB(io, mem, off, 0x10u, 5u, /*bias=*/true, intended);
}

// Ring-buffer byte access by LOGICAL position (can legitimately be a small
// negative number, e.g. reading a position 1-4 bytes "before" a cursor near
// the very start of the window -- these fall into the 256-byte prefix mirror
// this project's Ring keeps at Base()-256). `logical_pos` arrives as a
// uint32_t (natural from the surrounding modular-ring arithmetic, which
// relies on wraparound), so a small negative value looks like e.g.
// 0xfffffffc; casting straight to a pointer offset would zero-extend that to
// +4 billion instead of -4 and read wildly out of bounds. Reinterpreting as
// int32_t first fixes that (sign-extends correctly through 64-bit pointer
// arithmetic) while leaving genuinely-large legitimate offsets (well under
// INT32_MAX for any realistic window capacity) unaffected.
inline std::uint8_t& RingAt(std::uint8_t* base, std::uint32_t logical_pos) {
    return base[static_cast<std::int32_t>(logical_pos)];
}
inline std::uint8_t RingAt(const std::uint8_t* base, std::uint32_t logical_pos) {
    return base[static_cast<std::int32_t>(logical_pos)];
}

// The external "align" table FUN_0809e600 reaches through a stored pointer at
// param_1+0x3d640 (confirmed via GDB: this offset is read-only within the
// whole function -- grep found exactly one reference -- so it must be
// initialized once, outside FUN_0809e600, to a small separately-allocated
// buffer; live GDB dumps at the pointer target across 4 different archives
// all showed the same cold-uniform 0x8000-per-u16-entry pattern as every
// other length/distance table, just living outside the main 0x3f700 object).
// This port places that table inline at the end of `mem_` instead of chasing
// a fake pointer value.
constexpr int kAlignTableOff = static_cast<int>(kMemSize);
constexpr std::size_t kAlignTableSize = 128u;  // generous; real usage needs <64B
constexpr std::size_t kTotalMemSize = kMemSize + kAlignTableSize;

}  // namespace

// ---------------------------------------------------------------------------
// Window size formula (method_p1 -> ring capacity). See header for the
// formula's provenance.
// ---------------------------------------------------------------------------
std::uint32_t NzOptimumLzWindowSizeFromP1(std::uint8_t method_p1) {
    std::uint32_t xp1 = static_cast<std::uint32_t>(method_p1) + 1u;
    std::uint32_t m = xp1 & 0xfu;
    std::uint32_t s = xp1 >> 4;
    if (s) m = (m + 16u) << (s - 1u);
    return m << 16;
}

// ---------------------------------------------------------------------------
// NzOptimumLzDecoder
// ---------------------------------------------------------------------------
NzOptimumLzDecoder::NzOptimumLzDecoder(std::uint32_t window_capacity) {
    mem_ = OptimumColdState();
    mem_.resize(kTotalMemSize, 0);
    // The extra "align table" region cold-starts at 0x8000 per u16 entry,
    // exactly like every other length/distance adaptive table (see
    // kAlignTableOff's comment above).
    for (std::size_t i = 0; i < kAlignTableSize; i += 2) {
        mem_[kAlignTableOff + i] = 0x00;
        mem_[kAlignTableOff + i + 1] = 0x80;
    }
    ring_.capacity = window_capacity;
    ring_.storage.assign(static_cast<std::size_t>(window_capacity) + 512u, 0u);
    ring_.cursor = 0;
    ring_.scrolled_once = false;
}

void NzOptimumLzDecoder::ResetModel() {
    mem_ = OptimumColdState();
    mem_.resize(kTotalMemSize, 0);
    for (std::size_t i = 0; i < kAlignTableSize; i += 2) {
        mem_[kAlignTableOff + i] = 0x00;
        mem_[kAlignTableOff + i + 1] = 0x80;
    }
}

std::uint32_t NzOptimumLzDecoder::Ring::EnsureHeadroom(std::uint32_t needed) {
    std::uint32_t cap = capacity;
    std::uint32_t cur = cursor;
    if (cap - cur < needed) {
        std::uint8_t* b = Base();
        if (!scrolled_once) {
            scrolled_once = true;
            std::memset(b + cur, 0, static_cast<std::size_t>(cap - cur) + 256u);
        }
        cursor = 0;
        std::memcpy(b - 256, b + cap - 256, 256);
    }
    return cursor;
}

// ---------------------------------------------------------------------------
// DecodeBlock -- transcription of FUN_0809e600.
//
// Variable names below deliberately mirror the raw Ghidra decompile
// (uVar8/uVar10/uVar15/uVar17/uVar18/uVar20/uVar21, iVar9/iVar26,
// local_a4/local_ac/local_a8/local_a0/local_9c/local_81/local_94) rather than
// being renamed for "clarity" -- every offset/shift/mask constant below was
// copied directly from the captured decompile
// (/tmp/nzre_work/optdbg/ghidra_full_9e600.log in the RE session's scratch
// area; see the architecture doc for the equivalent excerpts) and cross-
// checked against live disassembly for the sections the architecture doc
// flagged as empirically ground-truth-verified (dispatch bit, rep-slot select,
// length, distance). All `param_1`-relative memory accesses become Rd8/Wr8/
// Rd16/Wr16(mem, OFFSET) calls using the exact same offset arithmetic as the
// original (mem_.data() stands in for `param_1`); the original's small handful
// of pure bookkeeping "scratch pointer" fields (addresses stored purely to
// avoid recomputing them a few lines later, e.g. 0x3f6d4/0x29674) are kept as
// plain local C++ variables instead of round-tripping through `mem`, since
// they are always written immediately before being read and never need to
// survive past the current bit/byte -- this is a pure bookkeeping
// simplification, not a behavioral change.
// ---------------------------------------------------------------------------
template <class IO>
bool NzOptimumLzDecoder::RunBlock(IO& io, const OptimumDecision* dec, std::size_t ndec,
                                  std::uint8_t* out, std::uint32_t out_size) {
    if (out_size == 0) return true;
    if (O1_DBG_ENV("NZOPT_DEBUG"))
        fprintf(stderr, "ENTER DecodeBlock ndec=%u out_size=%u cursor=%u capacity=%u\n",
                (unsigned)ndec, out_size, ring_.cursor, ring_.capacity);
    // the decision cursor (encode side); a zero decision when decoding
    std::size_t di = 0;
    OptimumDecision cur{};
    if (dec != nullptr && ndec != 0) cur = dec[0];
    else if (feed_) { OptimumDecision d{}; if (feed_(d)) cur = d; }
    auto next_dec = [&]() {
        if (dec != nullptr) { ++di; cur = (di < ndec) ? dec[di] : OptimumDecision{}; }
        else if (feed_) { OptimumDecision d{}; cur = feed_(d) ? d : OptimumDecision{}; }
    };

    std::uint32_t rep[4] = {1, 1, 1, 1};
    std::uint8_t* mem = mem_.data();
    // Debug-only position tracker for NZOPT_TRACE3_POS instrumentation below
    // (set right before the literal loop that uses it); must be declared
    // before MixerBit's lambda definition so the by-reference capture sees it.
    std::uint32_t debugPos = 0;

    // ---- shared literal-mixer helpers (used for BOTH bits of each LOOP-B
    // iteration; the raw decompile inlines/duplicates this logic twice with
    // only the context/APM-row inputs differing -- factored here to avoid
    // copy-paste divergence between the two call sites, NOT to "simplify" the
    // math itself, which is transcribed verbatim). ----

    // One mixer bit: read the 4 context cells, mix via the per-row weights,
    // refine via the 11-row APM2 table (true byte base 0x20670 -- see the
    // units-doubling note below), range-decode, then update everything
    // (weights, the 4 context cells, the APM2 cell). Returns (bit, pFinal)
    // where pFinal is needed by the caller's node-advance step to compute the
    // next confidence flag.
    auto MixerBit = [&](int ctxA, int ctxB, int ctxCoff, int ctxDoff,
                         std::uint32_t uVar10, std::uint32_t uVar15b,
                         std::uint32_t apm2RowExtra,
                         std::uint32_t intended, std::uint32_t* outPFinal) -> std::uint32_t {
        std::uint8_t sA = Rd8(mem, ctxA);
        std::int32_t stA = Stretch(sA);
        std::uint8_t sB = Rd8(mem, ctxB);
        std::int32_t stB = Stretch(sB);
        std::uint8_t sC = Rd8(mem, ctxCoff);
        std::int32_t stC = Stretch(sC);
        std::uint8_t sD = Rd8(mem, ctxDoff);
        std::int32_t stD = Stretch(sD);

        int wRowOff = 0x60 + static_cast<int>((((uVar15b >> 6) & 3u) + (uVar10 >> 8) * 4u) * 0x10u);
        std::int32_t w0 = Rd32(mem, wRowOff + 0);
        std::int32_t w1 = Rd32(mem, wRowOff + 4);
        std::int32_t w2 = Rd32(mem, wRowOff + 8);
        std::int32_t w3 = Rd32(mem, wRowOff + 12);
        if (const char* dpp = O1_DBG_ENV("NZOPT_TRACE3_POS")) {
            if (debugPos == static_cast<std::uint32_t>(atoi(dpp))) {
                fprintf(stderr, "    MixerBit pos=%u wRowOff=%#x w=(%d,%d,%d,%d) sA=%u sB=%u sC=%u sD=%u stA=%d stB=%d stC=%d stD=%d apm2RowExtra=%u uVar10=%u uVar15b=%u lo=%#x hi=%#x code=%#x\n",
                        debugPos, wRowOff, w0, w1, w2, w3, sA, sB, sC, sD, stA, stB, stC, stD, apm2RowExtra, uVar10, uVar15b, io.Lo(), io.Hi(), io.Code());
            }
        }

        std::int32_t dot = stB * w1 + stC * w2 + stA * w0 + w3 * stD;
        std::int32_t p_s = (dot >> 16) + 0x800;
        std::uint32_t p = (p_s < 0) ? 0u : static_cast<std::uint32_t>(p_s);
        // real: `p = ((-(uint)(p<0xfff) & (p-0xfff)) + 0xfff) * 0xb` -- this is
        // just `min(p,0xfff)*0xb` (the masked term wraps back to `p` via
        // unsigned overflow when p<0xfff, since (p-0xfff)+0xfff==p mod 2^32).
        p = ((p < 0xfffu) ? p : 0xfffu) * 0xbu;
        std::uint32_t frac = p & 0xfffu;
        // units fix: real `iVar26_units=(p>>12)+0x10338+apm2RowExtra*0xc`,
        // addr=param_1+iVar26_units*2; true byte base = 0x10338*2 = 0x20670,
        // row stride = 0xc*2 = 0x18 (24) bytes (12 u16 entries/row).
        int apm2Off = 0x20670 + static_cast<int>(apm2RowExtra) * 24 + static_cast<int>(p >> 12) * 2;
        std::uint16_t aLo = Rd16(mem, apm2Off);
        std::uint16_t aHi = Rd16(mem, apm2Off + 2);
        int aNear = apm2Off + static_cast<int>((frac >> 11) * 2u);
        std::uint16_t aOld = Rd16(mem, aNear);
        std::uint32_t mixed = (static_cast<std::uint32_t>(aLo) * (0x1000u - frac) +
                               frac * static_cast<std::uint32_t>(aHi)) >> 16;
        std::uint32_t pFinal = mixed + ((mixed < 0x800u) ? 1u : 0u);

        std::uint32_t bit = io.Bit(pFinal, intended);

        Wr16(mem, aNear,
             static_cast<std::uint16_t>((static_cast<std::int32_t>(bit * 0x1007eu - aOld) >> 7) + aOld));
        std::int32_t err = static_cast<std::int32_t>(bit * 0xfffu - pFinal) * 8;
        Wr32(mem, wRowOff + 0, w0 + ((stA * err) >> 16));
        Wr32(mem, wRowOff + 4, w1 + ((stB * err) >> 16));
        Wr32(mem, wRowOff + 8, w2 + ((stC * err) >> 16));
        Wr32(mem, wRowOff + 12, w3 + ((err * stD) >> 16));

        std::uint32_t upd8 = bit * 0x100u;
        Wr8(mem, ctxDoff, static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - sD) + upd8) >> 3) + sD));
        Wr8(mem, ctxA,    static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - sA) + upd8) >> 3) + sA));
        Wr8(mem, ctxB,    static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - sB) + upd8) >> 3) + sB));
        Wr8(mem, ctxCoff, static_cast<std::uint8_t>((static_cast<std::int32_t>(upd8 - sC + 2u) >> 2) + sC));

        *outPFinal = pFinal;
        return bit;
    };

    // Shared "node advance" tail (raw decompile lines ~318-358 / ~439-475,
    // confirmed byte-for-byte symmetric between bit1 and bit2 -- transcribed
    // verbatim, not re-derived from intuition, per this project's established
    // caution about this specific mechanism). Writes the 0x29690 confidence
    // flag, advances ctxA/ctxB in place, and returns the (nextC, nextD)
    // context indices for the following bit.
    auto NodeAdvance = [&](std::uint32_t bit, std::uint32_t pFinal, int& ctxA, int& ctxB,
                           std::uint32_t uVar15b_old) -> std::pair<std::uint32_t, std::uint32_t> {
        if (O1_DBG_ENV("NZOPT_TRACE_NA") && debugPos == static_cast<std::uint32_t>(atoi(O1_DBG_ENV("NZOPT_TRACE_NA")))) {
            fprintf(stderr, "  NA-IN bit=%u pFinal=%u ctxA=%#x ctxB=%#x uVar15b_old=%u subcIn=%u shiftregIn=%u\n",
                    bit, pFinal, ctxA, ctxB, uVar15b_old, Rd8(mem, 0x2968d), Rd8(mem, 0x2968c));
        }
        Wr8(mem, 0x29690, (0xa01u < (bit * 0x1000u - pFinal) + 0x500u) ? std::uint8_t{1} : std::uint8_t{0});

        std::uint8_t shiftreg = static_cast<std::uint8_t>(bit + Rd8(mem, 0x2968c) * 2);
        Wr8(mem, 0x2968c, shiftreg);
        Wr16(mem, 0x29684, static_cast<std::uint16_t>(Rd16(mem, 0x29684) << 1));
        std::uint8_t subc = static_cast<std::uint8_t>(Rd8(mem, 0x2968d) + 1);
        Wr8(mem, 0x2968d, subc);

        std::uint32_t nodeStep;
        if (subc == 4) {
            std::uint8_t scaleAcc = Rd8(mem, 0x2968f);
            nodeStep = (static_cast<std::uint32_t>(shiftreg) * 0xfu - scaleAcc) - 0xe1u;
        } else {
            nodeStep = (bit + 1u) << ((subc & 3u) - 1u);
            std::uint8_t scaleAcc = Rd8(mem, 0x2968f);
            Wr8(mem, 0x2968f, static_cast<std::uint8_t>(scaleAcc + static_cast<std::uint8_t>(nodeStep)));
        }
        ctxA += static_cast<int>(nodeStep);
        ctxB += static_cast<int>(nodeStep);

        std::uint16_t hist29684 = Rd16(mem, 0x29684);  // POST-shift value (shift already applied above)
        std::uint16_t curD = static_cast<std::uint16_t>(
            ((static_cast<std::uint32_t>(hist29684) >> 6) & 2u) +
            static_cast<std::uint32_t>(subc >> 1) * 4u +
            (uVar15b_old & 0xfff0u) +
            (((static_cast<std::uint32_t>(hist29684) >> 8) == shiftreg) ? 1u : 0u));
        Wr16(mem, 0x29688, curD);

        std::uint16_t oldTreeC = Rd16(mem, 0x29682);
        std::uint16_t treeTemp = static_cast<std::uint16_t>((oldTreeC & 0xff00u) | shiftreg);
        Wr16(mem, 0x29682, treeTemp);
        std::uint16_t curC;
        if (oldTreeC < 0x200u) {
            curC = treeTemp;
        } else {
            curC = static_cast<std::uint16_t>(static_cast<std::uint32_t>(shiftreg) + 0x100u);
            Wr16(mem, 0x29682, curC);
            if (bit == (oldTreeC & 1u)) {
                std::uint8_t hist2968e = Rd8(mem, 0x2968e);
                std::uint8_t confid2 = static_cast<std::uint8_t>(hist2968e * 2);
                Wr8(mem, 0x2968e, confid2);
                std::int16_t signext = static_cast<std::int16_t>(static_cast<std::int8_t>(shiftreg));
                std::uint32_t hi = (static_cast<std::uint16_t>(~signext) >> 15) *
                                    (static_cast<std::uint32_t>(shiftreg) * 2u);
                curC = static_cast<std::uint16_t>(hi + 0x200u + (static_cast<std::uint32_t>(confid2) >> 7));
                Wr16(mem, 0x29682, curC);
            }
        }
        if (O1_DBG_ENV("NZOPT_TRACE_NA") && debugPos == static_cast<std::uint32_t>(atoi(O1_DBG_ENV("NZOPT_TRACE_NA")))) {
            fprintf(stderr, "  NA-OUT ctxA=%#x ctxB=%#x curC=%u curD=%u m29690=%u m29684=%#x m29688=%#x m2968f=%u m2968d=%u\n",
                    ctxA, ctxB, curC, curD, Rd8(mem, 0x29690), Rd16(mem, 0x29684), Rd16(mem, 0x29688),
                    Rd8(mem, 0x2968f), Rd8(mem, 0x2968d));
        }
        return std::make_pair(static_cast<std::uint32_t>(curC), static_cast<std::uint32_t>(curD));
    };

    if (const char* rd = O1_DBG_ENV("NZOPT_DUMP_RING")) {
        // Whole ring (with the 256-byte prefix mirror and tail slack) at block
        // entry, one file per DecodeBlock call, for diffing against the original.
        static int seq = 0; char nm[512];
        snprintf(nm, sizeof(nm), "%s.%d", rd, seq++);
        if (FILE* f = fopen(nm, "wb")) { fwrite(ring_.storage.data(), 1, ring_.storage.size(), f); fclose(f); }
        fprintf(stderr, "[OPT] DecodeBlock entry: cursor=%u capacity=%u scrolled=%d rep=%u,%u,%u,%u in_len=%u out_size=%u -> %s\n",
                ring_.cursor, ring_.capacity, (int)ring_.scrolled_once, rep[0], rep[1], rep[2], rep[3], (unsigned)ndec, out_size, nm);
    }
    std::uint32_t local_74 = 0;     // absolute bytes produced so far (this call)
    std::uint8_t  local_81 = 0xff;  // recent literal(1)/match(0) decision history
    std::uint32_t local_9c = 0;     // recent-2-bytes accumulator (see header comment)

    while (local_74 < out_size) {
        std::uint32_t chunk_size = std::min(out_size - local_74, 0x8000u);
        // NOTE: the architecture doc's pseudocode reads `iVar9 =
        // FUN_080bd380(&window, chunk_size); if (iVar9 == 0)
        // FUN_080bcc00(param_1+0x40);` and separately states FUN_080bcc00 is
        // a no-op, which would suggest this branch has zero effect. An
        // earlier attempt at "fixing" this to a plain EnsureHeadroom() call
        // (removing the rep reset) was tried and reverted in this same
        // session: it broke smalldist_co (which scrolls the ring inside a
        // single DecodeBlock call) at the exact scroll boundary, so the
        // doc's "no-op" annotation is evidently incomplete/wrong for
        // whatever `iVar9==0` actually signals here, or FUN_080bcc00 is not
        // as side-effect-free as documented. Keep the rep reset -- it is
        // empirically required for byte-exact decode across a real ring
        // scroll and is validated against all 4 golden vectors.
        std::uint32_t headroom = ring_.EnsureHeadroom(chunk_size);
        if (headroom == 0) {
            rep[0] = rep[1] = rep[2] = rep[3] = 1;
        }
        std::uint8_t* base = ring_.Base();
        std::uint32_t chunk_start = ring_.cursor;
        std::uint32_t local_50 = chunk_start + chunk_size;  // chunk_end

        std::uint32_t saved4;
        std::memcpy(&saved4, base + local_50, 4);

        // Revalidate rep offsets against the (possibly just-scrolled) window.
        for (int k = 0; k < 4; k++) {
            std::uint32_t p = chunk_start - (rep[k] + 1u);
            if (chunk_start < rep[k] + 1u) p += ring_.capacity;
            if (ring_.capacity <= p || (p < local_50 && chunk_start <= p))
                rep[k] = 1;
        }

        std::uint32_t local_94 = chunk_size;
        std::uint32_t local_54 = chunk_start;
        bool failed = false;

        do {  // one (literal run; one match) cycle
            std::uint32_t uVar15 = 0;  // dispatch-bit packed matchmask/predicted_byte
            for (;;) {  // LOOP-A: dispatch bit, one output position per iter
                if (const char* dlh = O1_DBG_ENV("NZOPT_DUMP_LOHI"); dlh && local_54 <= static_cast<std::uint32_t>(atoi(dlh))) {
                    const char* dlm = O1_DBG_ENV("NZOPT_DUMP_LOHI_MIN");
                    std::uint32_t minp = dlm ? static_cast<std::uint32_t>(atoi(dlm)) : 0u;
                    if (local_54 >= minp) {
                        fprintf(stderr, "%u %#x %#x %#x rep=[%u,%u,%u,%u]\n", local_54, io.Lo(), io.Hi(), io.Code(),
                                rep[0], rep[1], rep[2], rep[3]);
                    }
                }
                std::uint32_t iVar26 = local_54 - (rep[0] + 1u);
                if (local_54 < rep[0] + 1u) iVar26 += ring_.capacity;
                std::uint32_t pos_of_pred = iVar26;
                {
                    std::uint32_t boundcheck = iVar26 - 4u;
                    if (boundcheck < local_50 && local_54 <= boundcheck) {
                        pos_of_pred = local_54 - 1u;  // fallback: repeat-last-byte prediction
                    }
                }
                std::uint8_t predB = RingAt(base, pos_of_pred);
                std::uint8_t pm1 = RingAt(base, pos_of_pred - 1u), pm2 = RingAt(base, pos_of_pred - 2u);
                std::uint8_t pm3 = RingAt(base, pos_of_pred - 3u), pm4 = RingAt(base, pos_of_pred - 4u);
                std::uint8_t am1 = RingAt(base, local_54 - 1u), am2 = RingAt(base, local_54 - 2u);
                std::uint8_t am3 = RingAt(base, local_54 - 3u), am4 = RingAt(base, local_54 - 4u);
                std::uint32_t matchmask = (pm1 == am1 ? 1u : 0u) |
                                          ((pm2 == am2 ? 1u : 0u) << 1) |
                                          ((pm3 == am3 ? 1u : 0u) << 2) |
                                          ((pm4 == am4 ? 1u : 0u) << 3);
                uVar15 = matchmask | (static_cast<std::uint32_t>(predB) << 24) |
                         (static_cast<std::uint32_t>(am2) << 16);

                int dispIdx = static_cast<int>((matchmask & 7u) + static_cast<std::uint32_t>(predB) * 8u);
                std::uint8_t dat380 = OptimumDat08172380()[local_81];
                std::uint32_t apmRow = (matchmask & 0xfu) + static_cast<std::uint32_t>(dat380) * 8u;

                std::uint8_t dstate = Rd8(mem, 0x3e380 + dispIdx);
                std::uint32_t apmIn = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(Stretch(dstate)) * 4 + 0x2000);
                std::uint32_t frac = apmIn & 0xfffu;
                // units fix: real base 0x1f5c8 (units) -> true byte base 0x3eb90,
                // row stride 5*2=10 bytes.
                int apmCellOff = 0x3eb90 + static_cast<int>(apmRow) * 10 + static_cast<int>(apmIn >> 12) * 2;
                std::uint16_t apmLo = Rd16(mem, apmCellOff);
                std::uint16_t apmHi = Rd16(mem, apmCellOff + 2);
                int nearOff = apmCellOff + static_cast<int>((frac >> 11) * 2u);
                std::uint16_t apmOld = Rd16(mem, nearOff);

                // real: `uVar18 = state*0x10 + 2 + (interp>>0x10)*3 >> 2` -- C
                // operator precedence means the FINAL >>2 applies to the WHOLE
                // sum (state*16+2+interp*3), not just the interp term; confirmed
                // against live disassembly (0x0809e9a5-e9b7: lea sums all three
                // terms THEN a separate `shr $0x2` over the total).
                std::uint32_t interpTerm =
                    ((static_cast<std::uint32_t>(apmLo) * (0x1000u - frac) +
                      frac * static_cast<std::uint32_t>(apmHi)) >> 16) * 3u;
                std::uint32_t mixedP = (static_cast<std::uint32_t>(dstate) * 16u + 2u + interpTerm) >> 2;

                std::uint32_t bit = io.Bit(mixedP + ((mixedP < 0x800u) ? 1u : 0u), cur.is_literal ? 1u : 0u);

                Wr8(mem, 0x3e380 + dispIdx,
                    static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - dstate) + bit * 0x100) >> 3) + dstate));
                Wr16(mem, nearOff,
                     static_cast<std::uint16_t>((static_cast<std::int32_t>(bit * 0x1001e - apmOld) >> 5) + apmOld));

                if (O1_DBG_ENV("NZOPT_TRACE") && local_54 >= 873 && local_54 <= 880) fprintf(stderr, "pos=%u dispatch_bit=%u\n", local_54, bit);
                if (bit == 0) break;  // MATCH path

                if (const char* dp = O1_DBG_ENV("NZOPT_DUMP_POS")) {
                    if (local_54 == static_cast<std::uint32_t>(atoi(dp))) {
                        auto dump = [&](const char* name, int off, int len) {
                            std::string path = std::string("/tmp/claude-1000/-home-forum-git-nanozip/93d70e29-fad1-41da-9662-f8517e7dfa01/scratchpad/port_") + name + ".bin";
                            FILE* f = fopen(path.c_str(), "wb");
                            fwrite(mem + off, 1, len, f);
                            fclose(f);
                        };
                        dump("ctxA", 0x7630, 0x100);
                        dump("ctxB", 0x17e50, 0x100);
                        dump("ctxC", 0x10140, 0x300);
                        dump("ctxD", 0x20460, 0x300);
                        dump("weights", 0x60, 0x80);
                        dump("apm2", 0x20670, 1024);
                        dump("apm2_wide", 0x20670, 0x9000);
                        fprintf(stderr, "DUMPED at pos=%u\n", local_54);
                    }
                }

                // ============ literal byte: 4-context mixer (LOOP-B) ============
                int ctxA = 0x130 + static_cast<int>(local_9c & 0xffu) * 0x100;
                int ctxB = 0x10450 + static_cast<int>((uVar15 >> 8) & 0xff00u);
                std::uint32_t predicted_byte = (uVar15 >> 24) & 0xffu;
                std::uint32_t p9684seed = predicted_byte + 0x100u;
                std::uint32_t ctxD_seed =
                    (local_94 & 3u) * 0x10u + 1u + (uVar15 & 7u) * 0x40u + ((p9684seed >> 6) & 2u);

                Wr16(mem, 0x29684, static_cast<std::uint16_t>(p9684seed));
                Wr8(mem, 0x2968d, 0);
                std::uint32_t ctxC_idx = 1;
                Wr8(mem, 0x2968f, 0);
                Wr8(mem, 0x29690, 0);
                Wr8(mem, 0x2968c, 1);
                Wr16(mem, 0x29682, 1);
                if ((local_81 & 1u) == 0u) {
                    std::uint8_t prevHi = static_cast<std::uint8_t>(local_9c >> 8);
                    Wr8(mem, 0x2968e, prevHi);
                    // Real disassembly (0x0809eb9e-0x0809ebb5): `mov eax,[esp+0x40];
                    // shr eax,8; mov [ebx+0x2968e],al; movzx eax,al; sar eax,7; add
                    // ax,0x202`. The `movzx eax,al` ZERO-extends prevHi into eax
                    // BEFORE the `sar eax,7` -- i.e. eax is always in [0,255], so
                    // `sar eax,7` just extracts bit 7 of prevHi as 0 or 1 (an
                    // unsigned shift in practice, since the value is never
                    // negative). An earlier version of this port instead
                    // sign-extended prevHi to int8_t first (giving -1 for
                    // prevHi>=128), which is wrong: ground-truthed via GDB against
                    // arc_source.cpp.nz's match at distance=23137 (prevHi=0xe2),
                    // where the real binary computes signshift=1 (uv8=0x203) but
                    // the sign-extending version computed signshift=-1 (uv8=0x201)
                    // -- a wrong ctxC seed that desynced the arithmetic decoder a
                    // few bits into the very next literal.
                    std::uint32_t signshift = static_cast<std::uint32_t>(prevHi) >> 7;
                    std::uint32_t uv8 = signshift + 0x202u;
                    Wr16(mem, 0x29682, static_cast<std::uint16_t>(uv8));
                    ctxC_idx = uv8;
                }
                std::uint32_t local_a4 = 0;
                const std::uint32_t litctx = local_9c & 0xffu;
                std::uint32_t litcost = 0;
                local_9c = 0;
                std::uint32_t local_ac = 4;
                std::uint32_t uVar10 = ctxC_idx;
                std::uint32_t uVar15b = ctxD_seed;
                debugPos = local_54;
                bool trace = O1_DBG_ENV("NZOPT_TRACE2") && local_54 <= 1;
                if (trace) fprintf(stderr, "LIT pos=0 ctxA=%#x ctxB=%#x ctxC_seed=%u ctxD_seed=%u predB=%u matchmask=%u\n",
                                    ctxA, ctxB, ctxC_idx, ctxD_seed, predicted_byte, uVar15 & 0xfu);

                while (true) {
                    std::uint32_t pFinal1;
                    std::uint32_t bit1 = MixerBit(ctxA, ctxB, 0x10140 + static_cast<int>(uVar10),
                                                   0x20460 + static_cast<int>(uVar15b),
                                                   uVar10, uVar15b, local_a4 + uVar10 * 2u,
                                                   (static_cast<std::uint32_t>(cur.byte) >> ((7u - 2u * (4u - local_ac)) & 31u)) & 1u, &pFinal1);
                    if (trace) fprintf(stderr, "  bit1=%u pFinal1=%u uVar10=%u uVar15b=%u ctxA=%#x ctxB=%#x\n", bit1, pFinal1, uVar10, uVar15b, ctxA, ctxB);
                    litcost += PriceBit(bit1, pFinal1);
                    auto [curC1, curD1] = NodeAdvance(bit1, pFinal1, ctxA, ctxB, uVar15b);
                    uVar10 = curC1;
                    uVar15b = curD1;

                    std::uint32_t confidByte = Rd8(mem, 0x29690);
                    std::uint32_t pFinal2;
                    std::uint32_t bit2 = MixerBit(ctxA, ctxB, 0x10140 + static_cast<int>(uVar10),
                                                   0x20460 + static_cast<int>(uVar15b),
                                                   uVar10, uVar15b, confidByte + uVar10 * 2u,
                                                   (static_cast<std::uint32_t>(cur.byte) >> ((6u - 2u * (4u - local_ac)) & 31u)) & 1u, &pFinal2);
                    if (trace) fprintf(stderr, "  bit2=%u pFinal2=%u uVar10=%u uVar15b=%u ctxA=%#x ctxB=%#x\n", bit2, pFinal2, uVar10, uVar15b, ctxA, ctxB);
                    litcost += PriceBit(bit2, pFinal2);

                    local_ac -= 1;
                    local_9c = bit2 + (bit1 + local_9c * 2u) * 2u;
                    if (local_ac == 0) break;

                    auto [curC2, curD2] = NodeAdvance(bit2, pFinal2, ctxA, ctxB, uVar15b);
                    uVar10 = curC2;
                    uVar15b = curD2;
                    local_a4 = Rd8(mem, 0x29690);  // refresh for the NEXT iteration's bit1
                }
                if (trace) fprintf(stderr, "LIT pos=0 byte=%#x (%u)\n", local_9c & 0xffu, local_9c & 0xffu);
                if (O1_DBG_ENV("NZOPT_TRACE_LIT") && local_54 >= 132400 && local_54 <= 132410) {
                    fprintf(stderr, "LIT pos=%u byte=%#x w29682=%#x w29684=%#x w29688=%#x w2968c=%#x w2968d=%#x w2968f=%#x w29690=%#x\n",
                            local_54, local_9c & 0xffu,
                            Rd16(mem, 0x29682), Rd16(mem, 0x29684), Rd16(mem, 0x29688),
                            Rd8(mem, 0x2968c), Rd8(mem, 0x2968d), Rd8(mem, 0x2968f), Rd8(mem, 0x29690));
                }

                if (feed_) StoreLiteralCost(litctx, static_cast<std::uint8_t>(local_9c), litcost);
                base[local_54] = static_cast<std::uint8_t>(local_9c);
                local_54 += 1;
                local_94 -= 1;
                local_81 = static_cast<std::uint8_t>(local_81 * 2 + 1);
                if (record_) decisions_.push_back(OptimumDecision{1u, static_cast<std::uint8_t>(local_9c), 0u, 0u, 0u});
                next_dec();
                if (local_94 == 0) goto chunk_done;
            }

            // ===================== MATCH DECODE =====================
            {
                if (const char* dp = O1_DBG_ENV("NZOPT_DUMP_POS")) {
                    if (local_54 == static_cast<std::uint32_t>(atoi(dp))) {
                        FILE* f = fopen("/tmp/claude-1000/-home-forum-git-nanozip/93d70e29-fad1-41da-9662-f8517e7dfa01/scratchpad/port_lentable.bin", "wb");
                        fwrite(mem + 0x396c0, 1, 0x39f40 - 0x396c0, f);
                        fclose(f);
                        fprintf(stderr, "DUMPED lentable pos=%u\n", local_54);
                    }
                }
                int unit_idx = static_cast<int>(((uVar15 & 7u) * 0x10u + (local_81 & 0xfu)) * 8u);
                if (O1_DBG_ENV("NZOPT_TRACE_RS")) fprintf(stderr, "REPSEL pos=%u uVar15&7=%u local_81=%#x unit_idx=%d addr=%#x lo=%#x hi=%#x code=%#x\n",
                                                        local_54, uVar15 & 7u, local_81, unit_idx, 0x3d980+unit_idx*2, io.Lo(), io.Hi(), io.Code());
                if (feed_) RefreshMatchPrices(cur, uVar15, local_81);
                std::uint32_t b1 = DecodeAdaptive16(io, mem, 0x3d980 + unit_idx * 2, cur.sg == 0u ? 1u : 0u);
                if (O1_DBG_ENV("NZOPT_TRACE_RS")) fprintf(stderr, "  after B1: b1=%u lo=%#x hi=%#x code=%#x\n", b1, io.Lo(), io.Hi(), io.Code());
                unit_idx += 1;
                std::uint32_t slot_group = 0;   // 0 == brand-new distance
                if (b1 == 0) {
                    slot_group = 1;
                    for (;;) {
                        std::uint32_t bitk = DecodeAdaptive16(io, mem, 0x3d980 + unit_idx * 2, (cur.sg == slot_group) ? 1u : 0u);
                        unit_idx += 1;
                        if (bitk == 0) slot_group += 1;
                        if (slot_group == 4 || bitk != 0) break;
                    }
                }

                std::uint32_t local_a0 = 4, rep0_bias = 0;
                if (slot_group != 0) {
                    local_a0 = slot_group - 1;
                    rep0_bias = (local_a0 == 0) ? 0x10u : 0u;
                }

                // ---- length ----
                // NOTE: the raw unary/length-class loop (0x396c0-based) uses
                // (K=0x10,S=5) like the rep-selector, but -- confirmed via direct
                // disassembly re-check (0x0809f828-0809f841: `shr $0x4,%edx` goes
                // straight into the mid computation, no `cmp $0x7ff`/`setbe` at
                // all) -- it does NOT get the +1-if-<0x800 bias. An earlier pass
                // over this file misattributed a *different* address's bias check
                // to this loop; DecodeAdaptiveKS (bias=false) is correct here, not
                // DecodeAdaptive16.
                //
                // rep0_bias is a UNIT count (real decompile: `iVar9 =
                // (local_a0==0)<<4`, i.e. 16 UNITS, used later as `iVar25 +
                // iVar9*2` -- the address formula doubles it same as every other
                // per-iteration unit index). An earlier pass applied it directly
                // as a BYTE offset (0x396c0+0x10) instead of doubling it to bytes
                // (0x396c0+0x20) -- ground-truthed via GDB against bigdist_co.nz:
                // real binary's rep0-biased first-unary-bit cell lives at 0x396e0,
                // not 0x396d0 (dumped table diff showed an exact swapped-pair
                // divergence between those two cells' cold/touched state).
                // the encoder's view of the length code: v = len - 2, raw = its bit
                // length (1 for v < 2), U1 = raw - 1 bits follow the leading one
                const std::uint32_t vE = (cur.len >= 2u) ? cur.len - 2u : 0u;
                const std::uint32_t rawE = (vE < 2u) ? 1u : BitLenU(vE);
                const std::uint32_t U1E = rawE - 1u;
                std::uint32_t raw = 0;
                {
                    int lenOff = 0x396c0 + static_cast<int>(rep0_bias) * 2;
                    std::uint32_t b;
                    do {
                        int coff = lenOff + static_cast<int>(raw) * 2;
                        // This unary length loop has NO upper bound in the
                        // original: a corrupt bitstream that keeps returning a
                        // set bit walks `coff` up 2 bytes at a time straight
                        // past the model buffer, and DecodeAdaptiveKSB both
                        // READS and WRITES the cell -- an out-of-bounds heap
                        // write on malformed input. Found by fuzzing single-byte
                        // corruptions of a real archive under ASAN. A valid
                        // stream stays inside the length table, far below this
                        // bound, so declining here cannot reject anything the
                        // original would have decoded.
                        if (coff < 0 || static_cast<std::size_t>(coff) + 2u > mem_.size()) {
                            if (O1_DBG_ENV("NZOPT_DEBUG")) fprintf(stderr, "FAIL@coff: coff=%lld mem=%zu raw=%u local_74=%u local_54=%u\n", (long long)coff, mem_.size(), raw, local_74, local_54);
                            return false;
                        }
                        b = DecodeAdaptiveKS(io, mem, coff, 0x10u, 5u, (raw + 1u < rawE) ? 1u : 0u);
                        raw += 1;
                    } while (b != 0);
                }
                std::uint32_t U1 = raw - 1u;
                std::uint32_t nbits = (raw < 5u) ? std::max<std::uint32_t>(1u, U1) : 4u;
                std::uint32_t local_a4v = (raw > 1u) ? 1u : 0u;
                {
                    std::uint32_t persisted = (slot_group == 0u) ? 3u : 1u;
                    for (std::uint32_t i = 0; i < nbits; i++) {
                        std::uint32_t iVar9u = persisted + U1 * 32u + 0x60u;
                        int cellOff = 0x396c0 + static_cast<int>(iVar9u) * 2;
                        std::uint32_t bit = DecodeAdaptiveKS(io, mem, cellOff, 8u, 4u,
                                                             (rawE == 1u) ? (vE & 1u) : ((vE >> ((U1E - 1u - i) & 31u)) & 1u));
                        if (O1_DBG_ENV("NZOPT_TRACE_RS")) fprintf(stderr, "  extrabit[%u]=%u cellOff=%#x lo=%#x hi=%#x code=%#x\n", i, bit, cellOff, io.Lo(), io.Hi(), io.Code());
                        persisted = bit + persisted * 2u;
                        local_a4v = bit + local_a4v * 2u;
                    }
                }
                if (raw >= 5u) {
                    for (std::uint32_t i = 0; i < U1 - 4u; i++) {
                        std::uint32_t bit = io.RawBit((vE >> ((U1E - 5u - i) & 31u)) & 1u);
                        local_a4v = bit + local_a4v * 2u;
                    }
                }
                std::uint32_t length = local_a4v + 2u;
                if (O1_DBG_ENV("NZOPT_TRACE_RS")) fprintf(stderr, "  LENGTH raw=%u U1=%u local_a4v=%u length=%u lo=%#x hi=%#x code=%#x\n", raw, U1, local_a4v, length, io.Lo(), io.Hi(), io.Code());

                if (local_94 < length) {
                    if (O1_DBG_ENV("NZOPT_DEBUG")) fprintf(stderr, "FAIL@length: local_74=%u local_54=%u local_94=%u length=%u slot_group=%u U1=%u\n", local_74, local_54, local_94, length, slot_group, U1);
                    failed = true; break;
                }

                if (slot_group == 0) {
                    // ---- 5-bit distance slot tree, WITH its own two-cell secondary
                    // refinement (lines 657-694 of the raw decompile) ----
                    // NOTE: this is min(LENGTH ACCUMULATOR VALUE, 15), i.e. `local_a4`
                    // in the raw decompile at this point (still holding the length
                    // decoder's accumulator, local_a4v here -- NOT U1 and NOT the
                    // final length+2). Confirmed via direct GDB address comparison:
                    // using U1 here silently computed a WRONG (but coincidentally
                    // harmless on a cold/virgin table) row bias.
                    std::uint32_t length_code = std::min<std::uint32_t>(local_a4v, 15u);
                    std::uint8_t lengthBucket = OptimumDat081724d0()[length_code];
                    std::uint32_t rowBias = static_cast<std::uint32_t>(lengthBucket) << 5;  // UNITS
                    // the encoder's view: D = dist - 1; slot = its bit length - 1 (0 for D < 2)
                    const std::uint32_t DE = (cur.dist >= 1u) ? cur.dist - 1u : 0u;
                    const std::uint32_t slotE = (DE < 2u) ? 0u : BitLenU(DE) - 1u;
                    const std::uint32_t slotAccE = slotE ^ 0x1fu;
                    std::uint32_t treepos = 1;
                    std::uint32_t slotAcc = 0;
                    for (int i = 0; i < 5; i++) {
                        std::uint32_t iVar9u = treepos + rowBias;
                        int cell1Off = 0x39f40 + static_cast<int>(iVar9u) * 2;
                        std::uint32_t cell1 = Rd16(mem, cell1Off);
                        std::uint32_t prob1 = cell1 >> 4;
                        std::uint32_t iVar26u = static_cast<std::uint32_t>(
                            (static_cast<std::int32_t>(Stretch(static_cast<std::uint8_t>(cell1 >> 8))) + 0x800) >> 8)
                            + 0x140u + treepos * 0x11u;
                        int cell2Off = 0x39f40 + static_cast<int>(iVar26u) * 2;
                        std::uint16_t cell2lo = Rd16(mem, cell2Off);
                        std::uint16_t cell2hi = Rd16(mem, cell2Off + 2);
                        // same whole-sum->2 grouping fix as the dispatch-bit APM combine above.
                        std::uint32_t combined =
                            (prob1 + 2u +
                             (((static_cast<std::uint32_t>(cell2hi) + 1u + static_cast<std::uint32_t>(cell2lo)) >> 5) * 3u)) >> 2;
                        std::uint32_t bit = io.Bit(combined + ((combined < 0x800u) ? 1u : 0u), (slotAccE >> ((4u - static_cast<std::uint32_t>(i)) & 31u)) & 1u);

                        std::uint32_t upd1 = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>((0x10u - cell1) + bit * 0x10000u) >> 5) + cell1;
                        Wr16(mem, cell1Off, static_cast<std::uint16_t>(upd1));
                        std::uint32_t upd2lo = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(bit * 0x1000eu - cell2lo) >> 4) + cell2lo;
                        std::uint32_t upd2hi = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(bit * 0x1000eu - cell2hi) >> 4) + cell2hi;
                        Wr16(mem, cell2Off, static_cast<std::uint16_t>(upd2lo));
                        Wr16(mem, cell2Off + 2, static_cast<std::uint16_t>(upd2hi));

                        if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "    slot-tree bit[%d]=%u treepos_before=%u lo=%#x hi=%#x code=%#x combined=%u cell1Off=%#x cell2Off=%#x\n",
                                                                i, bit, treepos, io.Lo(), io.Hi(), io.Code(), combined, cell1Off, cell2Off);
                        treepos = bit + treepos * 2u;
                        slotAcc = bit + slotAcc * 2u;
                    }
                    std::uint32_t slot = slotAcc ^ 0x1fu;
                    if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "  after slot-tree: lo=%#x hi=%#x code=%#x slot=%u\n", io.Lo(), io.Hi(), io.Code(), slot);

                    std::uint32_t acc = (slot != 0u) ? 1u : 0u;
                    // tier 1: always runs (n1 adaptive bits, MSB-first, its own
                    // small bit-tree with per-slot base 0xf80+slot*0x60,
                    // update (K=8,S=4))
                    {
                        std::uint32_t n1 = (slot < 2u) ? 1u : 2u;
                        std::uint32_t t1pos = 1;
                        for (std::uint32_t i = 0; i < n1; i++) {
                            std::uint32_t iVar9u = t1pos + 0xf80u + slot * 0x60u;
                            int cellOff = 0x39f40 + static_cast<int>(iVar9u) * 2;
                            std::uint32_t bit = DecodeAdaptiveKS(io, mem, cellOff, 8u, 4u,
                                                                 (slot < 2u) ? (DE & 1u) : ((DE >> ((slot - 1u - i) & 31u)) & 1u));
                            t1pos = bit + t1pos * 2u;
                            acc = bit + acc * 2u;
                        }
                    }
                    if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "  after tier1: lo=%#x hi=%#x code=%#x\n", io.Lo(), io.Hi(), io.Code());
                    // tier 2: slot>2, LSB-first bits via the external "align"
                    // table (its own small bit-tree, update (K=0x10,S=5),
                    // NO +1 bias -- confirmed via disassembly, distinct from
                    // every other (K=0x10,S=5) call site in this function).
                    if (slot > 2u) {
                        std::uint32_t n2 = (slot < 6u) ? (slot - 2u) : 4u;
                        acc <<= n2;
                        std::uint32_t t2pos = 1;
                        for (std::uint32_t i = 0; i < n2; i++) {
                            int cellOff = kAlignTableOff + static_cast<int>(t2pos) * 2;
                            std::uint32_t bit = DecodeAdaptiveKSB(io, mem, cellOff, 0x10u, 5u, /*bias=*/false, (DE >> (i & 31u)) & 1u);
                            if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "    tier2 bit[%u]=%u lo=%#x hi=%#x code=%#x t2pos=%u\n", i, bit, io.Lo(), io.Hi(), io.Code(), t2pos);
                            t2pos = bit + t2pos * 2u;
                            acc |= bit << i;
                        }
                    }
                    if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "  after tier2: lo=%#x hi=%#x code=%#x\n", io.Lo(), io.Hi(), io.Code());
                    // tier 3: slot>6, MSB-first bits via a per-(slot-6) adaptive
                    // sub-table (FLAT/incrementing index, NOT a doubling tree;
                    // update (K=0x20,S=6)); final combine matches the raw
                    // decompile's line 799 exactly.
                    if (slot > 6u) {
                        std::uint32_t n3 = slot - 6u;
                        std::uint32_t hi_bits = 0;
                        if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "  tier3 start: lo=%#x hi=%#x code=%#x\n", io.Lo(), io.Hi(), io.Code());
                        for (std::uint32_t i = 0; i < n3; i++) {
                            std::uint32_t iVar9u = i + 0x380u + (slot - 6u) * 0x60u;
                            int cellOff = 0x39f40 + static_cast<int>(iVar9u) * 2;
                            std::uint32_t bit = DecodeAdaptiveKS(io, mem, cellOff, 0x20u, 6u, ((DE >> 4u) >> ((n3 - 1u - i) & 31u)) & 1u);
                            if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "    tier3 bit[%u]=%u cellOff=%#x\n", i, bit, cellOff);
                            hi_bits = (hi_bits << 1) | bit;
                        }
                        std::uint32_t low4 = acc & 0xfu;
                        std::uint32_t hiPart = acc & 0xfffffff0u;
                        if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "    tier3 hi_bits=%u low4=%u hiPart=%u n3=%u acc_before=%u\n", hi_bits, low4, hiPart, n3, acc);
                        acc = (hi_bits << 4) | (hiPart << n3) | low4;
                    }
                    if (O1_DBG_ENV("NZOPT_TRACE_T3")) fprintf(stderr, "  slot=%u acc_final=%u (dist-1)\n", slot, acc);

                    if (ring_.capacity <= acc) {
                        if (O1_DBG_ENV("NZOPT_DEBUG")) fprintf(stderr, "FAIL@distance: local_74=%u local_54=%u acc=%u capacity=%u slot=%u\n", local_74, local_54, acc, ring_.capacity, slot);
                        // The ring as it stands at the failing match (NZOPT_DUMP_RING,
                        // above, is the per-call dump and writes one numbered file per
                        // DecodeBlock -- 66 of them on a 16-stream archive).
                        if (const char* rp = O1_DBG_ENV("NZOPT_DUMP_RING_AT_FAIL")) {
                            FILE* rf = fopen(rp, "wb");
                            if (rf) { fwrite(base, 1, local_54, rf); fclose(rf); }
                            fprintf(stderr, "dumped ring [0,%u) at the failing match to %s\n", local_54, rp);
                        }
                        failed = true; break;
                    }
                    rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = acc;
                } else {
                    std::uint32_t chosen = rep[local_a0];
                    for (std::uint32_t i = local_a0; i > 0; i--) rep[i] = rep[i - 1];
                    rep[0] = chosen;
                }

                std::uint32_t distance = rep[0] + 1u;
                if (O1_DBG_ENV("NZOPT_TRACE_MATCH")) fprintf(stderr, "MATCH pos=%u length=%u distance=%u slot_group=%u rep=[%u,%u,%u,%u]\n",
                                                           local_54, length, distance, slot_group, rep[0], rep[1], rep[2], rep[3]);
                local_81 = static_cast<std::uint8_t>(local_81 * 2);

                std::uint32_t srcStart = local_54 - distance;
                bool underflow = (local_54 < distance);
                if (underflow) srcStart += ring_.capacity;
                if (distance >= 4u) {
                    std::uint32_t i = 0;
                    for (; i + 4u <= length; i += 4u) {
                        std::memcpy(base + local_54 + i, base + srcStart + i, 4);
                    }
                    for (; i < length; i++) base[local_54 + i] = base[srcStart + i];
                } else {
                    for (std::uint32_t i = 0; i < length; i++) base[local_54 + i] = base[srcStart + i];
                }

                // histHi = the byte ONE PAST the last SOURCE byte read by this
                // copy (i.e. base[srcStart+length]), NOT "second-to-last of the
                // match" as an earlier pass assumed -- ground-truthed via GDB
                // against two real matches in matchfix_co.nz (distances 750 and
                // 790): base[srcStart+length] matched the real binary's local_9c
                // high byte exactly (0x6d/0x6f) while base[srcStart+length-2] did
                // not (0x6d/0x7a). Confirmed against the real disassembly at
                // 0x0809fbcf: `edi = *(byte*)(local_58+NEW_local_54+corrected_srcStart-local_58... )`
                // reduces to base[srcStart+length] once the wraparound-corrected
                // source pointer arithmetic is followed through.
                std::uint8_t histHi = base[srcStart + length];
                std::uint8_t histLo = base[local_54 + length - 1u];
                local_9c = (static_cast<std::uint32_t>(histHi) << 8) | histLo;

                if (record_) decisions_.push_back(OptimumDecision{0u, 0u, static_cast<std::uint8_t>(slot_group), length, distance});
                next_dec();
                local_54 += length;
                local_94 -= length;
            }
        } while (!failed && local_94 != 0);

    chunk_done:
        if (failed) {
            if (O1_DBG_ENV("NZOPT_DEBUG_DUMP")) {
                std::uint32_t n = local_54 - chunk_start;
                std::memcpy(out + local_74, base + chunk_start, n);
                fprintf(stderr, "partial bytes written this call: %u\n", local_74 + n);
            }
            return false;
        }
        std::memcpy(base + local_50, &saved4, 4);
        std::memcpy(out + local_74, base + chunk_start, chunk_size);
        local_74 += chunk_size;
        // Advance the ring's persistent write cursor so the NEXT chunk's
        // EnsureHeadroom() call and chunk_start computation continue from
        // where this chunk left off, instead of restarting at ring position 0
        // every chunk (an earlier version of this port never advanced
        // ring_.cursor at all -- byte-exact for any single-chunk fixture, i.e.
        // every isolated golden vector <=0x8000 bytes, but silently re-decoded
        // every subsequent chunk on top of ring position 0, corrupting
        // multi-chunk real archives >0x8000 bytes; ground-truthed by comparing
        // real binary's `local_54` value entering chunk 2 of bigdist_co.nz --
        // it continues from chunk 1's end (32768), not 0).
        ring_.cursor = local_50;
    }

    if (local_74 != out_size && O1_DBG_ENV("NZOPT_DEBUG"))
        fprintf(stderr, "FAIL@short: local_74=%u out_size=%u\n", local_74, out_size);
    return local_74 == out_size;
}


bool NzOptimumLzDecoder::DecodeBlock(const std::uint8_t* in, std::uint32_t in_len,
                                      std::uint8_t* out, std::uint32_t out_size) {
    // NZOPT_RECODE=1: after the decode, re-encode the decisions from the state the
    // block started in and compare with the input -- the encoder's mirror check.
    static const bool recode = (NZ_ENV("NZOPT_RECODE") != nullptr);
    std::unique_ptr<NzOptimumLzDecoder> before;
    const bool parsechk = (NZ_ENV("NZOPT_PARSECHK") != nullptr);
    const bool want_dec = recode || parsechk || (NZ_ENV("NZOPT_DUMP_DECISIONS") != nullptr);
    if (want_dec) { record_ = true; decisions_.clear(); }
    if (recode || parsechk) before = std::make_unique<NzOptimumLzDecoder>(*this);
    DecodeIO io;
    io.rc.Init(in, in_len);
    const bool ok = RunBlock(io, nullptr, 0u, out, out_size);
    if (const char* dd = NZ_ENV("NZOPT_DUMP_DECISIONS")) {
        // one line per decision of this block, for the parser oracle
        static thread_local int blk = 0;
        std::fprintf(stderr, "[DEC] block=%d out_size=%u in_len=%u ndec=%zu\n", blk++, out_size, in_len, decisions_.size());
        if (*dd == 'v') for (std::size_t i = 0; i < decisions_.size(); ++i) {
            const OptimumDecision& d = decisions_[i];
            if (d.is_literal) std::fprintf(stderr, "[DEC] %zu lit %02x\n", i, d.byte);
            else std::fprintf(stderr, "[DEC] %zu match sg=%u len=%u dist=%u\n", i, d.sg, d.len, d.dist);
        }
    }
    if (NZ_ENV("NZOPT_PARSECHK") != nullptr && ok && before) {
        // run the parser from the pre-block state and compare its decisions
        std::vector<OptimumDecision> mine;
        std::vector<std::uint8_t> mypayload;
        NzOptimumLzDecoder snap(*before);
        bool pok = false;
        try { pok = snap.EncodeBlockParsed(out, out_size, mypayload, &mine); }
        catch (...) { pok = false; }
        std::size_t first = 0;
        while (first < mine.size() && first < decisions_.size()) {
            const OptimumDecision& a = mine[first];
            const OptimumDecision& b = decisions_[first];
            if (a.is_literal != b.is_literal) break;
            if (a.is_literal) { if (a.byte != b.byte) break; }
            else if (a.sg != b.sg || a.len != b.len || a.dist != b.dist) break;
            ++first;
        }
        const bool same = pok && mine.size() == decisions_.size() && first == mine.size();
        const bool paysame = (mypayload.size() == in_len) &&
                             std::memcmp(mypayload.data(), in, in_len) == 0;
        std::fprintf(stderr, "[PARSECHK] out=%u target=%zu mine=%zu match=%zu -> %s payload=%zu/%u %s\n",
                     out_size, decisions_.size(), mine.size(), first, same ? "IDENTICAL" : "DIFF",
                     mypayload.size(), in_len, paysame ? "EXACT" : "diff");
        if (!same) {
            for (std::size_t i = (first > 2 ? first - 2 : 0); i < first + 3 && i < std::max(mine.size(), decisions_.size()); ++i) {
                auto pr = [&](const char* tag, const std::vector<OptimumDecision>& v) {
                    if (i >= v.size()) { std::fprintf(stderr, "  %s[%zu] -\n", tag, i); return; }
                    const OptimumDecision& d = v[i];
                    if (d.is_literal) std::fprintf(stderr, "  %s[%zu] lit %02x\n", tag, i, d.byte);
                    else std::fprintf(stderr, "  %s[%zu] match sg=%u len=%u dist=%u\n", tag, i, d.sg, d.len, d.dist);
                };
                pr("want", decisions_); pr("got ", mine);
            }
        }
    }
    if (recode && ok) {
        std::vector<std::uint8_t> payload;
        const bool eok = before->EncodeBlock(decisions_.data(), decisions_.size(), out_size, payload);
        std::size_t first = 0; while (first < payload.size() && first < in_len && payload[first] == in[first]) ++first;
        const bool same = eok && payload.size() == in_len && first == in_len;
        fprintf(stderr, "[RECODE] out=%u decisions=%zu in_len=%u recoded=%zu -> %s%s\n", out_size, decisions_.size(), in_len, payload.size(),
                same ? "IDENTICAL" : "DIFF", same ? "" : (std::string(" first diff at ") + std::to_string(first)).c_str());
    }
    return ok;
}

bool NzOptimumLzDecoder::EncodeBlock(const OptimumDecision* dec, std::size_t ndec, std::uint32_t out_size,
                                     std::vector<std::uint8_t>& payload) {
    EncodeIO io;
    std::vector<std::uint16_t> q;
    io.q = &q;
    std::vector<std::uint8_t> tmp(static_cast<std::size_t>(out_size) + 16u);
    const bool saved_record = record_;
    record_ = false;
    const bool ok = RunBlock(io, dec, ndec, tmp.data(), out_size);
    record_ = saved_record;
    if (!ok) return false;
    RangeEncodePairs(q, payload);
    return true;
}

bool NzOptimumLzDecoder::EncodeBlockParsed(const std::uint8_t* data, std::uint32_t size,
                                           std::vector<std::uint8_t>& payload,
                                           std::vector<OptimumDecision>* out_decisions) {
    if (size == 0u || size > 0x8000u) return false;   // one chunk at a time for now
    BeginParse(data, size);
    EncodeIO io;
    std::vector<std::uint16_t> q;
    io.q = &q;
    std::vector<std::uint8_t> tmp(static_cast<std::size_t>(size) + 16u);
    std::vector<OptimumDecision> pending;
    std::size_t pi = 0;
    std::uint32_t produced = 0;
    bool parse_ok = true;
    feed_ = [&](OptimumDecision& d) -> bool {
        if (produced >= size) return false;   // the block is covered; a clean end
        while (pi >= pending.size()) {
            pending.clear();
            pi = 0;
            if (!ParseNextFlush(pending) || pending.empty()) { parse_ok = false; return false; }
        }
        d = pending[pi++];
        produced += d.is_literal ? 1u : d.len;
        if (out_decisions != nullptr) out_decisions->push_back(d);
        return true;
    };
    const bool ok = RunBlock(io, nullptr, 0u, tmp.data(), size);
    feed_ = nullptr;
    if (!ok || !parse_ok) return false;
    RangeEncodePairs(q, payload);
    return true;
}

std::uint32_t NzOptimumLzDecoder::WindowCapacity() const { return ring_.capacity; }

void NzOptimumLzDecoder::FeedWindow(const std::uint8_t* data, std::uint32_t len) {
    if (O1_DBG_ENV("NZOPT_DEBUG"))
        fprintf(stderr, "FEED len=%u cursor_before=%u capacity=%u\n", len, ring_.cursor, ring_.capacity);
    // Transcription of the compact engine's ring-feed (entry around 0x080bcc60),
    // which pushes bytes that did NOT come out of the LZ engine (stored blocks,
    // post-filter output) through the same window later matches read from. It is
    // the sibling of nz_optimum2_lz.cpp's FeedWindow -- byte-for-byte the same
    // four cases, minus the LZP-table sweep (this engine has no LZP predictor,
    // and its split path correspondingly ignores the reserve's return value):
    //
    //   len > capacity            -> DROP the head, keep the last `capacity`
    //                                bytes, pos = 0, clear the scroll flag
    //   len + 0x8000 >= capacity  -> same reset, then write at 0
    //   len > capacity - pos      -> SPLIT: fill the ring to its END first, then
    //                                reserve the remainder (which wraps) and
    //                                write the rest
    //   otherwise                 -> write in place, pos += len
    //
    // Collapsing these into one "reserve then write" leaves the cursor at `len`
    // where the original leaves it at (pos + len) mod capacity, so every later
    // match resolves against the wrong ring offset. Verified against the binary
    // by watching the persistent ring descriptor's pos field across a feed that
    // straddles the ring end: both engines walk the identical position sequence.
    const std::uint32_t cap = ring_.capacity;
    if (cap == 0u || data == nullptr || len == 0u) return;

    if (len > cap) {
        data += len - cap;
        len = cap;
        ring_.cursor = 0;
        ring_.scrolled_once = false;
    } else if (len + 0x8000u >= cap) {
        ring_.cursor = 0;
        ring_.scrolled_once = false;
    } else if (len > cap - ring_.cursor) {
        const std::uint32_t tail = cap - ring_.cursor;
        std::memcpy(ring_.Base() + ring_.cursor, data, tail);
        ring_.cursor += tail;  // == cap
        data += tail;
        len -= tail;
        ring_.EnsureHeadroom(len);
    }
    std::memcpy(ring_.Base() + ring_.cursor, data, len);
    ring_.cursor += len;
}

}  // namespace optimum
}  // namespace nzr
