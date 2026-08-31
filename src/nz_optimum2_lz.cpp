#include <cstdio>
#include <cstdlib>
// Native linux32 `-cO` (nz_optimum2) LZ/CM engine. See include/nz_optimum2_lz.h
// for the architecture summary and RE provenance. This file is a careful,
// mostly line-by-line transcription of the real binary's FUN_080a5d90
// (fresh Ghidra decompile captured in full this session, 1099 raw lines,
// cross-checked against live disassembly + GDB memory dumps for every
// offset/formula below) -- NOT a "clean reimplementation from
// understanding", following the exact same discipline the sibling `-co` port
// (src/nz_optimum_lz.cpp) already established for this codec family.
//
// This port's OWN findings, beyond what
// work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md's session 5
// already recorded (that session mapped the 8 literal-mixer contexts to
// table roles/bases but explicitly did NOT reduce them to explicit
// closed-form pseudocode -- see the doc's 5e/5h/5j):
//
//  - The literal-mixer's 4 "uniform tree-walk" contexts (Context P at
//    0x218c0 -- 16MB, order-2 on actual[pos-2..pos-1]; Context 2 at 0x160,
//    order-1 on actual[pos-1]; Context 1 at 0x1021d80/0x1031d80, a
//    4-bit-per-node NIBBLE-PACKED tree keyed by a "top-3-bits of 3 recent
//    bytes" seed; Context 3 at 0x10480, order-1 on actual[pos-2]) all share
//    ONE nodeStep-advance mechanism -- the SAME `iVar11` value (computed
//    once per bit from the shift-register/subcycle-counter cluster at
//    0x103ae1c-0x103ae20, structurally identical to the sibling `-co`
//    port's own 0x2968c-0x29690 cluster, just relocated) is added to all
//    four contexts' tree positions in the same statement group -- confirmed
//    via direct disassembly read (0x080a6b30-0x080a6b36 adds the identical
//    register to both 0x10218c0 and 0x1031dc0 in adjacent instructions).
//  - Context 0 (0x1021900, 256x32-bit modele[]-style cell) is keyed by
//    Context P's own STATE BYTE (walked via kLzModelLNext, i.e.
//    DAT_0813c640 -- confirmed identical to nz_cm.cpp's own table via a live
//    GDB dump/compare this session), and its update formula is confirmed to
//    be IDENTICAL to nz_cm.cpp's own modele[0] update (kDivideLookup-based),
//    reusing the exact same `DAT_081b37b0` table -- also confirmed
//    byte-identical to nz_cm.cpp's kDivideLookup via a live GDB dump/compare
//    this session -- with threshold `< 0x7f` (this port's fresh decompile
//    read shows a strict `<`, not `<=`; a small correction to session 5e's
//    paraphrase).
//  - CORRECTION to session 5e: contexts 1/4/7 are NOT additional modele[]-
//    style 32-bit cells. Direct re-reading of the fresh decompile shows only
//    ONE 32-bit kDivideLookup-based cell in this whole function (context 0).
//    Contexts 4 and 7 (and context 6, and context 2/3) are plain 8-bit
//    exponential-decay state bytes (the same `((K - state) + bit*256) >>
//    shift + state` shape used throughout this codec family, just with
//    per-context (K, shift) pairs: ctx2/ctx3/ctx6 use (4, 3), ctx7 uses
//    (8, 4), ctx4 uses (2, 2)); context 1 additionally carries its own
//    16-bit probability cell (0x1031d80 + nibble*2, a DIFFERENT, simpler
//    K=0x10000/shift=6/round=0x20 exponential decay, no kDivideLookup
//    involved at all) alongside its nibble-packed tree cell -- session 5's
//    "3 more modele-style cells, one modele[] threshold left to extract per
//    context" framing was an assumption of symmetry with nz_cm.cpp's own
//    8-model modele[] array that this port's fresh, address-level read does
//    not bear out.
//  - Context 4 (0x10170) and the weight-row selector are BOTH keyed by one
//    more persistent tree-index ("ctxC_idx" below, backed by mem offset
//    0x103ae12) recomputed via the exact same two-branch "if (prev < 0x200)
//    simple-shift; else signshift-based-reseed" shape as the sibling `-co`
//    port's own NodeAdvance "curC" computation -- i.e. this is `-co`'s
//    Context C, reused verbatim at a new address.
//  - Context 6 (0x20490) and Context 7 (0x208a0) each carry their OWN
//    seed/shift-register pair (0x103ae14/0x103ae18 for ctx6,
//    0x103ae16/0x103ae1a for ctx7) advanced via near-identical (but not
//    quite identical -- different bit-widths: 0xfff0 mask for ctx6 vs
//    0xffe0 for ctx7) formulas to `-co`'s own Context D; NEW versus `-co`:
//    ctx6's seed formula folds in the REP0-CONTINUATION predicted byte
//    (matching `-co`'s ctxD) while its rolling shift-register
//    (0x103ae14) ALSO tracks that same rep0-continuation byte bit-by-bit;
//    ctx7's seed formula and shift-register (0x103ae16) instead track the
//    LZP-PREDICTOR's predicted byte (`-co` has no LZP predictor at all) --
//    confirmed via careful disassembly-level data-flow tracing of the
//    packed `local_b4` value (this was the single most error-prone part of
//    this transcription: a naive read of the decompile might suggest
//    `local_b4`/`local_a4` mean "new ring position after a match" at the
//    literal-setup entry point, since the SAME stack slot is reassigned
//    that way inside the textually-adjacent match-decode branch; tracing
//    the ACTUAL last-write-before-read at the machine-code level (stack
//    slot 0x28(%esp)) confirms it is always the freshly-recomputed
//    dispatch-bit matchmask/predicted-byte pack from the CURRENT position's
//    dispatch iteration whenever control reaches literal-setup via a
//    `break`, never a stale value from a match branch that, per the
//    doc's own control-flow finding, always loops back to the TOP of the
//    dispatch loop instead of falling through here).
//  - Context 5 has no table of its own: it is `stretch((stretch(ctx4's raw
//    state) + 0x800) >> 4)` -- a derived/meta input, transcribed verbatim
//    (matches the architecture doc's own description exactly).
//  - The rolling 3-byte-hash LZP predictor's exact hash formula, re-read
//    from a fresh disassembly this session: `hash = (uint16_t)(actual[pos-3]
//    * 0xc5 + word16_le(actual[pos-2], actual[pos-1]))` -- a 16-BIT hash
//    (the raw hash value is stored into a `ushort` before use), NOT the
//    ~18-bit/256K-entry table the architecture doc's session 5f inferred
//    from decompile-reading alone without checking the actual truncation
//    width; the real table is exactly 65536 entries x 4 bytes = 256KB
//    (0x1042c00..0x1082c00), confirmed both by the highest literal offset
//    referenced anywhere in the function (0x1082c00) and by a live GDB
//    memory dump showing that exact region cold-zeroed with nothing of
//    interest beyond it.
//  - `FUN_080b9150(param_1+0x40)` (called instead of the sibling `-co`
//    port's harmless-no-op `FUN_080bcc00` whenever the ring scrolls) is a
//    256KB (0x40000-byte) zero-fill of `param_1+0x1042bc0`..`+0x1082bc0` --
//    i.e. it clears the ENTIRE LZP hash table (plus 64 bytes of padding
//    immediately before it) whenever the ring scrolls, exactly mirroring
//    the rep-offset array's own reset on the same condition.
//
// Memory model: same convention as nz_optimum_lz.cpp -- `param_1` (this
// engine's persistent ~0x1083000-byte object) becomes `mem_`, addressed via
// the exact same Rd8/Wr8/Rd16/Wr16/Rd32/Wr32(OFFSET) idiom, using the
// decompile's own literal hex offsets throughout rather than renamed
// symbolic constants. `&local_5c` (the stack ring descriptor) becomes
// `ring_`, a genuinely persistent member (one NzOptimum2LzDecoder instance
// per container stream). The literal-mixer's two per-bit computations
// (identical shape, only differing in which persistent tree-position/seed
// values feed them) are factored into `MixerBit`/`AdvanceAfterBit` lambdas
// -- mirroring nz_optimum_lz.cpp's own MixerBit/NodeAdvance factoring and
// its stated rationale (avoiding copy-paste divergence between the two
// bit-decodes, not "simplifying" the math) -- rather than duplicated inline
// as the raw decompile does.
#include "nz_optimum2_lz.h"
#include "nz_optimum2_lz_tables.h"
#include "nz_optimum_lz_tables.h"  // nzr::optimum::OptimumDat08172380()/nzr::optimum::OptimumDat081724d0() --
                                   // DAT_08173140/DAT_08173290 are byte-identical
                                   // to these (confirmed via GDB dump+cmp this
                                   // session) -- reused directly, not re-embedded.
#include "nz_cm.h"  // kLzModelInterpolation (== DAT_08172900, confirmed
                    // byte-identical this session), kLzModelLNext (==
                    // DAT_0813c640, confirmed byte-identical this session),
                    // kDivideLookup (== DAT_081b37b0, confirmed byte-identical
                    // this session).

#include <cstring>
#include <algorithm>
#include <cstdint>

extern int16_t kLzModelInterpolation[256];
extern const uint8_t kLzModelLNext[256 * 2];
extern uint32_t kDivideLookup[256];

namespace nzr {
namespace optimum2 {

namespace {

constexpr std::size_t kMemSize = 0x1083000u;

// The distance decoder's "tier 2" footer-bit table (used only when slot>2)
// is reached via `*(param_1+0x103f0c0)` -- a POINTER stored at that offset,
// dereferenced, NOT a `param_1`-relative literal address the way the tier1
// (0x103b9c0+...) and tier3 (0x103c140+...) tables are. `0x103f0c0` is never
// WRITTEN anywhere in FUN_080a5d90 (confirmed: exactly one reference in the
// whole function, the read itself), so it must be initialized once, outside
// this function, to a small separately-allocated buffer -- structurally
// identical to the sibling `-co` port's own "external align table"
// (param_1+0x3d640, see nz_optimum_lz.cpp's kAlignTableOff comment). This
// port places that table inline at the end of `mem_`, exactly like `-co`
// does, rather than chasing a fake pointer value. Ground-truthed via GDB
// against hientropy_cO.nz's first real slot>2 match (slot=4, expected
// distance 31 for a match reconstructing "the " from offset 0): an earlier
// pass over this file wrongly guessed this table lived at a per-slot
// literal address `0x103d940+slot*0xc0` (extrapolating tier1/tier3's own
// per-slot-stride shape without checking tier2's actual decompile lines),
// which desynced the footer bits for every slot>2 match -- the real
// tier2 table has NO per-slot stride at all, it's addressed purely by the
// bit-tree's own walking position (`treepos*2 + base`), shared across every
// slot.
constexpr int kTier2AlignOff = static_cast<int>(kMemSize);
constexpr std::size_t kTier2AlignSize = 128u;  // generous; real usage needs
                                                // <64B (max tree depth 4,
                                                // treepos resets to 1 every
                                                // match)
constexpr std::size_t kTotalMemSize = kMemSize + kTier2AlignSize;

inline std::uint8_t Rd8(const std::uint8_t* mem, int off) { return mem[off]; }
inline void Wr8(std::uint8_t* mem, int off, std::uint8_t v) { mem[off] = v; }
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

inline int Stretch(std::uint8_t state) { return kLzModelInterpolation[state]; }

// Same binary range decoder shape as nz_optimum_lz.cpp's RangeDecoder
// (confirmed byte-identical formula -- see the architecture doc's 5a/5c).
// Duplicated here rather than shared via a header to keep both engine ports
// self-contained, matching this project's per-codec-file convention.
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
    std::uint32_t DecodeBit(std::uint32_t prob) {
        std::uint32_t mid = ((hi - lo) >> 12) * prob + lo;
        std::uint32_t bit = (code <= mid) ? 1u : 0u;
        if (bit) hi = mid; else lo = mid + 1u;
        Renormalize();
        return bit;
    }
    std::uint32_t DecodeRawBit() {
        std::uint32_t mid = ((hi - lo) >> 12) * 0x800u + lo;
        std::uint32_t bit = (code <= mid) ? 1u : 0u;
        if (bit) hi = mid; else lo = mid + 1u;
        Renormalize();
        return bit;
    }
};

// Adaptive bit decode against a 16-bit direct-probability cell (same shape
// as nz_optimum_lz.cpp's DecodeAdaptiveKSB).
std::uint32_t DecodeAdaptiveKSB(RangeDecoder& rc, std::uint8_t* mem, int off,
                                 std::uint32_t K, std::uint32_t S, bool bias) {
    std::uint32_t cell = Rd16(mem, off);
    std::uint32_t prob = cell >> 4;
    if (bias) prob = prob + ((prob < 0x800u) ? 1u : 0u);
    std::uint32_t bit = rc.DecodeBit(prob);
    std::uint32_t upd = (std::uint32_t)((std::int32_t)((K - cell) + bit * 0x10000u) >> S) + cell;
    Wr16(mem, off, (std::uint16_t)upd);
    return bit;
}
inline std::uint32_t DecodeAdaptiveKS(RangeDecoder& rc, std::uint8_t* mem, int off,
                                       std::uint32_t K, std::uint32_t S) {
    return DecodeAdaptiveKSB(rc, mem, off, K, S, /*bias=*/false);
}
inline std::uint32_t DecodeAdaptive16(RangeDecoder& rc, std::uint8_t* mem, int off) {
    return DecodeAdaptiveKSB(rc, mem, off, 0x10u, 5u, /*bias=*/true);
}

inline std::uint8_t& RingAt(std::uint8_t* base, std::uint32_t logical_pos) {
    return base[static_cast<std::int32_t>(logical_pos)];
}
inline std::uint8_t RingAt(const std::uint8_t* base, std::uint32_t logical_pos) {
    return base[static_cast<std::int32_t>(logical_pos)];
}

}  // namespace

NzOptimum2LzDecoder::NzOptimum2LzDecoder(std::uint32_t window_capacity) {
    mem_ = Optimum2ColdState();
    mem_.resize(kTotalMemSize, 0);
    // The tier2 "align" table cold-starts at 0x8000 per u16 entry, exactly
    // like every other adaptive length/distance table in this engine (and
    // the sibling -co port's own external align table) -- see
    // kTier2AlignOff's comment above.
    for (std::size_t i = 0; i < kTier2AlignSize; i += 2) {
        mem_[static_cast<std::size_t>(kTier2AlignOff) + i] = 0x00;
        mem_[static_cast<std::size_t>(kTier2AlignOff) + i + 1] = 0x80;
    }
    ring_.capacity = window_capacity;
    ring_.storage.assign(static_cast<std::size_t>(window_capacity) + 512u, 0u);
    ring_.cursor = 0;
    ring_.scrolled_once = false;
}

std::uint32_t NzOptimum2LzDecoder::Ring::EnsureHeadroom(std::uint32_t needed) {
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
// DecodeBlock -- transcription of FUN_080a5d90.
// ---------------------------------------------------------------------------
bool NzOptimum2LzDecoder::DecodeBlock(const std::uint8_t* in, std::uint32_t in_len,
                                       std::uint8_t* out, std::uint32_t out_size) {
    if (out_size == 0) return true;

    RangeDecoder rc;
    rc.Init(in, in_len);

    std::uint32_t rep[4] = {1, 1, 1, 1};
    std::uint8_t* mem = mem_.data();

    std::uint32_t local_74 = 0;     // bytes produced so far (this call)
    std::uint8_t  local_81 = 0xff;  // recent literal(1)/match(0) decision history
    std::uint32_t local_a4 = 0;     // end-of-previous-position value: either the
                                    // fully decoded literal byte (0..255) or
                                    // CONCAT11(post-match histHi, histLo)

    // ---- one MixerBit half: 8 stretch-fed inputs -> weighted dot product
    // -> squash -> single APM stage -> range decode -> update everything.
    // Persistent tree-walk state (ctxP/ctx2/ctx3 byte offsets, ctx1's scaled
    // tree position, ctx6/ctx7 seed registers, ctxC_idx) is threaded through
    // explicit parameters rather than round-tripped through `mem` between
    // calls (`mem` itself still backs every context TABLE, just not these 7
    // "current tree position" scalars).
    auto MixerBit = [&](int ctxP, int ctx2, std::uint32_t ctx1p, int ctx3,
                         std::uint32_t ctx6s, std::uint32_t ctx7s, std::uint32_t ctxC,
                         std::uint32_t* outPFinal) -> std::uint32_t {
        std::uint8_t stateP = Rd8(mem, ctxP);
        int modele0Off = 0x1021900 + static_cast<int>(stateP) * 4;
        std::uint32_t modele0Cur = static_cast<std::uint32_t>(Rd32(mem, modele0Off));
        std::int32_t in0 = Stretch(static_cast<std::uint8_t>(modele0Cur >> 24));

        std::uint32_t nibbleShift = (ctx1p & 1u) * 4u;
        int nibblePackedOff = 0x1021d80 + static_cast<int>(ctx1p >> 1);
        std::uint8_t nibblePacked = Rd8(mem, nibblePackedOff);
        std::uint32_t ctx1_nibble = (static_cast<std::uint32_t>(nibblePacked) >> nibbleShift) & 0xfu;
        std::uint8_t state1 = Rd8(mem, 0x1031d81 + static_cast<int>(ctx1_nibble) * 2);
        std::int32_t in1 = Stretch(state1);

        std::uint8_t state2 = Rd8(mem, ctx2);
        std::int32_t in2 = Stretch(state2);

        std::uint8_t state3 = Rd8(mem, ctx3);
        std::int32_t in3 = Stretch(state3);

        std::uint8_t state4 = Rd8(mem, 0x10170 + static_cast<int>(ctxC));
        std::int32_t in4 = Stretch(state4);
        std::int32_t in5 = Stretch(static_cast<std::uint8_t>((in4 + 0x800) >> 4));

        std::uint8_t state6 = Rd8(mem, 0x20490 + static_cast<int>(ctx6s));
        std::int32_t in6 = Stretch(state6);

        std::uint8_t state7 = Rd8(mem, 0x208a0 + static_cast<int>(ctx7s));
        std::int32_t in7 = Stretch(state7);

        int wRowOff = 0x90 + static_cast<int>(((ctx6s >> 6) & 3u) + (ctxC >> 8) * 4u) * 0x10;
        std::int32_t w[8];
        for (int i = 0; i < 8; i++) w[i] = static_cast<std::int16_t>(Rd16(mem, wRowOff + i * 2));
        std::int32_t inputs[8] = {in0, in1, in2, in3, in4, in5, in6, in7};
        std::int32_t dot = 0;
        for (int i = 0; i < 8; i++) dot += w[i] * inputs[i];

        std::int32_t sq = (dot >> 16) + 0x800;
        std::uint32_t sqU = (sq < 0) ? 0u : static_cast<std::uint32_t>(sq);
        std::uint32_t sqMin = (sqU < 0xfffu) ? sqU : 0xfffu;
        std::uint32_t scaled = sqMin * 0xbu;
        std::uint16_t apmSeed = Optimum2Dat081732c0()[sqMin >> 4];
        std::uint32_t frac = scaled & 0xfffu;
        std::uint8_t confByte = Rd8(mem, 0x103ae20);
        int apmOff = 0x1031e00 + static_cast<int>(confByte + ctxC * 2u) * 24 + static_cast<int>(scaled >> 12) * 2;
        std::uint16_t apmLo = Rd16(mem, apmOff);
        std::uint16_t apmHi = Rd16(mem, apmOff + 2);
        int apmNear = apmOff + static_cast<int>((frac >> 11) * 2u);
        std::uint16_t apmOld = Rd16(mem, apmNear);
        std::uint32_t interp = (static_cast<std::uint32_t>(apmLo) * (0x1000u - frac) +
                                 frac * static_cast<std::uint32_t>(apmHi)) >> 16;
        std::uint32_t mixedP = (static_cast<std::uint32_t>(apmSeed) + 2u + interp * 3u) >> 2;
        std::uint32_t pFinal = mixedP + ((mixedP < 0x800u) ? 1u : 0u);

        std::uint32_t bit = rc.DecodeBit(pFinal);
        if (getenv("NZOPT2_TRACE_MIX")) fprintf(stderr, "  MIX ctxP=%#x ctx2=%#x ctx1p=%u ctx3=%#x ctx6s=%u ctx7s=%u ctxC=%u confByte=%u apmOff=%#x apmNear=%#x apmLo=%u apmHi=%u interp=%u in=[%d,%d,%d,%d,%d,%d,%d,%d] w=[%d,%d,%d,%d,%d,%d,%d,%d] wRowOff=%#x sqMin=%u apmSeed=%u mixedP=%u pFinal=%u bit=%u\n",
            ctxP, ctx2, ctx1p, ctx3, ctx6s, ctx7s, ctxC, confByte, apmOff, apmNear, apmLo, apmHi, interp, in0,in1,in2,in3,in4,in5,in6,in7, w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7], wRowOff, sqMin, apmSeed, mixedP, pFinal, bit);

        Wr16(mem, apmNear,
             static_cast<std::uint16_t>((static_cast<std::int32_t>(bit * 0x1003eu - apmOld) >> 6) + apmOld));
        std::int32_t err = static_cast<std::int32_t>(bit * 0xfffu) - static_cast<std::int32_t>(pFinal);
        for (int i = 0; i < 8; i++) {
            std::int64_t t1 = (static_cast<std::int64_t>(inputs[i]) * err * 16) >> 16;
            std::int64_t delta = (t1 + 1) >> 1;
            std::int64_t nv = delta + w[i];
            std::int16_t clamped = (nv < -32768) ? static_cast<std::int16_t>(-32768)
                                  : (nv > 32767)  ? static_cast<std::int16_t>(32767)
                                                   : static_cast<std::int16_t>(nv);
            Wr16(mem, wRowOff + i * 2, static_cast<std::uint16_t>(clamped));
        }

        std::uint32_t upd8 = bit * 0x100u;
        Wr8(mem, 0x208a0 + static_cast<int>(ctx7s),
            static_cast<std::uint8_t>((static_cast<std::int32_t>((8 - state7) + upd8) >> 4) + state7));
        Wr8(mem, 0x20490 + static_cast<int>(ctx6s),
            static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - state6) + upd8) >> 3) + state6));
        Wr8(mem, ctx2,
            static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - state2) + upd8) >> 3) + state2));
        Wr8(mem, ctx3,
            static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - state3) + upd8) >> 3) + state3));
        Wr8(mem, 0x10170 + static_cast<int>(ctxC),
            static_cast<std::uint8_t>((static_cast<std::int32_t>((upd8 - state4) + 2) >> 2) + state4));

        // context1's own probability cell (0x1031d80+nibble*2, K=0x10000,
        // S=6, round=0x20 -- NOT the kDivideLookup/modele[] shape).
        int ctx1CellOff = 0x1031d80 + static_cast<int>(ctx1_nibble) * 2;
        std::uint32_t ctx1Cell = Rd16(mem, ctx1CellOff);
        std::uint32_t ctx1Upd = static_cast<std::uint32_t>(
            (static_cast<std::int32_t>(bit * 0x10000u - ctx1Cell) + 0x20) >> 6) + ctx1Cell;
        Wr16(mem, ctx1CellOff, static_cast<std::uint16_t>(ctx1Upd));

        // context1's nibble-packed tree cell update (byte-level subtraction
        // of a value pre-shifted into the target nibble's bit position --
        // transcribed exactly as the original does, not "fixed" to avoid
        // cross-nibble borrow, since faithful transcription requires
        // reproducing this exactly).
        //
        // NOTE: decompile line 794's `bVar9` (the term subtracted from
        // `bit*0x12`) is `*(byte*)(0x1031dc8)` -- the SAVED NIBBLE VALUE
        // (0..15, set at line 643 from the SAME nibble read that feeds
        // `ctx1_nibble`/`ctx1CellOff` above), NOT `state1` (the 0..255 byte
        // read from the nibble-indexed probability table). An earlier pass
        // over this file used `state1` here by mistake -- ground-truthed
        // wrong via GDB against hientropy_cO.nz: this port's weight[1]
        // (Context 1's own mixer weight) matched the real binary's exactly
        // for the first 13 literal-mixer bit-decodes, then diverged (11 vs
        // the real binary's 2) on the 14th -- traced to this nibble-tree
        // update corrupting the packed table with the wrong delta magnitude
        // (bit*0x12-state1, using a 0..255 range, instead of bit*0x12-nibble,
        // using a 0..15 range), which then fed back wrong nibbles into later
        // reads, producing wrong Context 1 inputs and therefore wrong
        // weight-1 training -- exactly the "right on first update, wrong
        // once the model has adapted" shape the corrupted value's downstream
        // reuse produces.
        std::int32_t rawDelta = (static_cast<std::int32_t>(bit * 0x12u) - static_cast<std::int32_t>(ctx1_nibble)) >> 2;
        std::uint8_t deltaByte = static_cast<std::uint8_t>(-rawDelta);
        std::uint8_t shiftedDelta = static_cast<std::uint8_t>(deltaByte << nibbleShift);
        Wr8(mem, nibblePackedOff, static_cast<std::uint8_t>(Rd8(mem, nibblePackedOff) - shiftedDelta));

        // context0's modele[] cell (kDivideLookup-based, threshold `< 0x7f`)
        // + context P's own bit-history state-machine transition
        // (kLzModelLNext).
        std::uint32_t modeleNew =
            ((static_cast<std::uint32_t>(bit << 23) - (modele0Cur >> 9)) *
             kDivideLookup[static_cast<std::uint8_t>(modele0Cur)] & 0xffffff00u) +
            modele0Cur + ((static_cast<std::uint8_t>(modele0Cur) < 0x7fu) ? 1u : 0u);
        Wr32(mem, modele0Off, static_cast<std::int32_t>(modeleNew));
        Wr8(mem, ctxP, kLzModelLNext[static_cast<std::uint32_t>(stateP) * 2 + bit]);

        *outPFinal = pFinal;
        return bit;
    };

    // ---- shared tail: confidence flag, shift-registers, subcycle counter,
    // nodeStep application to the 4 uniform tree-walk contexts, ctx6/ctx7
    // seed recompute, ctxC_idx recompute. Runs unconditionally after bit1;
    // runs after bit2 only when more bit-pairs remain in this byte.
    auto AdvanceAfterBit = [&](std::uint32_t bit, std::uint32_t pFinal,
                                int& ctxP, int& ctx2, std::uint32_t& ctx1p, int& ctx3,
                                std::uint32_t& ctx6s, std::uint32_t& ctx7s, std::uint32_t& ctxC) {
        Wr8(mem, 0x103ae20, (0xa01u < (bit * 0x1000u - pFinal) + 0x500u) ? std::uint8_t{1} : std::uint8_t{0});

        std::uint8_t shiftreg = static_cast<std::uint8_t>(bit + Rd8(mem, 0x103ae1c) * 2);
        Wr8(mem, 0x103ae1c, shiftreg);
        Wr16(mem, 0x103ae14, static_cast<std::uint16_t>(Rd16(mem, 0x103ae14) << 1));
        Wr16(mem, 0x103ae16, static_cast<std::uint16_t>(Rd16(mem, 0x103ae16) << 1));
        std::uint8_t subc = static_cast<std::uint8_t>(Rd8(mem, 0x103ae1d) + 1);
        Wr8(mem, 0x103ae1d, subc);

        std::uint32_t nodeStep;
        std::uint32_t oldShiftregForCompare = shiftreg;
        if (subc == 4) {
            std::uint8_t scaleAcc = Rd8(mem, 0x103ae1f);
            nodeStep = (static_cast<std::uint32_t>(shiftreg) * 0xfu - scaleAcc) - 0xe1u;
        } else {
            nodeStep = (bit + 1u) << ((subc & 3u) - 1u);
            std::uint8_t scaleAcc = Rd8(mem, 0x103ae1f);
            Wr8(mem, 0x103ae1f, static_cast<std::uint8_t>(scaleAcc + static_cast<std::uint8_t>(nodeStep)));
        }
        ctxP += static_cast<int>(nodeStep);
        ctx2 += static_cast<int>(nodeStep);
        ctx1p += nodeStep;
        ctx3 += static_cast<int>(nodeStep);

        std::uint16_t rep0Hist = Rd16(mem, 0x103ae14);  // POST-shift value
        ctx6s = (ctx6s & 0xfff0u) +
                ((static_cast<std::uint32_t>(rep0Hist) >> 6) & 2u) +
                (static_cast<std::uint32_t>(subc >> 1) * 4u) +
                (((static_cast<std::uint32_t>(rep0Hist) >> 8) == oldShiftregForCompare) ? 1u : 0u);
        Wr16(mem, 0x103ae18, static_cast<std::uint16_t>(ctx6s));

        std::uint32_t oldCtxC = Rd16(mem, 0x103ae12);
        std::uint16_t lzpHist = Rd16(mem, 0x103ae16);  // POST-shift value
        ctx7s = (ctx7s & 0xffe0u) +
                static_cast<std::uint32_t>(subc) * 4u +
                ((static_cast<std::uint32_t>(lzpHist) >> 6) & 2u) +
                (((static_cast<std::uint32_t>(lzpHist) >> 8) == oldShiftregForCompare) ? 1u : 0u);
        Wr16(mem, 0x103ae1a, static_cast<std::uint16_t>(ctx7s));

        ctxC = (oldCtxC & 0xff00u) | shiftreg;
        Wr16(mem, 0x103ae12, static_cast<std::uint16_t>(ctxC));
        if (oldCtxC >= 0x200u) {
            std::uint8_t histByte = shiftreg;
            ctxC = static_cast<std::uint32_t>(histByte) + 0x100u;
            Wr16(mem, 0x103ae12, static_cast<std::uint16_t>(ctxC));
            if (bit == (oldCtxC & 1u)) {
                std::uint8_t hist2e = Rd8(mem, 0x103ae1e);
                std::uint8_t confid2 = static_cast<std::uint8_t>(hist2e * 2);
                Wr8(mem, 0x103ae1e, confid2);
                std::int16_t signext = static_cast<std::int16_t>(static_cast<std::int8_t>(histByte));
                std::uint32_t hi = (static_cast<std::uint16_t>(~signext) >> 15) *
                                    (static_cast<std::uint32_t>(histByte) * 2u);
                ctxC = hi + 0x200u + (static_cast<std::uint32_t>(confid2) >> 7);
                Wr16(mem, 0x103ae12, static_cast<std::uint16_t>(ctxC));
            }
        }
    };

    while (local_74 < out_size) {
        std::uint32_t chunk_size = std::min(out_size - local_74, 0x8000u);
        std::uint32_t headroom = ring_.EnsureHeadroom(chunk_size);
        if (headroom == 0) {
            rep[0] = rep[1] = rep[2] = rep[3] = 1;
            // FUN_080b9150(param_1+0x40): zero the entire LZP hash table
            // (plus 64 bytes of padding before it) whenever the ring
            // scrolls -- stale absolute positions from before a scroll must
            // not be trusted afterward, exactly like the rep-offset reset
            // just above.
            std::memset(mem + 0x1042bc0, 0, 0x40000u);
        }
        std::uint8_t* base = ring_.Base();
        std::uint32_t chunk_start = ring_.cursor;
        std::uint32_t local_50 = chunk_start + chunk_size;

        std::uint32_t saved4;
        std::memcpy(&saved4, base + local_50, 4);

        for (int k = 0; k < 4; k++) {
            std::uint32_t p = chunk_start - (rep[k] + 1u);
            if (chunk_start < rep[k] + 1u) p += ring_.capacity;
            if (ring_.capacity <= p || (p < local_50 && chunk_start <= p))
                rep[k] = 1;
        }

        std::uint32_t local_94 = chunk_size;
        std::uint32_t local_54 = chunk_start;
        bool failed = false;

        do {  // one (dispatch-loop; one literal byte) cycle
            std::uint32_t local_b4 = 0;  // packed matchmask/am2/predicted-byte (+ LZP fold)
            std::uint32_t local_9c = 0;  // matchmask (0..15)
            std::uint32_t local_a0 = 0;  // rep0-continuation predicted byte

            for (;;) {  // dispatch bit, one output position per iteration;
                        // stays resident across consecutive MATCHES (breaks
                        // out only when a literal is decoded)
                std::uint32_t iVar11_pos = local_54 - (rep[0] + 1u);
                if (local_54 < rep[0] + 1u) iVar11_pos += ring_.capacity;
                std::uint32_t boundcheck = iVar11_pos - 4u;
                std::uint32_t pos_of_pred = iVar11_pos;
                if (boundcheck < local_50 && local_54 <= boundcheck) {
                    pos_of_pred = local_54 - 1u;
                }
                std::uint8_t predB = RingAt(base, pos_of_pred);
                std::uint8_t pm1 = RingAt(base, pos_of_pred - 1u), pm2 = RingAt(base, pos_of_pred - 2u);
                std::uint8_t pm3 = RingAt(base, pos_of_pred - 3u), pm4 = RingAt(base, pos_of_pred - 4u);
                std::uint8_t am1 = RingAt(base, local_54 - 1u), am2b = RingAt(base, local_54 - 2u);
                std::uint8_t am3 = RingAt(base, local_54 - 3u), am4 = RingAt(base, local_54 - 4u);
                std::uint32_t matchmask = (pm1 == am1 ? 1u : 0u) |
                                          ((pm2 == am2b ? 1u : 0u) << 1) |
                                          ((pm3 == am3 ? 1u : 0u) << 2) |
                                          ((pm4 == am4 ? 1u : 0u) << 3);
                local_b4 = matchmask | (static_cast<std::uint32_t>(am2b) << 16) |
                           (static_cast<std::uint32_t>(predB) << 24);
                local_a0 = predB;
                local_9c = matchmask;

                int dispIdx = static_cast<int>((matchmask & 7u) + static_cast<std::uint32_t>(predB) * 8u);

                // ---- rolling 3-byte-hash LZP predictor: lookup + fold-in ----
                std::uint16_t am2am1 =
                    static_cast<std::uint16_t>(am2b) | (static_cast<std::uint16_t>(am1) << 8);
                std::uint16_t hash = static_cast<std::uint16_t>(
                    static_cast<std::uint16_t>(am3) * 0xc5u + am2am1);
                int lzpSlot = 0x1042c00 + static_cast<int>(hash) * 4;
                std::uint32_t storedPos = static_cast<std::uint32_t>(Rd32(mem, lzpSlot));
                if (storedPos != 0u) {
                    std::uint8_t there_m1 = RingAt(base, storedPos - 1u), there_m2 = RingAt(base, storedPos - 2u);
                    std::uint8_t there_m3 = RingAt(base, storedPos - 3u);
                    if (am1 == there_m1 && am2b == there_m2 && am3 == there_m3) {
                        std::uint8_t predicted = RingAt(base, storedPos);
                        std::uint8_t there_m4 = RingAt(base, storedPos - 4u);
                        bool m4ok = (am4 == there_m4);
                        std::uint8_t am5 = RingAt(base, local_54 - 5u), there_m5 = RingAt(base, storedPos - 5u);
                        std::uint32_t confidence = (m4ok ? 1u : 0u) + 1u + ((m4ok && am5 == there_m5) ? 1u : 0u);
                        local_b4 = local_b4 + static_cast<std::uint32_t>(predicted) * 0x100u + confidence * 0x10u;
                        local_a0 = local_b4 >> 0x18;
                        local_9c = local_b4 & 0xfu;
                    }
                }
                Wr32(mem, lzpSlot, static_cast<std::int32_t>(local_54));

                // ---- dispatch bit: two chained APM/SSE stages ----
                std::uint8_t dat380 = nzr::optimum::OptimumDat08172380()[local_81];
                std::uint32_t stage1Row = static_cast<std::uint32_t>(dat380) * 0x10u + local_9c;
                std::uint32_t stage2RowSeed = (local_b4 & 3u) * 0x10u + (local_a4 & 0xfu);

                std::uint8_t dstate = Rd8(mem, 0x1040480 + dispIdx);
                std::uint32_t apm1In = static_cast<std::uint32_t>(Stretch(dstate) * 4 + 0x2000);
                std::uint32_t frac1 = apm1In & 0xfffu;
                int apm1Off = 0x1040c90 + static_cast<int>(stage1Row) * 10 + static_cast<int>(apm1In >> 12) * 2;
                std::uint16_t apm1Lo = Rd16(mem, apm1Off);
                std::uint16_t apm1Hi = Rd16(mem, apm1Off + 2);
                int apm1Near = apm1Off + static_cast<int>((frac1 >> 11) * 2u);
                std::uint16_t apm1Old = Rd16(mem, apm1Near);
                std::uint32_t stage1 =
                    (static_cast<std::uint32_t>(dstate) * 0x10u + 2u +
                     (((static_cast<std::uint32_t>(apm1Lo) * (0x1000u - frac1) +
                        frac1 * static_cast<std::uint32_t>(apm1Hi)) >> 16) * 3u)) >> 2;

                // NOTE: decompile line 160 (`DAT_08172900[uVar13 >> 6]`) reads
                // this index against the RAW (pre-division-by-4) stage1
                // accumulator -- the division (`uVar13 >> 2`) happens in a
                // LATER statement (line 170). Since `stage1` here already has
                // that >>2 applied, the equivalent shift against `stage1` is
                // >>4, not >>6 (right-shift is associative: raw>>6 ==
                // (raw>>2)>>4 == stage1>>4). An earlier pass over this file
                // used `stage1 >> 6` directly, which silently applied an
                // extra >>2 (effectively raw>>8) -- ground-truthed wrong via
                // GDB: real binary's mixedP for aaa200_cO's very first
                // dispatch bit is 2047 (favoring literal), this port
                // computed 144 (favoring match) before the fix.
                std::uint32_t apm2In = static_cast<std::uint32_t>(Stretch(static_cast<std::uint8_t>(stage1 >> 4)) * 9 + 0x4800);
                std::uint32_t frac2 = apm2In & 0xfffu;
                // base units 0x820bf0 -> true byte base 0x820bf0*2 = 0x10417e0
                // (an earlier pass over this file mis-multiplied this as
                // 0x1041de0 -- ground-truthed wrong via GDB: real binary's
                // apm2 near-cell address for aaa200_cO's first dispatch bit
                // is 0x1041ba8/0x1041baa, only reachable from 0x10417e0).
                int apm2Off = 0x10417e0 + static_cast<int>(stage2RowSeed) * 20 + static_cast<int>(apm2In >> 12) * 2;
                std::uint16_t apm2Lo = Rd16(mem, apm2Off);
                std::uint16_t apm2Hi = Rd16(mem, apm2Off + 2);
                int apm2Near = apm2Off + static_cast<int>((frac2 >> 11) * 2u);
                std::uint16_t apm2Old = Rd16(mem, apm2Near);
                // `stage1` already has the decompile's own "uVar13 = uVar13>>2"
                // division baked in (see its definition above) -- adding a
                // second >>2 here (as an earlier pass over this file did) is
                // wrong; decompile line 170 is `(uVar13>>2) + 2 + ...`, where
                // that inner `uVar13` is the RAW (undivided) accumulator, so
                // `(uVar13>>2)` there equals this port's `stage1` directly.
                std::uint32_t mixedP =
                    (stage1 + 2u +
                     (((static_cast<std::uint32_t>(apm2Lo) * (0x1000u - frac2) +
                        frac2 * static_cast<std::uint32_t>(apm2Hi)) >> 16) * 3u)) >> 2;

                std::uint32_t bit = rc.DecodeBit(mixedP + ((mixedP < 0x800u) ? 1u : 0u));

                Wr8(mem, 0x1040480 + dispIdx,
                    static_cast<std::uint8_t>((static_cast<std::int32_t>((4 - dstate) + bit * 0x100) >> 3) + dstate));
                Wr16(mem, apm1Near,
                     static_cast<std::uint16_t>((static_cast<std::int32_t>(bit * 0x1000e - apm1Old) >> 4) + apm1Old));
                Wr16(mem, apm2Near,
                     static_cast<std::uint16_t>((static_cast<std::int32_t>(bit * 0x1001e - apm2Old) >> 5) + apm2Old));

                if (getenv("NZOPT2_TRACE")) fprintf(stderr, "pos=%u dispatch_bit=%u mixedP=%u lo=%#x hi=%#x code=%#x\n", local_54, bit, mixedP, rc.lo, rc.hi, rc.code);
                if (bit != 0) break;  // literal: fall through to mixer below

                // ===================== MATCH DECODE =====================
                // Rep-slot select: NOT a simple linear unit-index increment
                // like the sibling -co engine's own rep-selector (an earlier
                // pass over this file wrongly assumed it was, copying -co's
                // simpler addressing verbatim) -- ground-truthed via GDB
                // against aaa200_cO.nz's very first match (decoded length 47
                // came out right but the distance slot desynced): the real
                // decompile (lines 197-267) masks the first bit's index with
                // `& 0x3f8`, then for each of the "up to 3 more" bits reuses
                // a PERSISTED counter (mem 0x1040440) that increments by 1
                // every decode (across the first bit too), addressing
                // `iVar2 + (counter & 0x7ff)*2` whenever `(counter & 7) == 1`
                // and `iVar2 + counter*2` (unmasked) otherwise -- i.e. this
                // table is NOT walked as a simple bit-tree/incrementing
                // index the way -co's is; it is genuinely a different,
                // counter-driven addressing scheme.
                int unit_idx = static_cast<int>((local_9c * 0x10u + (local_81 & 0xfu)) * 8u);
                Wr16(mem, 0x1040440, static_cast<std::uint16_t>(unit_idx));
                std::uint32_t b1 = DecodeAdaptive16(rc, mem, 0x103f400 + (unit_idx & 0x3f8) * 2);
                Wr16(mem, 0x1040440, static_cast<std::uint16_t>(Rd16(mem, 0x1040440) + 1));
                std::uint32_t slot_group = 0;
                if (b1 == 0) {
                    std::uint32_t sg = 1;
                    std::uint32_t bitk;
                    do {
                        std::uint32_t counter = Rd16(mem, 0x1040440);
                        std::uint32_t idx = ((counter & 7u) == 1u) ? (counter & 0x7ffu) : counter;
                        int cellOff = 0x103f400 + static_cast<int>(idx) * 2;
                        bitk = DecodeAdaptive16(rc, mem, cellOff);
                        sg = sg + (1u - bitk);
                        Wr16(mem, 0x1040440, static_cast<std::uint16_t>(Rd16(mem, 0x1040440) + 1));
                    } while (sg != 4u && bitk == 0u);
                    slot_group = sg;
                }

                std::uint32_t local_a8_rep = 4, rep0_persist = 0;
                if (slot_group != 0) {
                    local_a8_rep = slot_group - 1;
                    rep0_persist = (local_a8_rep == 0) ? 0x10u : 0u;
                }

                std::uint32_t raw = 0;
                {
                    int lenOff = 0x103ae40 + static_cast<int>(rep0_persist) * 2;
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
                        if (coff < 0 || static_cast<std::size_t>(coff) + 2u > mem_.size()) return false;
                        b = DecodeAdaptiveKS(rc, mem, coff, 0x10u, 5u);
                        raw += 1;
                    } while (b != 0);
                }
                std::uint32_t U1 = raw - 1u;
                std::uint32_t nbits = (raw < 5u) ? std::max<std::uint32_t>(1u, U1) : 4u;
                std::uint32_t local_a4v = (raw > 1u) ? 1u : 0u;
                {
                    // NOTE: this loop's cell base is iVar27 (0x103ae40), the
                    // SAME base the raw/unary loop above uses -- NOT iVar1
                    // (0x103b9c0, the distance-slot-tree's own base). An
                    // earlier pass over this file used 0x103b9c0 here by
                    // mistake (copy-paste from the tier1/tier2/tier3 code
                    // below, which DOES use iVar1) -- ground-truthed wrong
                    // via GDB against aaa200_cO.nz: ALL 5 of the real
                    // binary's distance-slot-tree bit-decodes read the same
                    // cold `combined=2414` probability, but this port's
                    // bit 1 read a non-cold, already-trained cell (1647) --
                    // caused by this length-decode loop wrongly writing into
                    // (aliasing) the distance-slot-tree's own row 8, bit 1
                    // cell, corrupting an unrelated table.
                    std::uint32_t persisted = (slot_group == 0u) ? 3u : 1u;
                    for (std::uint32_t i = 0; i < nbits; i++) {
                        std::uint32_t iVar9u = persisted + U1 * 32u + 0x60u;
                        int cellOff = 0x103ae40 + static_cast<int>(iVar9u) * 2;
                        std::uint32_t bit2 = DecodeAdaptiveKS(rc, mem, cellOff, 8u, 4u);
                        persisted = bit2 + persisted * 2u;
                        local_a4v = bit2 + local_a4v * 2u;
                    }
                }
                if (raw >= 5u) {
                    for (std::uint32_t i = 0; i < U1 - 4u; i++) {
                        std::uint32_t bit2 = rc.DecodeRawBit();
                        local_a4v = bit2 + local_a4v * 2u;
                    }
                }
                std::uint32_t length = local_a4v + 2u;

                if (local_94 < length) { if (getenv("NZOPT2_TRACE")) fprintf(stderr, "FAIL@length pos=%u local_94=%u length=%u\n", local_54, local_94, length); failed = true; break; }

                if (slot_group == 0) {
                    if (getenv("NZOPT2_TRACE")) fprintf(stderr, "  entering slot-tree: lo=%#x hi=%#x code=%#x\n", rc.lo, rc.hi, rc.code);
                    std::uint32_t length_code = std::min<std::uint32_t>(local_a4v, 15u);
                    std::uint8_t lengthBucket = nzr::optimum::OptimumDat081724d0()[length_code];
                    std::uint32_t rowBias = static_cast<std::uint32_t>(lengthBucket) << 5;
                    std::uint32_t treepos = 1;
                    std::uint32_t slotAcc = 0;
                    for (int i = 0; i < 5; i++) {
                        std::uint32_t iVar9u = treepos + rowBias;
                        int cell1Off = 0x103b9c0 + static_cast<int>(iVar9u) * 2;
                        std::uint32_t cell1 = Rd16(mem, cell1Off);
                        std::uint32_t prob1 = cell1 >> 4;
                        std::uint32_t iVar26u = static_cast<std::uint32_t>(
                            (static_cast<std::int32_t>(Stretch(static_cast<std::uint8_t>(cell1 >> 8))) + 0x800) >> 8)
                            + 0x140u + treepos * 0x11u;
                        int cell2Off = 0x103b9c0 + static_cast<int>(iVar26u) * 2;
                        std::uint16_t cell2lo = Rd16(mem, cell2Off);
                        std::uint16_t cell2hi = Rd16(mem, cell2Off + 2);
                        std::uint32_t combined =
                            (prob1 + 2u +
                             (((static_cast<std::uint32_t>(cell2hi) + 1u + static_cast<std::uint32_t>(cell2lo)) >> 5) * 3u)) >> 2;
                        std::uint32_t bit2 = rc.DecodeBit(combined + ((combined < 0x800u) ? 1u : 0u));
                        if (getenv("NZOPT2_TRACE")) fprintf(stderr, "    slotbit[%d] treepos_before=%u cell1Off=%#x cell1=%u prob1=%u iVar26u=%u cell2lo=%u cell2hi=%u combined=%u bit=%u\n",
                                                              i, treepos, cell1Off, cell1, prob1, iVar26u, cell2lo, cell2hi, combined, bit2);

                        std::uint32_t upd1 = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>((0x10u - cell1) + bit2 * 0x10000u) >> 5) + cell1;
                        Wr16(mem, cell1Off, static_cast<std::uint16_t>(upd1));
                        std::uint32_t upd2lo = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(bit2 * 0x1000eu - cell2lo) >> 4) + cell2lo;
                        std::uint32_t upd2hi = static_cast<std::uint32_t>(
                            static_cast<std::int32_t>(bit2 * 0x1000eu - cell2hi) >> 4) + cell2hi;
                        Wr16(mem, cell2Off, static_cast<std::uint16_t>(upd2lo));
                        Wr16(mem, cell2Off + 2, static_cast<std::uint16_t>(upd2hi));

                        treepos = bit2 + treepos * 2u;
                        slotAcc = bit2 + slotAcc * 2u;
                    }
                    std::uint32_t slot = slotAcc ^ 0x1fu;
                    if (getenv("NZOPT2_TRACE")) fprintf(stderr, "  slotAcc=%u slot=%u lengthBucket=%u rowBias=%u\n", slotAcc, slot, lengthBucket, rowBias);

                    std::uint32_t acc = (slot != 0u) ? 1u : 0u;
                    {
                        std::uint32_t n1 = (slot < 2u) ? 1u : 2u;
                        std::uint32_t t1pos = 1;
                        for (std::uint32_t i = 0; i < n1; i++) {
                            std::uint32_t iVar9u = t1pos + 0xf80u + slot * 0x60u;
                            int cellOff = 0x103b9c0 + static_cast<int>(iVar9u) * 2;
                            std::uint32_t bit2 = DecodeAdaptiveKS(rc, mem, cellOff, 8u, 4u);
                            t1pos = bit2 + t1pos * 2u;
                            acc = bit2 + acc * 2u;
                        }
                    }
                    if (slot > 2u) {
                        // NOT slot-dependent (see kTier2AlignOff's header
                        // comment) -- a single shared bit-tree table,
                        // addressed purely by its own walking position.
                        std::uint32_t n2 = (slot < 6u) ? (slot - 2u) : 4u;
                        acc <<= n2;
                        std::uint32_t t2pos = 1;
                        for (std::uint32_t i = 0; i < n2; i++) {
                            int cellOff = kTier2AlignOff + static_cast<int>(t2pos) * 2;
                            std::uint32_t bit2 = DecodeAdaptiveKSB(rc, mem, cellOff, 0x10u, 5u, /*bias=*/false);
                            t2pos = bit2 + t2pos * 2u;
                            acc |= bit2 << i;
                        }
                    }
                    if (slot > 6u) {
                        // Base constant CORRECTED: the real per-iteration cell
                        // offset (in units, relative to iVar1==0x103b9c0) is
                        // `flatCounter + 0x380 + (slot-6)*0x60`, where
                        // flatCounter is 0 for the first iteration and
                        // increments by 1 each subsequent one (a flat,
                        // non-doubling index -- confirmed via the decompile's
                        // own persisted-counter reload/store pair, NOT a
                        // bit-tree walk). In bytes from iVar1, that is
                        // `0x700 + (slot-6)*0xc0 + i*2` -- i.e. base
                        // `iVar1+0x700 == 0x103c0c0`, NOT `0x103c140`
                        // (`iVar1+0x780`, which is actually the address of a
                        // DIFFERENT scratch field -- the persisted flat
                        // counter itself, confused with the cell-address
                        // base by an earlier pass over this file). 0x80
                        // bytes off. Ground-truthed via GDB against
                        // hientropy_cO.nz's first slot>6 match (slot=8,
                        // expected distance 385 reconstructing repeated text
                        // via a distance-385 back-reference): this port
                        // decoded a plausible-looking but wrong distance
                        // before this fix, confirmed wrong by directly
                        // comparing the referenced source bytes against the
                        // golden output (they didn't match, proving the
                        // match parameters -- not merely a downstream
                        // literal -- were the corrupted step here).
                        std::uint32_t n3 = slot - 6u;
                        std::uint32_t hi_bits = 0;
                        for (std::uint32_t i = 0; i < n3; i++) {
                            int cellOff = 0x103c0c0 + static_cast<int>(slot - 6u) * 0xc0 + static_cast<int>(i) * 2;
                            std::uint32_t bit2 = DecodeAdaptiveKS(rc, mem, cellOff, 0x20u, 6u);
                            hi_bits = (hi_bits << 1) | bit2;
                        }
                        std::uint32_t low4 = acc & 0xfu;
                        std::uint32_t hiPart = acc & 0xfffffff0u;
                        acc = (hi_bits << 4) | (hiPart << n3) | low4;
                    }

                    if (ring_.capacity <= acc) { if (getenv("NZOPT2_TRACE")) fprintf(stderr, "FAIL@distance pos=%u acc=%u capacity=%u\n", local_54, acc, ring_.capacity); failed = true; break; }
                    rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = acc;
                } else {
                    std::uint32_t chosen = rep[local_a8_rep];
                    for (std::uint32_t i = local_a8_rep; i > 0; i--) rep[i] = rep[i - 1];
                    rep[0] = chosen;
                }

                std::uint32_t distance = rep[0] + 1u;
                if (getenv("NZOPT2_TRACE")) fprintf(stderr, "MATCH pos=%u length=%u distance=%u slot_group=%u rep=[%u,%u,%u,%u]\n", local_54, length, distance, slot_group, rep[0], rep[1], rep[2], rep[3]);
                local_81 = static_cast<std::uint8_t>(local_81 * 2);

                std::uint32_t srcStart = local_54 - distance;
                bool underflow = (local_54 < distance);
                if (underflow) srcStart += ring_.capacity;
                if (distance >= 4u) {
                    std::uint32_t i = 0;
                    for (; i + 4u <= length; i += 4u) std::memcpy(base + local_54 + i, base + srcStart + i, 4);
                    for (; i < length; i++) base[local_54 + i] = base[srcStart + i];
                } else {
                    for (std::uint32_t i = 0; i < length; i++) base[local_54 + i] = base[srcStart + i];
                }

                std::uint8_t histHi = base[srcStart + length];
                std::uint8_t histLo = base[local_54 + length - 1u];
                local_a4 = (static_cast<std::uint32_t>(histHi) << 8) | histLo;

                local_54 += length;
                local_94 -= length;
                if (local_94 == 0) goto chunk_done;
            }
            if (failed) break;

            // ============ literal byte: 8-context mixer ============
            {
                std::uint32_t am2 = (local_b4 >> 16) & 0xffu;  // actual[pos-2]

                int ctxP_off = 0x218c0 + static_cast<int>((am2 & 0xffu) * 0x100u + (local_a4 & 0xffu)) * 0x100;
                std::uint32_t ctx1_pos =
                    (((local_a4 & 0xe0u) >> 5) +
                     (static_cast<std::uint32_t>(RingAt(base, local_54 - 3u)) & 0xe0u) * 2u +
                     ((am2 & 0xe0u) >> 2)) * 0x100u;
                int ctx2_off = 0x160 + static_cast<int>(local_a4 & 0xffu) * 0x100;
                int ctx3_off = 0x10480 + static_cast<int>(am2 & 0xffu) * 0x100;

                std::uint32_t predRep0 = local_a0;                    // rep0-continuation predicted byte
                std::uint32_t predLzp = (local_b4 >> 8) & 0xffu;      // LZP-predicted byte, or 0 if no hit

                std::uint32_t ctx6_seed = (local_94 & 3u) * 0x10u + 1u + local_9c * 0x40u +
                                          (((predRep0 + 0x100u) >> 6) & 2u);
                std::uint32_t ctx7_seed = (local_a4 & 0x1fu) * 0x80u + 1u + ((local_b4 >> 4) & 3u) * 0x20u +
                                          (((predLzp + 0x100u) >> 6) & 2u);

                Wr16(mem, 0x103ae14, static_cast<std::uint16_t>(predRep0 + 0x100u));
                Wr16(mem, 0x103ae16, static_cast<std::uint16_t>(predLzp + 0x100u));
                Wr16(mem, 0x103ae18, static_cast<std::uint16_t>(ctx6_seed));
                Wr16(mem, 0x103ae1a, static_cast<std::uint16_t>(ctx7_seed));
                Wr8(mem, 0x103ae1d, 0);
                Wr8(mem, 0x103ae1f, 0);
                Wr8(mem, 0x103ae20, 0);
                Wr8(mem, 0x103ae1c, 1);
                std::uint32_t ctxC_idx = 1;
                Wr16(mem, 0x103ae12, 1);
                if ((local_81 & 1u) == 0u) {
                    std::uint8_t prevHi = static_cast<std::uint8_t>(local_a4 >> 8);
                    Wr8(mem, 0x103ae1e, prevHi);
                    std::uint32_t signshift = static_cast<std::uint32_t>(prevHi) >> 7;
                    ctxC_idx = signshift + 0x202u;
                    Wr16(mem, 0x103ae12, static_cast<std::uint16_t>(ctxC_idx));
                }

                if (getenv("NZOPT2_TRACE_SETUP")) fprintf(stderr, "SETUP pos=%u am2=%#x local_a4=%#x ctxP_off=%#x ctx1_pos=%u ctx2_off=%#x ctx3_off=%#x predRep0=%#x predLzp=%#x local_9c=%u ctx6_seed=%u ctx7_seed=%u local_81=%#x\n",
                    local_54, am2, local_a4, ctxP_off, ctx1_pos, ctx2_off, ctx3_off, predRep0, predLzp, local_9c, ctx6_seed, ctx7_seed, local_81);
                std::uint32_t byteAcc = 0;
                std::uint32_t bitsLeft = 4;
                for (;;) {
                    std::uint32_t pFinal1;
                    std::uint32_t bit1 = MixerBit(ctxP_off, ctx2_off, ctx1_pos, ctx3_off,
                                                   ctx6_seed, ctx7_seed, ctxC_idx, &pFinal1);
                    AdvanceAfterBit(bit1, pFinal1, ctxP_off, ctx2_off, ctx1_pos, ctx3_off,
                                    ctx6_seed, ctx7_seed, ctxC_idx);

                    std::uint32_t pFinal2;
                    std::uint32_t bit2 = MixerBit(ctxP_off, ctx2_off, ctx1_pos, ctx3_off,
                                                   ctx6_seed, ctx7_seed, ctxC_idx, &pFinal2);

                    bitsLeft -= 1;
                    byteAcc = bit2 + (bit1 + byteAcc * 2u) * 2u;
                    if (bitsLeft == 0) break;

                    AdvanceAfterBit(bit2, pFinal2, ctxP_off, ctx2_off, ctx1_pos, ctx3_off,
                                    ctx6_seed, ctx7_seed, ctxC_idx);
                }

                local_a4 = byteAcc;
                if (getenv("NZOPT2_TRACE_LIT")) fprintf(stderr, "LIT pos=%u byte=%#x (%c)\n", local_54, byteAcc, (byteAcc>=32&&byteAcc<127)?(char)byteAcc:'.');
                base[local_54] = static_cast<std::uint8_t>(byteAcc);
                local_54 += 1;
                local_94 -= 1;
                local_81 = static_cast<std::uint8_t>(local_81 * 2 + 1);
                if (local_94 == 0) goto chunk_done;
            }
        } while (!failed && local_94 != 0);

    chunk_done:
        if (failed) return false;
        std::memcpy(base + local_50, &saved4, 4);
        std::memcpy(out + local_74, base + chunk_start, chunk_size);
        local_74 += chunk_size;
        ring_.cursor = local_50;
    }

    return local_74 == out_size;
}


void NzOptimum2LzDecoder::FeedWindow(const std::uint8_t* data, std::uint32_t len) {
    // Caveat: when `len` exceeds the ring capacity this writes in
    // capacity-sized chunks, leaving the cursor at the end of the last one.
    // Only the final `capacity` bytes are reachable either way, but the exact
    // cursor the original would land on in that case is NOT verified against
    // the real binary -- no observed BWT block was larger than the window. If
    // it ever is, a later match reads the wrong ring position and the block or
    // the entry checksum fails, i.e. it declines rather than emitting wrong
    // bytes.
    const std::uint32_t cap = ring_.capacity;
    if (cap == 0u || data == nullptr) return;
    while (len != 0u) {
        const std::uint32_t n = (len < cap) ? len : cap;
        const std::uint32_t start = ring_.EnsureHeadroom(n);
        std::memcpy(ring_.Base() + start, data, n);
        ring_.cursor = start + n;
        data += n;
        len -= n;
    }
}

}  // namespace optimum2
}  // namespace nzr
