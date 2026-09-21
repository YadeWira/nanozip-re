// nz_optimum2_lz_parser.cpp -- the `-cO` optimal parser (FUN_08083e90), the
// DAT_08183620 == 0 path (what `-t1` takes: the async secondary finder is never
// created). It turns a block's bytes into the decision list the original's
// parser picks; NzOptimum2LzDecoder::EncodeBlock then codes that list into the
// payload (that half is already byte-exact -- see the RunBlock template).
//
// FUN_08083e90 is the structural twin of the `-co` engine's FUN_0806f8e0, which
// src/nz_optimum_lz_parser.cpp already ports: same signature, same chunking,
// same forward DP with the four rep offsets probed first and the bt4 finder
// consulted only when they all miss, same long-range rolling-hash probe, same
// backtrack. What differs, read off a fresh decompile of both side by side:
//
//   * the node horizon is 0x1040 nodes, not 0x120, and a match is taken
//     immediately at 0x200 bytes, not 0x20;
//   * the match finder walks 0x100 chain steps per probe, not 0x10;
//   * every model table is the large engine's own (0x1040480 dispatch,
//     0x103f400 rep-select, 0x103ae40 length, 0x103b9c0 distance), and the
//     dispatch bit carries the SECOND APM stage the decoder already models;
//   * the match mask is four bits wide and carries the LZP predictor's own
//     confidence nibble and predicted byte, exactly as the decoder builds it;
//   * the only price cache is the length one (0x103b380, 16-bit cells, 0xffff
//     empty, consulted only under 0x20). The rep-select price, the distance
//     price and the literal price are all recomputed at every node -- the
//     compact engine's three byte-wide caches have no counterpart here.
//
// Pricing only READS the coding model (it writes the length cache and the
// engine's own scratch pointer fields, which the coder overwrites before use),
// so it is safe to run against the model the coder will advance.
#include "nz_optimum2_lz.h"
#include "nz_optimum_lz.h"          // NzOptimumLzWindowSizeFromP1's engine, for its tables
#include "nz_optimum_lz_tables.h"
#include "nz_optimum2_lz_tables.h"   // DAT_08173140 == OptimumDat08172380, DAT_08173290 == ...4d0
#include "nz_cm.h"
#include "nz_env.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern std::int16_t kLzModelInterpolation[256];   // DAT_08172900, the stretch table

namespace nzr {
namespace optimum2 {

namespace {

// The model image's size and the appended tier-2 align table -- the same two
// constants nz_optimum2_lz.cpp defines (see its kTier2AlignOff comment: the real
// object reaches that table through a pointer field, so this port appends it).
constexpr std::size_t kMemSize = 0x1083000u;
constexpr int kTier2AlignOff = static_cast<int>(kMemSize);

// FUN_080749a0 / DAT_08172500: the bit-cost table, byte for byte the one the
// `-co` parser builds (both engines price through the same table).
const std::uint8_t* CostTable() {
    static std::uint8_t t[0x400];
    static bool done = false;
    if (!done) {
        int i6 = 0x118;
        unsigned b = 0;
        for (;;) {
            i6 -= 0x1c;
            std::uint32_t i2 = 1u << b, i1 = i2 * 2u;
            std::uint32_t u4 = i2 * 0x1cu + (static_cast<std::uint32_t>(i6) << b);
            for (;;) {
                const std::uint32_t u5 = u4 >> b;
                t[i2] = (u5 < 0x100u) ? static_cast<std::uint8_t>(u5) : 0xffu;
                if (i1 == i2 + 1u) break;
                ++i2;
                u4 -= 0x1cu;
            }
            ++b;
            if (i6 == 0) break;
        }
        t[0] = t[1];
        done = true;
    }
    return t;
}
inline std::uint32_t Cost(const std::uint8_t* T, std::uint32_t bit, std::uint32_t prob) {
    return T[(((prob >> 2) ^ (0u - (bit ^ 1u))) - bit) & 0x3ffu];
}
inline std::uint32_t Bias(std::uint32_t p) { return p + ((p < 0x800u) ? 1u : 0u); }

inline std::uint8_t  Rd8 (const std::uint8_t* m, std::size_t o) { return m[o]; }
inline void          Wr8 (std::uint8_t* m, std::size_t o, std::uint8_t v) { m[o] = v; }
inline std::uint16_t Rd16(const std::uint8_t* m, std::size_t o) { std::uint16_t v; std::memcpy(&v, m + o, 2); return v; }
inline void          Wr16(std::uint8_t* m, std::size_t o, std::uint16_t v) { std::memcpy(m + o, &v, 2); }
inline std::int32_t  Rd32(const std::uint8_t* m, std::size_t o) { std::int32_t v; std::memcpy(&v, m + o, 4); return v; }
inline void          Wr32(std::uint8_t* m, std::size_t o, std::int32_t v) { std::memcpy(m + o, &v, 4); }
inline int Stretch(std::uint8_t s) { return kLzModelInterpolation[s]; }
inline std::uint32_t Load16(const std::uint8_t* p) { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
inline std::uint32_t Load32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
// the ring is read with SIGNED positions: just before the cursor is negative and
// lands in the 256-byte prefix mirror (the decoder's own RingAt)
inline std::uint8_t At(const std::uint8_t* b, std::uint32_t p) { return b[static_cast<std::int32_t>(p)]; }
inline std::uint32_t BitLen1(std::uint32_t v) { std::uint32_t n = 31; if (v == 0) return 0; while ((v >> n) == 0) --n; return n; }

// One relaxation candidate the DP considers at a position.
struct Cand { std::uint32_t len; std::uint32_t src; };

}  // namespace

// The finder object and the 256-byte rolling hash, which live past the model
// image in the original (obj + 0x1082c00). Identical machinery to the `-co`
// engine's -- FUN_08073ca0 and FUN_08082fa0 are literally the same functions,
// called with a different object and a chain depth of 0x100.
struct NzOptimum2LzDecoder::ParserState {
    std::uint32_t shift = 0, winsize = 0, maskA = 0, headmask = 0;
    std::uint32_t treemask = 0, treesize = 0;
    std::vector<std::uint32_t> head, cache, tree;
    std::vector<std::uint32_t> lr;
    std::uint32_t lrmask = 0, lrhash = 0;
    bool verbose = false;            // debug: dump one Find's chain walk
    bool ready = false;
    const std::uint8_t* block = nullptr;
    const std::uint8_t* src = nullptr;
    std::uint32_t size = 0, consumed = 0, pos0 = 0;
    bool staged = false;
    std::uint32_t rep0[4] = {1, 1, 1, 1};
    std::uint8_t hist0 = 0xff;
    std::uint16_t ctx0 = 0;
    bool started = false;

    void Init(std::uint32_t W, std::uint32_t blocksize) {
        if (ready) return;
        const std::uint32_t u2 = ((W < 0x400u) ? 0u : (W - 0x400u)) + 0x3ffu;
        const std::uint32_t b1 = BitLen1(u2);
        shift = b1 + 1u;
        winsize = W;
        maskA = (1u << shift) - 1u;
        const std::uint32_t b2 = (shift < 0x14u) ? 0x10u : (b1 - 0x13u) + 0x10u;
        headmask = (1u << b2) - 1u;
        head.assign(static_cast<std::size_t>(headmask) + 1u, 0u);
        cache.assign(0x10000u * 4u, 0u);
        const std::uint32_t tsz = blocksize * 3u;
        treemask = ((1u << (BitLen1(tsz) + 1u)) - 1u) >> 2u;
        treesize = tsz >> 2u;
        tree.assign(treesize + 2u, 0u);
        const std::uint32_t bits = 19u;
        lr.assign(static_cast<std::size_t>(1u) << bits, 0u);
        lrmask = (1u << bits) - 1u;
        ready = true;
    }

    // FUN_08082fa0: bulk-insert into the hash head and the 2-byte 4-slot cache.
    void Skip(const std::uint8_t* base, std::uint32_t from, std::uint32_t n) {
        if (n == 0u) return;
        const std::uint8_t* p = base + from;
        if (n > 0x402000u) { p += (n - 0x400000u); from += (n - 0x400000u); n = 0x400000u; }
        else {
            for (; n > 0x2000u; --n) {
                const std::uint32_t w = Load32(p);
                ++p;
                head[((w >> 19u) ^ w) & headmask] = (~maskA & w) | from;
                ++from;
            }
        }
        for (std::uint32_t k = 0; k < n; ++k) {
            const std::uint32_t w = Load32(p + k);
            const std::uint32_t at = k + from;
            head[((w >> 19u) ^ w) & headmask] = (~maskA & w) | at;
            cache[static_cast<std::size_t>(w & 0xffffu) * 4u] =
                (static_cast<std::uint32_t>(p[k + 2u]) << shift) + at;
        }
    }

    // FUN_08073ca0: the 2-byte 4-slot cache probes, then the bt4 tree descent.
    void Find(const std::uint8_t* base, std::uint32_t cur, std::uint32_t cend,
              std::uint32_t maxlen, std::vector<Cand>& outc, std::uint32_t depth) {
        const std::uint32_t w = Load32(base + cur);
        const std::uint32_t hidx = ((w >> 19u) ^ w) & headmask;
        std::uint32_t chain = head[hidx];
        if (verbose)
            std::fprintf(stderr, "[FIND] cur=%u w=%08x hidx=%u chain=%08x (pos=%u) winsize=%u maxlen=%u depth=%u\n",
                         cur, w, hidx, chain, chain & maskA, winsize, maxlen, depth);
        const std::uint32_t tagv = static_cast<std::uint32_t>(base[cur + 2u]) << shift;
        std::uint32_t* const cs = &cache[static_cast<std::size_t>(w & 0xffffu) * 4u];
        std::uint32_t bestlen = 1;
        const auto valid = [&](std::uint32_t p) { return cend <= p || p < cur; };
        bool got3 = false;
        if (cs[0] != 0u) {
            const std::uint32_t cp = cs[0] & maskA;
            if (Load16(base + cur) == Load16(base + cp) && valid(cp)) {
                if (maxlen < 2u) { bestlen = 1; }
                else {
                    outc.push_back({2u, cp});
                    bestlen = 2;
                    if ((~maskA & cs[0]) == tagv) {
                        if (base[cp + 2u] == base[cur + 2u] && maxlen > 2u) {
                            outc.push_back({3u, cp});
                            bestlen = 3; got3 = true;
                        }
                    }
                }
            }
        }
        if (!got3) {
            for (int k = 1; k < 4; ++k) {
                const std::uint32_t e = cs[k];
                if (e == 0u) break;
                if ((~maskA & e) == tagv) {
                    const std::uint32_t cp = maskA & e;
                    if (base[cp + 2u] == base[cur + 2u] && Load16(base + cur) == Load16(base + cp) &&
                        valid(cp) && maxlen > 2u) {
                        outc.push_back({3u, cp});
                        bestlen = 3;
                        break;
                    }
                }
            }
        }
        if (bestlen >= maxlen) return;
        cs[3] = cs[2]; cs[2] = cs[1]; cs[1] = cs[0]; cs[0] = tagv + cur;
        head[hidx] = cur | (~maskA & w);
        std::uint32_t ti = (cur * 2u) & treemask;
        if (treesize <= ti) ti -= treesize;
        std::uint32_t* gt = &tree[ti];
        std::uint32_t* ls = &tree[ti] + 1;
        std::uint32_t lg = 0, ll = 0;
        while (chain != 0u && --depth != 0u) {
            const std::uint32_t cp = maskA & chain;
            if (verbose) std::fprintf(stderr, "[FIND]   step cp=%u valid=%d\n", cp, (int)valid(cp));
            if (cp >= winsize || !valid(cp)) { if (verbose) std::fprintf(stderr, "[FIND]   stop: cp>=winsize||!valid\n"); break; }
            std::uint32_t ci = (cp * 2u) & treemask;
            std::uint32_t* ch = (ci < treesize) ? &tree[ci] : &tree[ci - treesize];
            std::uint32_t k = std::min(lg, ll);
            std::uint32_t lim = (cp + maxlen <= winsize) ? maxlen : (winsize - cp);
            if (lim <= k) { *ls = ch[0]; *gt = ch[1]; return; }
            if (base[cur + k] == base[cp + k]) {
                const std::int32_t pre = static_cast<std::int32_t>(k) - 1;
                if (pre > 2 && ((cp ^ chain) != (~maskA & w))) return;
                std::uint32_t j = k;
                for (;;) { const std::uint32_t nx = j + 1u; if (lim <= nx) { j = nx; break; } if (base[cur + nx] != base[cp + nx]) { j = nx; break; } j = nx; }
                if (bestlen < j) {
                    bool ok = true;
                    for (std::int32_t q = pre; q >= 0; --q) if (base[cur + q] != base[cp + q]) { ok = false; break; }
                    if (!ok) { *ls = ch[0]; *gt = ch[1]; return; }
                    outc.push_back({j, cp});
                    bestlen = j;
                    if (lim == j) { *ls = ch[0]; *gt = ch[1]; return; }
                }
                if (base[cp + j] < base[cur + j]) { *gt = chain; gt = ch + 1; chain = ch[1]; lg = j; }
                else { *ls = chain; chain = ch[0]; ls = ch; ll = j; }
            } else if (base[cp + k] < base[cur + k]) {
                *gt = chain; gt = ch + 1; chain = ch[1]; lg = k;
            } else {
                *ls = chain; chain = ch[0]; ls = ch; ll = k;
            }
        }
        *gt = 0; *ls = 0;
    }
};

namespace {

// DAT_08171d40: c * K^256, what leaves the 256-byte rolling window.
const std::uint32_t* LrOut() {
    static std::uint32_t t[256];
    static bool done = false;
    if (!done) {
        std::uint32_t k = 1;
        for (int i = 0; i < 0x100; ++i) k *= 0x104070bu;
        std::uint32_t v = 0;
        for (int i = 0; i < 256; ++i) { t[i] = v; v += k; }
        done = true;
    }
    return t;
}

// FUN_08088660: the dispatch probability, both APM stages, no update. The
// decoder's own dispatch-bit code with the three writes removed.
std::uint32_t DispatchProb(const std::uint8_t* mem, std::uint32_t dispIdx,
                           std::uint32_t row1, std::uint32_t row2) {
    const std::uint8_t dstate = Rd8(mem, 0x1040480 + dispIdx);
    const std::uint32_t apm1In = static_cast<std::uint32_t>(Stretch(dstate) * 4 + 0x2000);
    const std::uint32_t frac1 = apm1In & 0xfffu;
    const std::size_t a1 = 0x1040c90u + static_cast<std::size_t>(row1) * 10u +
                           static_cast<std::size_t>(apm1In >> 12u) * 2u;
    const std::uint32_t stage1 =
        (static_cast<std::uint32_t>(dstate) * 0x10u + 2u +
         (((static_cast<std::uint32_t>(Rd16(mem, a1)) * (0x1000u - frac1) +
            frac1 * static_cast<std::uint32_t>(Rd16(mem, a1 + 2u))) >> 16) * 3u)) >> 2;
    const std::uint32_t apm2In =
        static_cast<std::uint32_t>(Stretch(static_cast<std::uint8_t>(stage1 >> 4)) * 9 + 0x4800);
    const std::uint32_t frac2 = apm2In & 0xfffu;
    const std::size_t a2 = 0x10417e0u + static_cast<std::size_t>(row2) * 20u +
                           static_cast<std::size_t>(apm2In >> 12u) * 2u;
    const std::uint32_t mixed =
        (stage1 + 2u +
         (((static_cast<std::uint32_t>(Rd16(mem, a2)) * (0x1000u - frac2) +
            frac2 * static_cast<std::uint32_t>(Rd16(mem, a2 + 2u))) >> 16) * 3u)) >> 2;
    return Bias(mixed);
}

// The rep-select price for a0 (0..3 = rep slot, 4 = a brand-new distance),
// excluding the dispatch bit. Not cached in this engine: the counter-driven
// addressing the decoder models (0x1040440, masked with 0x7ff on every eighth
// step) means the cell a bit reads depends on how many bits were read before it,
// so a price computed once would not stay valid anyway.
std::uint32_t SelDelta(std::uint8_t* mem, const std::uint8_t* T, std::uint8_t hist,
                       std::uint32_t mm, std::uint32_t a0) {
    const std::uint32_t unit_idx = ((static_cast<std::uint32_t>(hist) & 0xfu) + (mm & 0xfu) * 0x10u) * 8u;
    std::uint32_t counter = unit_idx;
    const std::uint32_t p1 = Rd16(mem, 0x103f400u + static_cast<std::size_t>(unit_idx & 0x3f8u) * 2u) >> 4u;
    std::uint32_t px = Cost(T, (a0 >= 4u) ? 1u : 0u, Bias(p1));
    ++counter;
    if (a0 < 4u) {
        int left = 3;
        for (;;) {
            const std::uint32_t idx = ((counter & 7u) == 1u) ? (counter & 0x7ffu) : (counter & 0xffffu);
            const bool last = (static_cast<int>(a0) - 3 + left) == 0;
            const std::uint32_t p = Rd16(mem, 0x103f400u + static_cast<std::size_t>(idx) * 2u) >> 4u;
            ++counter;
            px += Cost(T, last ? 1u : 0u, Bias(p));
            --left;
            if (last || left == 0) break;
        }
    }
    return px;
}

// The length price, cached at 0x103b380 by (len, is-rep0) in 16-bit cells whose
// empty value is 0xffff -- and read back only while len - 2 is under 0x20. A
// length whose v = len - 2 reaches 0xff prices at zero, exactly as in `-co`.
std::uint32_t LenCost(std::uint8_t* mem, const std::uint8_t* T, std::uint32_t L,
                      std::uint32_t a0, bool use_cache) {
    const std::uint32_t v = L - 2u;
    if (v >= 0xffu) return 0u;
    const std::size_t cell = 0x103b380u + static_cast<std::size_t>(L) * 4u + ((a0 == 0u) ? 2u : 0u);
    // The original remembers THIS cell in a scratch field (0x103b988) and decays
    // whatever that field points at when a relaxation beats an existing node. The
    // field is only refreshed while v is under 0xff, so a length past that decays
    // the last cell some earlier, shorter length left behind -- kept as it is.
    Wr32(mem, 0x103b988, static_cast<std::int32_t>(cell));
    if (use_cache && v < 0x20u) {
        const std::uint16_t c = Rd16(mem, cell);
        if (c != 0xffffu) {
            if (const char* cd = NZ_ENV("NZO2_CELLDBG")) {
                if (cell == (std::size_t)std::atoi(cd))
                    std::fprintf(stderr, "[CELL] hit cell=%zu L=%u a0=%u -> %u\n", cell, L, a0, c);
            }
            return c;
        }
    }
    std::uint32_t acc = 0;
    std::uint32_t idx = (a0 == 0u ? 1u : 0u) << 4u;
    std::uint32_t vv = v, nb = 0;
    for (;;) {
        vv >>= 1u;
        const std::uint32_t cellp = Rd16(mem, 0x103ae40u + static_cast<std::size_t>(idx) * 2u) >> 4u;
        ++idx; ++nb;
        acc += Cost(T, (vv != 0u) ? 1u : 0u, cellp);
        if (vv == 0u) break;
    }
    const std::uint32_t rowb = (nb - 1u) << 5u;
    std::uint32_t persisted = (a0 == 4u) ? 3u : 1u;
    const std::uint32_t nbits = (nb < 5u) ? ((nb - 1u) ? (nb - 1u) : 1u) : 4u;
    const std::uint32_t raws = (nb < 5u) ? 0u : (nb - 5u);
    std::uint32_t bits = v << (((nb < 5u) ? (0x20u - nbits) : (0x21u - nb)) & 0x1fu);
    for (std::uint32_t i = 0; i < nbits; ++i) {
        const std::uint32_t bit = (bits >> 31u) & 1u; bits <<= 1u;
        const std::size_t c2 = 0x103ae40u + static_cast<std::size_t>(persisted + rowb + 0x60u) * 2u;
        acc += Cost(T, bit, Rd16(mem, c2) >> 4u);
        persisted = bit + persisted * 2u;
    }
    if (raws != 0u) acc += raws * 0x1cu;
    if (const char* cd = NZ_ENV("NZO2_CELLDBG")) {
        if (cell == (std::size_t)std::atoi(cd))
            std::fprintf(stderr, "[CELL] store cell=%zu L=%u a0=%u acc=%u\n", cell, L, a0, acc);
    }
    Wr16(mem, cell, static_cast<std::uint16_t>(acc));
    return acc;
}

// The price of a brand-new distance: five slot-tree bits with their own two-cell
// refinement, one or two tier-1 bits, the shared align table's bits, and the
// tier-3 high bits. Recomputed at every candidate -- this engine keeps no
// distance-class cache.
std::uint32_t PriceDistance(const std::uint8_t* mem, const std::uint8_t* T,
                            const std::uint8_t* D4D0, std::uint32_t D, std::uint32_t len) {
    const std::uint32_t bl = BitLen1(D);
    const std::uint32_t v = len - 2u;
    const std::uint32_t bucket = D4D0[(v > 0xfu) ? 0xfu : v];
    std::uint32_t acc = 0;
    std::uint32_t tp = 1;
    std::uint32_t bits = (~bl) << 27u;
    for (int i = 0; i < 5; ++i) {
        const std::size_t c1 = 0x103b9c0u + static_cast<std::size_t>(tp + bucket * 0x20u) * 2u;
        const std::uint32_t cell1 = Rd16(mem, c1);
        const std::uint32_t i2 = static_cast<std::uint32_t>(
            ((static_cast<std::int32_t>(Stretch(static_cast<std::uint8_t>(cell1 >> 8))) + 0x800) >> 8)) + 0x140u + tp * 0x11u;
        const std::size_t c2 = 0x103b9c0u + static_cast<std::size_t>(i2) * 2u;
        const std::uint32_t comb = ((cell1 >> 4u) + 2u +
            ((static_cast<std::uint32_t>(Rd16(mem, c2 + 2u)) + 1u + static_cast<std::uint32_t>(Rd16(mem, c2))) >> 5u) * 3u) >> 2u;
        const std::uint32_t bit = (bits >> 31u) & 1u; bits <<= 1u;
        acc += Cost(T, bit, Bias(comb));
        tp = bit + tp * 2u;
    }
    const std::uint32_t n1 = (bl < 2u) ? 1u : 2u;
    {
        std::uint32_t t1 = 1;
        std::uint32_t b1 = D << ((0x20u - ((bl > 1u) ? bl : 1u)) & 0x1fu);
        for (std::uint32_t i = 0; i < n1; ++i) {
            const std::uint32_t bit = (b1 >> 31u) & 1u; b1 <<= 1u;
            const std::size_t c = 0x103b9c0u + static_cast<std::size_t>(t1 + 0xf80u + bl * 0x60u) * 2u;
            acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            t1 = bit + t1 * 2u;
        }
    }
    if (bl > 2u) {
        const std::uint32_t n2 = (bl < 6u) ? (bl - 2u) : 4u;
        std::uint32_t t2 = 1, d = D;
        for (std::uint32_t i = 0; i < n2; ++i) {
            const std::uint32_t bit = d & 1u; d >>= 1u;
            const std::size_t c = static_cast<std::size_t>(kTier2AlignOff) + static_cast<std::size_t>(t2) * 2u;
            acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            t2 = bit + t2 * 2u;
        }
        if (bl > 6u) {
            const std::uint32_t n3 = bl - 6u;
            std::uint32_t b3 = D << ((0x1cu - n3) & 0x1fu);
            for (std::uint32_t i = 0; i < n3; ++i) {
                const std::uint32_t bit = (b3 >> 31u) & 1u; b3 <<= 1u;
                const std::size_t c = 0x103c0c0u + static_cast<std::size_t>(n3) * 0xc0u + static_cast<std::size_t>(i) * 2u;
                acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            }
        }
    }
    return acc;
}


// The cost of coding `lit` with the 8-input mixer as it stands: the decoder's
// literal loop with every update removed and the bit costs summed instead. All
// the per-byte state the decoder keeps in `mem` scratch fields (0x103ae12..20)
// lives in locals here, so pricing leaves the model untouched.
std::uint32_t PriceLiteral(const std::uint8_t* mem, const std::uint8_t* T,
                           std::uint32_t ctxWord, std::uint8_t hist, std::uint8_t lit,
                           std::uint32_t mm4, std::uint8_t predRep0, std::uint8_t predLzp,
                           std::uint32_t lzpConf, std::uint8_t am2, std::uint8_t am3,
                           std::uint32_t remain) {
    int ctxP = 0x218c0 + static_cast<int>((static_cast<std::uint32_t>(am2) * 0x100u + (ctxWord & 0xffu)) * 0x100u);
    int ctx2 = 0x160 + static_cast<int>((ctxWord & 0xffu) * 0x100u);
    int ctx3 = 0x10480 + static_cast<int>(static_cast<std::uint32_t>(am2) * 0x100u);
    std::uint32_t ctx1p = (((ctxWord & 0xe0u) >> 5) +
                           (static_cast<std::uint32_t>(am3) & 0xe0u) * 2u +
                           ((static_cast<std::uint32_t>(am2) & 0xe0u) >> 2)) * 0x100u;
    std::uint16_t rep0Hist = static_cast<std::uint16_t>(predRep0 + 0x100u);
    std::uint16_t lzpHist  = static_cast<std::uint16_t>(predLzp + 0x100u);
    std::uint32_t ctx6s = (remain & 3u) * 0x10u + 1u + mm4 * 0x40u +
                          ((static_cast<std::uint32_t>(rep0Hist) >> 6) & 2u);
    std::uint32_t ctx7s = (ctxWord & 0x1fu) * 0x80u + 1u + (lzpConf & 3u) * 0x20u +
                          ((static_cast<std::uint32_t>(lzpHist) >> 6) & 2u);
    std::uint8_t confByte = 0, shiftreg = 1, subc = 0, scaleAcc = 0, hist2e = 0;
    std::uint32_t ctxC = 1;
    if ((hist & 1u) == 0u) {
        const std::uint8_t prevHi = static_cast<std::uint8_t>(ctxWord >> 8);
        hist2e = prevHi;
        ctxC = (static_cast<std::uint32_t>(prevHi) >> 7) + 0x202u;
    }

    // one mixer bit's probability -- MixerBit with every write dropped
    auto Prob = [&]() -> std::uint32_t {
        const std::uint8_t stateP = Rd8(mem, ctxP);
        const std::uint32_t modele0Cur = static_cast<std::uint32_t>(Rd32(mem, 0x1021900 + static_cast<int>(stateP) * 4));
        const std::int32_t in0 = Stretch(static_cast<std::uint8_t>(modele0Cur >> 24));
        const std::uint32_t nibbleShift = (ctx1p & 1u) * 4u;
        const std::uint8_t nibblePacked = Rd8(mem, 0x1021d80 + static_cast<int>(ctx1p >> 1));
        const std::uint32_t ctx1_nibble = (static_cast<std::uint32_t>(nibblePacked) >> nibbleShift) & 0xfu;
        const std::int32_t in1 = Stretch(Rd8(mem, 0x1031d81 + static_cast<int>(ctx1_nibble) * 2));
        const std::int32_t in2 = Stretch(Rd8(mem, ctx2));
        const std::int32_t in3 = Stretch(Rd8(mem, ctx3));
        const std::int32_t in4 = Stretch(Rd8(mem, 0x10170 + static_cast<int>(ctxC)));
        const std::int32_t in5 = Stretch(static_cast<std::uint8_t>((in4 + 0x800) >> 4));
        const std::int32_t in6 = Stretch(Rd8(mem, 0x20490 + static_cast<int>(ctx6s)));
        const std::int32_t in7 = Stretch(Rd8(mem, 0x208a0 + static_cast<int>(ctx7s)));
        const int wRowOff = 0x90 + static_cast<int>(((ctx6s >> 6) & 3u) + (ctxC >> 8) * 4u) * 0x10;
        const std::int32_t inputs[8] = {in0, in1, in2, in3, in4, in5, in6, in7};
        std::int32_t dot = 0;
        for (int i = 0; i < 8; i++)
            dot += static_cast<std::int32_t>(static_cast<std::int16_t>(Rd16(mem, wRowOff + i * 2))) * inputs[i];
        const std::int32_t sq = (dot >> 16) + 0x800;
        const std::uint32_t sqU = (sq < 0) ? 0u : static_cast<std::uint32_t>(sq);
        const std::uint32_t sqMin = (sqU < 0xfffu) ? sqU : 0xfffu;
        const std::uint32_t scaled = sqMin * 0xbu;
        const std::uint16_t apmSeed = Optimum2Dat081732c0()[sqMin >> 4];
        const std::uint32_t frac = scaled & 0xfffu;
        const int apmOff = 0x1031e00 + static_cast<int>(confByte + ctxC * 2u) * 24 +
                           static_cast<int>(scaled >> 12) * 2;
        const std::uint32_t interp = (static_cast<std::uint32_t>(Rd16(mem, apmOff)) * (0x1000u - frac) +
                                      frac * static_cast<std::uint32_t>(Rd16(mem, apmOff + 2))) >> 16;
        const std::uint32_t mixedP = (static_cast<std::uint32_t>(apmSeed) + 2u + interp * 3u) >> 2;
        return mixedP + ((mixedP < 0x800u) ? 1u : 0u);
    };
    // the shared tail -- AdvanceAfterBit against the locals
    auto Advance = [&](std::uint32_t bit, std::uint32_t pFinal) {
        confByte = (0xa01u < (bit * 0x1000u - pFinal) + 0x500u) ? std::uint8_t{1} : std::uint8_t{0};
        shiftreg = static_cast<std::uint8_t>(bit + shiftreg * 2u);
        rep0Hist = static_cast<std::uint16_t>(rep0Hist << 1);
        lzpHist  = static_cast<std::uint16_t>(lzpHist << 1);
        subc = static_cast<std::uint8_t>(subc + 1);
        std::uint32_t nodeStep;
        if (subc == 4) {
            nodeStep = (static_cast<std::uint32_t>(shiftreg) * 0xfu - scaleAcc) - 0xe1u;
        } else {
            nodeStep = (bit + 1u) << ((subc & 3u) - 1u);
            scaleAcc = static_cast<std::uint8_t>(scaleAcc + static_cast<std::uint8_t>(nodeStep));
        }
        ctxP += static_cast<int>(nodeStep);
        ctx2 += static_cast<int>(nodeStep);
        ctx1p += nodeStep;
        ctx3 += static_cast<int>(nodeStep);
        ctx6s = (ctx6s & 0xfff0u) + ((static_cast<std::uint32_t>(rep0Hist) >> 6) & 2u) +
                (static_cast<std::uint32_t>(subc >> 1) * 4u) +
                (((static_cast<std::uint32_t>(rep0Hist) >> 8) == shiftreg) ? 1u : 0u);
        ctx7s = (ctx7s & 0xffe0u) + static_cast<std::uint32_t>(subc) * 4u +
                ((static_cast<std::uint32_t>(lzpHist) >> 6) & 2u) +
                (((static_cast<std::uint32_t>(lzpHist) >> 8) == shiftreg) ? 1u : 0u);
        const std::uint32_t oldCtxC = ctxC;
        ctxC = (oldCtxC & 0xff00u) | shiftreg;
        if (oldCtxC >= 0x200u) {
            const std::uint8_t histByte = shiftreg;
            ctxC = static_cast<std::uint32_t>(histByte) + 0x100u;
            if (bit == (oldCtxC & 1u)) {
                hist2e = static_cast<std::uint8_t>(hist2e * 2);
                const std::int16_t signext = static_cast<std::int16_t>(static_cast<std::int8_t>(histByte));
                const std::uint32_t hi = (static_cast<std::uint16_t>(~signext) >> 15) *
                                          (static_cast<std::uint32_t>(histByte) * 2u);
                ctxC = hi + 0x200u + (static_cast<std::uint32_t>(hist2e) >> 7);
            }
        }
    };

    std::uint32_t cost = 0;
    std::uint32_t bitsLeft = 4;
    for (;;) {
        const std::uint32_t p1 = Prob();
        const std::uint32_t b1 = (static_cast<std::uint32_t>(lit) >> ((7u - 2u * (4u - bitsLeft)) & 31u)) & 1u;
        cost += Cost(T, b1, p1);
        Advance(b1, p1);
        const std::uint32_t p2 = Prob();
        const std::uint32_t b2 = (static_cast<std::uint32_t>(lit) >> ((6u - 2u * (4u - bitsLeft)) & 31u)) & 1u;
        cost += Cost(T, b2, p2);
        bitsLeft -= 1;
        if (bitsLeft == 0) break;
        Advance(b2, p2);
    }
    return cost;
}

}  // namespace

void NzOptimum2LzDecoder::EnableParser() {
    if (!parser_) parser_ = std::make_shared<ParserState>();
    parser_->Init(ring_.capacity, blocksize_);
}

// The window feed's tail: hand the appended span to the finder and keep the
// long-range index current over it (see the `-co` sibling for the reasoning --
// the two functions are the same code on a different object).
void NzOptimum2LzDecoder::FeedFinder(std::uint32_t cursor_before, std::uint32_t len) {
    if (!parser_) {
        if (NZ_ENV("NZO2_PARSECHK") == nullptr && NZ_ENV("NZO2_RECODE") == nullptr) return;
        parser_ = std::make_shared<ParserState>();
    }
    ParserState& F = *parser_;
    F.Init(ring_.capacity, blocksize_);
    const std::uint32_t cap = ring_.capacity;
    if (cap == 0u || len == 0u) return;
    std::uint32_t n = len, from = cursor_before;
    if (cap <= len + 0x8000u) { n = (len < cap) ? len : cap; from = 0; }
    std::uint8_t* const base = ring_.Base();
    const std::uint32_t* const LRO = LrOut();
    auto lr_span = [&](std::uint32_t at, std::uint32_t cnt) {
        std::uint32_t h = 0;
        for (std::uint32_t i = 0; i < 0x100u; ++i) h = h * 0x104070bu + base[at + i];
        F.lrhash = h;
        for (std::uint32_t i = 0; i < cnt; ++i) {
            const std::uint32_t pos = at + i;
            if ((pos & 0xffu) == 0u) F.lr[h & F.lrmask] = (h & 0xffc00000u) + (pos >> 8u);
            h = h * 0x104070bu + base[pos + 0x100u] - LRO[base[pos]];
            F.lrhash = h;
        }
    };
    if (from < ring_.cursor) { F.Skip(base, from, n); lr_span(from, n); }
    else {
        const std::uint32_t tail = cap - from;
        if (tail >= n) { F.Skip(base, from, n); lr_span(from, n); }
        else { F.Skip(base, from, tail); lr_span(from, tail); F.Skip(base, 0u, n - tail); lr_span(0u, n - tail); }
    }
}

// The pieces param15's encoder borrows: the long-range index the window feed
// maintains (the ring itself comes from WindowBase/WindowCapacity).
std::uint32_t* NzOptimum2LzDecoder::ParserArena() { return parser_ ? parser_->tree.data() : nullptr; }
std::size_t NzOptimum2LzDecoder::ParserArenaWords() const { return parser_ ? parser_->tree.size() : 0u; }

const std::uint32_t* NzOptimum2LzDecoder::LongRangeTable() const { return parser_ ? parser_->lr.data() : nullptr; }
std::uint32_t NzOptimum2LzDecoder::LongRangeMask() const { return parser_ ? parser_->lrmask : 0u; }

bool NzOptimum2LzDecoder::ChunkExhausted() const {
    return !parser_ || parser_->consumed >= parser_->size;
}

void NzOptimum2LzDecoder::BeginChunk(std::uint32_t off, std::uint32_t len,
                                     std::uint32_t ring_pos, bool reset_reps) {
    if (!parser_) return;
    ParserState& F = *parser_;
    F.src = F.block + off;
    F.size = len;
    F.consumed = 0;
    F.pos0 = ring_pos;
    F.staged = true;
    std::uint8_t* const b0 = ring_.Base();
    std::memcpy(b0 + ring_pos, F.src, len);
    const std::uint32_t cap = ring_.capacity;
    if (reset_reps) F.rep0[0] = F.rep0[1] = F.rep0[2] = F.rep0[3] = 1;
    const std::uint32_t e0 = ring_pos + len;
    for (int k = 0; k < 4; ++k) {
        std::uint32_t p = ring_pos - (F.rep0[k] + 1u);
        if (ring_pos < F.rep0[k] + 1u) p += cap;
        if (cap <= p || (p < e0 && ring_pos <= p)) F.rep0[k] = 1;
    }
    std::uint32_t lrh = 0;
    for (std::uint32_t i = 0; i < 0x100u; ++i) lrh = lrh * 0x104070bu + b0[ring_pos + i];
    F.lrhash = lrh;
}

void NzOptimum2LzDecoder::BeginParse(const std::uint8_t* data, std::uint32_t size) {
    if (!parser_) parser_ = std::make_shared<ParserState>();
    ParserState& F = *parser_;
    F.Init(ring_.capacity, blocksize_);
    F.block = data; F.src = data; F.size = size; F.consumed = 0;
    F.started = false; F.staged = false; F.pos0 = 0;
    F.rep0[0] = F.rep0[1] = F.rep0[2] = F.rep0[3] = 1;
    F.hist0 = 0xff; F.ctx0 = 0;
}

// One flush of the DP, from the ring and the models as they stand right now.
bool NzOptimum2LzDecoder::ParseNextFlush(std::vector<Optimum2Decision>& out) {
    if (!parser_) return false;
    ParserState& F = *parser_;
    if (F.consumed >= F.size) return false;

    const std::uint8_t* const T = CostTable();
    const std::uint32_t* const LRO = LrOut();
    std::uint8_t* const mem = mem_.data();
    const std::uint32_t cap = ring_.capacity;
    const std::uint8_t* const D140 = nzr::optimum::OptimumDat08172380();   // == DAT_08173140
    const std::uint8_t* const D290 = nzr::optimum::OptimumDat081724d0();   // == DAT_08173290
    const bool trace = (NZ_ENV("NZO2_TRACE_PARSE") != nullptr);

    // The original's node is 32 bytes: tag, price, back, len, ctx, hist, the
    // slot (0..3 = rep, 4 = a new distance) and the four rep offsets.
    struct Node {
        std::uint16_t tag = 0, price = 0, back = 0, len = 0, ctx = 0;
        std::uint8_t hist = 0;
        std::uint8_t sg = 0;            // 0..3 rep, 4 new distance, 0xff literal
        std::uint32_t dist = 0;
        std::uint32_t rep[4] = {0, 0, 0, 0};
    };
    // The lookahead below reads up to node ni+6, and the original reads the
    // stack locals that follow its own array there.
    //
    // The array has to arrive CLEAR (a node counts as written only while its
    // tag is this chunk's, and the tag of an untouched one must not be), but
    // clearing all of it costs more than the parse: this runs once per handful
    // of input bytes and the array is 133 KB, which was 64 % of a `-cO` encode.
    // So only what the last call dirtied is cleared -- everything above it is
    // still Node{} from before.
    constexpr std::uint32_t kNodes = 0x1040u + 8u;
    static thread_local std::vector<Node> nodes;
    static thread_local std::uint32_t nodes_dirty = 0;
    if (nodes.size() != kNodes) nodes.assign(kNodes, Node{});
    else if (nodes_dirty != 0u) std::fill_n(nodes.begin(), nodes_dirty, Node{});
    nodes_dirty = kNodes;              // pessimistic until the parse has ended
    std::uint32_t dirty_hi = 0;        // the highest node this call writes

    std::uint32_t* const rep0 = F.rep0;
    std::uint8_t& hist0 = F.hist0;
    std::uint16_t& ctx0 = F.ctx0;
    if (!F.started && !F.staged) {
        F.started = true;
        ring_.EnsureHeadroom(F.size);
        F.pos0 = ring_.cursor;
        std::memcpy(ring_.Base() + F.pos0, F.src, F.size);
        std::uint8_t* const b0 = ring_.Base();
        const std::uint32_t e0 = F.pos0 + F.size;
        for (int k = 0; k < 4; ++k) {
            std::uint32_t p = F.pos0 - (rep0[k] + 1u);
            if (F.pos0 < rep0[k] + 1u) p += cap;
            if (cap <= p || (p < e0 && F.pos0 <= p)) rep0[k] = 1;
        }
        std::uint32_t lrh = 0;
        for (std::uint32_t i = 0; i < 0x100u; ++i) lrh = lrh * 0x104070bu + b0[F.pos0 + i];
        F.lrhash = lrh;
    }

    std::uint8_t* const base = ring_.Base();
    const std::uint32_t chunk = F.size;
    const std::uint32_t pos0 = F.pos0;
    const std::uint32_t cend = pos0 + chunk;
    const std::uint32_t emitted = F.consumed;
    {
        std::uint32_t lrh = 0;
        for (std::uint32_t i = 0; i < 0x100u; ++i) lrh = lrh * 0x104070bu + base[pos0 + emitted + i];
        F.lrhash = lrh;
    }
    const std::uint32_t remain0 = chunk - emitted;
    nodes[0].price = 0; nodes[0].hist = hist0; nodes[0].ctx = ctx0;
    for (int k = 0; k < 4; ++k) nodes[0].rep[k] = rep0[k];
    std::uint32_t front = 1;
    std::uint32_t ni = 0;
    std::uint32_t endnode = 0;
    const std::uint16_t TAG = static_cast<std::uint16_t>(chunk);

    while (true) {
        Node& nd = nodes[ni];
        const std::uint32_t cur = pos0 + emitted + ni;
        const std::uint32_t remain = chunk - emitted - ni;
        if (nd.rep[0] >= cap) return false;
        std::uint32_t pr = cur - (nd.rep[0] + 1u);
        if (cur < nd.rep[0] + 1u) pr += cap;
        std::uint32_t predpos = pr;
        { const std::uint32_t bc = pr - 4u; if (bc < cend && cur <= bc) predpos = cur - 1u; }
        const std::uint8_t predB = At(base, predpos);
        const std::uint8_t am1 = At(base, cur - 1u), am2 = At(base, cur - 2u);
        const std::uint8_t am3 = At(base, cur - 3u), am4 = At(base, cur - 4u);
        const std::uint32_t mm =
            ((At(base, predpos - 1u) == am1) ? 1u : 0u) |
            ((At(base, predpos - 2u) == am2) ? 2u : 0u) |
            ((At(base, predpos - 3u) == am3) ? 4u : 0u) |
            ((At(base, predpos - 4u) == am4) ? 8u : 0u);
        const std::uint32_t dispIdx = (mm & 7u) + static_cast<std::uint32_t>(predB) * 8u;

        // ---- the dispatch probability, both APM stages
        const std::uint32_t row1 = static_cast<std::uint32_t>(D140[nd.hist]) * 0x10u + mm;
        const std::uint32_t row2 = (mm & 3u) * 0x10u + (static_cast<std::uint32_t>(nd.ctx) & 0xfu);
        const std::uint32_t dprob = DispatchProb(mem, dispIdx, row1, row2);
        const std::uint32_t dmatch = Cost(T, 0u, dprob);   // dispatch bit 0 = match
        const std::uint32_t dlit   = Cost(T, 1u, dprob);   // dispatch bit 1 = literal

        auto SelPrice = [&](std::uint32_t slot) -> std::uint32_t {
            return dmatch + SelDelta(mem, T, nd.hist, mm, slot);
        };
        // write one relaxed node; false means the existing path is cheaper,
        // which ends the whole relaxation
        auto Update = [&](std::uint32_t L, std::uint32_t slot, std::uint32_t dist,
                          const std::uint32_t* nr, std::uint32_t basep, std::uint32_t lenp) -> bool {
            Node& tg = nodes[ni + L];
            if (ni + L > dirty_hi) dirty_hi = ni + L;
            const std::uint32_t price = basep + lenp;
            if (tg.tag == TAG) {
                if (tg.price <= price) return false;
                // decay the length-price cell this relaxation just beat, through the
                // engine's own scratch pointer (see LenCost)
                const std::size_t lc = static_cast<std::size_t>(Rd32(mem, 0x103b988));
                if (lc >= 0x103b380u && lc < 0x103b788u) {
                    const std::uint16_t c = Rd16(mem, lc);
                    if (NZ_ENV("NZO2_DECAYDBG"))
                        std::fprintf(stderr, "[DECAY] cell=%zu L=%zu row=%s %u -> %u\n", lc,
                                     (lc - 0x103b380u) / 4u, ((lc - 0x103b380u) % 4u) ? "r0" : "nd",
                                     c, c - (c >> 7));
                    Wr16(mem, lc, static_cast<std::uint16_t>(c - (c >> 7)));
                }
            }
            tg.tag = TAG;
            tg.price = static_cast<std::uint16_t>(price);
            tg.back = static_cast<std::uint16_t>(ni);
            tg.len = static_cast<std::uint16_t>(L);
            tg.sg = static_cast<std::uint8_t>(slot);
            tg.dist = dist;
            tg.hist = static_cast<std::uint8_t>(nd.hist * 2u);
            const std::uint32_t sp = (cur >= dist) ? (cur - dist) : (cur + cap - dist);
            tg.ctx = static_cast<std::uint16_t>(At(base, sp + L) * 0x100u + At(base, cur + L - 1u));
            for (int k = 0; k < 4; ++k) tg.rep[k] = nr[k];
            return true;
        };
        // a match long enough (or far enough past the horizon) is taken whole
        auto TakeWhole = [&](std::uint32_t L, std::uint32_t slot, std::uint32_t dist,
                             const std::uint32_t* nr) {
            Node& tg = nodes[ni + 1u];
            if (ni + 1u > dirty_hi) dirty_hi = ni + 1u;
            tg.tag = TAG;
            tg.back = static_cast<std::uint16_t>(ni);
            tg.len = static_cast<std::uint16_t>(L);
            tg.sg = static_cast<std::uint8_t>(slot);
            tg.dist = dist;
            tg.hist = static_cast<std::uint8_t>(nd.hist * 2u);
            const std::uint32_t sp = (cur >= dist) ? (cur - dist) : (cur + cap - dist);
            tg.ctx = static_cast<std::uint16_t>(At(base, sp + L) * 0x100u + At(base, cur + L - 1u));
            for (int k = 0; k < 4; ++k) tg.rep[k] = nr[k];
            front = ni + 1u;
        };

        // ---- the four rep offsets
        std::uint32_t best = 1;
        std::uint32_t thrv = 2;
        bool took_long = false;
        for (std::uint32_t i = 0; i < 4u && !took_long; ++i) {
            const std::uint32_t r = nd.rep[i];
            if (!(cur <= r || Load16(base + cur - r - 1u) == Load16(base + cur))) continue;
            std::uint32_t src = cur - (r + 1u);
            if (cur < r + 1u) src += cap;
            if (src >= cap) continue;
            const std::uint32_t avail = std::min<std::uint32_t>(cap - src, remain);
            if (avail == 0u) continue;
            std::uint32_t len = 0;
            while (len < avail && At(base, cur + len) == At(base, src + len)) ++len;
            if (trace) std::fprintf(stderr, "[R2] ni=%u rep%u r=%u src=%u len=%u best=%u avail=%u\n",
                                    ni, i, r, src, len, best, avail);
            if (len <= best || len == 1u) { best = std::max(best, len); continue; }
            best = len;
            std::uint32_t nr[4];
            for (int k = 0; k < 4; ++k) nr[k] = nd.rep[k];
            for (std::uint32_t k = i; k > 0u; --k) nr[k] = nr[k - 1u];
            nr[0] = r;
            if (len < 0x200u && ni + len < 0x1040u) {
                if (ni + len > front) front = ni + len;
                const std::uint32_t basep = nd.price + SelPrice(i);
                for (std::uint32_t L = len; L >= 2u; --L) {
                    const std::uint32_t lenp = LenCost(mem, T, L, i, true);
                    if (!Update(L, i, r + 1u, nr, basep, lenp)) break;
                    if (L > thrv) thrv = L;
                }
            } else {
                TakeWhole(len, i, r + 1u, nr);
                took_long = true;
            }
        }
        if (took_long) { endnode = front; break; }

        // ---- the bt4 finder, then the long-range index
        std::vector<Cand> cands;
        if (const char* fd = NZ_ENV("NZO2_FINDDBG"))
            F.verbose = (cur == static_cast<std::uint32_t>(std::atoi(fd)));
        F.Find(base, cur, cend, remain, cands, 0x100u);
        if (F.verbose) {
            std::fprintf(stderr, "[FIND] -> %zu candidates:", cands.size());
            for (const Cand& cc : cands) std::fprintf(stderr, " {src=%u len=%u dist=%u}", cc.src, cc.len, cur - cc.src);
            std::fprintf(stderr, "\n");
            F.verbose = false;
        }
        {
            const std::uint32_t bestf = cands.empty() ? 0u : cands.back().len;
            const std::uint32_t lidx = F.lrhash & F.lrmask;
            const std::uint32_t prev = F.lr[lidx];
            const std::uint32_t tag = F.lrhash & 0xffc00000u;
            if ((cur & 0xffu) == 0u) F.lr[lidx] = tag + (cur >> 8u);
            if ((prev & 0xffc00000u) == tag) {
                const std::uint32_t lsrc = (prev & 0x3fffffu) << 8u;
                const std::uint32_t w = F.winsize - lsrc;
                const std::uint32_t avail = (remain < w) ? remain : w;
                std::uint32_t a = 0;
                for (;;) {
                    if (base[lsrc + a] != base[cur + a]) break;
                    ++a;
                    if (avail <= a) break;
                }
                if (bestf < a) cands.push_back({a, lsrc});
            }
            F.lrhash = F.lrhash * 0x104070bu + base[cur + 0x100u] - LRO[base[cur]];
        }
        if (trace) {
            std::fprintf(stderr, "[C2] rem=%u ni=%u n=%zu:", chunk - emitted, ni, cands.size());
            for (const Cand& cc : cands) std::fprintf(stderr, " {src=%u len=%u}", cc.src - pos0, cc.len);
            std::fprintf(stderr, "\n");
        }
        // The top candidate is popped first; its SOURCE is then checked against
        // the part of the chunk that has not been written yet (the long-range
        // probe's answer is never validated the way the tree's is), and while it
        // falls there the length is walked down one step at a time, switching to
        // the next candidate whenever that one still reaches it.
        std::size_t ci = cands.empty() ? 0u : cands.size() - 1u;
        std::uint32_t toplen = cands.empty() ? 0u : cands.back().len;
        std::uint32_t topsrc = cands.empty() ? 0u : cands.back().src;
        if (!cands.empty() && toplen > thrv && cur <= topsrc && topsrc < cend) {
            for (;;) {
                --toplen;
                if (toplen <= thrv) break;
                if (ci != 0u && toplen <= cands[ci - 1u].len) { --ci; topsrc = cands[ci].src; }
                if (!(cur <= topsrc && topsrc < cend)) break;
            }
        }
        if (!cands.empty() && toplen > thrv) {
            const std::uint32_t topdist = (cur >= topsrc) ? (cur - topsrc) : (cur + cap - topsrc);
            if (topdist != 0u && topdist <= cap) {
                if (toplen >= 0x200u || ni + toplen >= 0x1040u) {
                    const std::uint32_t nr[4] = {topdist - 1u, nd.rep[0], nd.rep[1], nd.rep[2]};
                    TakeWhole(toplen, 4u, topdist, nr);
                    took_long = true;
                } else {
                    if (ni + toplen > front) front = ni + toplen;
                    const std::uint32_t sel = SelPrice(4u);
                    {
                        const Node& tgt = nodes[ni + toplen];
                        if (trace) std::fprintf(stderr, "[W2] ni=%u toplen=%u thrv=%u sel=%u ndprice=%u skip=%d\n",
                                                ni, toplen, thrv, sel, nd.price, (int)(tgt.tag == TAG && tgt.price <= nd.price + sel * 2u));
                        if (tgt.tag == TAG && tgt.price <= nd.price + sel * 2u) goto walk_done;
                    }
                    {
                    std::uint32_t dprice = 0, lastsrc = 0xffffffffu;
                    std::uint32_t src = topsrc;
                    for (std::uint32_t L = toplen; L > thrv; --L) {
                        if (ci != 0u && L <= cands[ci - 1u].len) { --ci; src = cands[ci].src; }
                        const std::uint32_t dist = (cur >= src) ? (cur - src) : (cur + cap - src);
                        if (dist == 0u || dist > cap) break;
                        if (src != lastsrc) { dprice = PriceDistance(mem, T, D290, dist - 1u, L); lastsrc = src; }
                        const std::uint32_t bp = nd.price + sel + dprice;
                        const Node& tgc = nodes[ni + L];
                        if (trace) std::fprintf(stderr, "[W2] ni=%u L=%u dist=%u dprice=%u bp=%u tgtag=%d tgprice=%u\n",
                                                ni, L, dist, dprice, bp, (int)(tgc.tag == TAG), tgc.price);
                        if (tgc.tag == TAG && tgc.price <= (dprice >> 3u) + bp) break;
                        const std::uint32_t nr[4] = {dist - 1u, nd.rep[0], nd.rep[1], nd.rep[2]};
                        const std::uint32_t lenp = LenCost(mem, T, L, 4u, true);
                        if (!Update(L, 4u, dist, nr, bp, lenp)) break;
                    }
                    }
                }
            }
        }
        walk_done:
        if (took_long) { endnode = front; break; }

        // ---- the literal
        {
            Node& tg = nodes[ni + 1u];
            const bool tagged = (tg.tag == TAG);
            if (tagged) {
                std::uint32_t m = tg.price;
                for (std::uint32_t k = 2u; k <= 6u; ++k) {
                    const Node& q = nodes[ni + k];
                    if (q.tag == TAG && q.price < m) m = q.price;
                }
                if (m <= nd.price + 3u + dlit * 2u) goto lit_done;
            }
            {
            // the LZP predictor's contribution, looked up but never stored: only
            // the literal's own ctx7 input sees it
            std::uint8_t predLzp = 0;
            std::uint32_t lzpConf = 0;
            {
                const std::uint16_t am2am1 = static_cast<std::uint16_t>(
                    static_cast<std::uint16_t>(am2) | (static_cast<std::uint16_t>(am1) << 8));
                const std::uint16_t hash = static_cast<std::uint16_t>(
                    static_cast<std::uint16_t>(am3) * 0xc5u + am2am1);
                const std::uint32_t storedPos =
                    static_cast<std::uint32_t>(Rd32(mem, 0x1042c00 + static_cast<int>(hash) * 4));
                if (storedPos != 0u) {
                    if (am1 == At(base, storedPos - 1u) && am2 == At(base, storedPos - 2u) &&
                        am3 == At(base, storedPos - 3u)) {
                        predLzp = At(base, storedPos);
                        const bool m4ok = (am4 == At(base, storedPos - 4u));
                        const std::uint8_t am5 = At(base, cur - 5u);
                        lzpConf = (m4ok ? 1u : 0u) + 1u +
                                  ((m4ok && am5 == At(base, storedPos - 5u)) ? 1u : 0u);
                    }
                }
            }
            const std::uint8_t lit = base[cur];
            const std::uint32_t lp =
                dlit + PriceLiteral(mem, T, nd.ctx, nd.hist, lit, mm, predB, predLzp, lzpConf,
                                    am2, am3, remain);
            const std::uint32_t price = nd.price + lp;
            if (!tagged || price <= tg.price + 3u + (lp >> 4u)) {
                if (ni + 1u > dirty_hi) dirty_hi = ni + 1u;
                tg.tag = TAG;
                tg.price = static_cast<std::uint16_t>(price);
                tg.back = static_cast<std::uint16_t>(ni);
                tg.len = 1u;
                tg.sg = 0xffu;    // literal
                tg.dist = 0u;
                tg.hist = static_cast<std::uint8_t>(nd.hist * 2u + 1u);
                tg.ctx = static_cast<std::uint16_t>(nd.ctx * 0x100u + lit);
                for (int k = 0; k < 4; ++k) tg.rep[k] = nd.rep[k];
                if (ni + 1u > front) front = ni + 1u;
            }
            }
        }
        lit_done:

        // ---- advance
        {
            const std::uint32_t nx = ni + 1u;
            if (nx == 0x1000u) { endnode = front; break; }
            if (front == nx || remain0 <= nx) { endnode = front; break; }
            if (nodes[nx].price > 0xefffu) { endnode = front; break; }
            ni = nx;
        }
    }
    if (endnode == 0u) endnode = 1u;
    nodes_dirty = std::min<std::uint32_t>(dirty_hi + 1u, kNodes);
    if (NZ_ENV("NZO2_NODES")) {
        static int fl = 0;
        std::fprintf(stderr, "[N2] flush=%d cur0=%u front=%u end=%u\n", fl++, pos0 + emitted, front, endnode);
        std::fprintf(stderr, "[N2]  lencache r0:");
        for (std::uint32_t L = 2; L <= 34u; ++L)
            std::fprintf(stderr, " %u", Rd16(mem, 0x103b380u + L * 4u + 2u));
        std::fprintf(stderr, "\n[N2]  lencache nd:");
        for (std::uint32_t L = 2; L <= 34u; ++L)
            std::fprintf(stderr, " %u", Rd16(mem, 0x103b380u + L * 4u));
        std::fprintf(stderr, "\n");
        const std::uint32_t nlim = NZ_ENV("NZO2_NODES_N") ? (std::uint32_t)std::atoi(NZ_ENV("NZO2_NODES_N")) : 48u;
        for (std::uint32_t k = 0; k < nlim; ++k) {
            const Node& n = nodes[k];
            if (n.tag == TAG || k == 0u)
                std::fprintf(stderr, "[N2]  node[%u] price=%u back=%u len=%u ctx=%04x hist=%02x sg=%u dist=%u\n",
                             k, n.price, n.back, n.len, n.ctx, n.hist, n.sg, n.dist);
        }
    }

    // ---- backtrack and emit
    std::vector<std::uint32_t> chain;
    for (std::uint32_t k = endnode; k != 0u; k = nodes[k].back) chain.push_back(k);
    std::reverse(chain.begin(), chain.end());
    std::uint32_t adv = 0;
    for (std::uint32_t k : chain) {
        const Node& n = nodes[k];
        Optimum2Decision d{};
        if (n.sg == 0xffu) {
            d.is_literal = 1u;
            d.byte = base[pos0 + emitted + adv];
            adv += 1u;
        } else {
            d.is_literal = 0u;
            d.sg = static_cast<std::uint8_t>((n.sg == 4u) ? 0u : (n.sg + 1u));
            d.len = n.len;
            d.dist = n.dist;
            adv += n.len;
        }
        out.push_back(d);
        hist0 = n.hist;
        ctx0 = n.ctx;
        for (int j = 0; j < 4; ++j) rep0[j] = n.rep[j];
    }
    if (adv == 0u) return false;
    if (trace) std::fprintf(stderr, "[PARSE2] emitted=%u adv=%u chain=%zu end=%u\n",
                            emitted, adv, chain.size(), endnode);
    F.consumed = emitted + adv;
    if (F.consumed > chunk) return false;
    return true;
}

// The frozen-model reference: parse a whole block without letting the coder
// advance the models in between.
bool NzOptimum2LzDecoder::ParseBlock(const std::uint8_t* data, std::uint32_t size,
                                     std::vector<Optimum2Decision>& out) {
    if (size == 0u) return true;
    if (size > 0x8000u) return false;   // one chunk at a time for now
    BeginParse(data, size);
    while (parser_->consumed < size) {
        if (!ParseNextFlush(out)) return false;
    }
    ring_.cursor = parser_->pos0 + size;
    return true;
}


}  // namespace optimum2
}  // namespace nzr
