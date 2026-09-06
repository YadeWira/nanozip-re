// nz_optimum_lz_parser.cpp -- the `-co` optimal parser (FUN_0806f8e0), the
// DAT_08183620 == 0 path (which is what `-t1` takes: the async secondary finder
// is never created). It turns a block's bytes into the decision list the
// original's parser picks; NzOptimumLzDecoder::EncodeBlock then codes that list
// into the payload (that half is already byte-exact, see the RunBlock template).
//
// Shape, straight from the decompile:
//   * per chunk of at most 0x8000 bytes: append to the window, rebuild the
//     256-byte rolling hash, clear a 0x120-entry node array;
//   * forward DP over positions. At each node the four rep offsets are probed
//     first (a 2-byte compare, then a byte-wise extension); only when all four
//     miss is the bt4 match finder (FUN_08073ca0) consulted, followed by the
//     long-range rolling-hash probe. Each candidate relaxes the nodes at
//     pos+len, pos+len-1, ... pos+2; the literal relaxes pos+1;
//   * a match of 0x20 bytes or more, or one reaching past the 0x120-node
//     horizon, is taken immediately and ends the DP;
//   * the chain is then reversed through the back-pointers and emitted.
//
// Prices are read from the live model cells through the cost table and kept in
// lazily filled caches inside mem_ (literal at 0x296a0, rep-select at 0x3e200,
// length at 0x39c08, distance class at 0x3d848). Pricing never writes a coding
// probability, so it is safe to run against the model the coder will advance.
#include "nz_optimum_lz.h"
#include "nz_optimum_lz_tables.h"
#include "nz_cm.h"
#include "nz_env.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>

// DAT_08172900, the stretch table: a plain global, declared the way
// nz_optimum_lz.cpp declares it.
extern "C" {}
extern std::int16_t kLzModelInterpolation[256];

namespace nzr {
namespace optimum {

namespace {

// FUN_080749a0: the bit-cost table (0x400 bytes of .bss, built on first use).
// cost(bit, p) = T[((p >> 2) ^ -(bit ^ 1)) - bit & 0x3ff].
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
        t[0] = t[1];   // the tail assignment of FUN_080749a0
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
inline int Stretch(std::uint8_t s) { return kLzModelInterpolation[s]; }
inline std::uint32_t Load16(const std::uint8_t* p) { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
inline std::uint32_t Load32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
// The ring is read with SIGNED positions: a position just before the cursor is
// negative and lands in the 256-byte prefix mirror (the decoder's RingAt).
inline std::uint8_t At(const std::uint8_t* b, std::uint32_t p) { return b[static_cast<std::int32_t>(p)]; }
inline std::uint32_t BitLen1(std::uint32_t v) { std::uint32_t n = 31; if (v == 0) return 0; while ((v >> n) == 0) --n; return n; }

// One relaxation candidate the DP considers at a position.
struct Cand { std::uint32_t len; std::uint32_t src; };

}  // namespace

// The finder object (FUN_08082e50 + the slot-10 config FUN_0806f440) and the
// 256-byte rolling hash (FUN_08059b20), which live past mem_ in the original.
struct NzOptimumLzDecoder::ParserState {
    // finder
    std::uint32_t shift = 0, winsize = 0, maskA = 0, headmask = 0;
    std::uint32_t treemask = 0, treesize = 0;
    std::vector<std::uint32_t> head, cache, tree;
    // long-range rolling hash
    std::vector<std::uint32_t> lr;
    std::uint32_t lrmask = 0, lrhash = 0;
    bool ready = false;
    // the block being parsed, and how much of it has been handed to the coder
    const std::uint8_t* src = nullptr;
    std::uint32_t size = 0, consumed = 0, pos0 = 0;
    std::uint32_t rep0[4] = {1, 1, 1, 1};
    std::uint8_t hist0 = 0xff;
    std::uint16_t ctx0 = 0;
    bool started = false;

    void Init(std::uint32_t W) {
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
        // slot 10: the tree buffer is 3 * the block-buffer size (GDB: size = 3 MB
        // for a 1 MB window), two words per position, wrapped by `treesize`.
        const std::uint32_t tsz = W * 3u;
        treemask = ((1u << (BitLen1(tsz) + 1u)) - 1u) >> 2u;
        treesize = tsz >> 2u;
        tree.assign(treesize + 2u, 0u);
        // FUN_08059b20 for the long-range hash: (window-1)>>6, one bit more.
        const std::uint32_t q = (W - 1u) >> 6u;
        const std::uint32_t bits = (q != 0u ? BitLen1(q) : 0u) + 1u;
        lr.assign(static_cast<std::size_t>(1u) << bits, 0u);
        lrmask = (1u << bits) - 1u;
        ready = true;
    }

    // FUN_08082fa0: bulk-insert positions into the hash head and the 2-byte
    // 4-slot cache (the binary tree is NOT touched) -- used over the bytes a
    // chosen match consumed.
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
        // refresh the cache and the head, then walk the tree
        cs[3] = cs[2]; cs[2] = cs[1]; cs[1] = cs[0]; cs[0] = tagv + cur;
        head[hidx] = cur | (~maskA & w);
        std::uint32_t ti = (cur * 2u) & treemask;
        if (treesize <= ti) ti -= treesize;
        std::uint32_t* gt = &tree[ti];        // the "greater" side link
        std::uint32_t* ls = &tree[ti] + 1;    // the "less" side link
        std::uint32_t lg = 0, ll = 0;         // matched prefix on each side
        while (chain != 0u && --depth != 0u) {
            const std::uint32_t cp = maskA & chain;
            if (cp >= winsize || !valid(cp)) break;
            std::uint32_t ci = (cp * 2u) & treemask;
            std::uint32_t* ch = (ci < treesize) ? &tree[ci] : &tree[ci - treesize];
            std::uint32_t k = std::min(lg, ll);
            std::uint32_t lim = (cp + maxlen <= winsize) ? maxlen : (winsize - cp);
            if (lim <= k) { *ls = ch[0]; *gt = ch[1]; return; }
            if (base[cur + k] == base[cp + k]) {
                const std::int32_t pre = static_cast<std::int32_t>(k) - 1;
                // the original abandons the walk here when four or more bytes
                // already matched but the chain entry's tag does not
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
// FUN_08074360: the price of a brand-new distance -- five slot-tree bits, one
// or two tier-1 bits, the align bits and the high bits -- cached per distance
// class at 0x3d848 (a class covers a bit length and the two bits under its top
// one; the cache is filled by whichever length bucket asked first).
std::uint32_t PriceDistance(std::uint8_t* mem, const std::uint8_t* T,
                            const std::uint8_t* D4D0, std::uint32_t D, std::uint32_t len,
                            bool use_cache) {
    const std::uint32_t bl = BitLen1(D);
    const std::uint32_t sh = (bl > 2u) ? (bl - 2u) : 0u;
    const std::size_t cls = (((D >> sh) & 3u) * 0x20u + bl) & 0x7fu;
    const std::size_t cell = 0x3d848u + cls * 2u;
    if (use_cache) {
        const std::uint16_t cached = Rd16(mem, cell);
        if (cached != 0u) return cached;
    }
    const std::uint32_t v = len - 2u;
    const std::uint32_t bucket = D4D0[(v > 0xfu) ? 0xfu : v];
    std::uint32_t acc = 0;
    // the five slot bits, MSB first, of slot ^ 0x1f
    std::uint32_t tp = 1;
    std::uint32_t bits = (~bl) << 27u;
    for (int i = 0; i < 5; ++i) {
        const std::size_t c1 = 0x39f40u + static_cast<std::size_t>(tp + bucket * 0x20u) * 2u;
        const std::uint32_t cell1 = Rd16(mem, c1);
        const std::uint32_t i2 = static_cast<std::uint32_t>(
            ((static_cast<std::int32_t>(Stretch(static_cast<std::uint8_t>(cell1 >> 8))) + 0x800) >> 8)) + 0x140u + tp * 0x11u;
        const std::size_t c2 = 0x39f40u + static_cast<std::size_t>(i2) * 2u;
        const std::uint32_t comb = ((cell1 >> 4u) + 2u +
            ((static_cast<std::uint32_t>(Rd16(mem, c2 + 2u)) + 1u + static_cast<std::uint32_t>(Rd16(mem, c2))) >> 5u) * 3u) >> 2u;
        const std::uint32_t bit = (bits >> 31u) & 1u; bits <<= 1u;
        acc += Cost(T, bit, Bias(comb));
        tp = bit + tp * 2u;
    }
    // tier 1
    const std::uint32_t n1 = (bl < 2u) ? 1u : 2u;
    {
        std::uint32_t t1 = 1;
        // the two tier-1 bits are the TOP of D (the leading one and the bit
        // under it), not its low pair: the shift is 0x20 - bl once bl reaches 3
        std::uint32_t b1 = D << ((0x20u - ((bl > 1u) ? bl : 1u)) & 0x1fu);
        for (std::uint32_t i = 0; i < n1; ++i) {
            const std::uint32_t bit = (b1 >> 31u) & 1u; b1 <<= 1u;
            const std::size_t c = 0x39f40u + static_cast<std::size_t>(t1 + 0xf80u + bl * 0x60u) * 2u;
            acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            t1 = bit + t1 * 2u;
        }
    }
    if (bl > 2u) {
        const std::uint32_t n2 = (bl < 6u) ? (bl - 2u) : 4u;
        std::uint32_t t2 = 1, d = D;
        for (std::uint32_t i = 0; i < n2; ++i) {
            const std::uint32_t bit = d & 1u; d >>= 1u;
            const std::size_t c = 0x3f700u + static_cast<std::size_t>(t2) * 2u;   // the align table
            acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            t2 = bit + t2 * 2u;
        }
        if (bl > 6u) {
            const std::uint32_t n3 = bl - 6u;
            std::uint32_t b3 = D << ((0x1cu - n3) & 0x1fu);
            for (std::uint32_t i = 0; i < n3; ++i) {
                const std::uint32_t bit = (b3 >> 31u) & 1u; b3 <<= 1u;
                const std::size_t c = 0x39f40u + static_cast<std::size_t>(i + 0x380u + n3 * 0x60u) * 2u;
                acc += Cost(T, bit, Rd16(mem, c) >> 4u);
            }
        }
    }
    Wr16(mem, cell, static_cast<std::uint16_t>(acc));
    return acc;
}

// The rep-select price for a0 (0..3 = rep slot, 4 = a brand-new distance),
// cached at 0x3e200 by (history, match mask, slot). The value excludes the
// dispatch bit, which the caller adds.
std::uint32_t SelDelta(std::uint8_t* mem, const std::uint8_t* T, std::uint8_t hist,
                       std::uint32_t mm, std::uint32_t a0, bool use_cache) {
    const std::uint32_t ti = (hist & 0xfu) + (mm & 7u) * 0x10u;
    const std::size_t off = 0x3d980u + static_cast<std::size_t>(ti) * 16u;
    const std::uint32_t sg = (a0 >= 4u) ? 0u : (a0 + 1u);
    const std::size_t ci = (hist & 7u) + (mm & 7u) * 8u + static_cast<std::size_t>(sg) * 0x40u;
    if (use_cache) {
        const std::uint8_t cv = Rd8(mem, 0x3e200 + ci);
        if (cv != 0xffu) return cv;
    }
    // b1 says new-distance (1) or rep (0), and each path prices it with its own
    // polarity -- the rep site costs a zero here, the finder site a one
    std::uint32_t px = Cost(T, (a0 >= 4u) ? 1u : 0u, Bias(Rd16(mem, off) >> 4u));
    if (a0 < 4u) {
        std::uint32_t tp = ti * 8u + 1u;
        int left = 3;
        for (;;) {
            const std::uint32_t at = tp;
            const bool last = (static_cast<int>(a0) - 3 + left) == 0;
            ++tp;
            px += Cost(T, last ? 1u : 0u, Bias(Rd16(mem, 0x3d980u + static_cast<std::size_t>(at) * 2u) >> 4u));
            --left;
            if (last || left == 0) break;
        }
    }
    Wr8(mem, 0x3e200 + ci, static_cast<std::uint8_t>((px < 0xfeu) ? px : 0xfeu));
    return px;
}

// The length price, cached at 0x39c08 by (len-2, is-rep0). A length whose
// v = len-2 reaches 0xff prices at zero: the original skips the whole block
// rather than clamping, so very long matches look free.
std::uint32_t LenCost(std::uint8_t* mem, const std::uint8_t* T, std::uint32_t L,
                      std::uint32_t a0, bool use_cache) {
    const std::uint32_t v = L - 2u;
    if (v >= 0xffu) return 0u;
    const std::size_t li = (a0 == 0u ? 1u : 0u) + static_cast<std::size_t>(v) * 2u;
    if (use_cache) {
        const std::uint8_t lc = Rd8(mem, 0x39c08 + li);
        if (lc != 0u) return lc;
    }
    std::uint32_t acc = 0;
    std::uint32_t idx = (a0 == 0u ? 1u : 0u) << 4u;
    std::uint32_t vv = v, nb = 0;
    for (;;) {
        vv >>= 1u;
        const std::uint32_t cellp = Rd16(mem, 0x396c0u + static_cast<std::size_t>(idx) * 2u) >> 4u;
        ++idx; ++nb;
        acc += Cost(T, (vv != 0u) ? 1u : 0u, cellp);
        if (vv == 0u) break;
    }
    const std::uint32_t rowb = (nb - 1u) << 5u;
    std::uint32_t persisted = (a0 == 4u) ? 3u : 1u;
    const std::uint32_t nbits = (nb < 5u) ? ((nb - 1u) ? (nb - 1u) : 1u) : 4u;
    const std::uint32_t raws = (nb < 5u) ? 0u : (nb - 5u);
    // past four bits the original shifts by 0x21 - nb, not 0x20 - nbits: a
    // length that needs six or more raw bits reads them one place over
    std::uint32_t bits = v << (((nb < 5u) ? (0x20u - nbits) : (0x21u - nb)) & 0x1fu);
    for (std::uint32_t i = 0; i < nbits; ++i) {
        const std::uint32_t bit = (bits >> 31u) & 1u; bits <<= 1u;
        const std::size_t c2 = 0x396c0u + static_cast<std::size_t>(persisted + rowb + 0x60u) * 2u;
        acc += Cost(T, bit, Rd16(mem, c2) >> 4u);
        persisted = bit + persisted * 2u;
    }
    if (raws != 0u) acc += raws * 0x1cu;
    Wr8(mem, 0x39c08 + li, static_cast<std::uint8_t>((acc < 0xffu) ? acc : 0xffu));
    return acc;
}

// The cost of coding `lit` with the models as they stand -- the decoder's
// literal loop with the updates removed and the bit costs summed instead.
std::uint32_t PriceLiteral(const std::uint8_t* mem, const std::uint8_t* T,
                           std::uint32_t ctxWord, std::uint8_t hist, std::uint8_t lit,
                           std::uint32_t mm, std::uint8_t predB, std::uint8_t am2,
                           std::uint32_t remain) {
    int ctxA = 0x130 + static_cast<int>(ctxWord & 0xffu) * 0x100;
    int ctxB = 0x10450 + static_cast<int>(am2) * 0x100;
    const std::uint32_t seed = static_cast<std::uint32_t>(predB) + 0x100u;
    std::uint32_t ctxD = (remain & 3u) * 0x10u + 1u + (mm & 7u) * 0x40u + ((seed >> 6u) & 2u);
    std::uint32_t ctxC = 1;
    std::uint16_t m84 = static_cast<std::uint16_t>(seed);
    std::uint8_t subc = 0, scale = 0, confid = 0, shiftreg = 1, m8e = 0;
    std::uint16_t treeC = 1;
    if ((hist & 1u) == 0u) {
        m8e = static_cast<std::uint8_t>(ctxWord >> 8u);
        ctxC = 0x202u + (static_cast<std::uint32_t>(m8e) >> 7u);
        treeC = static_cast<std::uint16_t>(ctxC);
    }
    std::uint32_t cost = 0;
    for (int k = 0; k < 8; ++k) {
        const std::uint8_t sA = Rd8(mem, ctxA), sB = Rd8(mem, ctxB);
        const std::uint8_t sC = Rd8(mem, 0x10140 + ctxC), sD = Rd8(mem, 0x20460 + ctxD);
        const int wRow = 0x60 + static_cast<int>((((ctxD >> 6u) & 3u) + (ctxC >> 8u) * 4u) * 0x10u);
        const std::int32_t dot = Stretch(sA) * Rd32(mem, wRow) + Stretch(sB) * Rd32(mem, wRow + 4) +
                                 Stretch(sC) * Rd32(mem, wRow + 8) + Stretch(sD) * Rd32(mem, wRow + 12);
        std::int32_t ps = (dot >> 16) + 0x800;
        std::uint32_t p = (ps < 0) ? 0u : static_cast<std::uint32_t>(ps);
        p = ((p < 0xfffu) ? p : 0xfffu) * 0xbu;
        const std::uint32_t frac = p & 0xfffu;
        const std::size_t a2 = 0x20670u + static_cast<std::size_t>(confid + ctxC * 2u) * 24u +
                               static_cast<std::size_t>(p >> 12u) * 2u;
        const std::uint32_t mix = (static_cast<std::uint32_t>(Rd16(mem, a2)) * (0x1000u - frac) +
                                   frac * static_cast<std::uint32_t>(Rd16(mem, a2 + 2u))) >> 16u;
        const std::uint32_t pf = Bias(mix);
        const std::uint32_t bit = (static_cast<std::uint32_t>(lit) >> (7 - k)) & 1u;
        cost += Cost(T, bit, pf);
        if (k == 7) break;
        confid = (0xa01u < (bit * 0x1000u - pf) + 0x500u) ? 1u : 0u;
        shiftreg = static_cast<std::uint8_t>(bit + shiftreg * 2u);
        m84 = static_cast<std::uint16_t>(m84 << 1u);
        subc = static_cast<std::uint8_t>(subc + 1u);
        std::uint32_t step;
        if (subc == 4u) { step = (static_cast<std::uint32_t>(shiftreg) * 0xfu - scale) - 0xe1u; }
        else { step = (bit + 1u) << ((subc & 3u) - 1u); scale = static_cast<std::uint8_t>(scale + step); }
        ctxA += static_cast<int>(step); ctxB += static_cast<int>(step);
        ctxD = static_cast<std::uint16_t>(((static_cast<std::uint32_t>(m84) >> 6u) & 2u) +
                                          static_cast<std::uint32_t>(subc >> 1u) * 4u + (ctxD & 0xfff0u) +
                                          (((static_cast<std::uint32_t>(m84) >> 8u) == shiftreg) ? 1u : 0u));
        const std::uint16_t oldC = treeC;
        std::uint16_t tmp = static_cast<std::uint16_t>((oldC & 0xff00u) | shiftreg);
        treeC = tmp;
        if (oldC < 0x200u) { ctxC = tmp; }
        else {
            std::uint16_t c = static_cast<std::uint16_t>(static_cast<std::uint32_t>(shiftreg) + 0x100u);
            treeC = c;
            if (bit == (oldC & 1u)) {
                m8e = static_cast<std::uint8_t>(m8e * 2u);
                const std::int16_t se = static_cast<std::int16_t>(static_cast<std::int8_t>(shiftreg));
                const std::uint32_t hi = (static_cast<std::uint16_t>(~se) >> 15u) * (static_cast<std::uint32_t>(shiftreg) * 2u);
                c = static_cast<std::uint16_t>(hi + 0x200u + (static_cast<std::uint32_t>(m8e) >> 7u));
                treeC = c;
            }
            ctxC = c;
        }
    }
    return cost;
}

}  // namespace

std::uint32_t NzOptimumLzDecoder::PriceBit(std::uint32_t bit, std::uint32_t pf) {
    return Cost(CostTable(), bit, pf);
}

// The literal price is the cost the coder actually paid, summed bit by bit while
// coding, exactly as the original accumulates it -- not a second transcription of
// the mixer that could drift from the coder's own.
void NzOptimumLzDecoder::StoreLiteralCost(std::uint32_t ctxLow, std::uint8_t lit, std::uint32_t cost) {
    std::uint8_t* const mem = mem_.data();
    const std::size_t lci = static_cast<std::size_t>(ctxLow & 0xffu) * 0x100u + lit;
    Wr8(mem, 0x296a0 + lci, static_cast<std::uint8_t>((cost < 0xfeu) ? cost : 0xfeu));
}

// Coding a symbol measures its real cost, and the original writes that cost
// straight back into the price cache it priced from. Recomputing each component
// against the model as it stands just before the decision is coded gives the same
// number, because the coder reads every cell before it updates it.
void NzOptimumLzDecoder::RefreshMatchPrices(const OptimumDecision& d, std::uint32_t mm,
                                            std::uint8_t hist) {
    if (d.is_literal) return;               // the coder stores its own measured cost
    std::uint8_t* const mem = mem_.data();
    const std::uint8_t* const T = CostTable();
    const std::uint32_t a0 = (d.sg == 0u) ? 4u : (d.sg - 1u);
    SelDelta(mem, T, hist, mm, a0, false);
    if (d.len >= 2u) LenCost(mem, T, d.len, a0, false);
    if (a0 == 4u && d.dist != 0u)
        PriceDistance(mem, T, OptimumDat081724d0(), d.dist - 1u, d.len, false);
}

void NzOptimumLzDecoder::BeginParse(const std::uint8_t* data, std::uint32_t size) {
    if (!parser_) parser_ = std::make_shared<ParserState>();
    ParserState& F = *parser_;
    F.Init(ring_.capacity);
    F.src = data; F.size = size; F.consumed = 0; F.started = false; F.pos0 = 0;
    F.rep0[0] = F.rep0[1] = F.rep0[2] = F.rep0[3] = 1;
    F.hist0 = 0xff; F.ctx0 = 0;
}

// One flush of the DP, from the ring and the models as they stand right now.
bool NzOptimumLzDecoder::ParseNextFlush(std::vector<OptimumDecision>& out) {
    if (!parser_) return false;
    ParserState& F = *parser_;
    if (F.consumed >= F.size) return false;

    const std::uint8_t* const T = CostTable();
    const std::uint32_t* const LRO = LrOut();
    std::uint8_t* const mem = mem_.data();
    const std::uint32_t cap = ring_.capacity;
    const std::uint8_t* const D380 = OptimumDat08172380();
    const std::uint8_t* const D4D0 = OptimumDat081724d0(); (void)LRO;
    const bool trace = (NZ_ENV("NZOPT_TRACE_PARSE") != nullptr);

    struct Node {
        std::uint16_t tag = 0, price = 0, back = 0, len = 0, ctx = 0;
        std::uint8_t hist = 0;
        std::uint8_t sg = 0;            // 0 = new distance, 1..4 = rep0..rep3
        std::uint32_t dist = 0;
        std::uint32_t rep[4] = {0, 0, 0, 0};
    };
    static thread_local std::vector<Node> nodes;
    // six extra slots: the lookahead below reads up to node ni+6, and the
    // original reads the stack locals that follow its array there
    nodes.assign(0x120u + 8u, Node{});

    std::uint32_t* const rep0 = F.rep0;
    std::uint8_t& hist0 = F.hist0;
    std::uint16_t& ctx0 = F.ctx0;
    if (!F.started) {
        F.started = true;
        // the coder will call EnsureHeadroom for the same span, so doing it here
        // first keeps the two in step; the whole block goes into the window up
        // front, the way the original appends the chunk before parsing it
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
    {
        std::uint8_t* const base = ring_.Base();
        const std::uint32_t chunk = F.size;
        const std::uint32_t pos0 = F.pos0;
        const std::uint32_t cend = pos0 + chunk;
        const std::uint32_t emitted = F.consumed;
        {
            const std::uint32_t remain0 = chunk - emitted;
            for (auto& n : nodes) n.tag = 0;
            nodes[0].price = 0; nodes[0].hist = hist0; nodes[0].ctx = ctx0;
            for (int k = 0; k < 4; ++k) nodes[0].rep[k] = rep0[k];
            std::uint32_t front = 1;       // uStack_230f4: furthest relaxed node
            std::uint32_t ni = 0;          // uStack_230d8
            bool flushed = false;
            std::uint32_t endnode = 0;

            while (true) {
                Node& nd = nodes[ni];
                const std::uint32_t cur = pos0 + emitted + ni;
                const std::uint32_t remain = chunk - emitted - ni;
                // ---- the dispatch context, exactly as the decoder builds it
                if (nd.rep[0] >= cap) return false;   // a rep can never point outside the window
                std::uint32_t pr = cur - (nd.rep[0] + 1u);
                if (cur < nd.rep[0] + 1u) pr += cap;
                std::uint32_t predpos = pr;
                { const std::uint32_t bc = pr - 4u; if (bc < cend && cur <= bc) predpos = cur - 1u; }
                const std::uint8_t predB = At(base, predpos);
                const std::uint32_t mm =
                    ((At(base, predpos - 1u) == At(base, cur - 1u)) ? 1u : 0u) |
                    ((At(base, predpos - 2u) == At(base, cur - 2u)) ? 2u : 0u) |
                    ((At(base, predpos - 3u) == At(base, cur - 3u)) ? 4u : 0u) |
                    ((At(base, predpos - 4u) == At(base, cur - 4u)) ? 8u : 0u);
                const std::uint8_t am2 = At(base, cur - 2u);
                const std::uint32_t dispIdx = (mm & 7u) + static_cast<std::uint32_t>(predB) * 8u;

                // ---- the dispatch probability (shared by the literal and match costs)
                const std::uint8_t dstate = Rd8(mem, 0x3e380 + dispIdx);
                const std::uint32_t apmRow = (mm & 0xfu) + static_cast<std::uint32_t>(D380[nd.hist]) * 8u;
                const std::uint32_t apmIn = static_cast<std::uint32_t>(Stretch(dstate) * 4 + 0x2000);
                const std::uint32_t dfrac = apmIn & 0xfffu;
                const std::size_t dcell = 0x3eb90u + apmRow * 10u + (apmIn >> 12u) * 2u;
                const std::uint32_t dlo = Rd16(mem, dcell), dhi = Rd16(mem, dcell + 2u);
                const std::uint32_t dmix = (static_cast<std::uint32_t>(dstate) * 16u + 2u +
                                            ((dlo * (0x1000u - dfrac) + dfrac * dhi) >> 16u) * 3u) >> 2u;
                const std::uint32_t dmatch = Cost(T, 0u, Bias(dmix));   // dispatch bit 0 = match
                const std::uint32_t dlit   = Cost(T, 1u, Bias(dmix));   // dispatch bit 1 = literal

                // ---- the rep-select price for a slot (0..3 = rep, 4 = new distance)
                auto SelPrice = [&](std::uint32_t slot) -> std::uint32_t {
                    return dmatch + SelDelta(mem, T, nd.hist, mm, slot, true);
                };
                // ---- the length price, cached at 0x39c08 by (len-2, is-rep0)
                auto LenPrice = [&](std::uint32_t L, std::uint32_t slot) -> std::uint32_t {
                    return LenCost(mem, T, L, slot, true);
                };
                // ---- write one relaxed node; false means the existing path is
                // cheaper, which ends the whole relaxation
                auto Update = [&](std::uint32_t L, std::uint32_t slot, std::uint32_t dist,
                                  const std::uint32_t* nr, std::uint32_t price) -> bool {
                    Node& tg = nodes[ni + L];
                    // the first writer keeps a tie, as the decompile compares
                    if (tg.tag == static_cast<std::uint16_t>(chunk) && price >= tg.price) return false;
                    tg.tag = static_cast<std::uint16_t>(chunk);
                    tg.price = static_cast<std::uint16_t>(price);
                    tg.back = static_cast<std::uint16_t>(ni);
                    tg.len = static_cast<std::uint16_t>(L);
                    tg.sg = static_cast<std::uint8_t>(slot == 4u ? 0u : slot + 1u);
                    tg.dist = dist;
                    tg.hist = static_cast<std::uint8_t>(nd.hist * 2u);
                    const std::uint32_t sp = (cur >= dist) ? (cur - dist) : (cur + cap - dist);
                    tg.ctx = static_cast<std::uint16_t>(At(base, sp + L) * 0x100u + At(base, cur + L - 1u));
                    for (int k = 0; k < 4; ++k) tg.rep[k] = nr[k];
                    return true;
                };

                // ---- the four rep offsets
                std::uint32_t best = 1;
                // The finder's threshold is NOT the longest rep match found: the
                // original keeps a separate counter that starts at 2 and rises to
                // the longest length a rep relaxation actually WROTE. A rep that
                // matched long but lost every comparison leaves it at 2, and the
                // finder then gets to price its own candidates.
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
                    if (len <= best || len == 1u) { best = std::max(best, len); continue; }
                    best = len;
                    std::uint32_t nr[4];
                    for (int k = 0; k < 4; ++k) nr[k] = nd.rep[k];
                    for (std::uint32_t k = i; k > 0u; --k) nr[k] = nr[k - 1u];
                    nr[0] = r;
                    if (len < 0x20u && ni + len < 0x120u) {
                        if (ni + len > front) front = ni + len;
                        const std::uint32_t sel = SelPrice(i);
                        for (std::uint32_t L = len; L >= 2u; --L) {
                            if (!Update(L, i, r + 1u, nr, nd.price + sel + LenPrice(L, i))) break;
                            if (L > thrv) thrv = L;
                        }
                    } else {
                        Node& tg = nodes[ni + 1u];
                        tg.tag = static_cast<std::uint16_t>(chunk);
                        tg.back = static_cast<std::uint16_t>(ni);
                        tg.len = static_cast<std::uint16_t>(len);
                        tg.sg = static_cast<std::uint8_t>(i + 1u);
                        tg.dist = r + 1u;
                        tg.hist = static_cast<std::uint8_t>(nd.hist * 2u);
                        for (int k = 0; k < 4; ++k) tg.rep[k] = nr[k];
                        front = ni + 1u;
                        took_long = true;
                    }
                }
                if (took_long) { endnode = front; break; }

                // ---- the bt4 finder. Its candidates are appended in increasing
                // length; the relaxation walks the LENGTH downward and switches to
                // the shortest candidate that still reaches it (the nearest distance
                // for that length), which is why each candidate is not relaxed on
                // its own. The threshold starts at 2, so a 2-byte brand-new distance
                // is never taken.
                std::vector<Cand> cands;
                F.Find(base, cur, cend, remain, cands, 0x10u);
                if (trace) {
                    std::fprintf(stderr, "[C] rem=%u ni=%u n=%zu:", chunk - emitted, ni, cands.size());
                    for (const Cand& cc : cands) std::fprintf(stderr, " {src=%u len=%u}", cc.src - pos0, cc.len);
                    std::fprintf(stderr, "\n");
                }
                const std::uint32_t thr = thrv;
                if (!cands.empty() && cands.back().len > thr) {
                    const std::uint32_t toplen = cands.back().len;
                    const std::uint32_t topdist = (cur >= cands.back().src)
                        ? (cur - cands.back().src) : (cur + cap - cands.back().src);
                    if (topdist != 0u && topdist <= cap) {
                        if (toplen >= 0x20u || ni + toplen >= 0x120u) {
                            Node& tg = nodes[ni + 1u];
                            tg.tag = static_cast<std::uint16_t>(chunk);
                            tg.back = static_cast<std::uint16_t>(ni);
                            tg.len = static_cast<std::uint16_t>(toplen);
                            tg.sg = 0u;
                            tg.dist = topdist;
                            tg.hist = static_cast<std::uint8_t>(nd.hist * 2u);
                            tg.rep[0] = topdist - 1u; tg.rep[1] = nd.rep[0];
                            tg.rep[2] = nd.rep[1]; tg.rep[3] = nd.rep[2];
                            front = ni + 1u;
                            took_long = true;
                        } else {
                            if (ni + toplen > front) front = ni + toplen;
                            const std::uint32_t sel = SelPrice(4u);
                            if (trace) std::fprintf(stderr, "[W] rem=%u ni=%u best=%u thr=%u toplen=%u sel=%u\n",
                                                    chunk - emitted, ni, best, thr, toplen, sel);
                            // walk the length down, switching to the shortest
                            // candidate that still reaches it (the nearest distance
                            // for that length)
                            std::size_t ci = cands.size() - 1u;
                            std::uint32_t dprice = 0, lastsrc = 0xffffffffu;
                            for (std::uint32_t L = toplen; L > thr; --L) {
                                while (ci > 0u && L <= cands[ci - 1u].len) --ci;
                                const Cand& c = cands[ci];
                                const std::uint32_t dist = (cur >= c.src) ? (cur - c.src) : (cur + cap - c.src);
                                if (dist == 0u || dist > cap) break;
                                if (c.src != lastsrc) { dprice = PriceDistance(mem, T, D4D0, dist - 1u, L, true); lastsrc = c.src; }
                                const std::uint32_t bp = nd.price + sel + dprice;
                                const Node& tgc = nodes[ni + L];
                                if (tgc.tag == static_cast<std::uint16_t>(chunk) && (dprice >> 3u) + bp >= tgc.price) break;
                                const std::uint32_t nr[4] = {dist - 1u, nd.rep[0], nd.rep[1], nd.rep[2]};
                                const std::uint32_t px = bp + LenPrice(L, 4u);
                                const bool okup = Update(L, 4u, dist, nr, px);
                                if (trace) std::fprintf(stderr, "[W]   L=%u dist=%u sel=%u dp=%u px=%u -> %d\n", L, dist, sel, dprice, px, (int)okup);
                                if (!okup) break;
                            }
                        }
                    }
                }
                if (took_long) { endnode = front; break; }

                // ---- the literal
                {
                    Node& tg = nodes[ni + 1u];
                    const bool tagged = (tg.tag == static_cast<std::uint16_t>(chunk));
                    // Before pricing anything the original looks six nodes ahead:
                    // if any of them is already at most three units plus twice the
                    // literal dispatch bit above this node, the literal cannot
                    // matter and it is skipped outright.
                    if (tagged) {
                        std::uint32_t m = tg.price;
                        for (std::uint32_t k = 2u; k <= 6u; ++k) {
                            const Node& q = nodes[ni + k];
                            if (q.tag == static_cast<std::uint16_t>(chunk) && q.price < m) m = q.price;
                        }
                        if (m <= nd.price + 3u + dlit * 2u) goto lit_done;
                    }
                    {
                    const std::uint8_t lit = base[cur];
                    const std::size_t lci = static_cast<std::size_t>(nd.ctx & 0xffu) * 0x100u + lit;
                    std::uint32_t lp;
                    const std::uint8_t lc = Rd8(mem, 0x296a0 + lci);
                    if (lc == 0xffu) {
                        lp = PriceLiteral(mem, T, nd.ctx, nd.hist, lit, mm, predB, am2, remain);
                        const std::uint32_t d = lp;
                        Wr8(mem, 0x296a0 + lci, static_cast<std::uint8_t>((d < 0xfeu) ? d : 0xfeu));
                        lp += dlit;
                    } else {
                        lp = lc + dlit;
                    }
                    const std::uint32_t price = nd.price + lp;
                    // A literal does not have to be CHEAPER to take the node: the
                    // original keeps it when it lands within three units plus a
                    // sixteenth of its own price, and pays for that by decaying the
                    // cached literal price it just used.
                    bool wr = !tagged;
                    if (tagged && price <= tg.price + 3u + (lp >> 4u)) {
                        const std::uint8_t cv = Rd8(mem, 0x296a0 + lci);
                        Wr8(mem, 0x296a0 + lci, static_cast<std::uint8_t>(cv - (cv >> 5u)));
                        wr = true;
                    }
                    if (wr) {
                        tg.tag = static_cast<std::uint16_t>(chunk);
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
                const std::uint32_t nx = ni + 1u;
                if (nx == 0x100u) { endnode = front; break; }
                if (front == nx || remain0 <= nx) { endnode = front; break; }
                if (nodes[nx].price > 0xefffu) { endnode = front; break; }
                ni = nx;
            }
            (void)flushed;
            if (endnode == 0u) endnode = 1u;
            const char* nodesenv = NZ_ENV("NZOPT_NODES");
            if (nodesenv != nullptr && (chunk - emitted) == static_cast<std::uint32_t>(std::atoi(nodesenv))) {
                std::fprintf(stderr, "[N] FLUSH front=%u end=%u rem=%u\n", front, endnode, chunk - emitted);
                {
                    std::string dc, lc2, rs;
                    char b[64];
                    for (int k = 0; k < 0x80; ++k) { std::uint16_t v = Rd16(mem, 0x3d848 + k*2); if (v) { std::snprintf(b,sizeof b,"(%d,%u)",k,v); dc += b; } }
                    for (int k = 0; k < 0x40; ++k) { std::uint8_t v = Rd8(mem, 0x39c08 + k); if (v) { std::snprintf(b,sizeof b,"(%d,%u)",k,v); lc2 += b; } }
                    for (int k = 0; k < 0x180; ++k) { std::uint8_t v = Rd8(mem, 0x3e200 + k); if (v != 0xff) { std::snprintf(b,sizeof b,"(%d,%u)",k,v); rs += b; } }
                    std::fprintf(stderr, "[N] distcache=%s\n[N] lencache=%s\n[N] repsel=%s\n", dc.c_str(), lc2.c_str(), rs.c_str());
                }
                for (std::uint32_t k = 0; k < 20u; ++k) {
                    const Node& n = nodes[k];
                    if (n.tag == static_cast<std::uint16_t>(chunk) || k == 0u)
                        std::fprintf(stderr, "[N]   node[%u] price=%u back=%u len=%u ctx=%04x hist=%02x sg=%u dist=%u rep=%u,%u,%u,%u\n",
                                     k, n.price, n.back, n.len, n.ctx, n.hist, n.sg, n.dist, n.rep[0], n.rep[1], n.rep[2], n.rep[3]);
                }
            }

            // ---- backtrack and emit
            std::vector<std::uint32_t> chain;
            for (std::uint32_t k = endnode; k != 0u; k = nodes[k].back) chain.push_back(k);
            std::reverse(chain.begin(), chain.end());
            std::uint32_t adv = 0;
            for (std::uint32_t k : chain) {
                const Node& n = nodes[k];
                OptimumDecision d{};
                if (n.sg == 0xffu) {
                    d.is_literal = 1u;
                    d.byte = base[pos0 + emitted + adv];
                    adv += 1u;
                } else {
                    d.is_literal = 0u;
                    d.sg = n.sg;
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
            if (trace) std::fprintf(stderr, "[PARSE] emitted=%u adv=%u chain=%zu end=%u\n", emitted, adv, chain.size(), endnode);
            // feed the finder over the bytes the chosen path consumed
            F.Skip(base, pos0 + emitted, adv);
            F.consumed = emitted + adv;
            if (F.consumed > chunk) return false;
        }
    }
    return true;
}

// The frozen-model reference: parse a whole block without letting the coder
// advance the models in between. Kept for comparison; the real encoder uses
// EncodeBlockParsed, which interleaves the two the way the original does.
bool NzOptimumLzDecoder::ParseBlock(const std::uint8_t* data, std::uint32_t size,
                                    std::vector<OptimumDecision>& out) {
    if (size == 0u) return true;
    if (size > 0x8000u) return false;   // one chunk at a time for now
    BeginParse(data, size);
    while (parser_->consumed < size) {
        if (!ParseNextFlush(out)) return false;
    }
    ring_.cursor = parser_->pos0 + size;
    return true;
}

}  // namespace optimum
}  // namespace nzr
