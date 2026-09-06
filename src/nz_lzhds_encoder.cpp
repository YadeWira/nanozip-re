// nz_lzhds_encoder.cpp -- the -cD (nz_lzhds) side of the lzhd compressor: the
// "big object" FUN_08061760's mode 0. Same container, same 32 KB chunks, same
// token columns as -cd; a different match finder (four rep offsets, a 256-byte
// rolling hash for long matches, hash chains with an adaptive depth) and a
// different literal coder: per-context MTF rank codes, with runs of bytes
// predicted from a chosen distance (residuals coded, the run lengths and the
// distance as Exp-Golomb codes in the "ratebits" side field). Every routine is a
// transliteration of one function of the original, named in its comment; the
// goto structure of FUN_08061d00 is kept as labelled states because the
// decoder (nz_lzhds.cpp) mirrors the same odd corners.
#include "nz_lzhd_encoder.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr::lzhd_enc {

namespace {

constexpr std::uint32_t kK = 0x104070bu;   // the rolling hash multiplier

inline std::uint32_t LoadU32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
inline std::uint16_t LoadU16(const std::uint8_t* p) { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
inline std::uint32_t BitLen1(std::uint32_t v) {   // 31 - clz(v), 0 for 0
    if (v == 0u) return 0u;
    std::uint32_t k = 31u;
    while ((v >> k) == 0u) --k;
    return k;
}

// DAT_08171d40: c * K^256, what leaves the 256-byte window (FUN_08059b20 builds it).
const std::uint32_t* OutTable() {
    static std::uint32_t t[256];
    static bool done = false;
    if (!done) {
        std::uint32_t k = 1;
        for (int i = 0; i < 0x100; ++i) k *= kK;
        std::uint32_t v = 0;
        for (int i = 0; i < 256; ++i) { t[i] = v; v += k; }
        done = true;
    }
    return t;
}
// DAT_081b3e20 (FUN_080bf140): the residual code, 2r for r >= 0 and 2(-1-r)|1 below.
const std::uint8_t* ResidualCode() {
    static std::uint8_t t[256];
    static bool done = false;
    if (!done) {
        for (int u = 0; u < 256; ++u) {
            const std::int8_t r = static_cast<std::int8_t>(u);
            t[u] = (r >= 0) ? static_cast<std::uint8_t>(r * 2) : static_cast<std::uint8_t>(((-1 - r) * 2) | 1);
        }
        done = true;
    }
    return t;
}
// DAT_081b4020 / DAT_081b4120 (FUN_080bf2d0): the cost of a residual byte and of a
// rank code, a saturating curve over |value|.
inline std::uint32_t CostCurve(std::uint32_t m) {
    if (m > 0x70u) return 0xffu;   // caller handles (the table doubles instead)
    if (m < 0x21u) {
        if (m < 0x11u) { if (m > 8u) m += m >> 3u; }
        else m += m >> 2u;
    } else m += m >> 1u;
    return m;
}
struct CostTables {
    std::uint8_t resid[256], rank[256];
    CostTables() {
        for (int u = 0; u < 256; ++u) {
            std::uint32_t m = (u & 0x80) ? (0xffu - static_cast<std::uint32_t>(u)) : static_cast<std::uint32_t>(u);
            resid[u] = (m > 0x70u) ? static_cast<std::uint8_t>(m * 2u) : static_cast<std::uint8_t>(CostCurve(m));
        }
        for (int u = 0; u < 256; ++u) {
            const std::uint32_t z = (static_cast<std::uint32_t>(u) >> 1u) ^ (0u - (static_cast<std::uint32_t>(u) & 1u));
            std::uint32_t m = z & 0xffu;
            if (m & 0x80u) m = 0xffu - m;
            rank[u] = (m > 0x70u) ? static_cast<std::uint8_t>(m * 2u) : static_cast<std::uint8_t>(CostCurve(m));   // the FOLDED magnitude doubled (LAB_080bf385 reuses uVar2)
        }
    }
};
const CostTables& Costs() { static const CostTables t; return t; }

// The word-wise compare (bytes equal from a/b up to `limit` on a).
std::uint32_t MatchLen(const std::uint8_t* a, const std::uint8_t* b, const std::uint8_t* limit) {
    const std::uint8_t* s = a;
    for (;;) {
        if (limit <= s) return static_cast<std::uint32_t>(limit - a);
        const std::uint32_t x = LoadU32(s) ^ LoadU32(b);
        if (x != 0u) {
            const bool lo0 = (x & 0xffffu) == 0u;
            const std::uint8_t* stop = s + (lo0 ? 2u : 0u) + ((((x >> (lo0 ? 16u : 0u)) & 0xffu) == 0u) ? 1u : 0u);
            if (limit < stop) stop = limit;
            return static_cast<std::uint32_t>(stop - a);
        }
        s += 4; b += 4;
    }
}

}  // namespace

// ---------------------------------------------------------------- objects
void HdsLrHash::Init(std::uint32_t window) {
    // FUN_08061760: bits = log2((window - 1) >> 6) + 1; FUN_08059b20 allocates 4 << bits
    const std::uint32_t q = (window - 1u) >> 6u;
    const std::uint32_t bits = (q != 0u ? BitLen1(q) : 0u) + 1u;
    table.assign(static_cast<std::size_t>(1u) << bits, 0u);
    mask = (1u << bits) - 1u;
    hash = 0;
}

void HdsFinder::Init(std::uint32_t window, std::uint32_t per) {
    win = window;
    std::uint32_t a = window - 1u; if (a < 0xffffu) a = 0xffffu;
    const std::uint32_t b = BitLen1(a);
    mask = 0xffffffffu >> (31u - b);
    tag = ~mask;
    std::uint32_t c = per - 1u; if (c < 0xffffu) c = 0xffffu;
    const std::uint32_t sh = BitLen1(c) - 3u;
    hmask = (1u << (sh & 31u)) - 1u;
    cmask = (1u << ((sh - ((window + (window >> 1u) < mask) ? 1u : 0u)) & 31u)) - 1u;
    depth = 0;
    head.assign(static_cast<std::size_t>(hmask) + 1u, 0u);
    chain.assign(static_cast<std::size_t>(cmask) + 1u, 0u);
}

void HdsBitWriter::Put(std::uint32_t v, std::uint32_t n) {   // FUN_080b1f20
    const std::uint32_t total = nbits + n;
    if (total < 0x21u) { nbits = total; acc = (acc << (n & 31u)) | v; return; }
    if (cur != 0xffu) {
        const std::uint32_t room = 0x20u - nbits;
        const std::uint32_t rest = n - room;
        nbits = rest;
        const std::uint32_t w = (acc << (room & 31u)) | (v >> (rest & 31u));
        if (0xffu < cur + 4u) cur = 0xffu;
        else {
            buf[cur] = static_cast<std::uint8_t>(w >> 24u); buf[cur + 1u] = static_cast<std::uint8_t>(w >> 16u);
            buf[cur + 2u] = static_cast<std::uint8_t>(w >> 8u); buf[cur + 3u] = static_cast<std::uint8_t>(w);
            cur += 4u;
        }
        acc = v;
    }
}
void HdsBitWriter::Flush() {   // FUN_080b2030
    while (nbits != 0u) {
        if (nbits < 8u) {
            const std::uint32_t k = nbits; nbits = 0;
            if (cur < 0xffu) buf[cur++] = static_cast<std::uint8_t>(acc << (8u - k));
        } else {
            nbits -= 8u;
            if (cur < 0xffu) buf[cur++] = static_cast<std::uint8_t>(acc >> (nbits & 31u));
        }
    }
}
void HdsBitWriter::PutEG(std::uint32_t v) {   // FUN_080c09f0 -> FUN_080c0970 -> FUN_080c0750
    if (std::getenv("NZ_TRACE_LZHDS")) std::fprintf(stderr, "[hds] EG %u\n", v);
    const std::uint32_t nb = (v != 0u ? BitLen1(v) : 0u) + 1u;   // bit length of v (1 for 0)
    const std::uint32_t k = nb - 1u;
    const std::uint32_t kn = (k != 0u ? BitLen1(k) : 0u) + 1u;   // bit length of k
    Put(((1u << kn) - 1u) ^ 1u, kn);                              // kn-1 ones and a zero
    const std::uint32_t m = (kn == 1u) ? 1u : kn - 1u;
    Put(k & ((1u << m) - 1u), m);
    const std::uint32_t mv = (k == 0u) ? 1u : k;
    Put(v & ((mv >= 32u) ? 0xffffffffu : ((1u << mv) - 1u)), mv);
}

void Hds::Init(std::uint32_t window) {
    lr.Init(window);
    finder.Init(window, window);
    ctx.assign(0x4000u, 0u);
    ResetCtx();
    // FUN_0805d330: the code ring, its sum, the tables
    std::memset(ring, 8, sizeof(ring)); ring_idx = 0; ring_sum = 0x800;
    finder.Clear(); lr.Clear();
    ratebits.clear();
    ResetSelection(0u);
}
void Hds::ResetCtx() {   // FUN_080beea0
    for (std::uint32_t c = 0; c < 256u; ++c) {
        std::uint8_t* r = ctx.data() + c * 0x40u;
        for (std::uint32_t i = 0; i < 0x20u; ++i) r[i] = static_cast<std::uint8_t>(i);
        r[0x20] = r[0x21] = r[0x22] = r[0x23] = 0xffu;
        for (std::uint32_t i = 0x24u; i < 0x40u; ++i) r[i] = 0u;
    }
    ctx_index = 0;
}
void Hds::ResetSelection(std::uint32_t pos) {   // FUN_080bf3f0(obj+0x4a00, base + pos)
    for (int i = 0; i < 256; ++i) lastpos[i] = pos;
    rowctr = 0;
    for (int i = 0; i < 17; ++i) counters[i] = 0x3f80u;
    std::memset(hist, 0x7f, sizeof(hist));
    std::memset(row, 0xff, sizeof(row));
    f8 = 0; e8 = 0; e4 = 0; f0 = 0; ec = 0; f4 = 0x11;
}

std::uint64_t HdsMemoryBytes(std::uint32_t window, unsigned threads) {   // FUN_0805d3d0
    HdsFinder f; f.Init(window, window);
    const std::uint32_t q = (window - 1u) >> 6u;
    const std::uint32_t bits = (q != 0u ? BitLen1(q) : 0u) + 1u;
    // FUN_080bf740: window + 0x40 + two FUN_080c1120(.., 0xf) objects of 0xa0000 each
    return static_cast<std::uint64_t>(window) + 0x140040ull
         + (static_cast<std::uint64_t>(f.hmask) + f.cmask + 2u) * 4u
         + 0xe0080ull * threads + ((1ull << bits) + 0u) * 4u + 0x30000ull;
}

// ---------------------------------------------------------------- FUN_0805da50
// A chunk that bypasses the parser: rehash from its start, then every 0x1383
// bytes insert 124 consecutive positions into the chains (and the long-range
// table at 256-multiples), starting 0x1307 bytes in.
void HdsAppend(State& st, std::uint32_t n) {
    Hds& h = *st.hds;
    Window& w = st.win;
    const std::uint8_t* const base = w.base;
    std::uint32_t pos = w.pos;
    const std::uint32_t endpos = pos + n;
    const std::uint32_t* const T = OutTable();
    std::uint32_t hash = 0;
    for (std::uint32_t i = 0; i < 0x100u; ++i) hash = hash * kK + base[pos + i];
    HdsFinder& f = h.finder;
    std::uint32_t* const lrt = h.lr.table.data();
    if (n >= 9u) {
        std::uint32_t m = n - 8u;
        while (m > 0x1406u) {
            pos += 0x1307u;
            hash = 0;
            for (std::uint32_t i = 0; i < 0x100u; ++i) hash = hash * kK + base[pos + i];
            for (int it = 0; it < 0x1f; ++it) {
                for (std::uint32_t k = 0; k < 4u; ++k) {
                    const std::uint32_t p = pos + k;
                    const std::uint32_t v = LoadU32(base + p);
                    const std::uint32_t hidx = ((v >> 19u) ^ v) & f.hmask;
                    const std::uint32_t old = f.head[hidx];
                    f.head[hidx] = (LoadU32(base + p) & f.tag) | p;
                    f.chain[p & f.cmask] = old;
                    if ((p & 0xffu) == 0u) lrt[h.lr.mask & hash] = (p >> 8u) + (hash & 0xffc00000u);
                    hash = (base[p + 0x100u] + hash * kK) - T[base[p]];
                }
                pos += 4u;
            }
            m -= 0x1383u;
        }
    }
    h.lr.hash = hash;
    w.pos = endpos;
    if (std::getenv("NZ_TRACE_LZHDS")) std::fprintf(stderr, "[hds] append pos=%u n=%u hash_out=%08x\n", w.pos - n, n, hash);
}

// ---------------------------------------------------------------- FUN_0805e6a0
// The literal estimate the audio decision weighs: a quick parse over the chunk
// with a 2-byte table and the finder's heads (read only).
static std::uint32_t HdsEstimateImpl(State& st, const std::uint8_t* p, std::uint32_t n);
std::uint32_t HdsEstimate(State& st, const std::uint8_t* p, std::uint32_t n) {
    const std::uint32_t r = HdsEstimateImpl(st, p, n);
    if (std::getenv("NZ_TRACE_LZHDS")) std::fprintf(stderr, "[hds] estimate n=%u -> %u\n", n, r);
    return r;
}
static std::uint32_t HdsEstimateImpl(State& st, const std::uint8_t* p, std::uint32_t n) {
    if (n <= 0x10u) return n;
    Hds& h = *st.hds;
    const HdsFinder& f = h.finder;
    const std::uint8_t* const base = st.win.base;
    static thread_local std::vector<const std::uint8_t*> tbl(0x2000u);
    for (auto& e : tbl) e = p;
    const std::uint8_t* q = p + 1;
    std::uint32_t rem = n - 1u, lastfill = n, lits = 0;
    for (;;) {
        const std::uint32_t k = LoadU16(q) & 0x1fffu;
        const std::uint8_t* prev = tbl[k];
        tbl[k] = q;
        const std::uint32_t v = LoadU32(q);
        bool chain_done = false;
        if (rem >= 4u) {
            const std::uint32_t hidx = ((v >> 19u) ^ v) & f.hmask;
            const std::uint32_t e = f.head[hidx];
            if ((f.tag & v) == (f.tag & e) && e != 0u) {
                const std::uint8_t* cand = base + (e & f.mask);
                if (v == LoadU32(cand)) {
                    const std::uint32_t room = static_cast<std::uint32_t>((base + f.win) - cand);
                    const std::uint8_t* limit = cand + std::min(room, rem);
                    const std::uint32_t len = MatchLen(cand + 4, q + 4, limit) + 4u;
                    if (len >= 4u) {
                        lits += lastfill - rem;
                        rem -= len;
                        if (rem == 0u) return lits;
                        q += len; lastfill = rem;
                        chain_done = true;
                    }
                }
            }
        }
        if (chain_done) continue;
        const std::uint32_t len2 = MatchLen(q, prev, q + rem);
        if (len2 < 4u) {
            if (--rem == 0u) return lits + lastfill;
            ++q;
            continue;
        }
        lits += lastfill - rem;
        rem -= len2;
        if (rem == 0u) return lits;
        q += len2; lastfill = rem;
    }
}

// ---------------------------------------------------------------- FUN_08061d00
static int g_hds_chunk_no = 0;
static bool g_trace_ms = false;
std::uint32_t HdsEncodeChunk(State& st, std::uint32_t n) {
    Hds& h = *st.hds;
    ++g_hds_chunk_no;
    { const char* e = std::getenv("NZ_TRACE_LZHDS_MS"); g_trace_ms = e && std::atoi(e) == g_hds_chunk_no; }
    Window& w = st.win;
    std::uint8_t* const base = w.base;
    const std::uint32_t size = w.size;          // local_5c
    std::uint32_t pos = w.pos;                  // local_54
    const std::uint32_t vend = w.end;           // local_50
    HdsFinder& f = h.finder;
    const std::uint32_t fwin = f.win, fmask = f.mask, ftag = f.tag, hmask = f.hmask, cmask = f.cmask;
    std::uint32_t depth = f.depth;              // local_70
    std::uint32_t* const head = f.head.data();
    std::uint32_t* const chain = f.chain.data();
    std::uint32_t* const lrt = h.lr.table.data();
    const std::uint32_t lrmask = h.lr.mask;
    std::uint32_t hash = 0;                     // local_38 = 0: the chunk's hash starts fresh (the object's slot is copied in and back, never read)
    if (std::getenv("NZ_TRACE_LZHDS")) std::fprintf(stderr, "[hds] chunk pos=%u n=%u depth=%u hash_in=%08x ctx=%u\n", pos, n, depth, hash, h.ctx_index);
    const std::uint32_t* const T = OutTable();
    const std::uint8_t* const RC = ResidualCode();
    const CostTables& C = Costs();
    std::uint8_t* const ctx0 = h.ctx.data();
    std::uint8_t* ctxp = ctx0 + h.ctx_index * 0x40u;   // local_274
    st.tb.Reset();
    std::vector<std::uint32_t>& tok = st.tb.tok;
    std::uint8_t* const lit = st.lits.data();
    std::uint8_t* out = lit;                    // local_258
    HdsBitWriter& bw = h.rate;
    bw.Reset();
    std::int32_t P[32] = {0};                   // local_11c[0..], 4 stages x (4 weights, 4 history)
    std::uint32_t stage = 0, order = 0;         // local_9c, local_98
    h.ResetSelection(pos);
    std::uint32_t rep[4] = {0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu};   // local_2c: negative offsets
    std::uint32_t budget = (n >> 4u) + 1u;      // local_250
    std::uint32_t litctr = 0;                   // local_27c
    std::uint32_t since = n;                    // local_290: `n` when the last token was emitted
    std::uint32_t lastflush = 0;                // local_248
    std::uint32_t curdist = 0;                  // local_24c
    std::uint32_t predrun = 0;                  // local_280
    std::uint32_t minbase = 4;                  // local_260
    std::uint8_t ringcodes[256];                // auStack_21c
    std::uint32_t slot = 0;                     // uVar21 at the literal
    std::uint32_t c = 0, code = 0;              // local_270, local_25c
    std::uint32_t mlen = 0, dist = 0, cls = 0, adj = 0, rcode = 0;   // local_294, local_298, iVar8, local_284
    bool have_rep = false;
    const std::uint8_t* const lowest = w.mem.data();
    enum { SEARCH, LITERAL, RUN_END, RAW, PRED_START, PRED_EMIT, MTFUPDATE, FINISH } state;

    for (std::uint32_t i = 0; i < 0x100u; ++i) hash = hash * kK + base[pos + i];
    if (pos == 0u) {
        lrt[lrmask & hash] = hash & 0xffc00000u;
        hash = (base[pos + 0x100u] + hash * kK) - T[base[pos]];
        slot = 1; litctr = 1;
        state = LITERAL;
    } else {
        state = SEARCH;
    }
    bool exhausted = false;   // the `param_3 == 0` flow through the literal states

    for (;;) {
        switch (state) {
        case SEARCH: {
            const std::uint8_t* const p = base + pos;
            // the four rep offsets, first match wins
            have_rep = false; rcode = 0;
            for (std::uint32_t i = 0; i < 4u; ++i) {
                const std::uint8_t* q = p + static_cast<std::int32_t>(rep[i]);
                if (q < lowest) continue;
                if (LoadU16(q) == LoadU16(p)) {
                    const std::uint32_t len = (n < 3u) ? 2u : MatchLen(p + 2, q + 2, p + n) + 2u;
                    rcode = i + len * 4u;
                    have_rep = 7u < rcode;
                    break;
                }
            }
            // the long-range table
            std::uint32_t* const le = lrt + (lrmask & hash);
            const std::uint32_t e = *le;
            if ((pos & 0xffu) == 0u) *le = (pos >> 8u) + (hash & 0xffc00000u);
            mlen = 0;
            std::uint32_t cpos = 0;
            if ((hash & 0xffc00000u) == (e & 0xffc00000u)) {
                cpos = (e & 0x3fffffu) << 8u;
                const std::uint32_t room = size - cpos;
                const std::uint32_t lim = std::min(n, room);
                std::uint32_t k = 0;
                do {
                    if (p[k] != base[cpos + k]) break;
                    ++k;
                } while (k < lim);
                mlen = k;
                dist = cpos;
            }
            hash = (p[0x100] - T[p[0]]) + hash * kK;
            if (mlen < 8u) {
                if (n < 5u) mlen = 0;
                else {
                    const std::uint32_t cur = LoadU32(p);
                    std::uint32_t* const hp = head + (((cur >> 19u) ^ cur) & hmask);
                    const std::uint32_t tag = cur & ftag;
                    std::uint32_t old = *hp;
                    *hp = tag | pos;
                    chain[cmask & pos] = old;
                    mlen = 0;
                    if (tag == (ftag & old) && old != 0u) {
                        std::uint32_t cand = fmask & old;
                        const std::uint8_t* q = base + cand;
                        if (cur == LoadU32(q)) {
                            if (vend <= cand || cand < pos) {
                                std::int32_t cbudget = static_cast<std::int32_t>(depth >> 2u) + 1;
                                depth += (depth < 0x40u) ? 1u : 0u;
                                bool done = false;
                                while (!done) {
                                    const std::uint32_t room = static_cast<std::uint32_t>((base + fwin) - q);
                                    const std::uint32_t lim = std::min(room, n);
                                    // a do-while in the original: byte 4 is compared before the
                                    // limit is looked at, so a candidate ending at the window's last
                                    // bytes can still match 5 (the slack past the window is zero)
                                    std::uint32_t k = 4;
                                    do { if (p[k] != q[k]) break; ++k; } while (k < lim);
                                    if (mlen < k) {
                                        dist = static_cast<std::uint32_t>(p - q);
                                        if (mlen != 0u) {
                                            depth += ((3u - mlen) + k) >> 2u;
                                            if (depth > 0x400u) depth = 0x400u;
                                        }
                                        mlen = k;
                                        if (0x80u < k || n <= k) break;
                                    }
                                    cbudget >>= (0x10u < mlen) ? 1 : 0;
                                    std::uint32_t saved = depth;
                                    for (;;) {
                                        saved = depth;
                                        --cbudget;
                                        if (cbudget < 1) { done = true; break; }
                                        if (cmask < pos - (fmask & old)) { done = true; break; }
                                        old = chain[old & cmask];
                                        if (old == 0u) { done = true; break; }
                                        cand = fmask & old;
                                        if (pos <= cand && cand < vend) { done = true; break; }
                                        depth -= depth >> 2u;
                                        if (tag != (ftag & old)) { done = true; break; }
                                        q = base + cand;
                                        depth = saved;
                                        if (LoadU32(q + (mlen - 3u)) == LoadU32(p + (mlen - 3u))) break;
                                    }
                                    if (done) break;
                                    if (cur != LoadU32(q)) { depth = saved >> 1u; break; }
                                }
                            }
                        }
                    }
                }
                dist += (static_cast<std::int32_t>(dist) < 0) ? size : 0u;   // LAB_08062883
            } else {
                if (cpos < vend && pos <= cpos) mlen = 0;
                else if (pos > cpos) dist = pos - cpos;
                else dist = (size + pos) - cpos;
                if (mlen == 0u && !(pos > cpos)) dist = (size + pos) - cpos;
            }
            // LAB_08062148: the cost classes and the minimum length
            if (g_trace_ms) std::fprintf(stderr, "M pos=%u mlen=%u dist=%u depth=%u rcode=%u hash=%08x\n", pos, mlen, dist, depth, rcode, hash);
            cls = (0x3fffu < dist ? 1u : 0u) + (0x3ffu < dist ? 1u : 0u) + (0x7fffffu < dist ? 1u : 0u);
            const std::uint32_t minlen = (0x100000u < dist ? 1u : 0u) + (0x40000u < dist ? 1u : 0u) + minbase + cls;
            bool newoff = false;
            if (mlen < minlen) {
                mlen = 0;
                if (!have_rep) { ++litctr; slot = litctr & 0xffu; state = LITERAL; break; }
            } else {
                if (mlen == 0u) { if (!have_rep) { ++litctr; slot = litctr & 0xffu; state = LITERAL; break; } }
                else if (!have_rep) newoff = true;
            }
            if (!newoff) {
                // LAB_080621b8: the rep match, unless the new offset is longer by two
                const std::uint32_t rlen = rcode >> 2u;
                if (rlen + 1u < mlen) newoff = true;
                else {
                    const std::uint32_t sel = rcode & 3u;
                    const std::uint32_t roff = rep[sel];
                    if (size < roff + rlen + pos || n == 1u) { ++litctr; slot = litctr & 0xffu; state = LITERAL; break; }
                    if (sel == 2u) { rep[2] = rep[1]; rep[1] = rep[0]; }
                    else if (sel == 3u) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
                    else if (sel == 1u) { rep[1] = rep[0]; }
                    adj = 2; rep[0] = roff; mlen = rlen; rcode = sel; dist = roff;
                }
            }
            if (newoff) {
                // LAB_08062238
                adj = cls + 4u;
                const std::uint32_t negoff = 0u - (dist - ((pos < dist) ? size : 0u));
                rcode = dist + 3u;
                rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = negoff;
                dist = negoff;
            }
            // the token
            tok.push_back(since - n); tok.push_back(rcode); tok.push_back(mlen - adj);
            ++pos;
            {
                // hash-chain entries for the matched bytes, sparse for long matches
                std::uint32_t count = mlen - 1u;
                const std::uint8_t* ptr = base + pos;
                std::uint32_t pp = pos;
                for (;;) {
                    std::uint32_t cnt2 = count; const std::uint8_t* ptr2 = ptr; std::uint32_t pp2 = pp;
                    if (0x3fu < count) {
                        cnt2 = count - 0x17u; ptr2 = ptr + 0x17; pp2 = pp + 0x17u;
                        if (0x3ffu < cnt2) { cnt2 = count - 0x20cu; ptr2 = ptr + 0x20c; pp2 = pp + 0x20cu; }
                    }
                    const std::uint32_t v = LoadU32(ptr2);
                    std::uint32_t* const hp = head + (((v >> 19u) ^ v) & hmask);
                    const std::uint32_t old = *hp;
                    *hp = (v & ftag) | pp2;
                    count = cnt2 - 1u;
                    chain[cmask & pp2] = old;
                    if (count == 0u) break;
                    ptr = ptr2 + 1; pp = pp2 + 1u;
                }
            }
            {
                const std::uint32_t m1 = mlen - 1u;
                if (m1 < 0x100u) {
                    for (std::uint32_t k = 0; k < m1; ++k) {
                        const std::uint32_t p2 = pos + k;
                        if ((p2 & 0xffu) == 0u) lrt[lrmask & hash] = (p2 >> 8u) + (hash & 0xffc00000u);
                        hash = (base[p2 + 0x100u] - T[base[p2]]) + hash * kK;
                    }
                } else {
                    const std::uint32_t np = pos + m1;
                    std::uint32_t hh = 0;
                    for (std::uint32_t i = 0; i < 0x100u; ++i) hh = hh * kK + base[np + i];
                    hash = hh;
                }
            }
            pos += mlen - 1u;
            stage += mlen;
            if (order != 0u) {
                stage %= order;
                if (order < 5u) for (std::uint32_t s = 0; s < order; ++s) { P[s * 8 + 4] = P[s * 8 + 5] = P[s * 8 + 6] = P[s * 8 + 7] = 0; }
            }
            n -= mlen;
            ctxp = ctx0 + static_cast<std::uint32_t>(base[pos - 1u]) * 0x40u;
            since = n;
            if (n == 0u) {
                since = 0;
                exhausted = true;
                if (predrun == 0u) { state = FINISH; break; }
                ++litctr;
                state = RUN_END; break;
            }
            state = SEARCH; break;
        }
        case LITERAL: {   // LAB_08062977
            if (std::getenv("NZ_TRACE_LZHDS")) { std::fprintf(stderr, "L rc=%u ec=%u f0=%u f8=%d f4=%u e4=%u e8=%u sum=%u ridx=%u c=", h.rowctr, h.ec, h.f0, h.f8, h.f4, h.e4, h.e8, h.ring_sum, h.ring_idx); for (int i = 0; i < 17; ++i) std::fprintf(stderr, "%u ", h.counters[i]); std::fprintf(stderr, "\n"); }
            c = base[pos];
            if (((ctxp[0x20u + (c >> 3u)] >> (c & 7u)) & 1u) == 0u) {
                code = c;
                while (code < 0x20u) code = ctxp[code];
            } else {
                code = 0;
                while (ctxp[code] != c) ++code;
            }
            *out = static_cast<std::uint8_t>(code);
            ringcodes[slot] = static_cast<std::uint8_t>(code);
            if (h.f8 != 0 && curdist == h.ec) {
                ++predrun;
                state = (predrun != 1u) ? PRED_EMIT : PRED_START;
                break;
            }
            if (predrun != 0u) { state = RUN_END; break; }
            state = RAW; break;
        }
        case RUN_END: {   // LAB_0806252e
            if (std::getenv("NZ_TRACE_LZHDS")) std::fprintf(stderr, "[hds] run_end pos=%u litctr=%u predrun=%u curdist=%u lastflush=%u f8=%d ec=%u\n", pos, litctr, predrun, curdist, lastflush, h.f8, h.ec);
            if (predrun < 200u) {
                std::uint32_t k = litctr - predrun;
                do {
                    out[static_cast<std::int32_t>(k - litctr)] = ringcodes[k & 0xffu];
                    ++k; --predrun;
                } while (predrun != 0u);
            } else {
                bw.PutEG(((litctr - 1u) - predrun) - lastflush);
                bw.PutEG(predrun - 200u);
                bw.PutEG(curdist - 1u);
                lastflush = litctr - 1u;
            }
            if (exhausted) { state = FINISH; break; }
            if (h.f8 == 0) { state = RAW; break; }
            curdist = h.ec; predrun = 1;
            state = PRED_START; break;
        }
        case PRED_START: {   // LAB_080625a7
            std::memset(P, 0, sizeof(P)); stage = 0; order = 0;
            order = curdist;
            state = PRED_EMIT; break;
        }
        case PRED_EMIT: {   // LAB_080625d2
            const std::uint32_t s = (stage < order) ? stage : 0u;
            std::uint8_t res;
            const std::uint8_t back = base[pos - curdist];
            if (order < 5u) {
                std::int32_t* S = P + s * 8;
                const std::int8_t d = static_cast<std::int8_t>(static_cast<std::uint8_t>(c - back));
                const std::int32_t tap = (S[0] * S[4] + 0x200 + S[1] * S[5] + S[2] * S[6] + S[3] * S[7]) >> 10;
                res = static_cast<std::uint8_t>(static_cast<std::int8_t>(d - static_cast<std::int8_t>(tap)));
                if (static_cast<std::int8_t>(res) != 0) {
                    const std::int32_t sg = (static_cast<std::int8_t>(res) < 0) ? -1 : 0;
                    for (int k = 0; k < 4; ++k) S[k] += (S[4 + k] ^ sg) - sg;
                }
                S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; S[4] = d;
            } else {
                res = static_cast<std::uint8_t>(c - back);
            }
            *out = RC[res];
            stage = s + 1u;
            budget += 2u;
            state = MTFUPDATE; break;
        }
        case RAW: {   // LAB_08062a13
            predrun = 0; curdist = h.ec;
            state = MTFUPDATE; break;
        }
        case MTFUPDATE: {
            if (code < 0x20u) {
                if (code != 0u) {
                    const std::uint32_t j = code - ((code + 3u) >> 2u);
                    ctxp[code] = ctxp[j];
                    ctxp[j] = static_cast<std::uint8_t>(c);
                }
            } else {
                const std::uint8_t ev = ctxp[0x1f];
                ctxp[0x20u + (ev >> 3u)] = static_cast<std::uint8_t>(ctxp[0x20u + (ev >> 3u)] ^ static_cast<std::uint8_t>(1u << (ev & 7u)));
                ctxp[0x20u + (c >> 3u)] = static_cast<std::uint8_t>(ctxp[0x20u + (c >> 3u)] | static_cast<std::uint8_t>(1u << (c & 7u)));
                for (int i = 0x1e; i >= 0x10; --i) ctxp[i + 1] = ctxp[i];
                ctxp[0x10] = static_cast<std::uint8_t>(c);
            }
            ctxp = ctx0 + c * 0x40u;
            if (budget == 0u) h.f8 = 0;
            else {
                // the distance-selection model
                h.ring_idx += 1u;
                const std::uint32_t ri = h.ring_idx & 0xffu;
                const std::uint8_t oldc = h.ring[ri];
                h.ring[ri] = static_cast<std::uint8_t>(code);
                h.ring_sum = (h.ring_sum - oldc) + (code & 0xffu);
                const std::uint8_t* const p = base + pos;
                const std::uint32_t sh = ((((h.ring_sum + 0x80u) >> 8u) < 0x71u) ? 0xdu : 0u) + 7u;
                budget = (budget - 1u) - (budget >> sh);
                h.row[h.e8] = 0x6f;
                h.row[h.f0] = C.resid[static_cast<std::uint8_t>(c - p[-static_cast<std::int32_t>(h.f0)])];
                const std::uint32_t old_e4 = h.e4;
                if (old_e4 != 0u) h.row[old_e4] = C.resid[static_cast<std::uint8_t>(c - p[-static_cast<std::int32_t>(old_e4)])];
                h.row[h.ec] = C.resid[static_cast<std::uint8_t>(c - p[-static_cast<std::int32_t>(h.ec)])];
                std::uint32_t d = pos - h.lastpos[c];
                h.lastpos[c] = pos;
                d = ((d - 0x11u) >> 24u) & d;
                h.row[d] = 0;
                h.rowctr += 1u;
                std::uint8_t* const hr = h.hist + (h.rowctr & 0x7fu) * 0x11u;
                h.e4 = d;
                h.row[0] = C.rank[code & 0xffu];
                for (int i = 16; i >= 0; --i) {
                    const std::uint8_t o = hr[i];
                    hr[i] = h.row[i];
                    h.counters[i] = (h.counters[i] - o) + h.row[i];
                }
                h.e8 = old_e4;
                if (--h.f4 == 0u) {
                    if (std::getenv("NZ_TRACE_LZHDS")) { std::fprintf(stderr, "[hds] resel pos=%u counters", pos); for (int i = 0; i < 17; ++i) std::fprintf(stderr, " %u", (h.counters[i] + 0x40u) >> 7u); std::fprintf(stderr, " ec=%u f0=%u f8=%d\n", h.ec, h.f0, h.f8); }
                    const std::uint32_t old_ec = h.ec;
                    const std::uint32_t old_f8 = static_cast<std::uint32_t>(h.f8);
                    h.ec = 0x10; h.f0 = 0xf;
                    std::uint32_t best = (h.counters[16] + 0x40u) >> 7u;
                    std::uint32_t second = (h.counters[15] + 0x40u) >> 7u;
                    if (second < best) { h.ec = 0xf; h.f0 = 0x10; std::swap(best, second); }
                    for (std::uint32_t i = 14; i != 0u; --i) {
                        const std::uint32_t ci = (h.counters[i] + 0x40u) >> 7u;
                        if (ci < best) { h.f0 = h.ec; h.ec = i; second = best; best = ci; }
                        else if (ci < second) { h.f0 = i; second = ci; }
                    }
                    const std::uint32_t raw = (h.counters[0] + 0x40u) >> 7u;
                    bool done_sel = false;
                    if (best * 4u < h.ec + raw * 4u) {
                        h.f8 = -1;
                        if (raw < 0x51u || best * 9u < raw * 8u) {
                            const std::uint32_t prev = old_f8 & old_ec;
                            h.f4 = 7;
                            if (prev != h.ec && prev == h.f0 && second * 3u <= best * 4u) { h.f0 = h.ec; h.ec = prev; }
                            done_sel = true;
                        } else h.f8 = 0;
                    } else h.f8 = 0;
                    if (!done_sel) h.f4 = 7;
                }
            }
            // LAB_0806301f
            ++out; --n; ++pos;
            if (n == 0u) {
                exhausted = true;
                if (predrun == 0u) { state = FINISH; break; }
                ++litctr;
                state = RUN_END; break;
            }
            minbase = (399u < predrun ? 1u : 0u) + 4u;
            state = SEARCH; break;
        }
        case FINISH: {   // LAB_08062781
            bw.PutEG(litctr - lastflush);
            bw.Flush();
            h.ratebits.assign(bw.buf, bw.buf + bw.cur);
            st.tb.trailing_lit = since;
            f.depth = depth;
            h.lr.hash = hash;
            w.pos = pos;
            h.ctx_index = static_cast<std::uint32_t>((ctxp - ctx0) >> 6u);
            return static_cast<std::uint32_t>(out - lit);
        }
        }
    }
}

}  // namespace nzr::lzhd_enc
