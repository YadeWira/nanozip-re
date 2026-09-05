// nz_lzhd_encoder.cpp -- see the header. Every routine mirrors one function of
// the original; the comments name it.
#include "nz_lzhd_encoder.h"
#include "nz_lzpf_encoder.h"
#include "nz_cd_tokens.h"
#include "nz_audio.h"
#include "nz_lzhd_text.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr::lzhd_enc {

namespace {

inline std::uint32_t LoadU32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
inline std::uint32_t BitLen1(std::uint32_t v) {   // 31 - clz(v), 0 for v == 0 (the original's masked bsr)
    if (v == 0u) return 0u;
    std::uint32_t k = 31u;
    while ((v >> k) == 0u) --k;
    return k;
}
// DAT_081b4380: 0, 2, 4, 8, ... (1 << k for k >= 1)
inline std::uint32_t Base(std::uint32_t k) { return k == 0u ? 0u : (1u << k); }

// FUN_0805ead0: the literal-run skip table, built once from a byte-wise CRC
// walk; entry i (16..255) is 1 when the walk's low byte is below a threshold
// that grows with i.
const std::uint8_t* SkipTable() {
    static std::uint8_t tbl[256];
    static bool done = false;
    if (!done) {
        for (int i = 0; i < 16; ++i) tbl[i] = 0;
        std::uint32_t crc = 0xffffffffu;
        for (std::uint32_t i = 16; i < 256; ++i) {
            const std::uint32_t x = crc & 0xffu;
            crc = x * 0xEF074001u ^ (crc >> 8u);
            const std::uint32_t thr = (i >> 2u) + (i >> 1u) + ((i - 0x81u) < 0x3fu ? 0x40u : 0x20u);
            tbl[i] = (x < thr) ? 1u : 0u;
        }
        done = true;
    }
    return tbl;
}

// The word-wise compare every matcher here uses: bytes equal from `a`/`b` up to
// `limit` (exclusive, on `a`), counted the original's way (whole words, then the
// low half / low byte tests on the differing word).
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

// ---------------------------------------------------------------- varint
void PutVar(std::vector<std::uint8_t>& out, std::uint32_t limit, std::uint32_t value) {
    if (!(value < 0x80u || limit < 0x101u)) {
        do {
            out.push_back(static_cast<std::uint8_t>(value | 0x80u));
            value >>= 7u;
            limit = ((limit & 0x7fu) != 0u ? 1u : 0u) + (limit >> 7u);
        } while (0x100u < limit && 0x7fu < value);
    }
    out.push_back(static_cast<std::uint8_t>(value));
}

// ---------------------------------------------------------------- window
void Window::Init(std::uint32_t sz) {
    size = sz;
    mem.assign(static_cast<std::size_t>(sz) + 0x200u + 0x8000u + 64u, 0);
    base = mem.data() + 0x100;
    pos = end = 0; wrapped = false;
}
void Window::Slide(std::uint32_t n) {
    if (size - pos < n) {
        if (!wrapped) { wrapped = true; std::memset(base + pos, 0, (size - pos) + 0x100u); }
        pos = 0;
        std::memcpy(base - 0x100, base + size - 0x100, 0x100u);
    }
}
void Window::Append(const std::uint8_t* s, std::uint32_t n) {
    std::memcpy(base + pos, s, n);
    end = pos + n;
}

// ---------------------------------------------------------------- finder
void Finder::Init(std::uint32_t window) {
    win = window;
    std::uint32_t a = window - 1u; if (a < 0xffffu) a = 0xffffu;
    const std::uint32_t b = BitLen1(a);
    shift = 31u - b;
    tagmask = static_cast<std::uint8_t>((1u << shift) - 1u);
    std::uint32_t c = window - 1u; if (c < 0xffffu) c = 0xffffu;
    const std::uint32_t bb = BitLen1(c);
    const std::uint32_t m = (1u << ((bb - 3u) & 31u)) - 1u;
    bmask = m & 0xfffffffcu;
    mask2 = m >> 3u;
    table.assign(bmask + 16u, 0u);
}
void Finder::Clear() { std::fill(table.begin(), table.end(), 0u); }

std::uint64_t FinderTableBytes(std::uint32_t window) {
    Finder f; f.Init(window);
    return static_cast<std::uint64_t>(f.bmask) * 4u + 0x10u;   // FUN_0805c4b0 (no second table below 128 MB)
}

void State::Init(std::uint32_t window) {
    win.Init(window);
    finder.Init(window);
    cont = 0;
    tb.Reset();
    lits.assign(0x8000u + 64u, 0);
    tmp.assign(0x10000u + 64u, 0);
    probe_ctx = lzpf_enc::AudioProbe{};
    exe_pos = 4;
    image.Reset();
}

// ---------------------------------------------------------------- FUN_0805e190
void SparseAppend(State& st, std::uint32_t n) {
    Window& w = st.win;
    Finder& f = st.finder;
    w.Slide(n);
    // (the caller copied the bytes in already: Append happened before)
    st.cont += n;
    const std::uint8_t* base = w.base;
    std::uint32_t p = w.pos;
    const std::uint32_t endpos = p + n;
    auto ins = [&](std::uint32_t at) {
        const std::uint32_t wv = LoadU32(base + at);
        const std::uint32_t h = (wv >> 19u) ^ (wv * 0x923249u);
        std::uint32_t* b = &f.table[(h & f.bmask)];
        b[3] = b[2]; b[2] = b[1]; b[1] = b[0];
        b[0] = ((h >> ((32u - f.shift) & 31u)) & f.tagmask) + (at << (f.shift & 31u));
    };
    for (std::int32_t rem = static_cast<std::int32_t>(n) - 1; rem >= 0; rem -= 0x493) {
        ins(p);
        if (rem == 0) break;
        ins(p + 1u);
        if (rem == 1) break;
        ins(p + 2u);
        if (rem - 0x25 < 0) break;
        ins(p + 3u);
        if (rem - 0x4c < 0) break;
        ins(p + 0x26u);
        if (rem - 0x71 < 0) break;
        ins(p + 0x4du);
        if (rem - 0x92 < 0) break;
        ins(p + 0x72u);
        if (rem - 0x492 < 0) break;
        ins(p + 0x93u);
        p += 0x493u;
    }
    w.pos = endpos;
}

// ---------------------------------------------------------------- FUN_0805f640
std::uint32_t LzEncodeChunk(State& st, std::uint32_t n) {
    Window& w = st.win;
    const Finder& f = st.finder;
    std::uint32_t* const table = st.finder.table.data();
    const std::uint8_t* const skip = SkipTable();
    st.tb.Reset();
    std::vector<std::uint32_t>& tok = st.tb.tok;
    std::uint8_t* const lit = st.lits.data();
    std::uint32_t nlit = 0;

    const std::uint32_t size = w.size;
    std::uint8_t* const base = w.base;
    std::uint32_t pos = w.pos;             // local_44
    const std::uint32_t vend = w.end;      // local_40: [pos, end) is the chunk being parsed
    std::uint32_t remaining = n;           // param_3
    std::int32_t rep[4] = {-1, -1, -1, -1};   // local_34[0..3], signed deltas
    std::uint32_t off = 0, mlen = 0;       // local_34[4], local_34[5]
    std::uint32_t cont = st.cont;          // local_b0
    std::uint32_t extra = 0;               // local_94
    std::uint32_t since = n;               // uVar13: `remaining` when the last token was emitted
    std::uint32_t run = 0;                 // local_7c
    bool from_cont = false;
    const std::uint8_t* const lowest = w.mem.data();   // reads below this would be the original's garbage

    auto emit = [&](std::uint32_t lit_run, std::uint32_t sel, std::uint32_t rawlen, std::uint32_t len) {
        tok.push_back(lit_run); tok.push_back(sel); tok.push_back(rawlen);
        for (std::uint32_t i = 0; i < lit_run; i += 4u) std::memcpy(lit + nlit + i, base + (pos - lit_run) + i, 4u);
        nlit += lit_run;
        pos += len; remaining -= len;
        since = 0;
    };
    auto rep_ok = [&](std::int32_t d) { return base + static_cast<std::int64_t>(pos) + d >= lowest; };

    if (cont != 0u) {
        // FUN_0805ef70: does the previous chunk's last match continue into this one?
        std::uint32_t c = cont;
        mlen = 0;
        bool inside;
        if (c < size) inside = (c < vend && pos <= c);
        else { c -= size; inside = (c < vend && pos <= c); }
        if (!inside) {
            const std::uint32_t lim = std::min(n, size - c);
            std::uint32_t k = 0;
            while (k < lim && base[pos + k] == base[c + k]) ++k;
            mlen = k;
            off = pos - c;
        }
        off += static_cast<std::uint32_t>(static_cast<std::int32_t>(off) >> 31) & size;
        extra = (0x63ffu < off ? 1u : 0u) + (0x4ffu < off ? 1u : 0u);
        if (10u < mlen) { rep[1] = -1; rep[2] = -1; cont = 0xffffffffu; from_cont = true; }
    }
    if (!from_cont && pos == 0u) {
        run = 1;
        ++pos; --remaining; cont = 0;
        if (remaining == 0u) goto finish;
    }
    for (;;) {
        std::uint32_t lit_run;
        if (from_cont) { from_cont = false; lit_run = 0; goto new_offset; }
        // ---- the literal-run skip filter
        for (;;) {
            const bool sk = (0x80u < run) ? skip[(run & 0xffu) | 0x80u] != 0u : skip[run & 0xffu] != 0u;
            if (!sk) break;
            ++run; ++pos; --remaining;
            if (remaining == 0u) goto end_after_match;   // LAB_0805f75c -> LAB_0805fa70
        }
        {
            const std::uint8_t* cur = base + pos;
            std::uint16_t w16; std::memcpy(&w16, cur, 2);
            int ridx = -1;
            for (int i = 0; i < 4; ++i) {
                if (!rep_ok(rep[i])) continue;
                std::uint16_t r16; std::memcpy(&r16, cur + rep[i], 2);
                if (r16 == w16) { ridx = i; break; }
            }
            if (ridx >= 0) {
                mlen = (remaining < 3u) ? 2u : 2u + MatchLen(cur + 2, cur + rep[ridx] + 2, cur + remaining);
                const std::int32_t rd = rep[ridx];
                off = static_cast<std::uint32_t>(rd);
                if (size < mlen + pos + off || remaining == 1u) { ++run; extra = 2u; goto literal; }
                if (ridx == 3) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
                else if (ridx == 2) { rep[2] = rep[1]; rep[1] = rep[0]; }
                else if (ridx == 1) { rep[1] = rep[0]; }
                rep[0] = rd;
                extra = 2u;
                emit(since - remaining, static_cast<std::uint32_t>(ridx), mlen - extra, mlen);
                if (remaining == 0u) goto end_after_match;
                run = 0; since = remaining;
                continue;
            }
            // ---- the hash buckets
            mlen = 0;
            bool inserted_skip = false;
            if (3u < remaining) {
                const std::uint32_t wv = LoadU32(cur);
                const std::uint32_t h = (wv >> 19u) ^ (wv * 0x923249u);
                const std::uint32_t tag = (h >> ((32u - f.shift) & 31u)) & f.tagmask;
                std::uint32_t* bucket = &table[h & f.bmask];
                const std::uint32_t head = bucket[0];
                std::uint32_t best = 0;
                if (head != 0u && tag == (f.tagmask & head)) {
                    std::uint32_t cpos = head >> (f.shift & 31u);
                    if (cpos < pos || vend <= cpos) {
                        std::uint32_t* e = bucket;
                        for (;;) {
                            const std::uint8_t* cand = base + cpos;
                            if (best < 4u || LoadU32(cur + (best - 3u)) == LoadU32(cand + (best - 3u))) {
                                const std::uint32_t lim = std::min(remaining, size - cpos);
                                const std::uint32_t l = MatchLen(cand, cur, cand + lim);
                                mlen = l;
                                if (best < l) {
                                    off = static_cast<std::uint32_t>(cur - cand);
                                    const std::uint32_t t = bucket[0]; bucket[0] = *e; *e = t;
                                    if (0x3fu < l || remaining <= l) { inserted_skip = true; break; }
                                    best = l;
                                }
                            }
                            ++e;
                            if ((reinterpret_cast<std::uintptr_t>(e) & 0xfu) == 0u) break;
                            const std::uint32_t ev = *e;
                            if (ev == 0u || tag != (f.tagmask & ev)) break;
                            cpos = ev >> (f.shift & 31u);
                            if (!(vend <= cpos || cpos < pos)) break;
                        }
                        if (!inserted_skip) mlen = best;
                    }
                }
                if (!inserted_skip) {
                    const std::uint32_t h0 = bucket[0];
                    const std::uint32_t o1 = bucket[1];
                    bucket[1] = h0; bucket[3] = bucket[2]; bucket[2] = o1;
                    bucket[0] = (pos << (f.shift & 31u)) + tag;
                }
            }
            off += static_cast<std::uint32_t>(static_cast<std::int32_t>(off) >> 31) & size;
            extra = (0x4ffu < off ? 1u : 0u) + (0x63ffu < off ? 1u : 0u);
            if (extra + 4u <= mlen) { lit_run = since - remaining; goto new_offset; }
            ++run;
            goto literal;
        }
new_offset:
        {
            const std::uint32_t b0 = (cont == 0xffffffffu) ? 0xffffffffu : static_cast<std::uint32_t>(rep[0]);
            const std::uint32_t sel = off + 3u;
            rep[3] = rep[2];
            const std::uint32_t nd = 0u - (off - ((pos < off) ? size : 0u));
            extra += 4u;
            rep[2] = rep[1];
            rep[1] = static_cast<std::int32_t>(b0);
            rep[0] = static_cast<std::int32_t>(nd);
            cont = sel;
            emit(lit_run, sel, mlen - extra, mlen);
            if (remaining == 0u) goto end_after_match;
            run = 0; since = remaining;
            continue;
        }
literal:
        ++pos; --remaining; cont = 0;
        if (remaining == 0u) goto finish;
    }
end_after_match:
    if (cont != 0u) cont = (pos - (cont - 3u)) + ((pos < cont - 3u) ? size : 0u);
finish:
    st.cont = cont;
    for (std::uint32_t i = 0; i < since; i += 4u) std::memcpy(lit + nlit + i, base + (pos - since) + i, 4u);
    st.tb.trailing_lit = since;
    nlit += since;
    w.pos = pos;
    if (std::getenv("NZ_TRACE_LZHD")) {
        std::fprintf(stderr, "[lzhd] chunk n=%u tokens=%zu lits=%u trailing=%u cont=%u\n", n, tok.size() / 3u, nlit, since, cont);
        for (std::size_t i = 0; i < tok.size() / 3u; ++i) std::fprintf(stderr, "  T%zu %u %u %u\n", i, tok[3*i], tok[3*i+1], tok[3*i+2]);
    }
    return nlit;
}

// ---------------------------------------------------------------- FUN_08090100
// The per-column run-length coder: bytes pass through; after two equal bytes
// (`thr` more for the length column) the rest of the run is replaced by
// floor(log2(run)) copies of the byte plus the run's low bits in the side stream.
static std::uint32_t ColumnRle(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst,
                               lzpf_enc::BitWriter& bw, std::uint32_t thr) {
    if (n == 0u) return 0u;
    std::uint32_t cnt = n + 1u;      // param_2 (remaining + 1)
    std::uint32_t prev = 0;          // the rolling window's low byte
    const std::uint8_t* s = src;
    std::uint8_t* d = dst;
    for (;;) {
        std::uint32_t left = cnt - 1u;
        if (left == 0u) return static_cast<std::uint32_t>(d - dst);
        std::uint8_t c = *s++; *d++ = c;
        cnt = left;
        const std::uint8_t pb = static_cast<std::uint8_t>(prev);
        prev = c;
        if (c != pb) continue;
        // a pair: copy up to thr + 1 more equal bytes verbatim
        std::uint32_t more = thr;
        bool broke = false;
        for (;;) {
            cnt = left - 1u;
            if (cnt == 0u) break;
            const std::uint8_t c2 = *s++; *d++ = c2;
            left = cnt;
            if (c2 != c) { prev = c2; broke = true; break; }
            const bool go = static_cast<std::int32_t>(more) > 0;
            --more;
            if (!go) break;
        }
        if (broke) continue;
        if (cnt == 0u) return static_cast<std::uint32_t>(d - dst);
        // the remainder of the run
        std::uint32_t k = 0;
        const std::uint8_t* q = s;
        std::uint32_t rem = cnt;
        for (;;) { --rem; if (rem == 0u) break; if (*q != c) break; ++q; }
        const std::uint32_t runlen = static_cast<std::uint32_t>(q - s);
        s = q; cnt -= runlen;
        if (1u < runlen) { std::uint32_t x = runlen >> 1u; do { ++k; *d++ = c; x >>= 1u; } while (x != 0u); }
        // FUN_080900c0: k == 0 writes one bit through the mask table's entry 0 (= 1)
        bw.Put(runlen & lzpf_enc::MaskBits(k), k == 0u ? 1u : k);
        prev = c;
    }
}

// FUN_0808ab90: one column -> `[b0][rle bits][count varint][arith | raw]`.
static void CodeColumn(State& st, std::vector<std::uint8_t>& col, std::uint32_t mode, std::vector<std::uint8_t>& out) {
    const std::uint32_t n = static_cast<std::uint32_t>(col.size());
    std::uint8_t rbuf[0x7f + 8];
    lzpf_enc::BitWriter bw; bw.base = rbuf; bw.end = rbuf + 0x7f; bw.cur = rbuf; bw.bitbuf = 0; bw.nbits = 0;
    std::uint8_t* const tmp = st.tmp.data();
    std::uint32_t rle_out = ColumnRle(col.data(), n, tmp, bw, mode);
    bw.Flush();
    const std::uint32_t rbytes = static_cast<std::uint32_t>(bw.cur - bw.base);
    if (bw.end <= bw.cur) rle_out = 0;   // FUN_0808fd30: an overflowing side stream cancels the RLE
    std::size_t b0_at;
    std::vector<std::uint8_t> arith(static_cast<std::size_t>(n) + 64u);
    if (rbytes + 8u + rle_out + (n >> 7u) < n) {
        if (rle_out != 0u) {
            b0_at = out.size(); out.push_back(static_cast<std::uint8_t>(rbytes * 2u));
            if (rbytes != 0u) {
                out.insert(out.end(), rbuf, rbuf + rbytes);
                col.assign(tmp, tmp + rle_out);
                PutVar(out, 0x8000u, static_cast<std::uint32_t>(col.size()));
            }
            goto arith;
        }
    }
    b0_at = out.size(); out.push_back(0u);
arith:
    {
        const std::uint32_t m = static_cast<std::uint32_t>(col.size());
        const std::size_t got = lzpf_enc::EncodeArithAt(col.data(), m, arith.data(), m, 0u);
        if (got != 0u) { out[b0_at] |= 1u; out.insert(out.end(), arith.begin(), arith.begin() + static_cast<std::ptrdiff_t>(got)); }
        else out.insert(out.end(), col.begin(), col.end());
    }
}

// FUN_0808aff0: token fields -> column bytes + extra bits, then the three coded
// columns; FUN_0808b6b0: their serialisation with the count varints.
void WriteColumns(State& st, std::vector<std::uint8_t>& out) {
    TokenBuf& tb = st.tb;
    tb.col_lit.clear(); tb.col_len.clear(); tb.col_off.clear();
    tb.bits.assign(0x20000u + 64u, 0);
    lzpf_enc::BitWriter bw; bw.base = tb.bits.data(); bw.end = tb.bits.data() + 0x20000u; bw.cur = bw.base; bw.bitbuf = 0; bw.nbits = 0;
    const unsigned char* const mlit = nzr::cd::NzCdModelTable(0);
    const unsigned char* const moff = nzr::cd::NzCdModelTable(1);
    const unsigned char* const mlen = nzr::cd::NzCdModelTable(2);
    auto field = [&](std::uint32_t v, std::uint32_t thr, const unsigned char* model, std::vector<std::uint8_t>& col) {
        if (v < thr) { col.push_back(static_cast<std::uint8_t>(v)); return; }
        const std::uint32_t d = v - thr;
        const std::uint32_t k = BitLen1(d);
        const std::uint32_t nbits = model[2u * k + 1u];
        if (nbits != 0u) {
            bw.Put(d & lzpf_enc::MaskBits(nbits), nbits);
            col.push_back(static_cast<std::uint8_t>(((d ^ Base(k)) >> nbits) + model[2u * k] + thr));
        } else {
            col.push_back(static_cast<std::uint8_t>(d + thr));
        }
    };
    const std::size_t ntok = tb.tok.size() / 3u;
    for (std::size_t i = 0; i < ntok; ++i) {
        field(tb.tok[3 * i + 0], 8u, mlit, tb.col_lit);
        field(tb.tok[3 * i + 1], 4u, moff, tb.col_off);
        field(tb.tok[3 * i + 2], 14u, mlen, tb.col_len);
    }
    field(tb.trailing_lit, 8u, mlit, tb.col_lit);
    bw.Flush();
    const std::size_t nbits_bytes = static_cast<std::size_t>(bw.cur - bw.base);
    tb.out_lit.clear(); tb.out_len.clear(); tb.out_off.clear();
    CodeColumn(st, tb.col_lit, 0u, tb.out_lit);
    if (ntok + 1u > 1u) {
        CodeColumn(st, tb.col_len, 1u, tb.out_len);
        CodeColumn(st, tb.col_off, 0u, tb.out_off);
    }
    // FUN_0808b6b0
    PutVar(out, 0x8000u - 1u, static_cast<std::uint32_t>(ntok));
    PutVar(out, 0x8000u, static_cast<std::uint32_t>(tb.out_lit.size())); out.insert(out.end(), tb.out_lit.begin(), tb.out_lit.end());
    PutVar(out, 0x8000u, static_cast<std::uint32_t>(tb.out_len.size())); out.insert(out.end(), tb.out_len.begin(), tb.out_len.end());
    PutVar(out, 0x8000u, static_cast<std::uint32_t>(tb.out_off.size())); out.insert(out.end(), tb.out_off.begin(), tb.out_off.end());
    PutVar(out, 0x20000u, static_cast<std::uint32_t>(nbits_bytes)); out.insert(out.end(), tb.bits.begin(), tb.bits.begin() + static_cast<std::ptrdiff_t>(nbits_bytes));
}

// ---------------------------------------------------------------- FUN_0805d690
void WriteChunk(State& st, const std::uint8_t* lits, std::uint32_t lit_size, std::uint32_t out_size,
                std::uint32_t flags, std::uint8_t text_param, const std::vector<std::uint8_t>& rle_side,
                std::vector<std::uint8_t>& out) {
    std::vector<std::uint8_t> arith(static_cast<std::size_t>(lit_size) + 64u);
    const std::size_t r = lzpf_enc::EncodeArithAt(lits, lit_size, arith.data(), lit_size, 0u);
    const bool coded = (r != 0u && r < lit_size);
    if (coded) flags |= 1u;
    PutVar(out, 0x80010u, lit_size == 0x8000u ? flags : (lit_size + 1u) * 16u + flags);
    if (lit_size != 0x8000u) PutVar(out, 0x8001u - lit_size, out_size - lit_size);
    if (lit_size < out_size) WriteColumns(st, out);
    if (coded) out.insert(out.end(), arith.begin(), arith.begin() + static_cast<std::ptrdiff_t>(r));
    else out.insert(out.end(), lits, lits + lit_size);
    if (flags & 8u) out.push_back(text_param);
    if (flags & 2u) { PutVar(out, 0x1001u, static_cast<std::uint32_t>(rle_side.size())); out.insert(out.end(), rle_side.begin(), rle_side.end()); }
}

// ---------------------------------------------------------------- FUN_0808fc20
// Block-RLE detection over a window: words are read from the first 16-byte
// boundary after `p` (an address property of the original's 64-byte-aligned
// chunk buffers, so `align` = p's offset within such a buffer).
static std::uint32_t BlockRleDetect(const std::uint8_t* p, std::uint32_t n, std::uint32_t thr, std::uint32_t align) {
    std::uint32_t budget = 0;
    if ((n >> 2u) > 9u) {
        const std::uint32_t need = n * thr;
        budget = (n >> 2u) - 5u;
        if (need != 0u) {
            std::uint32_t score = 0, prev = 0, bonus = 0;
            const std::uint8_t* q = p + ((0x10u - (align & 0xfu)) & 0xfu) + ((align & 0xfu) == 0u ? 0x10u : 0u);
            // ((p & ~0xf) + 0x10): the next 16-byte boundary strictly after p
            for (;;) {
                std::uint32_t w = LoadU32(q); q += 4;
                if (w != prev) {
                    for (;;) {
                        prev = w;
                        if (--budget == 0u) return 0u;
                        const std::uint8_t c = static_cast<std::uint8_t>(w >> 8u);
                        bonus = (c == static_cast<std::uint8_t>(w) ? 1u : 0u) + (c == static_cast<std::uint8_t>(w >> 16u) ? 1u : 0u) +
                                (((w >> 16u) & 0xffu) == (w >> 24u) ? 1u : 0u);
                        score += bonus;
                        if (need <= score) return budget;
                        w = LoadU32(q); q += 4;
                        if (w == prev) break;
                    }
                }
                if (--budget == 0u) return 0u;
                const std::uint8_t c = static_cast<std::uint8_t>(prev >> 8u);
                bonus = ((c == static_cast<std::uint8_t>(prev) ? 1u : 0u) + (c == static_cast<std::uint8_t>(prev >> 16u) ? 1u : 0u) +
                         (((prev >> 16u) & 0xffu) == (prev >> 24u) ? 1u : 0u) + bonus + 1u) & 0x7fu;
                score += bonus;
                if (!(score < need)) break;
            }
        }
    }
    return budget;
}

// FUN_080c03f0: an MZ or ELF header at the chunk start restarts the exe position.
static bool ExeHeaderAt(const std::uint8_t* p, std::uint32_t n) {
    if (n < 0x80u) return false;
    if (p[0] == 'M') return p[1] == 'Z';
    if (p[0] == 0x7f && p[1] == 'E' && p[2] == 'L') return p[3] == 'F';
    return false;
}

// ---------------------------------------------------------------- FUN_08064bb0
void CompressPiece(State& st, const std::uint8_t* src, std::uint32_t n, std::vector<std::uint8_t>& out) {
    // the two 64-byte-aligned 32 KB chunk buffers (their alignment feeds the RLE detector)
    alignas(64) static thread_local std::uint8_t bufA[0x8000 + 0x100];
    alignas(64) static thread_local std::uint8_t bufB[0x8000 + 0x100];
    std::uint32_t off = 0;
    while (off < n) {
        const std::uint32_t len0 = std::min<std::uint32_t>(n - off, 0x8000u);
        std::uint8_t* buf = bufA; std::uint8_t* tmpb = bufB;
        std::memcpy(buf, src + off, len0);
        std::uint32_t len = len0;
        std::uint32_t flags = 0;
        std::vector<std::uint8_t> rle_side;
        std::uint8_t text_param = 0;
        const bool in_span = st.probe_ctx.bytes_done < st.probe_ctx.audio_end;
        if (!in_span) {
            // the analysis: probe, exe metric + filter
            lzpf_enc::AudioProbeBlock(st.probe_ctx, buf, len);
            const std::uint32_t m = std::min<std::uint32_t>(len, 0x2000u);
            if (lzpf_enc::ExeMetric(buf, m) / ((m >> 12u) + 1u) != 0u) {
                if (ExeHeaderAt(buf, len)) st.exe_pos = 4;
                lzpf_enc::ExeFilterForward(buf, len, st.exe_pos);
                flags = 4;
            }
        }
        st.exe_pos += len;
        bool go_audio = false;
        if (st.probe_ctx.bytes_done < st.probe_ctx.audio_end) {
            // inside a header's audio span
            st.image.Reset();
            if (len < 0x200u) goto literal_small;
            if (flags == 0u) go_audio = true;   // LAB_08064dc0
        } else {
            // block RLE: any of up to five 0x7ff-byte windows
            std::uint32_t w1 = std::min<std::uint32_t>(len, 0x7ffu);
            bool rle = BlockRleDetect(buf, w1, 10u, 0u) != 0u;
            if (!rle && len > 0xffeu) {
                std::uint32_t w2 = std::min<std::uint32_t>(len - (len >> 1u), 0x7ffu);
                rle = BlockRleDetect(buf + (len >> 1u), w2, 10u, len >> 1u) != 0u;
                if (!rle) rle = BlockRleDetect(buf + (len - 0x7ffu), 0x7ffu, 10u, len - 0x7ffu) != 0u;
                if (!rle) {
                    const std::uint32_t third = len / 3u;
                    const std::uint32_t rest = len - third;
                    rle = BlockRleDetect(buf + third, std::min<std::uint32_t>(rest, 0x7ffu), 10u, third) != 0u;
                    if (!rle) rle = BlockRleDetect(buf + rest, std::min<std::uint32_t>(third, 0x7ffu), 10u, rest) != 0u;
                }
            }
            if (rle) {
                std::uint8_t bits[0x1000 + 8];
                lzpf_enc::BitWriter bw; bw.base = bits; bw.end = bits + 0x1000; bw.cur = bits; bw.bitbuf = 0; bw.nbits = 0;
                std::uint32_t out_n = ColumnRle(buf, len, tmpb, bw, 1u);
                bw.Flush();
                const std::uint32_t bbytes = static_cast<std::uint32_t>(bw.cur - bw.base);
                if (bw.end <= bw.cur) out_n = 0;
                if (out_n != 0u) {
                    const std::uint32_t slack = (len < 0x81u) ? (len >> 1u) : 0x80u;
                    if (bbytes + out_n + slack < len) {
                        flags |= 2u;
                        std::swap(buf, tmpb);
                        len = out_n;
                        rle_side.assign(bits, bits + bbytes);
                    }
                }
            }
            if (st.probe_ctx.bytes_done < st.probe_ctx.audio_end) { st.image.Reset(); if (len < 0x200u) goto literal_small; if (flags == 0u) go_audio = true; }
            else {
                if (flags == 0u) {
                    // the text pipeline (FUN_08054dc0 .. FUN_08059060)
                    const std::uint32_t bits = TextDetect(buf, len, tmpb);
                    if (bits != 0u) {
                        std::uint8_t applied = 0;
                        std::uint8_t* b2 = buf; std::uint8_t* t2 = tmpb;
                        const std::uint32_t r = TextPipeline(bits, b2, len, t2, 0x8040u, &applied);
                        if (r != 0u) { buf = b2; tmpb = t2; len = r; flags = 8u; text_param = applied; }
                        if (const char* dp = std::getenv("NZ_DUMP_LZHD_TEXT")) { if (FILE* f = std::fopen(dp, "ab")) { std::fwrite(buf, 1, len, f); std::fclose(f); } }
                    }
                }
                // image (n > 0x1ff, flags == 0): TODO -- FUN_0808aac0 with the -cd profile
                st.image.Reset();
                if (len < 0x200u) goto literal_small;
                if (flags == 0u) {
                    // LAB_080651a0: the audio decision outside a span
                    const bool dec = lzpf_enc::AudioDecide(st.probe_ctx, buf, std::min<std::uint32_t>(len, 0x400u), len);
                    if (dec) {
                        // (the LZ cost estimate FUN_0805f030 vs 3/4 of the chunk: TODO; assume audio)
                        go_audio = true;
                    }
                }
            }
        }
        if (go_audio) {
            // TODO: the -cd audio block (FUN_08082d00 with the 8/0x10/3 profile); fall through to LZ for now
        }
        {
            st.probe_ctx.bytes_done += len;
            st.audio.ResetAll();
            std::uint32_t lit_size;
            st.win.Slide(len);
            std::uint32_t guard; std::memcpy(&guard, st.win.base + st.win.pos + len, 4);
            st.win.Append(buf, len);
            if (len < 0x100u) { SparseAppend(st, len); lit_size = len; }
            else lit_size = LzEncodeChunk(st, len);
            std::memcpy(st.win.base + st.win.pos, &guard, 4);
            if (lit_size + 0x10u + (lit_size >> 7u) < len) WriteChunk(st, st.lits.data(), lit_size, len, flags, text_param, rle_side, out);
            else WriteChunk(st, buf, len, len, flags, text_param, rle_side, out);
            off += len0;
            continue;
        }
literal_small:
        {
            // a tiny chunk inside an audio span: window append, literal chunk
            st.probe_ctx.bytes_done += len;
            st.audio.ResetAll();
            st.win.Slide(len);
            std::uint32_t guard; std::memcpy(&guard, st.win.base + st.win.pos + len, 4);
            st.win.Append(buf, len);
            SparseAppend(st, len);
            std::memcpy(st.win.base + st.win.pos, &guard, 4);
            WriteChunk(st, buf, len, len, flags, text_param, rle_side, out);
            off += len0;
        }
    }
}

}  // namespace nzr::lzhd_enc
