// nz_lzhd_text.cpp -- see the header. Decompiles: ~/.cache/nzre_tools/encode/decomp/lzhd_text.c
#include "nz_lzhd_text.h"
#include "nz_cd_tokens.h"
#include "nz_cd_texttransform_dict.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr::lzhd_enc {

namespace {

inline std::uint32_t LoadU32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }

// DAT_081332e0 = the reference's kCharacterTraits_0 (letters 0x41/0x21, digits 4, ...)
const std::uint8_t* Traits0() { return nzr::cd::NzCdCharacterTraits0(); }

// The matcher the text transforms share (whole words, then the partial word).
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

// FUN_080b7120: bytes that continue a word (1) -- everything but the separators;
// and the bytes the dictionary output must escape (the codes' byte range).
struct WordTables {
    std::uint8_t cont[256];     // DAT_08186160
    std::uint8_t escape[256];   // DAT_08186260
    WordTables() {
        static const char kSep[] = " \n\r\t\"'\\/(<[{&-_|=>;.!?";
        for (int c = 0; c < 256; ++c) cont[c] = (std::memchr(kSep, c, sizeof(kSep) - 1) == nullptr || c == 0) ? 1u : 0u;
        // the separator string has 22 chars; a NUL byte is never "found" by the original's loop
        cont[0] = 1u;
        const std::uint8_t* t0 = Traits0();
        for (int c = 0; c < 256; ++c) {
            bool esc = false;
            if (c > 0x7f) esc = true;
            else if (t0[c] & 0x40u) esc = true;                        // upper case
            else if (!(c == 9 || c > 0x1f)) esc = (c != 10);            // control chars but \t \n
            else if (c == 0x7a || c == 0x7f || c == 0x7e || c == 0x78) esc = true;
            else if (c == 0x40 || c == 0x5e || c == 0x29 || c == 0x25 || c == 0x3f || c == 0x21 || c == 0x60 || c == 0x24) esc = true;
            escape[c] = esc ? 1u : (c == 'w' || c == 'v') ? 1u : 0u;
        }
        escape[0xff] = 1u;
    }
};
const WordTables& Words() { static WordTables w; return w; }
// FUN_080b7120 runs from the dictionary encoder's initialisation (FUN_08055000 ->
// FUN_080b7770 -> FUN_080b7210), so until the process has encoded one dictionary
// chunk the detector FUN_08055150 reads an all-zero continuation table.
bool g_word_tables_built = false;
const std::uint8_t kZeroCont[256] = {};

}  // namespace

// ------------------------------------------------------------ detectors
// FUN_08054dc0 + FUN_08054e60 + FUN_08054f80 over a histogram object.
struct TextHist { std::uint32_t count[256]; std::uint32_t n; std::uint8_t score; };
static void HistBuild(TextHist& h, const std::uint8_t* buf, std::uint32_t n) {
    // (n < 16: the original leaves the stack object uninitialised; we call it not text)
    std::memset(&h, 0, sizeof(h));
    if (n < 0x10u) return;
    for (std::uint32_t i = 0; i < n; ++i) ++h.count[buf[i]];
    const std::uint8_t* t0 = Traits0();
    std::uint32_t texty = 1;
    for (int c = 0; c < 256; ++c) if (h.count[c] != 0u && (t0[c] & 0x9du) != 0u) texty += h.count[c];
    h.n = n;
    h.score = (n / texty < 2u) ? 100u : 0u;
}
static bool HistIsText(const TextHist& h) { return h.score >= 0x58u; }
static bool HistCrlf(const TextHist& h) {
    const std::uint32_t nl = h.count[10], cr = h.count[13];
    return (h.n >> 7u) <= nl && nl <= (h.n >> 3u) && cr - (cr >> 6u) <= nl && nl <= (cr >> 6u) + cr;
}

// FUN_08055150: does the dictionary fit this text? Words are runs after a
// non-letter; the bucket sizes of their first two letters give the "dictionary
// richness" the ratio tests read.
static bool DictFits(const std::uint8_t* p, std::uint32_t n) {
    if (n <= 0xfu) return false;
    const std::uint8_t* t0 = Traits0();
    const std::uint8_t* const cont = g_word_tables_built ? Words().cont : kZeroCont;
    const std::uint16_t* bucket_start = nzr::cd::NzCdDictBucketStarts();   // DAT_08189880[0x2da]
    std::uint32_t words = 1, rich = 0;
    std::int32_t left = static_cast<std::int32_t>(n) - 4;
    const std::uint8_t* q = p + 4;
    for (;;) {
        const std::uint8_t* cur = q;
        if (--left == 0) break;
        q = cur + 1;
        if ((t0[*cur] & 1u) == 0u) {
            // a non-letter that itself continues a token (digits, most punctuation)
            // swallows the following continuation bytes
            std::uint8_t cv = cont[*cur];
            while (cv != 0u) {
                --left;
                const std::uint8_t b = *q;
                if (left == 0) goto done;
                ++q;
                cv = cont[b];
            }
            ++words;
            const std::uint32_t idx = nzr::cd::NzCdDictBucketIndex(cur[-2], cur[-1]);
            rich += bucket_start[idx + 1u] - bucket_start[idx];
        }
    }
done:
    const std::uint32_t avg = n / words;
    const std::uint32_t ratio = (n << 4u) / (rich | 1u);
    if (avg < 2u || 3u < ratio || 0x14u < avg) return (2u < avg && ratio < 5u) && avg < 9u;
    return true;
}

// FUN_08057e60: line statistics for the line-RLE decision.
static bool LineRleFits(const std::uint8_t* src, std::uint32_t n) {
    if (n < 0x80u) return false;
    const std::uint8_t term = 10;
    std::uint32_t lines = 0, starts_differ = 1, prefix_sum = 1, ge_count = 0, left = n;
    const std::uint8_t* p = src;            // param_2
    const std::uint8_t* prev = src;         // puVar11
    std::uint8_t c = *p;
    for (;;) {
        ++lines;
        const std::uint8_t* q = p;
        for (;;) {                          // find the terminator
            if (--left == 0) goto finish;
            ++q;
            if (term == c) break;
            c = *q;
        }
        c = *q; p = q;
        if (c != *prev) { ++starts_differ; prev = q; continue; }
        if (c == ' ') { ++starts_differ; prev = q; continue; }
        const std::uint32_t L = MatchLen(prev, q, prev + 0x1f);
        prefix_sum += L;
        ge_count += (prev[L] <= q[L]) ? 1u : 0u;
        const std::uint32_t adv = std::min(L, left);
        left -= adv;
        if (left == 0) goto finish;
        p = q + adv; c = *p; prev = q;
    }
finish:
    if (lines / starts_differ < 4u) return false;
    if (3u < prefix_sum / lines && n / lines < 0x28u) return true;
    return 2u < (ge_count * 4u) / lines && 3u < prefix_sum / lines;
}

std::uint32_t TextDetect(const std::uint8_t* buf, std::uint32_t n, std::uint8_t* scratch) {
    TextHist h;
    HistBuild(h, buf, n >> 3u);
    const bool tr = std::getenv("NZ_TRACE_LZHD") != nullptr;
    if (tr) std::fprintf(stderr, "[textdet] n=%u hist_n=%u score=%u istext=%d\n", n, h.n, h.score, (int)HistIsText(h));
    if (!HistIsText(h)) return 0u;
    std::uint32_t bits = 0;
    const std::uint32_t half = n >> 1u;
    const bool d1 = DictFits(buf, half), d2 = d1 && DictFits(buf + half, n - half);
    if (tr) std::fprintf(stderr, "[textdet] dict halves %d %d crlf=%d\n", (int)d1, (int)d2, (int)HistCrlf(h));
    if (d1 && d2) bits = 0x88u;
    if (n >> 5u >= 0x80u && TextChessEncode(buf, (n >> 5u) - 0x40u, scratch, n >> 5u) != 0u) bits |= 0x40u;
    else {
        const std::uint32_t k = n >> 7u;
        if (LineRleFits(buf, k) && LineRleFits(buf + k, n - k)) bits |= 0x20u;
        else if (bits == 0u) return 0u;
    }
    if (HistCrlf(h)) bits |= 1u;
    return bits;
}

// ------------------------------------------------------------ FUN_08056960
std::uint32_t TextCrlfEncode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap) {
    if (cap < n || n == 0u) return 0u;
    std::int32_t gain = static_cast<std::int32_t>(std::min<std::uint32_t>(cap - n, 0x100u));
    int state = 0;
    bool seen = false;
    std::uint8_t* d = dst;
    std::uint32_t left = n;
    std::uint8_t prev = 0;
    for (;;) {
        const std::uint8_t pv = prev;
        std::uint8_t c = *src++;
        std::uint8_t* at = d;
        *d++ = c;
        --left;
        if (left != 0u && !(c < 0xeu && (c == 0xdu || c == 0xau))) { prev = c; continue; }
        if (left == 0u) {
            if (gain < 0 || !seen) return 0u;
            const std::uint32_t out = static_cast<std::uint32_t>(d - dst);
            return out < n ? out : 0u;
        }
        if (state == 1) {
            if (c == 0xdu && 1u < left && *src == 0xau) { *at = 0xau; ++gain; --left; ++src; c = 0; }
            else { *at = 0xdu; *d = c; --gain; if (gain < 0) return 0u; state = 0; ++d; c = 0; }
        } else if (state == 2) {
            if (c == 0xdu) { *at = 0xau; c = 0; }
            else { *at = 0xdu; state = 0; c = 0; }
        } else if (c == 0xau) {
            if (pv == 0xdu) { state = 1; seen = true; }
        } else if (c == 0xdu && 0xdu < *src) { state = 2; seen = true; }
        prev = c;
    }
}

// ------------------------------------------------------------ FUN_08058050
std::uint32_t TextLineRleEncode(std::uint8_t term, const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap) {
    if (cap < n || n < 10u) return 0u;
    std::int32_t gain = ~static_cast<std::int32_t>(std::min<std::uint32_t>(cap - n, 0x10u));
    dst[0] = term;
    std::uint8_t* d = dst + 1;
    const std::uint8_t* prev = src;
    std::uint32_t left = n;
    for (;;) {
        std::uint8_t* at = d;
        const std::uint8_t c = *src++;
        *d++ = c;
        --left;
        if (left != 0u && c != term) continue;
        std::uint8_t* endp = d;
        if (left != 0u) {
            const std::uint8_t* cur = src;
            if (*cur != *prev) {
                prev = cur;
                if (0xdfu < *cur) { *d = 0xe0u; ++gain; if (gain >= 0) return 0u; d = at + 2; }
                continue;
            }
            std::uint32_t L = MatchLen(prev, cur, prev + 0x1f);
            if (left < L) L = left;
            *d = static_cast<std::uint8_t>(L - 0x20u);
            gain = (gain + 1) - static_cast<std::int32_t>(L);
            left -= L;
            endp = at + 2;
            if (left != 0u) { src = cur + L; d = endp; prev = cur; continue; }
        }
        if (gain >= 0) return 0u;
        const std::uint32_t out = static_cast<std::uint32_t>(endp - dst);
        return (out < n - n / 5u) ? out : 0u;
    }
}

// ------------------------------------------------------------ FUN_08055e70
std::uint32_t TextParam14Encode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap) {
    if (n == 0u) return 0u;
    const std::uint8_t* cls = nzr::cd::NzCdParam14ClassTable();
    std::uint8_t* const end = dst + cap;
    if (!(dst < end)) return 0u;
    const std::uint8_t* s = src;          // param_1
    std::int32_t left;                    // param_2 / local_30
    std::int32_t cnt = static_cast<std::int32_t>(n);
    std::uint8_t b = *s;                  // bVar2
    std::uint8_t c;                       // bVar3
    *dst = b;
    std::uint8_t* d = dst;                // pbVar6
    std::uint8_t* d1;                     // pbVar7
    std::uint8_t* w;                      // pbVar8
    const std::uint8_t* s1;               // pbVar5
    const std::uint8_t* s2;
    for (;;) {
        d1 = d + 1;
        for (;;) {
            left = cnt - 1; w = d1;
            if (left == 0) goto fin;
            s1 = s + 1; c = *s1;
            if (static_cast<std::int8_t>(c & b) < 0) break;
            cnt = left; d = d1;
            if ((cls[b] & 4u) == 0u && (((b & 0x80u) & ~static_cast<unsigned>(c)) == 0u || (c == 0x20u && static_cast<std::int8_t>(s[2]) < 0) || left == 1)) {
                s = s1;
                if (cls[c] & 8u) goto run;
                goto joined;
            }
            if (c == 0x20u) { s2 = s + 2; goto space2; }
            s = s1;
            if (cls[c] & 1u) goto joined;
            *d1 = 0x20u;
            if (end <= d1 + 1) return 0u;
            b = *s1; d1[1] = b; d1 += 2;
        }
        *d1 = c; w = d1 + 1;
        left = cnt - 2;
        if (left == 0) goto fin;
        s2 = s + 3;
        if (s[2] == 0x20u) {
space2:
            if (*s2 == 0x20u || (cls[*s2] & 1u) != 0u || left == 1) { *w = 0x20u; w[1] = 0x20u; w += 2; }
            cnt = left - 1; s = s2; d = w;
            if (left - 1 == 0) goto fin;
        } else {
            if ((cls[s[2]] & 1u) == 0u) { *w = 0x20u; w = d1 + 2; }
            cnt = left; s = s + 2; d = w;
        }
joined:
        if (end <= d) return 0u;
        b = *s; *d = b;
        continue;
run:
        for (;;) {
            const std::int32_t k = left - 1;
            *d1 = c; w = d1 + 1;
            if (k == 0) goto fin;
            const std::uint8_t* nx = s1 + 1;
            cnt = k; s = nx; d = w;
            if (end <= w) goto joined;
            if (cls[c] & 2u) { cnt = left; s = s1; d = d1; goto joined; }
            c = *nx; left = k; s1 = nx; d1 = w;
        }
    }
fin:
    return (w < end) ? static_cast<std::uint32_t>(w - dst) : 0u;
}

// ------------------------------------------------------------ stubs (next steps)
// ------------------------------------------------------------ the dictionary
// FUN_080b7020 / FUN_080b7210 / FUN_080b7770 / FUN_08055000 rebuilt from the
// decoder's reference arrays (verified against the original's runtime tables):
// the dictionary keeps its words REVERSED -- a word's bucket is its last two
// letters, its keys pack the earlier letters five bits each, back to front.
struct DictTables {
    std::uint8_t e60[256];  std::int32_t a60[256];  std::uint8_t f60[256];   // FUN_080b7020
    std::uint8_t two[736];                 // DAT_08186460: a60[c1] + e60[c0] -> code
    std::uint16_t three[0x2d9 * 2];        // DAT_08186740: (c0 & 1) + 2 * (e60[c1] + a60[c2]) -> c0 << 8 | code
    std::uint32_t mid_hash[0x800];         // DAT_081872c0: pairs {key, code | 0x80 | bucket << 8}
    std::uint16_t codes[16384];            // DAT_081a9e40: FUN_08055000's run/rank codes
    const std::uint16_t* ends;             // DAT_081892c0: bucket ends (after the build)
    const std::uint32_t* key1; const std::uint32_t* key2;   // DAT_08189e40 / DAT_08199e40
    DictTables() {
        const std::uint8_t* t0 = Traits0();
        for (int c = 0; c < 256; ++c) {
            const bool lower = (t0[c] & 0x20u) != 0u;
            e60[c] = lower ? static_cast<std::uint8_t>(c - 0x60) : 0u;
            a60[c] = lower ? 27 * (c - 0x60) : 0;
            f60[c] = lower ? static_cast<std::uint8_t>(c - 0x60) : ((t0[c] & 0x40u) ? 0x1fu : 0u);
        }
        nzr::cd::NzCdDictRef r; nzr::cd::NzCdDictRefArrays(&r);
        std::memset(two, 0, sizeof(two)); std::memset(three, 0, sizeof(three)); std::memset(mid_hash, 0, sizeof(mid_hash));
        for (int code = 0; code < 128; ++code) {
            const std::uint32_t v = r.ultrasmall[code];
            const std::uint32_t c0 = v & 0xffu, c1 = (v >> 8u) & 0xffu, c2 = (v >> 16u) & 0xffu;
            if ((v >> 24u) == 2u) two[a60[c1] + e60[c0]] = static_cast<std::uint8_t>(code);
            else if ((v >> 24u) == 3u) three[(c0 & 1u) + (e60[c1] + a60[c2]) * 2u] = static_cast<std::uint16_t>((c0 << 8u) | code);
        }
        for (int i = 0; i < 128; ++i) {
            const std::uint32_t key = r.mid[i], pair = r.mid_initial[i];
            const std::uint32_t bucket = e60[pair & 0xffu] + a60[(pair >> 8u) & 0xffu];
            const std::uint32_t h = (((key + 6u + (key >> 18u)) ^ (key >> 7u)) + bucket) & 0x3ffu;
            mid_hash[h * 2u] = key; mid_hash[h * 2u + 1u] = (static_cast<std::uint32_t>(i) | 0x80u) | (bucket << 8u);
        }
        std::uint32_t u4 = 0;
        while (u4 < 16384u) {
            std::uint32_t u2 = u4;
            do { ++u2; } while (u2 < 16384u && r.big_lo[u2] == r.big_lo[u4]);
            const std::uint32_t base = (u2 - u4 - 1u) * 0x100u;
            for (std::uint32_t k = u4; k < u2; ++k) codes[k] = static_cast<std::uint16_t>(base + (k - u4));
            u4 = u2;
        }
        ends = nzr::cd::NzCdDictBucketStarts();
        key1 = r.big_lo; key2 = r.big_hi;
    }
};
const DictTables& Dict() { static DictTables d; return d; }

// FUN_08055290. `src` needs one byte of slack (the space sentinel) and 16 of
// read-ahead; `dst` is written up to `cap`.
std::uint32_t TextDictEncode(const std::uint8_t* src0, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap) {
    if (n == 0u) return 0u;
    g_word_tables_built = true;   // FUN_08055000's table build happens before the size test's effects matter
    const DictTables& D = Dict();
    const WordTables& W = Words();
    const std::uint8_t* t0 = Traits0();
    const_cast<std::uint8_t*>(src0)[n] = 0x20u;
    std::uint32_t recent[20]; for (std::uint32_t i = 0; i < 20u; ++i) recent[i] = i;
    const std::uint8_t* src = src0;
    const std::uint8_t* const end1 = src0 + n + 1u;
    std::uint8_t* const limit = dst + cap - 0x1c;
    std::uint8_t* out = dst;                 // puVar8
    std::uint8_t* p9;                        // puVar9
    std::uint8_t* p10;                       // puVar10
    std::uint8_t wbuf[16];
    std::uint32_t sep;                       // local_a0: the byte that ended the letters
    bool flip;                               // bVar6
    bool capital;                            // bVar21

    for (;;) {
        if (limit <= out) return 0u;
        if (end1 <= src) { const std::uint32_t o = static_cast<std::uint32_t>(out - dst); return (o < n - (n >> 7u)) ? o : 0u; }
        std::memcpy(wbuf, src, 16);
        std::uint32_t letters = 0;
        while (letters < 15u && (t0[wbuf[letters]] & 1u)) ++letters;
        sep = wbuf[letters];
        src += letters + 1u;
        if (letters == 15u) { sep = wbuf[14]; --src; letters = 14u; }   // the original's 15-letter quirk
        flip = false; capital = false;
        if (letters != 0u) {
            p9 = out;
            std::uint32_t lw[4]; std::memcpy(lw, wbuf, 16);   // local_2c.. as the original lowers them
            if (t0[wbuf[0]] & 0x40u) {
                // a capital first letter: the "7f 20" prefix, then the lowered word
                wbuf[0] ^= 0x20u; lw[0] ^= 0x20u;
                out[0] = 0x7fu; out[1] = 0x20u; p9 = out + 2;
                capital = true;
                if (t0[wbuf[1]] & 0x40u) {
                    if (letters != 1u) {
                        p9[0] = 0x7fu; p9[1] = 0x20u; p9 = out + 4;
                        lw[0] ^= 0x20202000u; lw[1] ^= 0x20202020u;   // byte 0 was lowered already
                        if (letters > 7u) { lw[2] ^= 0x20202020u; lw[3] ^= 0x20202020u; }
                        std::memcpy(wbuf, lw, 16);
                        flip = true;
                        goto dispatch;
                    }
                    // a single capital letter
                    goto single;
                }
            }
            if (letters == 1u) {
single:
                {
                    const std::uint8_t b = wbuf[0];
                    flip = false;
                    p9[0] = b; p10 = p9 + 1; out = p10;
                    if (W.escape[b] == 0u) { p10 = p9 + 2; goto write_sep; }
                    p9[0] = 0x7fu; out = p9 + 2; p9[1] = b;
                    if (capital) { p9[-1] = static_cast<std::uint8_t>(b ^ 0x20u); flip = false; out = p9; p10 = p9 + 1; }
                    else p10 = p9 + 3;
                    goto write_sep;
                }
            }
dispatch:
            if (letters == 2u) {
                const std::uint8_t code = D.two[D.a60[wbuf[1]] + D.e60[wbuf[0]]];
                p9[0] = code; out = p9 + 1;
                if (code == 0u) { p9[0] = wbuf[0]; p9[1] = wbuf[1]; p10 = p9 + 3; out = p9 + 2; goto write_sep; }
                p10 = p9 + 2; goto write_sep;
            }
            if (letters == 3u) {
                const std::uint16_t e = D.three[(wbuf[0] & 1u) + (D.e60[wbuf[1]] + D.a60[wbuf[2]]) * 2u];
                p9[0] = static_cast<std::uint8_t>(e); out = p9 + 1;
                if (wbuf[0] == static_cast<std::uint8_t>(e >> 8u)) { p10 = p9 + 2; goto write_sep; }
                std::memcpy(p9, wbuf, 4); p10 = p9 + 4; out = p9 + 3; goto write_sep;
            }
            {
                // 4..14 letters: bucket by the last two, keys back to front
                const std::uint32_t L = letters;
                std::uint32_t k1 = 0, k2 = 0, low = 0;
                for (std::uint32_t k = 0; k < 6u && L >= 3u + k; ++k) { const std::uint32_t v = static_cast<std::uint32_t>(D.f60[wbuf[L - 3u - k]]) << (25u - 5u * k); k1 |= v; if (k >= 2u) low |= v; }
                for (std::uint32_t k = 0; k < 6u && L >= 9u + k; ++k) k2 |= static_cast<std::uint32_t>(D.f60[wbuf[L - 9u - k]]) << (25u - 5u * k);
                const std::uint32_t bucket = D.e60[wbuf[L - 2u]] + D.a60[wbuf[L - 1u]];
                if (L < 9u) {
                    const std::uint32_t h = (((k1 + 6u + (k1 >> 18u)) ^ (k1 >> 7u)) + bucket) & 0x3ffu;
                    if (D.mid_hash[h * 2u] == k1 && (D.mid_hash[h * 2u + 1u] >> 8u) == bucket && sep < 0x80u) {
                        p9[0] = static_cast<std::uint8_t>(D.mid_hash[h * 2u + 1u]); out = p9 + 1; p10 = p9 + 2; goto write_sep;
                    }
                }
                std::uint32_t hi = D.ends[bucket + 1u], lo = D.ends[bucket];
                std::uint32_t found = 0xffffffffu;
                std::uint32_t mid;
                bool hit = false;
                while ((mid = (hi + lo) >> 1u), mid < hi) {
                    bool nf = false;
                    while (k1 < D.key1[mid]) { const std::uint32_t m2 = (mid + lo) >> 1u; const bool stop = mid <= m2; hi = mid; mid = m2; if (stop) { nf = true; break; } }
                    if (nf) break;
                    if (k1 <= D.key1[mid]) {
                        if ((low & 0x1fu) == 0u) { found = mid; hit = true; break; }
                        std::uint32_t s = mid - (D.codes[mid] & 0xffu);
                        std::uint32_t e = s + 1u + (D.codes[mid] >> 8u);
                        // the second key inside the run of equal first keys
                        for (;;) {
                            std::uint32_t m = (e + s) >> 1u;
                            if (e <= m) break;
                            bool nf2 = false;
                            while (k2 < D.key2[m]) { const std::uint32_t m2 = (m + s) >> 1u; const bool stop = m <= m2; e = m; m = m2; if (stop) { nf2 = true; break; } }
                            if (nf2) break;
                            if (k2 <= D.key2[m]) { found = m; hit = true; break; }
                            s = m + 1u;
                        }
                        break;
                    }
                    lo = mid + 1u;
                }
                const std::uint32_t code = ~found;   // 0 when not found
                if (hit) { p9[0] = static_cast<std::uint8_t>(code >> 7u); p9[1] = static_cast<std::uint8_t>(code | 0x80u); }
                if (!hit || code == 0u) {
                    std::memcpy(p9, wbuf, 16);      // the raw word (LAB_08055590)
                    p10 = p9 + L + 1u; out = p9 + L;
                } else { p10 = p9 + 3; out = p9 + 2; }
                goto write_sep;
            }
        }
        // ---- a non-letter first byte
        {
            const std::uint8_t b = static_cast<std::uint8_t>(sep);   // local_b0
            if (W.escape[b] == 0u) {
                if ((t0[b] & 4u) == 0u || b == 0x30u) { p10 = out + 1; flip = false; goto write_sep; }
                // digits: a dotted quad becomes 7f 61 + 4 bytes, or 7f 62+i from the recent list
                std::uint32_t acc = 0, v = b - 0x30u;
                const std::uint8_t* q = src;   // param_1 (after the first digit)
                std::uint8_t c = *q; std::uint8_t cl = t0[c];
                std::uint32_t cur_c = c;       // uVar11: the byte that ended the digits (sep keeps the first digit)
                const std::uint8_t* la4;
                for (;;) {
                    for (;;) {
                        la4 = q; ++q; cur_c = c;
                        if ((cl & 4u) == 0u) break;
                        v = (c - 0x30u) + v * 10u;
                        if (0xffu < v) { if (acc < 0x1000000u) { p10 = out + 1; flip = false; goto write_sep; } goto number; }
                        c = *q; cl = t0[c];
                    }
                    acc = v + acc * 0x100u;
                    if (0xffffffu < acc) goto number;
                    if (cur_c != 0x2eu) { out[0] = b; flip = false; ++out; goto cont_copy; }
                    c = *q; cl = t0[c];
                    if ((cl & 4u) == 0u) { p10 = out + 1; flip = false; goto write_sep; }
                    v = 0;
                    if (c == 0x30u && (t0[la4[2]] & 4u)) break;
                }
                p10 = out + 1; flip = false; goto write_sep;
number:
                {
                    src = q; sep = cur_c;
                    int i = 0;
                    for (; i < 20; ++i) if (acc == recent[i]) break;
                    if (i < 20) {
                        out[1] = static_cast<std::uint8_t>(i + 0x62);
                        out[0] = 0x7fu;
                        for (int k = i; k > 0; --k) recent[k] = recent[k - 1];
                        recent[0] = acc;
                        p10 = out + 3; flip = false; out = out + 2; goto write_sep;
                    }
                    for (int k = 19; k > 0; --k) recent[k] = recent[k - 1];
                    recent[0] = acc;
                    const std::uint32_t d4 = acc - 0x1000000u;
                    out[0] = 0x7fu; out[1] = 0x61u;
                    out[2] = static_cast<std::uint8_t>(d4 >> 24u); out[3] = static_cast<std::uint8_t>(d4 >> 16u);
                    out[4] = static_cast<std::uint8_t>(d4 >> 8u); out[5] = static_cast<std::uint8_t>(d4);
                    p10 = out + 7; flip = false; out = out + 6; goto write_sep;
                }
            }
            out[0] = 0x7fu; out[1] = b; out += 2; flip = false;
            goto cont_copy;
        }
write_sep:
        *out = static_cast<std::uint8_t>(sep);
        out = p10;
cont_copy:
        if (W.cont[sep & 0xffu] != 0u) {
            for (;;) {
                std::uint8_t b = *src;
                std::uint8_t* p = out;
                ++src;
                if (limit <= p) { out = p; goto next_word; }
                *p = b; out = p + 1;
                if (W.cont[b] == 0u) goto next_word;
                if (flip) *p = static_cast<std::uint8_t>(((t0[b] & 1u) << 5u) ^ b);
            }
        }
next_word:
        continue;
    }
}
std::uint32_t TextChessEncode(const std::uint8_t*, std::uint32_t, std::uint8_t*, std::uint32_t) { return 0u; }

// ------------------------------------------------------------ FUN_08059060
std::uint32_t TextPipeline(std::uint32_t bits, std::uint8_t*& buf, std::uint32_t n, std::uint8_t*& tmp,
                           std::uint32_t cap, std::uint8_t* applied) {
    std::uint8_t done = 0;
    auto run = [&](std::uint32_t r, std::uint8_t bit) { if (r != 0u) { std::swap(buf, tmp); n = r; done |= bit; } };
    if (bits & 1u) run(TextCrlfEncode(buf, n, tmp, std::min(cap, n + 0x10u)), 1u);
    if (bits & 0x40u) run(TextChessEncode(buf, n, tmp, std::min(cap, n + 0x400u)), 0x40u);
    if (bits & 0x20u) run(TextLineRleEncode(10u, buf, n, tmp, n), 0x20u);
    if (bits & 8u) run(TextDictEncode(buf, n, tmp, n), 8u);
    if (bits & 0x80u) {
        if (done & 8u) run(TextParam14Encode(buf, n, tmp, n), 0x80u);
        else if (done == 0u) return 0u;
    } else if (done == 0u) return 0u;
    if (!(n < cap)) return 0u;
    *applied = done;
    return n;
}

}  // namespace nzr::lzhd_enc
