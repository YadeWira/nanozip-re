// nz_lzpf_image_enc.cpp -- the image side of the original's lzpf compressor:
// the format detector FUN_080899d0 (BMP FUN_08089770, PGM/PPM FUN_080898f0,
// TGA FUN_08089860, TIFF FUN_08089710 -> FUN_08089290) and the prefilter-image
// block encoder FUN_08089a80 for the lzpf configuration (flags 0: no LMS, no
// cascade, mode 2). Decompiles: ~/.cache/nzre_tools/encode/decomp/
// lzpf_image_encoder.c and image_headers.c.
#include "nz_lzpf_encoder.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr::lzpf_enc {

namespace {

inline std::uint32_t LoadU16(const std::uint8_t* p) { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
inline std::uint32_t LoadU32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
inline std::uint32_t BE16(const std::uint8_t* p) { return (std::uint32_t(p[0]) << 8) | p[1]; }
inline std::uint32_t BE32(const std::uint8_t* p) { return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3]; }

// FUN_08089770: a BMP (BITMAPINFOHEADER, 24-bit or grayscale-palette 8-bit).
bool DetectBmp(ImageProbe& pr, const std::uint8_t* b, std::uint32_t n) {
    if (n <= 0x35u) return false;
    if (LoadU16(b) != 0x4d42u) return false;             // "BM"
    if (LoadU32(b + 10) >= 0x480u) return false;         // bfOffBits
    if (LoadU32(b + 14) != 0x28u) return false;          // biSize == 40
    if (LoadU16(b + 26) != 1u) return false;             // biPlanes
    if (LoadU32(b + 30) != 0u) return false;             // biCompression
    if (LoadU32(b + 18) < 0x80u || LoadU32(b + 22) < 0x80u) return false;   // width/height >= 128
    const std::uint32_t bits = LoadU16(b + 28);
    if (bits == 0x18u) {
        pr.nch = 3; pr.bps = 1;
    } else if (bits == 8u) {
        if (b + 0x36u + 0x400u > b + n) return false;
        if (LoadU32(b + 0x36) != 0u) return false;       // palette[0] must be 0
        std::uint32_t exp = 0x10101u;
        const std::uint8_t* q = b + 0x3a;                // palette[1]
        for (;; q += 4, exp += 0x10101u) {
            if (LoadU32(q) != exp) return false;         // grayscale ramp
            if (q == b + 0x432) { pr.nch = 1; pr.bps = 1; break; }   // palette[254]
        }
    } else {
        return false;
    }
    pr.width = LoadU32(b + 18);
    pr.height = LoadU32(b + 22);
    pr.prefix = LoadU32(b + 10);
    return true;
}

// FUN_08089860: a TGA (uncompressed truecolor, no id, no colour map).
bool DetectTga(ImageProbe& pr, const std::uint8_t* b, std::uint32_t n) {
    if (n < 0x12u) return false;
    if (b[0] != 0 || b[1] != 0 || b[2] != 2) return false;
    if ((b[0x11] & 0xdfu) != 0u) return false;           // descriptor: only the top-down bit allowed
    const std::uint32_t w = LoadU16(b + 0xc), h = LoadU16(b + 0xe);
    if (w < 0x80u || w >= 0x4000u) return false;
    if (h < 0x80u || h >= 0x4000u) return false;
    pr.width = w; pr.height = h; pr.prefix = 0x12; pr.nch = 3; pr.bps = 1;
    return true;
}

// FUN_08089170: read one byte, skipping '#'-to-newline comments.
struct PgmCursor { const std::uint8_t* p; std::uint32_t n; };
std::uint8_t PgmByte(PgmCursor& c) {
    if (c.n == 0u) return 0;
    for (;;) {
        const std::uint8_t v = *c.p++; --c.n;
        if (c.n == 0u) return v;
        if (v != '#') return v;
        // a comment: skip to end of line
        for (;;) {
            const std::uint8_t w = *c.p; if (c.n == 0u) return 0;
            if (w < 0x20u) break;   // control char ends the comment
            ++c.p; --c.n; if (c.n == 0u) return 0;
        }
        // the newline byte; loop reads the next token byte
        const std::uint8_t w = *c.p++; --c.n; (void)w;
        if (c.n == 0u) return w;
        // FUN_08089170 returns after the newline; but we continue reading the token
        return *(c.p - 1) >= 0x20u ? *(c.p - 1) : PgmByte(c);
    }
}

// FUN_08089210: skip non-digits, then read a decimal number.
std::uint32_t PgmNumber(PgmCursor& c) {
    if (c.n == 0u) return 0;
    std::uint8_t d;
    do { d = PgmByte(c); if (d == 0u) return 0; } while (((d >= '0' && d <= '9')) == false);
    std::uint32_t v = 0;
    for (;;) {
        std::uint8_t e = PgmByte(c);
        if (c.n == 0u) return 0;
        v = static_cast<std::uint32_t>(d) - '0' + v * 10u;
        d = e;
        if (!(e >= '0' && e <= '9')) break;
    }
    return v;
}

// FUN_080898f0: a PGM (P5) or PPM (P6).
bool DetectPgm(ImageProbe& pr, const std::uint8_t* b, std::uint32_t n) {
    if (n < 0x100u) return false;
    if (b[0] != 'P') return false;
    if (b[2] >= 0x21u) return false;                     // whitespace after the magic
    int kind;
    if (b[1] == '6') kind = 6;
    else if (b[1] == '5') kind = 5;
    else return false;
    PgmCursor c{b + 3, n - 3u};
    const std::uint8_t* start = b;
    const std::uint32_t w = PgmNumber(c);
    const std::uint32_t h = PgmNumber(c);
    if (h < 0x40u || w < 0x80u) return false;
    const std::uint32_t maxval = PgmNumber(c);
    if (maxval != 0xffffu && maxval != 0xffu) return false;
    pr.bps = (maxval >> 15) + 1u;
    pr.nch = (kind != 5) ? 3u : 1u;
    pr.prefix = static_cast<std::uint32_t>(c.p - start);
    pr.width = w; pr.height = h;
    return true;
}

// FUN_08089290 (+ the FUN_08089710 field remap): a TIFF, little- or big-endian,
// uncompressed, 8 bits per sample, 1 or 3 samples. Width 128..0x3fff, height >= 128.
// The detector's fields become width/height/nch (SamplesPerPixel, default 1);
// prefix is always 8 and bps stays 1 (BitsPerSample is only validated == 8).
bool DetectTiff(ImageProbe& pr, const std::uint8_t* b, std::uint32_t n) {
    if (n <= 8u) return false;
    bool be;
    if (b[0] == 'M' && b[1] == 'M') be = true;
    else if (b[0] == 'I' && b[1] == 'I') be = false;
    else return false;
    const std::uint32_t magic = be ? BE16(b + 2) : LoadU16(b + 2);
    if (magic != 0x2au) return false;
    auto rd16 = [&](const std::uint8_t* q) { return be ? BE16(q) : LoadU16(q); };
    auto rd32 = [&](const std::uint8_t* q) { return be ? BE32(q) : LoadU32(q); };
    std::uint32_t comp = 0, bits = 0, samples = 1, width = 0, height = 0;
    const std::uint8_t* const end = b + n;
    const std::uint32_t ifd_off = rd32(b + 4);
    const std::uint8_t* ifd = b + ifd_off;
    if (ifd + 2 >= end || ifd < b) return false;
    std::uint32_t count = rd16(ifd);
    const std::uint8_t* e = ifd + 2;
    for (; count != 0u; --count, e += 12) {
        if (e + 3 > end) break;
        const std::uint32_t tag = rd16(e);
        const std::uint32_t typ = rd16(e + 2);
        auto val = [&]() -> std::uint32_t { return (typ == 3u) ? rd16(e + 8) : rd32(e + 8); };
        switch (tag) {
        case 0x100: width = val(); break;
        case 0x101: height = val(); break;
        case 0x102: {
            const std::uint32_t vcount = rd32(e + 4);
            if (typ == 3u && vcount == 1u) { bits = rd16(e + 8); }
            else { const std::uint8_t* q = b + rd32(e + 8); if (q > b && q + 1 < end) bits = rd16(q); }
            break;
        }
        case 0x103: comp = val(); break;
        case 0x115: samples = val(); break;
        default: break;
        }
    }
    if (comp != 1u) return false;
    if (bits != 8u) return false;
    if (samples != 3u && samples != 1u) return false;
    if (width < 0x80u || width >= 0x4000u) return false;
    if (height < 0x80u) return false;
    pr.width = width; pr.height = height; pr.nch = samples; pr.bps = 1; pr.prefix = 8;
    return true;
}

}  // namespace

// FUN_080899d0: the four detectors in order; a nonzero width means "image".
bool ImageDetect(ImageProbe& pr, const std::uint8_t* block, std::uint32_t len) {
    pr = ImageProbe{};
    DetectBmp(pr, block, len);
    if (pr.width == 0u) DetectPgm(pr, block, len);
    if (pr.width == 0u) DetectTga(pr, block, len);
    if (pr.width == 0u) DetectTiff(pr, block, len);
    return pr.width != 0u;
}

}  // namespace nzr::lzpf_enc

namespace nzr::lzpf_enc {

// FUN_08089a80, flags 0. The decoder's DecodeChunk (NzImageModel::Impl) run
// forwards: residual = sample - ((left + 1 + above) >> 1) (mode 2), one
// residual stream for all planes, one Huffman stream per plane, the side bits
// last; declined when that is not smaller than the aligned sample bytes.
std::size_t ImageEncodeBlock(ImageEncModel& m, const ImageProbe& pr, const std::uint8_t* block,
                             std::uint32_t len, std::vector<std::uint8_t>& out, std::uintptr_t align) {
    if (len < 0x200u) return 0;   // FUN_0808aac0 gate; FUN_08089a80's verbatim path (< 0x180) is unreachable
    std::uint32_t width, nch, bps, endian, prefix;
    if (pr.width != 0u) {
        width = pr.width; nch = pr.nch; bps = pr.bps; endian = pr.w5;
        prefix = pr.prefix & 0xffffu;
        m.rows_done = 0;
        m.height = pr.height & 0xffffu;
    } else {
        width = m.width; nch = m.nch; bps = m.bps; endian = m.endian;
        if (width < 0x81u || nch * width * bps + 0x80u <= len) {
            if (m.height <= m.rows_done) return 0;
        } else if (m.rows_done != m.height) {
            if (m.height <= m.rows_done) return 0;
        } else if (width <= m.col) {
            return 0;
        }
        prefix = (m.align != 0u) ? ((static_cast<std::uint32_t>(m.grp) - m.align) & 0xffffu) : 0u;
    }
    if (width < 2u) return 0;
    const std::uint32_t grp = nch * bps;
    std::uint32_t* const tbl = m.stack_tbl.data();

    // ---- the gate: the first min(len, 0x400) bytes (flags & 4 would widen it to 64 KB) ----
    const std::uint32_t win = len < 0x400u ? len : 0x400u;
    if (win > 0x1ffu) {
        const std::uint32_t nb = win - 8u;
        const std::uint8_t* const p = block;
        const std::uint8_t* const end = p + nb;
        std::uint32_t vsum = 0, matched = 0;
        std::uint32_t i = 0;
        while (i < nb) {
            const std::int32_t d = static_cast<std::int32_t>(p[i]) - static_cast<std::int32_t>(p[i + grp]);
            vsum += static_cast<std::uint32_t>(d < 0 ? -d : d);
            const std::uint32_t w = LoadU32(p + i);
            const std::uint32_t h = ((w >> 19u) ^ w) & 0xffffu;
            const std::uint32_t prev = tbl[h];
            tbl[h] = i;
            std::uint32_t next = i + 1u;
            if (prev < i) {
                const std::uint8_t* q = p + prev;
                const std::uint8_t* s = p + i;
                const std::uint8_t* stop;
                for (;;) {
                    if (end <= s) { stop = s; break; }
                    const std::uint32_t x = LoadU32(s) ^ LoadU32(q);
                    q += 4;
                    if (x != 0u) {
                        const bool lo0 = (x & 0xffffu) == 0u;
                        stop = s + (lo0 ? 2u : 0u) + ((((x >> (lo0 ? 16u : 0u)) & 0xffu) == 0u) ? 1u : 0u);
                        break;
                    }
                    s += 4;
                }
                const std::uint8_t* lim = (end < stop) ? end : stop;
                const std::uint32_t mlen = static_cast<std::uint32_t>(lim - (p + i));
                if (mlen != 0u) { matched += mlen; next = i + mlen; }
            }
            i = next;
        }
        if (nb * 0x32u < vsum && (grp == 3u || grp == 1u)) return 0;
        if (nb * 5u <= matched * 8u && grp + 4u <= nb) {
            const std::uint32_t n = nb - 4u - grp;
            std::uint32_t hist_a[256] = {}, hist_b[256] = {};
            std::vector<std::uint32_t> cache(4096u, 0u);
            const std::uint8_t* const s = block + grp;
            for (std::uint32_t k = 0; k < n; ++k) {
                const std::uint8_t b = s[k];
                const std::uint32_t ctx = LoadU16(s + k - 2) & 0xfffu;
                const std::uint32_t c = cache[ctx];
                std::uint32_t sym = b;
                if (b == static_cast<std::uint8_t>(c >> 8u) || b == static_cast<std::uint8_t>(c) ||
                    b == static_cast<std::uint8_t>(c >> 24u) || b == static_cast<std::uint8_t>(c >> 16u)) sym = 0u;
                cache[ctx] = (c << 8u) | b;
                ++hist_a[sym];
                ++hist_b[static_cast<std::uint8_t>(b - block[k])];   // s[k - grp] with a signed offset
            }
            std::uint8_t lens[256], codes[256];
            std::uint32_t cost_a = 0, cost_b = 0;
            BuildCodeLengths(hist_a, 0x100u, lens, codes);
            for (int k = 0; k < 256; ++k) cost_a += lens[k] * hist_a[k];
            BuildCodeLengths(hist_b, 0x100u, lens, codes);
            for (int k = 0; k < 256; ++k) cost_b += lens[k] * hist_b[k];
            if (cost_a < cost_b) return 0;
            if (n > 0x3ffu) {   // never with the 1024-byte window (n <= 1011); kept for the record
                std::uint8_t bitmap[2048] = {};
                std::uint32_t h1 = 0, h2 = 0, nov1 = 0, nov2 = 0;
                for (std::uint32_t k = 0; k < n - grp; ++k) {
                    const std::uint8_t b = s[k];
                    const std::uint32_t x1 = h1 ^ b; h1 = x1 << 8u;
                    const std::uint32_t i1 = (x1 & 0x1fffu) >> 3u, b1 = b & 7u;
                    const std::uint32_t x2 = h2 ^ static_cast<std::uint8_t>(b - block[k]); h2 = x2 << 8u;
                    const std::uint32_t i2 = ((x2 & 0x1fffu) + 0x2000u) >> 3u, b2 = x2 & 7u;
                    nov1 += ((bitmap[i1] >> b1) + 1u) & 1u; bitmap[i1] |= static_cast<std::uint8_t>(1u << b1);
                    nov2 += ((bitmap[i2] >> b2) + 1u) & 1u; bitmap[i2] |= static_cast<std::uint8_t>(1u << b2);
                }
                if (nov1 <= nov2) return 0;
            }
        }
    }
    if (prefix >= len) return 0;   // (the original would wrap; unreachable with 32 KB blocks)

    // ---- commit and header ----
    const std::size_t start = out.size();
    const bool width_known = (m.width == width);
    const std::int32_t fmt = (static_cast<std::int32_t>(endian) + (static_cast<std::int32_t>(bps) - 3 + static_cast<std::int32_t>(nch) * 2) * 2) * 2;
    const std::int32_t wk = width_known ? 1 : 0;
    if (prefix < 6u) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::int32_t>(prefix) * 0x20 + wk + fmt));
    } else if (prefix < 0xfau) {
        out.push_back(static_cast<std::uint8_t>(wk - 0x40 + fmt));
        out.push_back(static_cast<std::uint8_t>(prefix - 6u));
    } else {
        out.push_back(static_cast<std::uint8_t>(wk - 0x20 + fmt));
        out.push_back(static_cast<std::uint8_t>(prefix - 0xfau));
        out.push_back(static_cast<std::uint8_t>((prefix - 0xfau) >> 8u));
    }
    if (!width_known) { out.push_back(static_cast<std::uint8_t>(width - 1u)); out.push_back(static_cast<std::uint8_t>((width - 1u) >> 8u)); }
    out.insert(out.end(), block, block + prefix);
    const std::uint8_t* const src = block + prefix;
    const std::uint32_t body = len - prefix;
    const std::uint32_t rem = body % grp;
    const std::uint32_t aligned = body - rem;
    out.insert(out.end(), src + aligned, src + aligned + rem);
    m.align = static_cast<std::uint8_t>(rem);
    m.width = width; m.grp = static_cast<std::uint8_t>(grp); m.nch = static_cast<std::uint8_t>(nch);
    m.bps = static_cast<std::uint8_t>(bps); m.endian = static_cast<std::uint8_t>(endian);

    std::vector<std::uint8_t> side(0x8000u + 8u);
    BitWriter w; w.base = side.data(); w.end = side.data() + 0x8000u; w.cur = side.data(); w.bitbuf = 0; w.nbits = 0;
    w.Put(2u, 3u);   // mode 2
    w.Put(0u, 1u);   // no plane shifts
    w.Put(0u, 1u);   // no cascade shifts
    for (auto& pl : m.plane) pl.shift = 0x0fu;   // the object's plane_shift_ bytes (0x52936...), never changed

    // ---- the pixel loop ----
    const std::uint32_t per_ch = (aligned / nch) / bps;
    std::int32_t* const planes = reinterpret_cast<std::int32_t*>(tbl);
    const std::uint32_t stride = width * nch;
    std::int16_t* const ring = m.ring1.data();
    const std::uint8_t* sp = src;
    std::uint32_t left[4] = {0, 0, 0, 0};
    std::uint32_t done = 0, pix = 0;
    while (done < per_ch) {
        std::uint32_t run = per_ch - done; if (run > width) run = width;
        if (m.col != 0u) {
            const std::uint32_t lir = width - m.col; m.col = 0;
            if (run > lir) run = lir;
        } else {
            ++m.rows_done;
            m.col = (width == run) ? 0u : run;
            if (m.flags & 2u) for (auto& pl : m.plane) {   // FUN_080bdb20: the planes' windows restart per row
                pl.ring_off = 0x1000; std::memset(pl.area + 0x1000, 0, pl.order * 2u); std::memset(pl.area + 0x1400, 0, pl.order * 2u); pl.pred = 0;
            }
        }
        {
            const std::uint32_t ai = (m.r1 - stride) & 0x7fffu;
            for (std::uint32_t c = 0; c < 4u; ++c) left[c] = static_cast<std::uint16_t>(ring[ai + c]);
        }
        done += run;
        for (; run != 0u; --run, ++pix) {
            const std::uint32_t ai = (m.r1 - stride) & 0x7fffu;
            std::int32_t d[4] = {0, 0, 0, 0};
            for (std::uint32_t c = 0; c < nch; ++c) {
                const std::uint32_t above = static_cast<std::uint16_t>(ring[ai + c]);
                const std::uint32_t pred = static_cast<std::uint32_t>(static_cast<std::int32_t>(left[c] + 1u + above) >> 1);
                std::uint32_t v;
                if (bps == 1u) { v = *sp++; }
                else { v = endian ? (static_cast<std::uint32_t>(sp[0]) | (static_cast<std::uint32_t>(sp[1]) << 8u))
                                  : ((static_cast<std::uint32_t>(sp[0]) << 8u) | sp[1]); sp += 2; }
                d[c] = static_cast<std::int32_t>(v - pred);
                left[c] = v;
            }
            if (m.flags & 2u) {
                // the LMS planes: each channel's plane first, then the shared fifth
                // plane over every channel (FUN_080bddc0 on value and residual)
                std::int32_t r1v[4] = {0, 0, 0, 0};
                for (std::uint32_t c = 0; c < nch; ++c) { r1v[c] = d[c] - m.plane[c].pred; std::int32_t rr = r1v[c]; m.plane[c].Run(&rr, 1u); }
                for (std::uint32_t c = 0; c < nch; ++c) { std::int32_t r2 = r1v[c] - m.plane[4].pred; std::int32_t rr = r2; m.plane[4].Run(&rr, 1u); planes[c * per_ch + pix] = r2; }
            } else {
                for (std::uint32_t c = 0; c < nch; ++c) planes[c * per_ch + pix] = d[c];
            }
            for (std::uint32_t c = 0; c < nch; ++c) ring[m.r1 + c] = static_cast<std::int16_t>(left[c]);
            m.r1 = (m.r1 + nch) & 0x7fffu;
        }
    }
    // FUN_080b64d0: a block that ended inside a pixel accounts it as one zero sample group
    if (m.align != 0u) {
        for (std::uint32_t c = 0; c < nch; ++c) ring[m.r1 + c] = 0;
        m.r1 = (m.r1 + nch) & 0x7fffu;
        const std::uint32_t c = m.col + 1u;
        m.col = (width == c) ? 0u : c;
    }

    // ---- streams ----
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(per_ch) * nch + 8u);
    ResidualEncode(planes, per_ch * nch, bytes.data(), w);
    w.Flush();
    if (w.end <= w.cur) { out.resize(start); return 0; }
    const std::size_t side_bytes = static_cast<std::size_t>(w.cur - w.base) + ((w.nbits + 7u) >> 3u);
    std::vector<std::uint8_t> ar(static_cast<std::size_t>(aligned) + 64u);
    std::size_t a_total = 0;
    for (std::uint32_t c = 0; c < nch; ++c) {
        const std::uintptr_t al = (align + (out.size() - start) + a_total) & 3u;
        const std::size_t got = EncodeArithAt(bytes.data() + static_cast<std::size_t>(c) * per_ch, per_ch, ar.data() + a_total, per_ch, al);
        if (got == 0u) { out.resize(start); return 0; }
        a_total += got;
    }
    const std::size_t produced = (out.size() - start) + a_total + side_bytes;
    if (std::getenv("NZ_TRACE_LZPFENC"))
        std::fprintf(stderr, "[imgblk] len=%u prefix=%u w=%u nch=%u bps=%u per=%u hdr=%02x rows=%u col=%u align=%u arith=%zu side=%zu produced=%zu aligned=%u\n",
                     len, prefix, width, nch, bps, per_ch, out[start], m.rows_done, m.col, m.align, a_total, side_bytes, produced, aligned);
    if (produced >= aligned) { out.resize(start); return 0; }
    out.insert(out.end(), ar.begin(), ar.begin() + static_cast<std::ptrdiff_t>(a_total));
    out.insert(out.end(), side.begin(), side.begin() + static_cast<std::ptrdiff_t>(side_bytes));
    return produced;
}

}  // namespace nzr::lzpf_enc
