// param1 of the -co family's compressor (reference FUN_0806e7a0 and helpers).
//
// The decoder side lives in src/nz_postfilter.cpp (NzAddBytesFilter); this file
// is its inverse. Everything here is a transcription of the reference, quirks
// included -- the frequency table the LZP estimator shares with its own "match"
// counter (bin 128) and the truncating x87 entropy among them.
#include "nz_optimum_param1.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr {
namespace opt_enc {
namespace {

inline std::uint32_t Bsr(std::uint32_t v) {
    return v ? (31u - static_cast<std::uint32_t>(__builtin_clz(v))) : 0u;
}
inline std::uint32_t Mask(std::uint32_t nb) {
    return nb >= 32u ? 0xffffffffu : ((1u << nb) - 1u);
}
inline std::uint32_t Rd32(const std::uint8_t* p) {
    std::uint32_t v; std::memcpy(&v, p, 4); return v;
}
inline std::uint16_t Rd16(const std::uint8_t* p) {
    std::uint16_t v; std::memcpy(&v, p, 2); return v;
}

// ---------------------------------------------------------------------------
// The side stream's bit writer (FUN_080b1f20 / FUN_080b2030 / FUN_080c0750 /
// FUN_080c0970 / FUN_080c09f0 / FUN_080bc920 / FUN_080bca40), the exact inverse
// of AddBytesFilter's BitReader: 32-bit big-endian words, MSB first, and a
// trailing partial word flushed byte by byte.
// ---------------------------------------------------------------------------
struct BitWriter {
    std::uint8_t* base = nullptr;
    std::uint8_t* end = nullptr;
    std::uint8_t* cur = nullptr;
    std::uint32_t bitbuf = 0, bitcount = 0;
    std::uint32_t offset_ = 0;                 // obj+0x18, AddBytesFilter::offset_

    void Reset(std::uint8_t* b, std::uint8_t* e) {
        base = b; end = e; cur = b; bitbuf = 0; bitcount = 0; offset_ = 0;
    }
    std::size_t Size() const { return static_cast<std::size_t>(cur - base); }

    void PutBits(std::uint32_t v, std::uint32_t nb) {          // FUN_080b1f20
        const std::uint32_t total = bitcount + nb;
        if (total < 0x21u) {
            bitcount = total;
            bitbuf = (bitbuf << (nb & 31u)) | v;
            return;
        }
        if (cur == end) return;
        const std::uint32_t k = 32u - bitcount;
        const std::uint32_t rem = nb - k;
        bitcount = rem;
        const std::uint32_t word = (bitbuf << (k & 31u)) | (v >> (rem & 31u));
        std::uint8_t* nc = cur + 4;
        bitbuf = v;
        if (end < nc) {
            cur = end;
        } else {
            const std::uint32_t be = __builtin_bswap32(word);
            std::memcpy(cur, &be, 4);
            cur = nc;
        }
    }
    void Flush() {                                              // FUN_080b2030
        while (bitcount != 0u) {
            std::uint8_t* p = cur;
            if (bitcount < 8u) {
                const std::uint32_t n = bitcount;
                bitcount = 0;
                if (end <= p) continue;
                *p = static_cast<std::uint8_t>(bitbuf << ((8u - n) & 31u));
                cur = p + 1;
            } else {
                bitcount -= 8u;
                if (end <= p) continue;
                *p = static_cast<std::uint8_t>(bitbuf >> (bitcount & 31u));
                cur = p + 1;
            }
        }
    }
    // FUN_080c0750: (k-1) ones, a zero, then max(k-1,1) low bits of m.
    void PutX(std::uint32_t m, std::uint32_t k) {
        PutBits(((1u << (k & 31u)) - 1u) ^ 1u, k);
        const std::uint32_t k2 = (k > 1u) ? (k - 1u) : k;
        PutBits(m & Mask(k2), k2);
    }
    void PutXAuto(std::uint32_t m) { PutX(m, Bsr(m) + 1u); }    // caller's bsr(m)+1
    // FUN_080c0970 / FUN_080c09f0, the inverse of BitReader::GetY.
    void PutYn(std::uint32_t v, std::uint32_t nbits) {
        PutXAuto(nbits - 1u);
        const std::uint32_t nb2 = (nbits > 1u) ? (nbits - 1u) : nbits;
        PutBits(v & Mask(nb2), nb2);
    }
    void PutY(std::uint32_t v) { PutYn(v, Bsr(v) + 1u); }
    // FUN_080bc920, the inverse of BitReader::GetZ.
    void PutZ(std::uint32_t v, std::uint32_t b) {
        if (b != 0u) { PutBits(v & Mask(b), b); v >>= (b & 31u); }
        PutY(v);
    }
    // FUN_080bca40: one AddBytesFilter triple.
    void Emit(std::uint32_t copy_offset, std::uint32_t start, std::uint32_t num_delta) {
        PutY(copy_offset);
        if (copy_offset != 0u) {
            PutZ(num_delta, 8u);
            PutZ(start - offset_, 8u);
            offset_ = num_delta + start;
        }
    }
};

// ---------------------------------------------------------------------------
// FUN_0805d080: LSD radix sort over 32-bit keys, starting at bit `shift`,
// ping-ponging between `arr` and `scratch`; returns the buffer holding the
// result.
// ---------------------------------------------------------------------------
std::uint32_t* RadixSort(std::uint32_t* arr, std::uint32_t count,
                         std::uint32_t* scratch, std::uint32_t maxval,
                         std::uint32_t shift) {
    std::uint32_t hist[256];
    std::uint8_t* bucket[256];
    maxval >>= (shift & 31u);
    std::uint32_t* src = arr;
    std::uint32_t* res = arr;
    if (maxval == 0u) return arr;
    for (;;) {
        const std::uint32_t limit = (maxval < 0xffu) ? maxval : 0xffu;
        for (std::uint32_t i = 0; i <= limit; ++i) hist[i] = 0;
        for (std::uint32_t i = 0; i < count; ++i)
            ++hist[(src[i] >> (shift & 31u)) & 0xffu];
        res = src;
        if (hist[(src[0] >> (shift & 31u)) & 0xffu] != count) {
            std::uint32_t* w = scratch;
            for (std::uint32_t i = 0; w < scratch + count; ++i) {
                bucket[i] = reinterpret_cast<std::uint8_t*>(w);
                w += hist[i];
            }
            res = scratch;
            scratch = src;
            for (std::uint32_t i = 0; i < count; ++i) {
                const std::uint32_t b = (src[i] >> (shift & 31u)) & 0xffu;
                std::uint32_t* d = reinterpret_cast<std::uint32_t*>(bucket[b]);
                *d = src[i];
                bucket[b] = reinterpret_cast<std::uint8_t*>(d + 1);
            }
        }
        maxval >>= 8u;
        if (maxval == 0u) break;
        shift += 8u;
        src = res;
    }
    return res;
}

// ---------------------------------------------------------------------------
// FUN_0805cbe0: Huffman code lengths (Moffat/Katajainen in place, with a
// length-limiting rescale loop). Fills lens[sym] and returns the number of
// symbols with a non-zero frequency.
// ---------------------------------------------------------------------------
std::uint32_t HuffLengths(std::uint8_t* lens, const int* freq, std::uint32_t limit) {
    std::uint8_t syms[268];
    std::uint32_t A[257];
    std::uint32_t sc[256];

    std::uint32_t m = 0;
    for (int i = 0; i < 0x100; ++i)
        if (freq[i] != 0) syms[m++] = static_cast<std::uint8_t>(i);

    if (m != 0u) {
        std::uint32_t or_freq = 0, or_key = 0;
        for (std::uint32_t i = 0; i < m; ++i) {
            const std::uint32_t f = static_cast<std::uint32_t>(freq[syms[i]]);
            or_freq |= f;
            const std::uint32_t key = f * 0x100u + syms[i];
            A[i + 1] = key;
            or_key |= key;
        }
        std::uint32_t sh = 8;
        for (; (or_freq & 1u) == 0u && or_freq != 0u; or_freq >>= 1) ++sh;
        const std::uint32_t* sorted = RadixSort(A + 1, m, sc, or_key, sh);
        for (std::uint32_t i = 0; i < m; ++i)
            syms[i] = static_cast<std::uint8_t>(sorted[i]);
    }

    std::memset(lens, 0, 256);

    std::uint32_t h, leaf, s, r, t;
    if (2u < m) {
        for (std::uint32_t i = 0; i < m; ++i) {
            const std::uint32_t f = static_cast<std::uint32_t>(freq[syms[i]]);
            A[i + 1] = f;
            sc[i] = f;
        }
        A[0] = m - 1u;
    L_restart:
        h = 1; leaf = 2; s = A[2] + A[1]; r = 0;
        A[1] = s;
        for (;;) {
            if (leaf < m && (t = A[leaf + 1]) <= s) {
                ++leaf;
                A[h + 1] = t;
                if (m <= leaf) goto L_cd6a;
            L_cd9a:
                if (r < h) {
                    if (A[r + 1] < A[leaf + 1]) {
                        A[h + 1] = t + A[r + 1];
                        A[r + 1] = h;
                        ++r;
                    } else {
                        A[h + 1] = t + A[leaf + 1];
                        ++leaf;
                    }
                } else {
                    A[h + 1] = t + A[leaf + 1];
                    ++leaf;
                }
            } else {
                A[h + 1] = s;
                A[r + 1] = h;
                ++r;
                t = A[h + 1];
                if (leaf < m) goto L_cd9a;
            L_cd6a:
                A[h + 1] = t + A[r + 1];
                A[r + 1] = h;
                ++r;
            }
            if (h == m - 2u) break;
            s = A[r + 1];
            ++h;
        }
        // depths
        A[m - 1u] = 0;
        for (int i = static_cast<int>(m) - 3; i >= 0; --i)
            A[i + 1] = A[A[i + 1] + 1] + 1u;
        if (A[1] + 1u > limit) {
            const std::uint8_t b =
                static_cast<std::uint8_t>(static_cast<char>(A[1] + 1u) - static_cast<char>(limit));
            for (std::uint32_t i = 0; i < m; ++i) {
                const std::uint32_t v = (sc[i] + (1u << (b & 31u)) - 1u) >> (b & 31u);
                A[i + 1] = v;
                sc[i] = v;
            }
            goto L_restart;
        }
        {
            std::uint32_t depth = 0, at_depth = 1, cur = A[0], avail = m;
            for (;;) {
                std::uint32_t next = 0, cnt = 0;
                if (cur != 0u && A[cur] == depth) {
                    const std::uint32_t key = A[cur];
                    do { --cur; ++cnt; if (cur == 0u) break; } while (A[cur] == key);
                    next = cnt * 2u;
                }
                if (cnt < at_depth) {
                    std::uint32_t w = avail, k = at_depth;
                    do { --k; A[w] = depth; --w; } while (k != cnt);
                    avail = (avail - at_depth) + k;
                }
                if (next == 0u) break;
                ++depth;
                at_depth = next;
            }
        }
        for (int i = static_cast<int>(A[0]); i >= 0; --i)
            lens[syms[i]] = static_cast<std::uint8_t>(A[i + 1]);
        return m;
    }
    if (m == 1u) {
        lens[syms[0]] = 1;
    } else if (m == 2u) {
        lens[syms[1]] = 1;
        lens[syms[0]] = 1;
    } else {
        return 0;
    }
    return m;
}

// FUN_0805cb70: total code length in bits.
int HuffBits(const std::uint8_t* lens, const int* freq) {
    int total = 0;
    for (int i = 0; i < 0x100; ++i) total += static_cast<int>(lens[i]) * freq[i];
    return total;
}

// ---------------------------------------------------------------------------
// FUN_080522c0 + FUN_080525b0 + FUN_080526c0: sort the block's positions by
// (data[i+4], the 32-bit word at data+i), read out data[idx + 5] and score the
// resulting sequence with an MTF + run-length model whose bins go through a
// truncating x87 entropy.
// ---------------------------------------------------------------------------
void PosSort(const std::uint8_t* data, std::uint16_t* idx, std::uint32_t n) {
    std::uint32_t hist[260];
    std::memset(hist, 0, sizeof(hist));
    for (std::uint32_t i = 0; i < n; ++i) ++hist[data[4 + i]];

    std::uint32_t run = 0, last = 0;
    for (std::uint32_t j = 0;; ++j) {
        run += hist[j];
        hist[j] = run;
        last = j;
        if (run >= n) break;
    }
    for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
        const std::uint8_t b = data[4 + i];
        idx[--hist[b]] = static_cast<std::uint16_t>(i);
    }

    const auto key = [data](std::uint16_t v) { return Rd32(data + v); };

    std::uint32_t bend = n;
    std::int32_t bp = static_cast<std::int32_t>(last);
    for (;;) {
        std::uint32_t start = 0, len = 0;
        for (;;) {
            if (bend == 0u) return;
            start = hist[bp];
            --bp;
            len = bend - start;
            bend = start;
            if (len >= 2u) break;
        }
        // comb sort over idx[start .. start+len), key = the 32-bit word at data+idx
        std::uint16_t* const b0 = idx + start;
        std::uint32_t gap = len;
        bool swapped = false;
        int off = 0, cnt = 0;
        std::uint16_t *p9 = nullptr, *p10 = nullptr;
        for (;;) {                                    // the outer do-while
            if (gap < 2u) goto L_2500;
            for (;;) {                                // while (gap = gap*10/13, gap < 0xb)
                gap = (gap * 10u) / 0xdu;
                if (gap >= 0xbu) break;
                gap += (gap == 0u) ? 1u : 0u;
                if (gap < 9u) {
                    off = static_cast<int>(gap) * 2 - 2;
                    swapped = (gap > 1u);
                } else {
                    off = 0x14;
                    swapped = true;
                    gap = 0xb;
                }
                for (;;) {
                    p10 = reinterpret_cast<std::uint16_t*>(
                              reinterpret_cast<std::uint8_t*>(b0) + off);
                    cnt = static_cast<int>(len - gap);
                    p9 = b0 - 1;
                    for (;;) {
                        ++p9; ++p10; --cnt;
                        if (cnt < 0) break;
                        const std::uint16_t v = *p10;
                        if (key(*p9) < key(v)) { *p10 = *p9; *p9 = v; swapped = true; }
                    }
                    if (!swapped) goto L_next_bucket;
                    if (gap > 1u) break;
                L_2500:
                    swapped = false;
                    off = static_cast<int>(gap) * 2 - 2;
                }
            }
            p9 = reinterpret_cast<std::uint16_t*>(
                     reinterpret_cast<std::uint8_t*>(b0) - 2 + gap * 2u);
            cnt = static_cast<int>(len - gap);
            p10 = b0 - 1;
            for (;;) {
                ++p10; ++p9; --cnt;
                if (cnt < 0) break;
                const std::uint16_t v = *p9;
                if (key(*p10) < key(v)) { *p9 = *p10; *p10 = v; }
            }
        }
    L_next_bucket:;
    }
}

// FUN_080526c0: MTF ranks + run lengths -> truncating x87 entropy.
int MtfEntropy(const char* data, std::uint32_t n) {
    char mtf[256];
    std::uint32_t bins[288];
    for (int i = 0; i < 0x100; ++i) mtf[i] = static_cast<char>(i);
    std::memset(bins, 0, sizeof(bins));

    std::uint32_t total = 1, runlen = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t prev_run = runlen;
        const char c = data[i];
        if (c == mtf[0]) {
            ++runlen;
            continue;
        }
        std::uint32_t r = 0;
        do { ++r; } while (c != mtf[r]);
        for (std::uint32_t k = r; k > 0; --k) mtf[k] = mtf[k - 1];
        mtf[0] = c;
        ++runlen;
        if (r > 2u) {
            if (runlen > 1u) {
                ++total;
                runlen = 0;
                const std::uint32_t v = prev_run - 1u;
                bins[Bsr(v) + 0x100u] += 1u;
            }
            ++total;
            bins[r] += 1u;
        }
    }

    int acc = 0;
    const long double tot = static_cast<long double>(total);
    for (int i = 0; i < 0x120; ++i) {
        const std::uint32_t c = bins[i];
        if (c == 0u) continue;                 // x87 stores the indefinite; low dword is 0
        const long double cc = static_cast<long double>(c);
        const long double e = -(cc * log2l(cc / tot)) * 64.0L;
        acc += static_cast<int>(static_cast<long long>(e));   // fistpll, round-to-zero
    }
    return acc;
}

// ---------------------------------------------------------------------------
// FUN_0806e690: slide a 256-byte window backwards over the run and keep the one
// where the delta alphabet is smallest relative to the raw alphabet.
// ---------------------------------------------------------------------------
const std::uint8_t* PlaceRegion(const std::uint8_t* start, const std::uint8_t* end,
                                std::uint32_t off, std::uint32_t* out_nd) {
    const std::uint8_t* win = start + 0x100;
    *out_nd = 1;
    const std::uint8_t* best = start;
    if (win >= end) return best;
    std::uint32_t best_score = 0;
    do {
        std::uint8_t seen_r[256], seen_d[256];
        std::memset(seen_r, 0, sizeof(seen_r));
        std::memset(seen_d, 0, sizeof(seen_d));
        const std::uint8_t* p = start;
        const std::uint8_t* nextp = start;
        if (start < win) {
            std::uint32_t nd = 0, nr = 0;
            do {
                const std::uint8_t b = *p;
                const std::uint8_t b2 = *(p - off);
                if (seen_r[b] == 0) ++nr;
                seen_r[b] = 1;
                const std::uint8_t d = static_cast<std::uint8_t>(b - b2);
                if (seen_d[d] == 0) ++nd;
                seen_d[d] = 1;
                ++p;
            } while (p < win);
            const std::uint32_t score = (nr > nd) ? (nr - nd) : (nd - nr);
            if (nd < nr && best_score < score) {
                best = win - 0x100;
                *out_nd = nd;
                best_score = score;
            }
            nextp = win;
        }
        start = nextp - 0xc0;
        win = nextp + 0x40;
    } while (win < end);
    return best;
}

// ---------------------------------------------------------------------------
// FUN_0806e3c0: how far the delta stays profitable from `pos`, forwards
// (backward == false) or backwards.
// ---------------------------------------------------------------------------
std::uint32_t ExtendRegion(const std::uint8_t* pos, std::uint32_t maxlen,
                           std::uint32_t off, bool backward) {
    if (maxlen <= 0x200u) return 0;
    int tbl[512];

    std::uint32_t base = 0;
    std::memset(tbl, 0, 256 * sizeof(int));
    {
        const std::uint8_t* q = pos - off;
        for (int i = 0; i < 0x200; ++i) {
            const std::uint8_t d = static_cast<std::uint8_t>(q[off] - q[0]);
            if (tbl[d] == 0) ++base;
            ++tbl[d];
            ++q;
        }
    }
    if (base >= 0xc0u) return 0;

    std::uint32_t total = 0, step = 0x200;
    for (;;) {
        std::memset(tbl, 0, 512 * sizeof(int));
        const std::uint32_t rem = maxlen - total;
        const std::uint32_t chunk = (step < rem) ? step : rem;
        std::uint32_t nd = 0, nr = 0;
        if (!backward) {
            const std::uint8_t* q = pos - off + total;
            for (std::uint32_t k = 0; k < chunk; ++k) {
                const std::uint8_t b = q[off];
                const std::uint8_t d = static_cast<std::uint8_t>(b - q[0]);
                if (tbl[d] == 0) ++nd;
                tbl[d] = 1;
                if (tbl[b + 0x100] == 0) ++nr;
                tbl[b + 0x100] = 1;
                ++q;
            }
        } else {
            const std::uint8_t* q = pos - off - total;
            for (std::uint32_t k = 0; k < chunk; ++k) {
                const std::uint8_t b = q[off];
                const std::uint8_t d = static_cast<std::uint8_t>(b - q[0]);
                if (tbl[d] == 0) ++nd;
                tbl[d] = 1;
                if (tbl[b + 0x100] == 0) ++nr;
                tbl[b + 0x100] = 1;
                --q;
            }
        }
        const std::uint32_t diff = (nd > nr) ? (nd - nr) : (nr - nd);
        const bool ok = ((nd < 0xe1u) || (diff > 0x1fu)) &&
                        (nd * 3u <= nr * 4u) &&
                        ((nd < 0x41u) || (nd * 2u <= base * 3u)) &&
                        (nd <= (step >> 2) + base * 2u);
        if (ok) {
            if (step == 0x200u) {
                base = (nd + 4u + base * 7u) >> 3;
                total += chunk;
            } else {
                step >>= 1;
                if (step < 8u) return total;
                base >>= 1;
                total += chunk;
            }
        } else {
            step >>= 1;
            if (step < 8u) return total;
            base >>= 1;
        }
        if (total >= maxlen) return maxlen;
    }
}

// ---------------------------------------------------------------------------
// The driver (FUN_0806e7a0).
// ---------------------------------------------------------------------------
struct Driver {
    const std::uint8_t* data = nullptr;
    std::uint32_t n = 0;
    std::uint8_t* out = nullptr;
    BitWriter w;

    // the three context models over a 512-entry window
    std::int16_t ctx[0x600];
    std::uint32_t distinct[3];
    std::uint16_t ring[512][3];
    std::uint32_t ringpos = 0;

    std::uint8_t offs[4];                  // abStack_20; [1] and [2] are the candidates
    std::int64_t lastpos[256];
    // The reference's recency ring is 256 POINTER slots -- 1024 bytes, i.e.
    // 1024 one-byte distances (FUN_0806e7a0 wraps it with `* -0x100` on a
    // 4-byte pointer type, which is -0x400 bytes).
    std::uint8_t dring[1024];
    std::uint32_t dringpos = 0;
    std::int32_t dcnt[256];
    std::uint32_t cache[0x1000][2];

    // scratch shared with the reference's one big stack buffer
    std::vector<std::uint8_t> bits;        // the distinct-context bit tables
    std::vector<std::uint8_t> scratch;     // local_6e68: freq / index / byte views
    std::vector<std::uint8_t> dbuf;        // local_3e65: the delta buffer
    std::vector<std::uint16_t> lzp;

    bool Run(std::vector<std::uint8_t>* side, std::uint32_t cap);
    bool EvalRegion(const std::uint8_t* rstart, std::uint32_t total, std::uint32_t off);
};

bool Driver::EvalRegion(const std::uint8_t* rstart, std::uint32_t total, std::uint32_t off) {
    // (1) does the delta shrink the order-2.5 alphabet by ~14%?
    {
        std::memset(bits.data(), 0, 0x20000u);
        std::uint32_t h_raw = 0, h_del = 0, c_raw = 0, c_del = 0;
        for (std::uint32_t i = 0; i < total; ++i) {
            const std::uint8_t b = rstart[i];
            std::uint32_t x = b ^ h_raw;
            h_raw = x << 8;
            x = (x & 0x7ffffu) >> 3;
            const std::uint32_t bit = b & 7u;
            std::uint32_t y = static_cast<std::uint8_t>(b - rstart[static_cast<std::int32_t>(i) - static_cast<std::int32_t>(off)]) ^ h_del;
            h_del = y << 8;
            y = (y & 0x7ffffu) + 0x80000u;
            const std::uint32_t bit2 = y & 7u;
            std::uint8_t& cr = bits[x];
            c_raw += ((cr >> bit) + 1u) & 1u;
            cr = static_cast<std::uint8_t>((1u << bit) | cr);
            y >>= 3;
            std::uint8_t& cd = bits[y];
            c_del += ((cd >> bit2) + 1u) & 1u;
            cd = static_cast<std::uint8_t>((1u << bit2) | cd);
        }
        if (!(c_del * 7u < c_raw * 6u)) return false;
    }

    const std::uint32_t nn = (total < 0x1800u) ? total : 0x1800u;

    // (2) an order-2 LZP over the raw and the delta bytes, scored with Huffman.
    std::uint32_t cost[2] = {0, 0};
    for (int pass = 0; pass < 2; ++pass) {
        int* freq = reinterpret_cast<int*>(scratch.data());
        std::memset(freq, 0, 0x400);
        std::memset(lzp.data(), 0, 0x4000u);
        const std::uint8_t* src = rstart;
        if (pass != 0) {
            for (std::uint32_t j = 0; j < nn; ++j)
                dbuf[j] = static_cast<std::uint8_t>(
                    rstart[j] - rstart[static_cast<std::int32_t>(j) - static_cast<std::int32_t>(off)]);
            std::memcpy(dbuf.data() + nn, dbuf.data(), 4);
            dbuf[nn + 4] = dbuf[4];
            src = dbuf.data();
        }
        std::uint32_t idx = 0, k = 1;
        for (;;) {
            lzp[idx] = static_cast<std::uint16_t>(k);
            const std::uint32_t k2 = k + 1u;
            if (nn <= k2) break;
            idx = Rd16(src + k - 1u) & 0x1fffu;
            k = k2;
            if (src[k2] == src[lzp[idx]]) freq[128] += 1;
            else freq[src[k2]] += 1;
        }
        std::uint8_t lens[512];
        const std::uint32_t nsym = HuffLengths(lens, freq, 0x1fu);
        const int b = HuffBits(lens, freq);
        cost[pass] = (static_cast<std::uint32_t>(b) >> 3) + (nsym >> 1);
    }
    if (!(cost[1] < cost[0])) return false;

    // (3) the same comparison through a positional sort + MTF entropy.
    {
        std::uint16_t* ix = reinterpret_cast<std::uint16_t*>(scratch.data());
        PosSort(rstart, ix, nn);
        std::uint8_t* by = scratch.data();
        for (std::uint32_t i = 0; i < nn; ++i) by[i] = rstart[5 + ix[i]];
        const int c0 = MtfEntropy(reinterpret_cast<const char*>(by), nn);
        PosSort(dbuf.data(), ix, nn);
        for (std::uint32_t i = 0; i < nn; ++i) by[i] = dbuf[5 + ix[i]];
        const int c1 = MtfEntropy(reinterpret_cast<const char*>(by), nn);
        if (!(static_cast<std::uint32_t>(c1) < static_cast<std::uint32_t>(c0))) return false;
    }

    // (4) a long run of exact matches at `off` means the LZ pass will do better.
    if (off > 0x13u) {
        std::uint32_t m = (total < 0x4000u) ? total : 0x4000u;
        std::uint32_t run = 0, matched = 0, i = 0;
        while (--m != 0u) {
            const bool eq = rstart[i] == rstart[static_cast<std::int32_t>(i) - static_cast<std::int32_t>(off)];
            run = eq ? (run + 1u) : 0u;
            if (off <= run) { matched += off; run = 0; }
            ++i;
        }
        if (total <= matched * 8u) return false;
    }
    return true;
}

bool Driver::Run(std::vector<std::uint8_t>* side, std::uint32_t cap) {
    if (n <= 0x107u) return false;

    side->assign(cap, 0);
    w.Reset(side->data(), side->data() + cap);

    for (int i = 0; i < 256; ++i) lastpos[i] = -0x40000000LL;
    for (int i = 0; i < 0x1000; ++i) { cache[i][0] = 0; cache[i][1] = 0; }
    std::memset(dring, 0, sizeof(dring));
    std::memset(dcnt, 0, sizeof(dcnt));
    offs[1] = 1; offs[2] = 2;
    std::memset(ctx, 0, sizeof(ctx));
    distinct[0] = distinct[1] = distinct[2] = 1;
    ctx[0] = 0x200; ctx[0x200] = 0x200; ctx[0x400] = 0x200;
    std::memset(ring, 0, sizeof(ring));
    ringpos = 0;
    dringpos = 0;

    std::memcpy(out, data, n);

    const std::uint8_t* p = data;
    const std::uint8_t* const dend = data + n;
    std::uint32_t h0 = 0, h1 = 0, h2 = 0;
    std::uint32_t runlen = 0;
    std::uint8_t mode = 0;
    signed char countdown = 'd';
    const std::uint8_t* lastEnd = data + 0xff;

    for (;;) {
        bool emit = false;
        if (p == dend) {
            if (mode == 0) break;
            emit = true;
        }
        if (!emit) {
            const std::uint8_t b = *p;
            const std::uint8_t bA = *(p - offs[1]);
            const std::uint8_t bB = *(p - offs[2]);
            ++p;
            ++runlen;
            h0 = b + h0 * 0x100u;
            h1 = static_cast<std::uint8_t>(b - bA) + h1 * 0x100u;
            h2 = static_cast<std::uint8_t>(b - bB) + h2 * 0x100u;
            const std::uint32_t c0 = ((h0 >> 5) ^ h0) & 0x1ffu;
            const std::uint32_t c1 = ((h1 >> 5) ^ h1) & 0x1ffu;
            const std::uint32_t c2 = ((h2 >> 5) ^ h2) & 0x1ffu;

            const std::int16_t o0 = ctx[c0];         ctx[c0] = static_cast<std::int16_t>(o0 + 1);
            const std::int16_t o1 = ctx[0x200 + c1]; ctx[0x200 + c1] = static_cast<std::int16_t>(o1 + 1);
            const std::int16_t o2 = ctx[0x400 + c2]; ctx[0x400 + c2] = static_cast<std::int16_t>(o2 + 1);

            const std::uint16_t e0 = ring[ringpos][0];
            const std::uint16_t e1 = ring[ringpos][1];
            const std::uint16_t e2 = ring[ringpos][2];
            ring[ringpos][0] = static_cast<std::uint16_t>(c0);
            ring[ringpos][1] = static_cast<std::uint16_t>(c1);
            ring[ringpos][2] = static_cast<std::uint16_t>(c2);
            ringpos = (ringpos + 1u) & 511u;

            const std::int16_t g0 = ctx[e0];         ctx[e0] = static_cast<std::int16_t>(g0 - 1);
            const std::int16_t g1 = ctx[0x200 + e1]; ctx[0x200 + e1] = static_cast<std::int16_t>(g1 - 1);
            const std::int16_t g2 = ctx[0x400 + e2]; ctx[0x400 + e2] = static_cast<std::int16_t>(g2 - 1);

            distinct[0] = (o0 == 0 ? 1u : 0u) + (distinct[0] - ((std::int16_t)(g0 - 1) == 0 ? 1u : 0u));
            distinct[1] = (o1 == 0 ? 1u : 0u) + (distinct[1] - ((std::int16_t)(g1 - 1) == 0 ? 1u : 0u));
            distinct[2] = (distinct[2] - ((std::int16_t)(g2 - 1) == 0 ? 1u : 0u)) + (o2 == 0 ? 1u : 0u);

            const std::int64_t here = static_cast<std::int64_t>(p - data);
            const std::int64_t d64 = here - lastpos[b];
            lastpos[b] = here;
            if (d64 < 1 || d64 > 255) continue;
            const std::uint32_t d = static_cast<std::uint32_t>(d64);

            const std::uint8_t oldd = dring[dringpos];
            dring[dringpos] = static_cast<std::uint8_t>(d);
            dcnt[oldd] -= 1;
            dringpos = (dringpos + 1u) & 1023u;
            const std::int32_t newcnt = ++dcnt[d];

            if (offs[1] == d || offs[2] == d) continue;
            if (--countdown != 0) continue;

            // the 100-byte re-evaluation
            if (std::getenv("NZOPT_TRACE_P1DEC") != nullptr)
                std::fprintf(stderr, "DEC p=%d run=%u mode=%u d=[%u,%u,%u] offs=[%u,%u]\n",
                             (int)(p - data), runlen, mode,
                             distinct[0], distinct[1], distinct[2], offs[1], offs[2]);
            bool do_emit = false;
            bool try_a = false;
            if (mode == 0) {
                if (distinct[0] < 3u) {
                    try_a = true;
                } else if (distinct[2] <= distinct[1] || distinct[0] <= distinct[1]) {
                    if (distinct[2] < distinct[1] && distinct[2] < distinct[0]) {
                        runlen = 0;
                        mode = 2;
                    }
                    try_a = true;
                } else {
                    runlen = 0;
                    mode = 1;
                }
            } else {
                countdown = 'd';
                if (distinct[0] <= distinct[mode]) do_emit = true;
                else if (mode != 1) try_a = true;
            }
            if (!do_emit) {
                if (try_a) {
                    if (dcnt[offs[1]] < newcnt) {
                        countdown = 'd';
                        offs[1] = static_cast<std::uint8_t>(d);
                        continue;
                    }
                }
                if (mode != 2 && dcnt[offs[2]] < newcnt) {
                    countdown = 'd';
                    offs[2] = static_cast<std::uint8_t>(d);
                    continue;
                }
                countdown = 'd';
                continue;
            }
        }

        // ---- emit path (LAB_0806ecd0) ----
        {
            const std::uint32_t off = offs[mode];
            const std::uint8_t* regionStart = p - runlen;
            const std::uint8_t* lo = regionStart - 0x800;
            if (lo < lastEnd) lo = lastEnd;
            std::uint32_t nd = 0;
            const std::uint8_t* pos = PlaceRegion(lo, regionStart, off, &nd);
            const bool tr = std::getenv("NZOPT_TRACE_P1") != nullptr;
            if (tr)
                std::fprintf(stderr, "PLACE lo=%d regionStart=%d off=%u\n  POS=%d nd=%u\n",
                             (int)(lo - data), (int)(regionStart - data), off, (int)(pos - data), nd);
            const std::uint32_t q = (nd - 1u) >> 4;
            const std::uint32_t ci = off * 0x10u + q;
            if (cache[ci][1] <= static_cast<std::uint32_t>(pos - data) ||
                static_cast<std::uint32_t>(pos - data) <= cache[ci][0] ||
                cache[ci][0] < static_cast<std::uint32_t>(lastEnd - data)) {
                const std::uint32_t back = ExtendRegion(pos, static_cast<std::uint32_t>(pos - lastEnd), off, true);
                const std::uint32_t fwd = ExtendRegion(pos, static_cast<std::uint32_t>(dend - pos), off, false);
                if (tr)
                    std::fprintf(stderr, "EXT pos=%d maxlen=%u off=%u dir=1\n  BACK=%u\n"
                                         "EXT pos=%d maxlen=%u off=%u dir=0\n  FWD=%u\n",
                                 (int)(pos - data), (unsigned)(pos - lastEnd), off, back,
                                 (int)(pos - data), (unsigned)(dend - pos), off, fwd);
                const std::uint8_t* rstart = pos - back;
                const std::uint32_t total = fwd + back;
                cache[ci][0] = static_cast<std::uint32_t>(rstart - data);
                cache[ci][1] = static_cast<std::uint32_t>((pos + fwd) - data);
                if (total > 7u && off * 8u <= total && total > 0xfu &&
                    EvalRegion(rstart, total, off)) {
                    const std::size_t at = static_cast<std::size_t>(rstart - data);
                    for (std::uint32_t i = 0; i < total; ++i)
                        out[at + i] = static_cast<std::uint8_t>(
                            out[at + i] - rstart[static_cast<std::int32_t>(i) - static_cast<std::int32_t>(off)]);
                    if (std::getenv("NZOPT_TRACE_P1") != nullptr)
                        std::fprintf(stderr, "TRIPLE copy_offset=%u start=%u num_delta=%u\n",
                                     off, static_cast<unsigned>(at), total - 8u);
                    w.Emit(off, static_cast<std::uint32_t>(at), total - 8u);
                    p = rstart + total;
                    lastEnd = p;
                }
            }
            if (p == dend) break;
            mode = 0;
        }
    }

    w.Emit(0, 0, 0);
    w.Flush();
    std::size_t bytes = w.Size();
    const std::uint32_t half = cap >> 1;
    if (bytes > half) bytes = half;
    side->resize(bytes);
    if (!(bytes < half)) return false;
    if (lastEnd == data + 0xff) return false;
    if (n <= 0x3ffu) return true;

    // The reference's last word: fewer distinct order-2.5 contexts than before.
    std::memset(bits.data(), 0, 0x40000u);
    std::uint32_t ho = 0, hf = 0, co = 1, cf = 1;
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint32_t x = data[i] ^ ho;
        ho = x << 8;
        x = (x & 0xfffffu) >> 3;
        std::uint32_t y = out[i] ^ hf;
        const std::uint32_t bit = data[i] & 7u;
        hf = y << 8;
        std::uint8_t& a = bits[x];
        y = (y & 0xfffffu) + 0x100000u;
        co += ((a >> bit) + 1u) & 1u;
        const std::uint32_t bit2 = y & 7u;
        a = static_cast<std::uint8_t>((1u << bit) | a);
        y >>= 3;
        std::uint8_t& c = bits[y];
        cf += ((c >> bit2) + 1u) & 1u;
        c = static_cast<std::uint8_t>((1u << bit2) | c);
    }
    return cf < co;
}

}  // namespace

bool NzOptimumParam1Encode(const std::uint8_t* data, std::uint32_t n,
                           std::vector<std::uint8_t>* out,
                           std::vector<std::uint8_t>* side,
                           std::uint32_t cap) {
    if (data == nullptr || out == nullptr || side == nullptr) return false;
    out->assign(n, 0);
    side->clear();
    if (n <= 0x107u) return false;

    // The reference runs over the codec's own block buffer, so its window
    // probes reach outside the block into the rest of that allocation, which
    // is zero on a fresh buffer. A copy padded on BOTH sides reproduces that
    // without reading memory we do not own:
    //   * behind, up to 255 bytes: the very first bytes of a block are
    //     delta-coded against `data[-offsetA]` / `data[-offsetB]`, and the two
    //     offsets are 1 and 2 only until the first re-evaluation;
    //   * ahead, the 512-byte look-ahead in FUN_0806e3c0 (which always scans
    //     FORWARD, even when it was called to extend backwards) and the
    //     `data[index + 5]` read in FUN_080525b0.
    static const std::size_t kFrontPad = 0x100u;
    std::vector<std::uint8_t> padded(kFrontPad + static_cast<std::size_t>(n) + 0x1000u, 0);
    std::memcpy(padded.data() + kFrontPad, data, n);

    Driver d;
    d.data = padded.data() + kFrontPad;
    d.n = n;
    d.out = out->data();
    d.bits.assign(0x40000u, 0);
    d.scratch.assign(0x3003u, 0);
    d.dbuf.assign(0x1805u, 0);
    d.lzp.assign(0x2000u, 0);
    return d.Run(side, cap);
}

}  // namespace opt_enc
}  // namespace nzr
