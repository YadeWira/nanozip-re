// nz_optimum_text.cpp -- see the header.
#include "nz_optimum_text.h"
#include "nz_lzhd_text.h"
#include "nz_cd_texttransform_dict.h"
#include "nz_text_transform.h"
#include "nz_texttransform_num.h"
#include "nz_bwt.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace nzr::opt_enc {

namespace {

// DAT_081332e0
const std::uint8_t* Traits0() { return nzr::cd::NzCdCharacterTraits0(); }

inline std::uint32_t LoadU16(const std::uint8_t* p) {
    std::uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

// FUN_080ae940 with param_4 = 1: a plain histogram that REPLACES what is there.
void HistAll(std::uint32_t* hist, const std::uint8_t* buf, std::uint32_t n) {
    std::memset(hist, 0, 256u * sizeof(std::uint32_t));
    for (std::uint32_t i = 0; i < n; ++i) ++hist[buf[i]];
}

// The digit sum three of the predicates share.
std::uint32_t DigitSum(const CoTextObj& o) {
    std::uint32_t s = 0;
    for (unsigned c = 0x30u; c < 0x3au; ++c) s += o.hist[c];
    return s;
}

}  // namespace

// ------------------------------------------------------------ FUN_08054b50
void CoTextAnalyze(CoTextObj& o, const std::uint8_t* buf, std::uint32_t n) {
    std::memset(&o, 0, sizeof(o));
    if (n < 0x10u) return;

    // 8192 slots of "the last position whose two preceding bytes hashed here".
    // Slot 0 doubles as "never seen", so an unseen hash compares against position
    // 0 of the block -- which the original does too, and which can therefore
    // report a match at the very start.
    std::vector<std::uint32_t> last(0x2000u, 0u);
    std::uint32_t hist[256] = {};
    std::uint32_t linesum = 0;      // local_8424
    std::uint32_t lastlf = 0;       // local_8420
    std::uint32_t dedup = 1;        // local_8428
    std::uint32_t i = 2;            // uVar8 / uVar11

    for (;;) {
        std::uint32_t prev = 0;
        // The scan: one position at a time until the byte at the hashed position
        // repeats the current byte.
        for (;;) {
            if (n <= i) goto finish;
            const std::uint32_t h = LoadU16(buf + i - 2u) & 0x1fffu;
            prev = last[h];
            last[h] = i;
            const std::uint32_t c = buf[i];
            ++dedup;
            ++hist[c];
            if (c == 10u) { linesum += i - lastlf; lastlf = i; }
            if (buf[prev] == c) break;
            ++i;
        }
        // Two bytes have to repeat before the run is measured; one is no reason
        // to skip anything, and the scan resumes at the next position either way.
        if (buf[i + 1u] != buf[prev + 1u]) { ++i; continue; }
        std::uint32_t k = i + 1u;                       // uVar5
        const std::uint8_t* q = buf + prev + 1u;        // pbVar9
        for (;;) {
            if (n <= k) break;
            ++q;
            if (buf[k + 1u] != *q) break;
            ++k;
        }
        // A run of five bytes or more (k - i is its length less one) takes its own
        // bytes out of the histogram entirely: the scan resumes past it. Anything
        // shorter is left to the ordinary one-at-a-time walk.
        i = (3u < k - i) ? (k + 1u) : (i + 1u);
    }

finish:
    o.meanline = linesum / (hist[10] + 1u);
    const std::uint8_t* t0 = Traits0();
    std::uint32_t s9d = 1, s19 = 1;
    for (unsigned c = 0; c < 0x100u; ++c) {
        if (hist[c] == 0u || (t0[c] & 0x9du) == 0u) continue;
        s9d += hist[c];
        if ((t0[c] & 0x19u) != 0u) s19 += hist[c];
    }
    o.n = n;
    o.dedup = dedup;
    o.s9d = static_cast<std::uint8_t>(static_cast<std::uint64_t>(s9d) * 100ull / dedup);
    o.s19 = static_cast<std::uint8_t>(static_cast<std::uint64_t>(s19) * 100ull / dedup);
    // Only once the sample reads as text is the histogram rebuilt over every byte
    // of it: the deduplicated counts decided the question, the full counts answer
    // every predicate after it.
    if (o.s9d > 0x57u || (o.s19 > 0x4fu && o.s9d > 0x4fu)) HistAll(hist, buf, n);
    std::memcpy(o.hist, hist, sizeof(hist));
}

// ------------------------------------------------------------ the predicates
bool CoIsText(const CoTextObj& o) {
    return o.s9d >= 0x58u || (o.s9d > 0x4fu && o.s19 > 0x4fu);
}
bool CoInsertLfFits(const CoTextObj& o) {          // 30..80 characters a line
    return (o.meanline - 0x1eu) < 0x33u;
}
bool CoHtmlFits(const CoTextObj& o) {
    const std::uint32_t gt = o.hist['>'], lt = o.hist['<'], sl = o.hist['/'];
    return gt / 3u <= sl && lt - (lt >> 4u) <= gt;
}
bool CoEnoughDigits(const CoTextObj& o) { return (o.dedup >> 5u) <= DigitSum(o); }
bool CoMostlyDigits(const CoTextObj& o) { return (o.dedup >> 1u) + 0x400u <= DigitSum(o); }
bool CoNumber1(const CoTextObj& o) { return DigitSum(o) > 0x13u; }
bool CoCrlfFits(const CoTextObj& o) {
    const std::uint32_t lf = o.hist[10], cr = o.hist[13];
    if ((o.n >> 7u) > lf || lf > (o.n >> 3u)) return false;
    if (cr - (cr >> 6u) > lf) return false;
    return lf <= (cr >> 6u) + cr;
}
bool CoNumber2(const CoTextObj& o) { return (o.n >> 8u) < o.hist[10] + o.hist[13]; }

// ------------------------------------------------------------ FUN_080550c0
bool CoDigitDotFits(const std::uint8_t* buf, std::uint32_t n) {
    if (n < 0x10u) return false;
    const std::uint8_t* t0 = Traits0();
    const std::uint8_t* p = buf;
    std::uint32_t left = n;
    std::uint32_t hits = 0;
    for (;;) {
        const std::uint8_t* cur = p;
        const std::uint32_t was = left;
        left = was - 1u;
        if (left == 0u) break;
        p = cur + 1u;
        if ((t0[*cur] & 4u) == 0u) continue;
        left = was - 2u;
        if (left == 0u) break;
        std::uint32_t nxt = cur[1];
        std::uint32_t val = static_cast<std::uint32_t>(*cur) - 0x30u;
        p = cur + 2u;
        while ((t0[nxt] & 4u) != 0u) {
            if (--left == 0u) goto done;
            val = (nxt - 0x30u) + val * 10u;
            nxt = *p++;
        }
        // The number has to be a real one below 256 and the character after it a
        // dot: version strings, dotted quads, the "1." of an enumeration.
        if (val != 0u && nxt == 0x2eu) hits += (val < 0x100u) ? 1u : 0u;
    }
done:
    return (n >> 8u) < hits;
}

// ------------------------------------------------------------ FUN_0808da10, text
std::uint32_t CoTextFlags(const std::uint8_t* buf, std::uint32_t n, std::uint8_t* scratch,
                          bool cm, bool* number_route) {
    using nzr::lzhd_enc::DictFits;
    using nzr::lzhd_enc::LineRleFits;
    const bool tr = std::getenv("NZOPT_TRACE_TDO") != nullptr;
    bool route = false;
    if (number_route != nullptr) *number_route = false;

    CoTextObj o;
    CoTextAnalyze(o, buf, n >> 3u);
    // The gate: text by the histogram, or line-RLE-shaped over at most 1 KB.
    const std::uint32_t rle_probe = std::min(n >> 10u, 0x400u);
    if (tr)
        std::fprintf(stderr, "[tdo] obj n=%u sample=%u dedup=%u s9d=%u s19=%u mean=%u h10=%u h13=%u\n",
                     n, o.n, o.dedup, o.s9d, o.s19, o.meanline, o.hist[10], o.hist[13]);
    if (!CoIsText(o) && !LineRleFits(buf, rle_probe)) {
        if (tr) std::fprintf(stderr, "[tdo] NOT TEXT (rle probe %u)\n", rle_probe);
        return 0u;
    }

    std::uint32_t flags = 0;
    const std::uint32_t half = n >> 1u;
    if (DictFits(buf, half) && DictFits(buf + half, n - half)) {
        flags = 8u;
    } else if (CoEnoughDigits(o) && CoDigitDotFits(buf, n >> 2u)) {
        // The digit route: the dictionary is asked for on the strength of dotted
        // numbers rather than of words, and `-cc` throws the whole mask away for it.
        flags = 8u;
        route = true;
    }

    const std::uint32_t chess_probe = n >> 6u;
    bool to_crlf = false;
    if (chess_probe >= 0x80u &&
        nzr::lzhd_enc::TextChessEncode(buf, chess_probe - 0x40u, scratch, chess_probe) != 0u) {
        flags |= 0x40u;
        route = false;
        to_crlf = true;
    } else {
        const std::uint32_t k = n >> 7u;
        if (LineRleFits(buf, k) && LineRleFits(buf + k, n - k)) {
            // Line RLE REPLACES the mask outside the CM codec, and takes the
            // dictionary out of it either way.
            if (!cm) flags = 0x20u;
            flags &= ~8u;
        }
        to_crlf = (flags != 0u);
    }

    bool to_number = false;
    if (to_crlf) {
        if (CoCrlfFits(o)) flags |= 1u;
        if (CoInsertLfFits(o)) flags |= 2u;
        to_number = (flags != 0u);
    }
    if (!to_number) to_number = CoEnoughDigits(o);
    if (to_number) {
        if (CoNumber1(o) && (flags & 0x40u) == 0u && CoNumber2(o)) flags |= 0x10u;
        if (CoHtmlFits(o)) flags |= 4u;
    }

    // What `-cc` refuses: a mask that came from the digit route, and a block that
    // is mostly digits. For `-co` and `-cO` the CM object is null, so neither
    // applies and the only question left is whether the mask is non-empty.
    if (route && cm) flags = 0u;
    else if ((flags & 0x10u) != 0u && CoMostlyDigits(o) && cm) flags = 0u;

    if (number_route != nullptr) *number_route = route;
    if (tr)
        std::fprintf(stderr, "[tdo] n=%u s9d=%u s19=%u mean=%u dedup=%u flags=0x%02x route=%d\n",
                     n, o.s9d, o.s19, o.meanline, o.dedup, flags, (int)route);
    return flags;
}


// ------------------------------------------------------------ FUN_08052ec0
// The entropy estimate the number step's trial compares: per chunk of at most
// 64 KB, sort the positions by their byte and then by the four bytes before it
// (FUN_080522c0: a counting sort, then a comb sort inside each byte's bucket
// keyed on the preceding four bytes as one little-endian word), take the byte
// after each sorted position, move-to-front code that (FUN_08052df0), and price
// the ranks with the length of an optimal prefix code over their histogram
// (FUN_0805d000: sum of length * count, in bytes, plus half the symbol count).
// The original reads the four bytes before the buffer and the one after it;
// `before` and `after` supply them (zero when the caller has nothing there).
namespace {

std::uint32_t HuffmanCost(const std::uint32_t* hist, std::uint32_t* nsyms_out) {
    std::vector<std::uint32_t> w;
    for (unsigned c = 0; c < 256u; ++c) if (hist[c]) w.push_back(hist[c]);
    *nsyms_out = static_cast<std::uint32_t>(w.size());
    if (w.empty()) return 0;
    if (w.size() == 1u) return w[0];                 // FUN_0805cbe0 gives the lone symbol length 1
    // Every optimal prefix code has the same total length: the sum of the
    // internal node weights of any Huffman tree (Moffat/Katajainen in place).
    std::sort(w.begin(), w.end());
    std::uint64_t total = 0;
    std::size_t leaf = 0, node = 0;
    std::vector<std::uint64_t> merged;
    for (std::size_t made = 0; made + 1u < w.size(); ++made) {
        std::uint64_t a, b;
        auto take = [&]() -> std::uint64_t {
            if (node < merged.size() && (leaf >= w.size() || merged[node] < w[leaf])) return merged[node++];
            return w[leaf++];
        };
        a = take(); b = take();
        merged.push_back(a + b);
        total += a + b;
    }
    return static_cast<std::uint32_t>(total);
}

std::uint32_t EstimateChunk(const std::uint8_t* d, std::uint32_t n, const std::uint8_t* before4,
                            std::uint8_t after) {
    // key bytes: data[i-1..i-4] with the four bytes before the chunk supplying i < 4
    auto at = [&](std::int64_t i) -> std::uint32_t {
        if (i < 0) return before4[4 + i];
        if (i >= static_cast<std::int64_t>(n)) return after;
        return d[i];
    };
    auto key = [&](std::uint32_t i) -> std::uint32_t {   // the LE word at buf + i = data[i-4..i-1]
        return at(static_cast<std::int64_t>(i) - 4) | (at(static_cast<std::int64_t>(i) - 3) << 8) |
               (at(static_cast<std::int64_t>(i) - 2) << 16) | (at(static_cast<std::int64_t>(i) - 1) << 24);
    };
    std::vector<std::uint16_t> sorted(n);
    std::uint32_t cnt[257] = {0};
    for (std::uint32_t i = 0; i < n; ++i) ++cnt[d[i]];
    std::uint32_t cum[257];
    cum[0] = 0;
    for (unsigned c = 0; c < 256u; ++c) cum[c + 1u] = cum[c] + cnt[c];
    // the counting sort walks the data from the end, so ties keep position order
    {
        std::uint32_t fill[256];
        for (unsigned c = 0; c < 256u; ++c) fill[c] = cum[c + 1u];
        for (std::uint32_t i = n; i-- > 0;) sorted[--fill[d[i]]] = static_cast<std::uint16_t>(i);
    }
    // FUN_080522c0's comb sort per bucket, gap sequence g = g*10/13 down to 1,
    // finishing with the bubble passes it runs until nothing moves
    for (unsigned c = 0; c < 256u; ++c) {
        const std::uint32_t lo = cum[c], sz = cum[c + 1u] - lo;
        if (sz < 2u) continue;
        std::uint16_t* a = sorted.data() + lo;
        std::uint32_t gap = sz;
        bool swapped = true;
        while (gap > 1u || swapped) {
            gap = (gap * 10u) / 13u;
            if (gap < 11u) {
                gap += (gap == 0u);
                if (gap >= 9u) gap = 11u;
            }
            swapped = false;
            for (std::uint32_t i = 0; i + gap < sz; ++i) {
                if (key(a[i + gap]) < key(a[i])) { std::swap(a[i], a[i + gap]); swapped = true; }
            }
        }
    }
    // the byte after each sorted position, move-to-front coded
    std::uint8_t mtf[256];
    for (unsigned i = 0; i < 256u; ++i) mtf[i] = static_cast<std::uint8_t>(i);
    std::uint32_t hist[256] = {0};
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint8_t b = static_cast<std::uint8_t>(at(static_cast<std::int64_t>(sorted[i]) + 1));
        unsigned r = 0;
        while (mtf[r] != b) ++r;
        for (unsigned k = r; k > 0; --k) mtf[k] = mtf[k - 1u];
        mtf[0] = b;
        ++hist[r];
    }
    std::uint32_t nsyms = 0;
    const std::uint32_t bits = HuffmanCost(hist, &nsyms);
    return (bits >> 3) + (nsyms >> 1);
}

}  // namespace

std::uint32_t CoEntropyEstimate(const std::uint8_t* buf, std::uint32_t n, const std::uint8_t* before4,
                                std::uint8_t after) {
    std::uint32_t total = 0;
    const std::uint8_t zeros[4] = {0, 0, 0, 0};
    const std::uint8_t* prev = before4 ? before4 : zeros;
    std::uint8_t prevbuf[4];
    while (n != 0u) {
        const std::uint32_t len = (n > 0x10000u) ? 0x10000u : n;
        const std::uint8_t next = (n > len) ? buf[len] : after;
        total += EstimateChunk(buf, len, prev, next);
        // the next chunk's four preceding bytes are this one's last four
        for (int i = 0; i < 4; ++i) prevbuf[i] = (len >= 4u - i) ? buf[len - 4u + i] : prev[i];
        prev = prevbuf;
        buf += len;
        n -= len;
    }
    return total;
}

// ------------------------------------------------------------ FUN_08059060, -co
std::uint32_t CoTextPipeline(std::uint32_t bits, std::uint8_t*& buf, std::uint32_t n, std::uint8_t*& tmp,
                             std::uint32_t cap, std::uint8_t* applied, std::vector<std::uint8_t>* tt2,
                             std::vector<std::uint8_t>* tt16, bool reorder_ascii, bool cm) {
    using namespace nzr::lzhd_enc;
    std::uint8_t done = 0;
    tt2->clear();
    tt16->clear();
    auto run = [&](std::uint32_t r, std::uint8_t bit) { if (r != 0u) { std::swap(buf, tmp); n = r; done |= bit; } };
    if (bits & 1u) run(TextCrlfEncode(buf, n, tmp, std::min(cap, n + 0x10u)), 1u);
    if (bits & 0x40u) run(TextChessEncode(buf, n, tmp, std::min(cap, n + 0x400u)), 0x40u);
    if (bits & 0x20u) run(TextLineRleEncode(10u, buf, n, tmp, n), 0x20u);
    if (bits & 0x02u) {
        std::vector<std::uint8_t> side;
        const std::uint32_t r = NzTextTransformInsertLfEncode(buf, n, tmp, n, &side, kCoAuxStreamBytes);
        if (r != 0u) { *tt2 = side; run(r, 0x02u); }
    }
    if (bits & 0x04u) run(NzTextTransformHtmlEncode(buf, n, tmp, n), 0x04u);
    if (bits & 0x08u) {
        const std::uint32_t r = TextDictEncode(buf, n, tmp, n);
        if (r != 0u) {
            run(r, 0x08u);
            if (reorder_ascii) {
                static std::uint8_t inv[256];
                static bool built = false;
                if (!built) { const unsigned char* f = nzr::cd::NzCdReorderAscii(); for (unsigned c = 0; c < 256u; ++c) inv[f[c]] = (std::uint8_t)c; built = true; }
                for (std::uint32_t i = 0; i < n; ++i) buf[i] = inv[buf[i]];
            }
        }
    }
    if ((bits & 0x10u) && (done & 0x40u) == 0u) {
        // The trial on the second half: worth it when the estimate of the coded
        // half plus its side bytes beats the estimate of the plain half by more
        // than 1/32, or does not lose and the side stream is small.
        const std::uint32_t half = n >> 1;
        const std::uint32_t len = (half > 0x10000u) ? 0x10000u : half;
        std::vector<std::uint8_t> side;
        const std::uint32_t t = NzTextTransformNumberEncode(buf + half, len, tmp, len, &side, kCoAuxStreamBytes);
        bool go = (t == 0u);
        if (!go) {
            const std::uint32_t est_in = CoEntropyEstimate(buf + half, len, buf + half - 4, (half + len < n) ? buf[half + len] : 0u);
            const std::uint32_t est_out = CoEntropyEstimate(tmp, t, nullptr, 0u);
            const std::uint32_t aux = static_cast<std::uint32_t>(side.size());
            go = ((est_out + aux) * 0x20u < est_in * 0x21u) || (est_out <= est_in && aux < 0x200u);
        }
        if (go) {
            const std::uint32_t r = NzTextTransformNumberEncode(buf, n, tmp, n, &side, kCoAuxStreamBytes);
            if (r != 0u) { *tt16 = side; run(r, 0x10u); }
        }
    }
    if (bits & 0x80u) {
        if (done & 8u) run(TextParam14Encode(buf, n, tmp, n), 0x80u);
        else if (done == 0u) return 0u;
    } else if (done == 0u) return 0u;
    if (!(n < cap)) return 0u;
    (void)cm;
    *applied = done;
    return n;
}

// ------------------------------------------------------------ FUN_080b8910
std::uint32_t CoSideStreamBytes(std::uint8_t applied, const std::vector<std::uint8_t>& tt2,
                                const std::vector<std::uint8_t>& tt16, std::vector<std::uint8_t>* out) {
    auto varint = [&](std::uint32_t v) {   // FUN_080b8560: LEB128, low bits first
        while (v >= 0x80u) { out->push_back(static_cast<std::uint8_t>((v & 0x7fu) | 0x80u)); v >>= 7; }
        out->push_back(static_cast<std::uint8_t>(v));
    };
    const std::size_t start = out->size();
    if (applied & 0x02u) { varint(static_cast<std::uint32_t>(tt2.size())); out->insert(out->end(), tt2.begin(), tt2.end()); }
    if (applied & 0x10u) { varint(static_cast<std::uint32_t>(tt16.size())); out->insert(out->end(), tt16.begin(), tt16.end()); }
    return static_cast<std::uint32_t>(out->size() - start);
}

// ------------------------------------------------------------ FUN_0808f8e0
bool CoTrialGate(const std::uint8_t* buf, std::uint32_t n, std::uint32_t mask, bool reorder_ascii, bool cm) {
    const std::uint32_t sample = (n >> 3) < 0x20000u ? (n >> 3) : 0x20000u;
    std::vector<std::uint8_t> bwt(sample + 4u), payload;
    // baseline: the sample as it is, or its own size when it does not compress
    NzBwtTransform(buf, sample, bwt.data());
    std::uint32_t baseline = NzBwtEncodeInput(bwt.data(), sample, 0x600487u, payload);
    if (baseline == 0u) baseline = sample;
    // candidate: the sample through the pipeline, plus its side streams
    std::uint32_t candidate = sample;
    std::vector<std::uint8_t> a(sample + 0x1000u), b(sample + 0x1000u), tt2, tt16, side;
    std::memcpy(a.data(), buf, sample);
    std::uint8_t* pa = a.data();
    std::uint8_t* pb = b.data();
    std::uint8_t applied = 0;
    const std::uint32_t t = CoTextPipeline(mask, pa, sample, pb, 0x100040u, &applied, &tt2, &tt16, reorder_ascii, cm);
    if (t != 0u) {
        bwt.assign(t + 4u, 0);
        NzBwtTransform(pa, t, bwt.data());
        const std::uint32_t c = NzBwtEncodeInput(bwt.data(), t, 0x600487u, payload);
        if (c != 0u) candidate = c + CoSideStreamBytes(applied, tt2, tt16, &side);
    }
    const bool refuse = baseline <= candidate + (candidate >> 10);
    if (std::getenv("NZOPT_TRACE_TDO"))
        std::fprintf(stderr, "[tdo] gate n=%u sample=%u mask=0x%02x baseline=%u candidate=%u (%s, applied=0x%02x)\n",
                     n, sample, mask, baseline, candidate, refuse ? "REFUSED" : "accepted", applied);
    return !refuse;
}

}  // namespace nzr::opt_enc
