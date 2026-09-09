// nz_optimum_text.cpp -- see the header.
#include "nz_optimum_text.h"
#include "nz_lzhd_text.h"
#include "nz_cd_texttransform_dict.h"

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

}  // namespace nzr::opt_enc
