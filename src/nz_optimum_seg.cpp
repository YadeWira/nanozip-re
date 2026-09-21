// nz_optimum_seg.cpp -- see the header.
#include "nz_optimum_seg.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nzr::opt_enc {

namespace {

constexpr std::size_t kLeftTotal  = 0x000u;   // + ctx
constexpr std::size_t kRightTotal = 0x100u;   // + ctx
constexpr std::size_t kLeftCell   = 0x200u;   // + ctx * 0x100 + byte
constexpr std::size_t kRightCell  = 0x10200u; // + ctx * 0x100 + byte
constexpr std::size_t kCountWords = 0x20200u; // 0x80800 bytes

// The fixed-point log2 of nz_cm.cpp's Build_kModelInterpolation, at the shift
// FUN_0808c410 asks for (31): BSR for the integer part, then one squaring per
// fractional bit.
std::uint64_t Log2Fixed(std::uint64_t v, unsigned shift) {
    if (v <= 1u) return 0;
    unsigned bits = 0;
    for (std::uint64_t t = v; t > 1u; t >>= 1) ++bits;
    std::uint64_t result = static_cast<std::uint64_t>(bits) << shift;
    std::uint64_t q = std::uint64_t{1} << shift;
    std::uint64_t m = (v << shift) >> bits;
    while ((q >>= 1) != 0u) {
        m = (m * m) >> shift;
        if (m >= (std::uint64_t{2} << shift)) { result += q; m >>= 1; }
    }
    return result;
}

// FUN_0808c410 builds both tables over 1 .. 0x4000, the second one biased by
// -2 so that tbl2[k] is the exact k -> k+1 step of the cost.
//   tbl1[v] = round(log2(v) * 4096)                      (the per-symbol cost)
//   M(c)    = (log2fp(c) * c + 0x40000) >> 19            (the whole cell's cost)
//   tbl2[k] = M(k+1) - M(k), truncated to 16 bits
// Verified against both tables dumped out of the running original: 0 of 16385
// entries differ.
struct CostTables {
    std::uint16_t log1[0x4001];
    std::uint16_t step[0x4001];
    CostTables() {
        std::memset(log1, 0, sizeof(log1));
        std::memset(step, 0, sizeof(step));
        std::uint64_t prev = 0;
        for (std::uint32_t k = 1; k <= 0x4000u; ++k) {
            const std::uint64_t L = Log2Fixed(k, 31);
            log1[k] = static_cast<std::uint16_t>((L + 0x40000u) >> 19);
            const std::uint64_t M = (L * k + 0x40000u) >> 19;
            step[k - 1u] = static_cast<std::uint16_t>(M - prev);
            prev = M;
        }
    }
};
const CostTables& Tab() { static const CostTables t; return t; }

// The per-cell cost of a count: the table below 0x4001, and above it the table
// entry of the top 14 bits plus a bit per shift.
inline std::uint32_t LogCost(std::uint32_t v) {
    const CostTables& t = Tab();
    if (v < 0x4001u) return t.log1[v];
    unsigned bsr = 0;
    for (std::uint32_t x = v; x > 1u; x >>= 1) ++bsr;
    const unsigned sh = bsr - 13u;
    return t.log1[v >> sh] + sh * 0x1000u;
}
inline std::int64_t Mul(std::uint32_t v) { return static_cast<std::int64_t>(v) * LogCost(v); }

// The cost of moving one count between `lo` and `lo + 1`: the step table where
// it reaches, the from-scratch difference above it.
inline std::int64_t Step(std::uint32_t lo) {
    if (lo < 0x4000u) return Tab().step[lo];
    return Mul(lo + 1u) - Mul(lo);
}

}  // namespace

CoSegmenter::CoSegmenter() : counts(kCountWords, 0u), snapshot(kCountWords, 0u) {}

void CoSegmenter::Reset() {
    prev_cost = 0;
    cost = 0;
    ctx = 0;
    std::fill(counts.begin(), counts.end(), 0u);
}

void CoSegmenter::Fold() {
    for (std::uint32_t cv = 0; cv < 0x100u; ++cv) {
        counts[kLeftTotal + cv] += counts[kRightTotal + cv];
        counts[kRightTotal + cv] = 0u;
        std::uint32_t* l = &counts[kLeftCell + cv * 0x100u];
        std::uint32_t* r = &counts[kRightCell + cv * 0x100u];
        for (std::uint32_t b = 0; b < 0x100u; ++b) { l[b] += r[b]; r[b] = 0u; }
    }
}

void CoSegmenter::Prime(const std::uint8_t* buf, std::uint32_t n) {
    std::uint32_t c = ctx;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t b = buf[i];
        ++counts[kLeftCell + c * 0x100u + b];
        c = (c * 0x20u + b) & 0xffu;
    }
    ctx = c;

    std::int64_t total_cost = 0;
    for (std::uint32_t cv = 0; cv < 0x100u; ++cv) {
        std::uint32_t sum = 0;
        for (std::uint32_t b = 0; b < 0x100u; ++b) {
            const std::uint32_t v = counts[kLeftCell + cv * 0x100u + b];
            sum += v;
            total_cost -= static_cast<std::int64_t>(v) * LogCost(v);
        }
        counts[kLeftTotal + cv] = sum;
        total_cost += static_cast<std::int64_t>(LogCost(sum)) * sum;
    }
    // As written in the original: the low half of the OLD cost and the high half
    // of the NEW one land in the saved slot, because the save happens after the
    // store. Only the multi-round path reads it back.
    const std::uint32_t old_low = static_cast<std::uint32_t>(cost);
    cost = total_cost;
    prev_cost = static_cast<std::int64_t>(
        (static_cast<std::uint64_t>(static_cast<std::uint32_t>(cost >> 32)) << 32) | old_low);
    snapshot = counts;
}

std::uint32_t CoSegmenter::Split(const std::uint8_t* buf, std::uint32_t n, std::uint32_t lower) {
    if (n <= lower + 0x1000u) return n;

    std::int64_t left = cost;
    std::int64_t right = 0;
    // A split has to beat the unsplit cost by a thirty-second of it plus
    // 0x2000000, which in these units (4096 per bit) is 1 KB.
    std::int64_t best = cost - static_cast<std::int64_t>(static_cast<std::uint64_t>(cost) >> 5) -
                        0x2000000;
    std::uint32_t best_len = n;
    std::uint32_t pos = n;
    for (;;) {
        --pos;
        if (pos < lower + 2u) break;
        const std::uint32_t c = (static_cast<std::uint32_t>(buf[pos - 2u]) * 0x20u +
                                 buf[pos - 1u]) & 0xffu;
        const std::uint32_t cell = c * 0x100u + buf[pos];

        const std::uint32_t lc = counts[kLeftCell + cell];
        counts[kLeftCell + cell] = lc - 1u;
        left += Step(lc - 1u);

        const std::uint32_t rc = counts[kRightCell + cell];
        counts[kRightCell + cell] = rc + 1u;
        right -= Step(rc);

        const std::uint32_t lt = counts[kLeftTotal + c];
        counts[kLeftTotal + c] = lt - 1u;
        left -= Step(lt - 1u);

        const std::uint32_t rt = counts[kRightTotal + c];
        counts[kRightTotal + c] = rt + 1u;
        right += Step(rt);

        const std::int64_t total = left + right;
        if (const char* rp = std::getenv("NZOPT_SPLIT_AT")) {
            if (pos == static_cast<std::uint32_t>(std::atoi(rp)))
                std::fprintf(stderr, "[SPLIT] at pos=%u total=%lld (best so far %lld at %u)\n",
                             pos, (long long)total, (long long)best, best_len);
        }
        if (total < best) { best = total; best_len = pos; }
    }
    if (std::getenv("NZOPT_TRACE_SPLIT"))
        std::fprintf(stderr, "[SPLIT] n=%u lower=%u -> best_len=%u best=%lld cost=%lld\n",
                     n, lower, best_len, (long long)best, (long long)cost);
    return best_len;
}

std::uint32_t CoBlockLength(const std::uint8_t* buf, std::uint32_t n, std::uint32_t block_size) {
    const std::uint32_t take = (block_size < n) ? block_size : n;
    CoSegmenter seg;
    seg.Prime(buf, take);
    const std::uint32_t r = seg.Split(buf, take, 0u);
    if (std::getenv("NZOPT_TRACE_TDO") != nullptr)
        std::fprintf(stderr, "[tdo] segment n=%u take=%u -> %u\n", n, take, r);
    return r;
}

void CoBlockFeeder::Feed(const std::uint8_t* p, std::size_t n) {
    if (n == 0u) return;
    if (pend_off != 0u) { pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(pend_off)); pend_off = 0; }
    pending.insert(pending.end(), p, p + n);
}

bool CoBlockFeeder::Next(std::uint32_t block_size, bool final) {
    if (std::getenv("NZOPT_TRACE_FEED"))
        std::fprintf(stderr, "[FEED] enter block_size=%u final=%d pending=%zu ring=%zu total=%u\n",
                     block_size, (int)final, pending.size() - pend_off, ring.size(), total);
    if (dst.size() < static_cast<std::size_t>(block_size) + 0x2010u)
        dst.resize(static_cast<std::size_t>(block_size) + 0x2010u, 0u);
    if (!started) { total = 0; budget = block_size; }
    for (;;) {                                   // LAB_0808d0de
        // The read loop. The reader is asked for more until the buffer holds
        // 0xff000 bytes or it hands back nothing; the audio/image detector that
        // sits in this loop is not written, so a detected region is not forced
        // into its own block here.
        while (ring.size() + 0x1000u <= 0xfffffu && pend_off < pending.size()) {
            const std::size_t got = std::min<std::size_t>(0x100000u - ring.size(),
                                                          pending.size() - pend_off);
            ring.insert(ring.end(), pending.begin() + static_cast<std::ptrdiff_t>(pend_off),
                        pending.begin() + static_cast<std::ptrdiff_t>(pend_off + got));
            pend_off += got;
        }
        if (pend_off >= pending.size() && !pending.empty()) { pending.clear(); pend_off = 0; }
        if (ring.size() + 0x1000u <= 0xfffffu && !final) {
            // the reader would have gone on into the next piece; wait for it
            started = (total != 0u);
            return false;
        }
        if (ring.empty()) {                      // LAB_0808d237, param_1[3] == 0
            started = false;
            if (total == 0u) return false;       // the stream is over
            blk_len = total;
            return true;
        }
        const std::uint32_t take = std::min<std::uint32_t>(budget, static_cast<std::uint32_t>(ring.size()));
        const std::uint32_t prev = total;
        if (prev == 0u) seg.Reset(); else seg.Fold();
        std::memcpy(dst.data() + prev, ring.data(), take);   // FUN_080aee40
        ring.erase(ring.begin(), ring.begin() + static_cast<std::ptrdiff_t>(take));
        seg.Prime(dst.data() + prev, take);
        total = prev + take;
        // A detected audio/image span ends the block by itself: the reference
        // sets the length in the read loop and never reaches the entropy split.
        std::uint32_t forced = 0;
        if (prev == 0u && span_probe) forced = span_probe(dst.data(), take);
        const std::uint32_t split = (forced != 0u && forced <= total)
                                        ? forced
                                        : seg.Split(dst.data(), total, prev);
        if (std::getenv("NZOPT_TRACE_FEED"))
            std::fprintf(stderr, "[FEED] prev=%u take=%u total=%u forced=%u split=%u\n",
                         prev, take, total, forced, split);
        if (split < total) {                     // LAB_0808d355
            const std::uint32_t tail = total - split;
            started = false;
            if (static_cast<std::size_t>(tail) + ring.size() > 0x100000u) {
                blk_len = total;                 // no room to give it back: keep it whole
                return true;
            }
            ring.insert(ring.begin(), dst.begin() + split, dst.begin() + total);
            blk_len = split;                     // the tail stays in `dst` as the slack
            return true;
        }
        budget -= take;
        if (budget < 0x1001u) { started = false; blk_len = total; return true; }
        started = true;                          // go back for more and extend this block
    }
}

}  // namespace nzr::opt_enc
