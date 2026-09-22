// The forward BWT (the -co family's encoder): the rotation sort, both routes.
//
// NzBwtTransform sorts the rotations of a block with a linear-time suffix sort
// over the block written twice, and falls back to prefix doubling for a block
// whose rotations are not all distinct (a periodic one), where the suffix order
// goes on comparing past the end of the rotation and the two orders part.
//
// So this checks two things. Against a NAIVE rotation sort, on every block
// whose rotations are distinct -- there the answer is unique and the reference
// is the definition itself. And against NzBwtUntransform on every block,
// periodic ones included, where the order is a convention of the original's and
// only the round trip is meaningful.
//
// Run it a second time with NZOPT_BWT_DOUBLING=1 in the environment to put the
// same cases through the doubling route (the switch is read once per run).
#include "nz_bwt.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

int checks = 0, failed = 0;

void Check(bool ok, const std::string& what) {
    ++checks;
    if (!ok) { ++failed; std::printf("FAIL: %s\n", what.c_str()); }
}

struct Rng {
    std::uint32_t s;
    explicit Rng(std::uint32_t seed) : s(seed ? seed : 1u) {}
    std::uint32_t operator()() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
};

// Every rotation its own? Only then is the sort's answer unique.
bool Distinct(const std::vector<std::uint8_t>& in) {
    const std::uint32_t n = (std::uint32_t)in.size();
    for (std::uint32_t d = 1; d < n; ++d) {
        bool same = true;
        for (std::uint32_t i = 0; i < n && same; ++i) same = in[i] == in[(i + d) % n];
        if (same) return false;
    }
    return true;
}

// The definition: sort the rotations, write the byte before each one.
std::uint32_t Naive(const std::vector<std::uint8_t>& in, std::vector<std::uint8_t>& out) {
    const std::uint32_t n = (std::uint32_t)in.size();
    std::vector<std::uint32_t> sa(n);
    for (std::uint32_t i = 0; i < n; ++i) sa[i] = i;
    std::sort(sa.begin(), sa.end(), [&](std::uint32_t a, std::uint32_t b) {
        for (std::uint32_t t = 0; t < n; ++t) {
            const std::uint8_t x = in[(a + t) % n], y = in[(b + t) % n];
            if (x != y) return x < y;
        }
        return false;
    });
    out.resize(n);
    std::uint32_t primary = 0;
    for (std::uint32_t j = 0; j < n; ++j) {
        if (sa[j] == 0u) primary = j;
        out[j] = in[(sa[j] + n - 1u) % n];
    }
    return primary;
}

void OneBlock(const std::vector<std::uint8_t>& in, const std::string& what) {
    const std::uint32_t n = (std::uint32_t)in.size();
    std::vector<std::uint8_t> got(n);
    const std::uint32_t primary = NzBwtTransform(in.data(), n, got.data());
    if (n <= 2000u && Distinct(in)) {
        std::vector<std::uint8_t> want;
        const std::uint32_t want_primary = Naive(in, want);
        Check(got == want && primary == want_primary, what + ": contra el orden de rotaciones");
    }
    std::vector<std::uint8_t> back = got;
    Check(NzBwtUntransform(back.data(), n, primary) && back == in, what + ": ida y vuelta");
}

}  // namespace

int main() {
    std::printf("ruta: %s\n", std::getenv("NZOPT_BWT_DOUBLING") ? "doubling" : "suffix sort lineal");
    Rng rng(20260922u);
    // Sizes around the point where the linear route takes over (1024) and well
    // past it, over the shapes that stress a rotation sort: long runs, a tiny
    // alphabet, a periodic block, and one that is periodic but for a byte.
    const std::uint32_t sizes[] = {1, 2, 3, 17, 255, 256, 1023, 1024, 1025, 4096, 40000};
    for (std::uint32_t n : sizes) {
        for (int kind = 0; kind < 8; ++kind) {
            std::vector<std::uint8_t> in(n);
            for (std::uint32_t i = 0; i < n; ++i) {
                switch (kind) {
                    case 0: in[i] = (std::uint8_t)rng(); break;
                    case 1: in[i] = (std::uint8_t)(rng() & 1u); break;
                    case 2: in[i] = 'a'; break;                       // toda rotación igual
                    case 3: in[i] = (std::uint8_t)"abcabcabc"[i % 9]; break;
                    case 4: in[i] = (std::uint8_t)(i % 4u ? 'x' : (std::uint8_t)('a' + rng() % 3u)); break;
                    case 5: in[i] = (std::uint8_t)(i & 1u ? 0u : (std::uint8_t)rng()); break;
                    case 6: in[i] = (std::uint8_t)(i < n / 2u ? 0u : 255u); break;
                    default: in[i] = (std::uint8_t)(i % 251u); break;
                }
            }
            OneBlock(in, "n=" + std::to_string(n) + " forma=" + std::to_string(kind));
            if (n > 4u) {   // the same block one byte away from periodic
                std::vector<std::uint8_t> broken = in;
                broken[n / 2u] ^= 0x55u;
                OneBlock(broken, "n=" + std::to_string(n) + " forma=" + std::to_string(kind) + " roto");
            }
        }
    }
    // Exact repetitions: the case the periodic fallback exists for.
    for (std::uint32_t period : {1u, 2u, 3u, 7u, 100u, 1100u}) {
        std::vector<std::uint8_t> pat(period);
        for (std::uint32_t i = 0; i < period; ++i) pat[i] = (std::uint8_t)rng();
        for (std::uint32_t reps : {2u, 3u, 37u}) {
            std::vector<std::uint8_t> in(period * reps);
            for (std::uint32_t i = 0; i < in.size(); ++i) in[i] = pat[i % period];
            OneBlock(in, "periodo=" + std::to_string(period) + " x" + std::to_string(reps));
        }
    }
    std::printf("%d checks, %d failed\n", checks, failed);
    return failed != 0;
}
