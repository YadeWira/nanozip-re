// param1 (the -co AddBytes delta filter) encoder <-> decoder round trip.
//
// The byte-exactness of the encoder against the original is checked by the
// archive comparison in tdo/e2e_html (47/47 corpus files); what this guards is
// the pair: whatever regions the encoder decides to emit, our own
// NzAddBytesFilter must reconstruct the block from them exactly.
#include "nz_optimum_param1.h"
#include "nz_postfilter.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
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

// A block with a strong periodic component at `period`, the shape param1 looks
// for: consecutive records whose bytes differ from the record before by a small
// alphabet.
std::vector<std::uint8_t> MakePeriodic(std::size_t n, std::uint32_t period,
                                       std::uint32_t seed, int noise) {
    Rng rng(seed);
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        if (i < period) v[i] = static_cast<std::uint8_t>('0' + (rng() % 10u));
        else v[i] = static_cast<std::uint8_t>(v[i - period] +
                                              static_cast<std::uint8_t>(rng() % (noise + 1)));
    }
    return v;
}

void RoundTrip(const std::vector<std::uint8_t>& in, const std::string& name) {
    std::vector<std::uint8_t> out, side;
    const bool taken = nzr::opt_enc::NzOptimumParam1Encode(
        in.data(), static_cast<std::uint32_t>(in.size()), &out, &side);
    if (!taken) return;                       // declining is a valid answer
    Check(out.size() == in.size(), name + ": output keeps the block size");
    Check(!side.empty(), name + ": a taken filter has a side stream");
    Check(side.size() < 0x800u, name + ": the side stream stays under half its budget");

    std::vector<std::uint8_t> back(in.size() + 16, 0);
    const bool ok = NzAddBytesFilter(side.data(), static_cast<std::uint32_t>(side.size()),
                                     out.data(), static_cast<std::uint32_t>(out.size()),
                                     back.data());
    Check(ok, name + ": the decoder accepts the stream");
    if (!ok) return;
    Check(std::memcmp(back.data(), in.data(), in.size()) == 0,
          name + ": the decoder reconstructs the block");
}

}  // namespace

int main() {
    // Blocks the filter should like: a periodic record structure, several
    // offsets, a few noise levels.
    for (std::uint32_t period : {16u, 32u, 48u, 69u, 128u}) {
        for (int noise : {0, 1, 3}) {
            for (std::uint32_t seed : {1u, 7u, 12345u}) {
                char nm[96];
                std::snprintf(nm, sizeof(nm), "periodic p=%u noise=%d seed=%u",
                              period, noise, seed);
                RoundTrip(MakePeriodic(20000, period, seed, noise), nm);
            }
        }
    }
    // Blocks it should not crash on: too short, all one byte, pure noise.
    for (std::size_t n : {0u, 1u, 100u, 263u, 264u, 300u, 5000u}) {
        std::vector<std::uint8_t> z(n, 0x41);
        RoundTrip(z, "constant n=" + std::to_string(n));
        Rng rng(static_cast<std::uint32_t>(n) + 1u);
        std::vector<std::uint8_t> r(n);
        for (std::size_t i = 0; i < n; ++i) r[i] = static_cast<std::uint8_t>(rng());
        RoundTrip(r, "random n=" + std::to_string(n));
    }
    // A block whose tail is periodic and whose head is not: the region must not
    // start before byte 255, which the decoder copies verbatim.
    {
        Rng rng(99);
        std::vector<std::uint8_t> v(16000);
        for (std::size_t i = 0; i < 4000; ++i) v[i] = static_cast<std::uint8_t>(rng());
        for (std::size_t i = 4000; i < v.size(); ++i)
            v[i] = static_cast<std::uint8_t>((i < 4032) ? (rng() % 251u)
                                                        : (v[i - 32] + (rng() % 2u)));
        RoundTrip(v, "mixed head/tail");
    }
    std::printf("co_param1: %d checks, %d failed\n", checks, failed);
    return failed == 0 ? 0 : 1;
}
