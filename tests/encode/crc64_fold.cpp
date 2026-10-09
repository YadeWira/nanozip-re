// crc64_fold.cpp -- the self-check's folded CRC-64 against its table version.
//
// Random lengths (0..70000, plus every length up to 600), random start offsets
// (the loads are unaligned) and random split points through Update, which is
// how the writer and the reader feed it. Prints how many cases ran and whether
// the fold was available; any mismatch fails.
// build: g++ -std=c++17 -O2 -Iinclude tests/encode/crc64_fold.cpp src/nz_selfcheck_crc.cpp -o /tmp/crc64_fold
#include "nz_selfcheck.h"

#include <cstdio>
#include <random>
#include <vector>

using nzr::selfcheck::Crc64;

static std::uint64_t TableOnly(const unsigned char* p, std::size_t n) {
    Crc64 c; c.UpdateTable(p, n); return c.Final();
}

int main() {
    std::mt19937_64 rng(12345);
    std::vector<unsigned char> buf(70000 + 64);
    for (auto& b : buf) b = static_cast<unsigned char>(rng());
    // the standard check value of CRC-64/XZ
    const unsigned char* nine = reinterpret_cast<const unsigned char*>("123456789");
    if (Crc64::Of(nine, 9) != 0x995dc9bbdf1939faull) { std::printf("crc64_fold: check value wrong\n"); return 1; }
    std::size_t cases = 0, bad = 0;
    auto one = [&](std::size_t off, std::size_t n, std::size_t split) {
        const std::uint64_t want = TableOnly(buf.data() + off, n);
        Crc64 a; a.Update(buf.data() + off, n);
        Crc64 b; b.Update(buf.data() + off, split); b.Update(buf.data() + off + split, n - split);
        ++cases;
        if (a.Final() != want || b.Final() != want) {
            if (++bad <= 5) std::printf("MISMATCH off=%zu n=%zu split=%zu\n", off, n, split);
        }
    };
    for (std::size_t n = 0; n <= 600; ++n) one(n % 17, n, n / 3);
    for (int t = 0; t < 3000; ++t) {
        const std::size_t n = static_cast<std::size_t>(rng() % 70001);
        const std::size_t off = static_cast<std::size_t>(rng() % 64);
        const std::size_t split = n == 0 ? 0 : static_cast<std::size_t>(rng() % (n + 1));
        one(off, n, split);
    }
    std::printf("crc64_fold: %zu/%zu same (fold %s)\n", cases - bad, cases,
                nzr::selfcheck::Crc64FoldAvailable() ? "available" : "NOT available: table only");
    return bad == 0 ? 0 : 1;
}
