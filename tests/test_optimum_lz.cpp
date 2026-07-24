// Standalone isolation test for the -co (nz_optimum1) LZ/CM engine port
// (NzOptimumLzDecoder, src/nz_optimum_lz.cpp) against 4 golden vectors
// captured live from the real linux32/nz binary (GDB capture at the exact
// point FUN_0809e600's caller returns, i.e. the LZ core's own direct
// input/output, before any outer text-transform/RLE postfilter). See
// include/nz_optimum_lz.h and work/reports/decomp_optimum/
// optimum_lz_core_ARCHITECTURE.md for the full RE provenance.
//
// This MUST pass byte-exact on all 4 fixtures before the decoder is wired
// into sfx_archive.cpp's live dispatcher.
#include "nz_optimum_lz.h"
#include "nz_cm.h"  // NzCmInitAll() -- builds kLzModelInterpolation, which
                    // nz_optimum_lz.cpp's Stretch() reads; main.cpp calls this
                    // once at process startup for the live dispatcher, so this
                    // standalone harness must do the same.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "FATAL: cannot open %s\n", path.c_str());
        std::exit(2);
    }
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
}

int g_failed = 0;
int g_total = 0;

bool RunFixture(const std::string& dir, const std::string& name, std::uint32_t window_capacity) {
    ++g_total;
    auto in = ReadFile(dir + "/" + name + ".blk1.in.bin");
    auto expected = ReadFile(dir + "/" + name + ".blk1.out.bin");

    nzr::optimum::NzOptimumLzDecoder dec(window_capacity);
    std::vector<std::uint8_t> got(expected.size());
    bool ok = dec.DecodeBlock(in.data(), static_cast<std::uint32_t>(in.size()),
                               got.data(), static_cast<std::uint32_t>(expected.size()));
    if (!ok) {
        std::printf("FAIL %-16s: DecodeBlock returned false (in=%zu out_expected=%zu)\n",
                    name.c_str(), in.size(), expected.size());
        std::size_t first_diff = 0;
        while (first_diff < got.size() && got[first_diff] == expected[first_diff]) ++first_diff;
        std::printf("       first diverging byte (of partially-written buffer) @ %zu (got=%02x want=%02x)\n",
                    first_diff, first_diff < got.size() ? got[first_diff] : 0,
                    first_diff < expected.size() ? expected[first_diff] : 0);
        ++g_failed;
        return false;
    }
    if (got != expected) {
        std::size_t first_diff = 0;
        while (first_diff < got.size() && first_diff < expected.size() &&
               got[first_diff] == expected[first_diff]) {
            ++first_diff;
        }
        std::size_t ndiff = 0;
        for (std::size_t i = 0; i < got.size() && i < expected.size(); i++) {
            if (got[i] != expected[i]) ++ndiff;
        }
        std::printf("FAIL %-16s: byte mismatch, first diff @ %zu (got=%02x want=%02x), "
                    "%zu/%zu bytes differ\n",
                    name.c_str(), first_diff,
                    first_diff < got.size() ? got[first_diff] : 0,
                    first_diff < expected.size() ? expected[first_diff] : 0,
                    ndiff, expected.size());
        ++g_failed;
        return false;
    }
    std::printf("PASS %-16s: %zu -> %zu bytes byte-exact\n", name.c_str(), in.size(), expected.size());
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    NzCmInitAll();

    std::string dir = "tests/fixtures/optimum_golden";
    if (argc > 1) dir = argv[1];

    // Window capacities as captured live via GDB against the real archives
    // these blocks came from (subengine+0x40 -> ring struct's field[0]):
    //   matchfix_co: 0x10000, bigdist_co/smalldist_co: 0x60000, hientropy_co: 0x90000.
    RunFixture(dir, "matchfix_co", 0x10000u);
    RunFixture(dir, "bigdist_co", 0x60000u);
    RunFixture(dir, "smalldist_co", 0x60000u);
    RunFixture(dir, "hientropy_co", 0x90000u);

    std::printf("\n%d/%d golden vectors passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
