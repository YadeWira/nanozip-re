// The `-co` text detector (src/nz_optimum_text.cpp) against golden values read
// live out of the original binary.
//
// Every fixture below is generated here by a fixed rule, so the test carries no
// data files. `--dump <dir>` writes them out; the goldens were then captured from
// work/linux32/nz with two GDB probes:
//
//   break *0x08054e60   -- FUN_08054e60's argument is FUN_08054b50's finished
//                          object, so its +0x400/404/408/409/40c and hist[10]/[13]
//                          are the analysis, field for field
//   break *0x0808eb0f   -- the instruction that loads FUN_0808f8e0's fourth
//                          argument, which is the mask the driver ASKS for,
//                          before the trial gate has a say
//
//   nz a -co -t1 -m4m -y out.nz <fixture>
//
// A fixture that never reaches the second probe asked for nothing: mask 0.
#include "nz_optimum_text.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

// A 32-bit xorshift, so the fixtures are the same bytes on every platform.
struct Rng {
    std::uint32_t s;
    explicit Rng(std::uint32_t seed) : s(seed) {}
    std::uint32_t operator()() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    std::uint32_t Upto(std::uint32_t n) { return (*this)() % n; }
};

void Line(std::string& out, Rng& r, const char* const* words, int nwords, std::uint32_t len) {
    std::uint32_t w = 0;
    while (w < len) {
        const char* s = words[r.Upto(static_cast<std::uint32_t>(nwords))];
        out += s;
        out += ' ';
        w += static_cast<std::uint32_t>(std::strlen(s)) + 1u;
    }
    out += '\n';
}

const char* const kWords[] = {"the", "value", "return", "buffer", "size", "block", "index",
                              "count", "table", "offset", "length", "stream", "record", "data"};

// Source-shaped text: short indented lines, punctuation, a few numbers.
std::string MakeSource(std::uint32_t bytes) {
    Rng r(0x5eed0001u);
    std::string out;
    while (out.size() < bytes) {
        switch (r.Upto(4u)) {
            case 0: out += "    if (size > 0x"; out += "0123456789abcdef"[r.Upto(16u)];
                    out += "00u) return count;\n"; break;
            case 1: out += "  const unsigned "; Line(out, r, kWords, 14, 24u); break;
            case 2: out += "\tbuffer[index + "; out += static_cast<char>('0' + r.Upto(10u));
                    out += "] = table[offset];\n"; break;
            default: out += "  // "; Line(out, r, kWords, 14, 40u); break;
        }
    }
    out.resize(bytes);
    return out;
}

// Prose: long lines, no digits, no markup.
std::string MakeProse(std::uint32_t bytes) {
    Rng r(0x5eed0002u);
    std::string out;
    while (out.size() < bytes) Line(out, r, kWords, 14, 110u);
    out.resize(bytes);
    return out;
}

// Markup: angle brackets and slashes in the proportion the html predicate wants.
std::string MakeMarkup(std::uint32_t bytes) {
    Rng r(0x5eed0003u);
    std::string out;
    while (out.size() < bytes) {
        out += "<p class=\"row\">";
        Line(out, r, kWords, 14, 30u);
        out += "</p>\n";
    }
    out.resize(bytes);
    return out;
}

// Dotted numbers: the digit route's own shape (version strings, quads).
std::string MakeDotted(std::uint32_t bytes) {
    Rng r(0x5eed0004u);
    std::string out;
    char buf[64];
    while (out.size() < bytes) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u host%u\n", r.Upto(250u) + 1u, r.Upto(250u) + 1u,
                      r.Upto(250u) + 1u, r.Upto(250u) + 1u, r.Upto(1000u));
        out += buf;
    }
    out.resize(bytes);
    return out;
}

// Not text at all: a byte stream with no letter bias.
std::string MakeBinary(std::uint32_t bytes) {
    Rng r(0x5eed0005u);
    std::string out;
    out.reserve(bytes);
    while (out.size() < bytes) out += static_cast<char>(r() & 0xffu);
    return out;
}

struct Fixture {
    const char* name;
    std::string (*make)(std::uint32_t);
    std::uint32_t size;
    // the original's analysis, field for field, then the mask it asks for
    std::uint32_t sample, dedup;
    unsigned s9d, s19, meanline, h10, h13;
    unsigned mask;
    // Whether the analysis itself is compared. The original cuts its blocks by
    // what the LZ parser does with them, not by a size rule, and 30 KB of random
    // bytes comes out as three blocks with three separate analyses -- so for that
    // fixture only the answer is pinned, which is that the block is not text.
    bool check_obj;
};

// Read out of the original with the two probes above.
const Fixture kFixtures[] = {
    {"source", MakeSource, 30000u, 3750u, 1347u, 100u, 89u, 78u, 89u, 0u, 0x1eu, true},
    {"prose",  MakeProse,  30000u, 3750u, 1870u, 100u, 100u, 113u, 32u, 0u, 0x0cu, true},
    {"markup", MakeMarkup, 30000u, 3750u, 1220u, 100u, 95u, 64u, 140u, 0u, 0x0eu, true},
    {"dotted", MakeDotted, 30000u, 3750u, 3598u, 100u, 38u, 22u, 168u, 0u, 0x1cu, true},
    {"binary", MakeBinary, 30000u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0x00u, false},
};

int g_failed = 0, g_total = 0;

void Check(const char* what, const char* fx, unsigned long got, unsigned long want) {
    ++g_total;
    if (got == want) return;
    ++g_failed;
    std::printf("FAIL %-8s %-9s got %lu, want %lu\n", fx, what, got, want);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::strcmp(argv[1], "--dump") == 0) {
        for (const Fixture& f : kFixtures) {
            const std::string s = f.make(f.size);
            const std::string path = std::string(argv[2]) + "/" + f.name + ".bin";
            std::ofstream o(path, std::ios::binary);
            o.write(s.data(), static_cast<std::streamsize>(s.size()));
            std::printf("%s %zu bytes\n", path.c_str(), s.size());
        }
        return 0;
    }

    for (const Fixture& f : kFixtures) {
        const std::string s = f.make(f.size);
        // The detector reads a few bytes past the sample, as the original does
        // inside a block that is always followed by more of the buffer.
        std::vector<std::uint8_t> buf(s.size() + 0x40u, 0);
        std::memcpy(buf.data(), s.data(), s.size());
        std::vector<std::uint8_t> scratch(s.size() + 0x1000u, 0);

        if (f.check_obj) {
            nzr::opt_enc::CoTextObj o;
            nzr::opt_enc::CoTextAnalyze(o, buf.data(), f.size >> 3u);
            Check("sample", f.name, o.n, f.sample);
            Check("dedup", f.name, o.dedup, f.dedup);
            Check("s9d", f.name, o.s9d, f.s9d);
            Check("s19", f.name, o.s19, f.s19);
            Check("meanline", f.name, o.meanline, f.meanline);
            Check("hist[10]", f.name, o.hist[10], f.h10);
            Check("hist[13]", f.name, o.hist[13], f.h13);
        }

        bool route = false;
        const std::uint32_t mask =
            nzr::opt_enc::CoTextFlags(buf.data(), f.size, scratch.data(), false, &route);
        Check("mask", f.name, mask, f.mask);
    }

    std::printf("co_textdetect: %d checks, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
