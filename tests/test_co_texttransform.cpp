// The `-co` text transforms' FORWARD passes against the original's own output.
//
// insert-LF (bit 0x02): the fixtures are generated (co_text_fixtures.h), and the
// side streams they must produce were read out of work/linux32/nz with the
// capture script cap.py (~/.cache/nzre_tools/encode/tt_forward): an entry
// breakpoint on FUN_080587f0 and one on its caller's return, dumping the input,
// the output and the aux-stream bytes the call appended. The original runs the
// pass twice per block -- on the trial gate's sample of n >> 3 bytes, then on
// the block -- so each fixture pins both sizes. Beyond the side bytes, the
// output has to round-trip through the decoder back to the text.
#include "nz_text_transform.h"
#include "nz_cm.h"
#include "co_text_fixtures.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
using namespace co_text_fixtures;

int g_failed = 0, g_total = 0;
void Check(const char* fx, const char* what, bool ok) {
    ++g_total;
    if (ok) return;
    ++g_failed;
    std::printf("FAIL %-8s %s\n", fx, what);
}

struct LfGolden {
    const char* name;
    std::string (*make)(std::uint32_t);
    std::uint32_t size;      // the whole fixture; the probe is size >> 3
    const char* side_probe;  // hex, the aux bytes of the n >> 3 pass
    const char* side_full;   // hex, the aux bytes of the whole block
};
const LfGolden kLf[] = {
    {"source", MakeSource, 30000u, "08ffffffffffff", "08ffffffffffffff"},
    {"markup", MakeMarkup, 30000u, "08ffff", "08ffff"},
};

std::vector<std::uint8_t> Hex(const char* h) {
    std::vector<std::uint8_t> v;
    for (; h[0] && h[1]; h += 2) v.push_back((std::uint8_t)std::stoul(std::string(h, 2), nullptr, 16));
    return v;
}

void InsertLfCase(const LfGolden& g, std::uint32_t n, const char* golden) {
    const std::string s = g.make(g.size);
    std::vector<std::uint8_t> in(s.begin(), s.begin() + n);
    in.resize(n + 64u);                                   // read-ahead slack
    std::vector<std::uint8_t> out(n + 64u), side, back(n + 64u);
    const std::uint32_t r = NzTextTransformInsertLfEncode(in.data(), n, out.data(), n + 64u, &side, n / 2u);
    char what[96];
    std::snprintf(what, sizeof(what), "n=%u accepted", n);
    Check(g.name, what, r == n);
    std::snprintf(what, sizeof(what), "n=%u side stream is the original's", n);
    Check(g.name, what, side == Hex(golden));
    const std::uint32_t m = NzTextTransformInsertLf(side.data(), (std::uint32_t)side.size(), out.data(), r, back.data(), n + 64u);
    std::snprintf(what, sizeof(what), "n=%u round trip", n);
    Check(g.name, what, m == n && std::memcmp(back.data(), s.data(), n) == 0);
}

// html (bit 0x04): FUN_08056080 captured the same way (entry breakpoint, return
// breakpoint at 0x08059328). The output is too long to spell out, so it is
// pinned by size and a 64-bit FNV-1a; `source` has no markup and the original
// declines it (returns 0) at both sizes, which is pinned too.
std::uint64_t Fnv(const std::uint8_t* p, std::size_t n) {
    std::uint64_t h = 0xcbf29ce484222325ull;
    for (std::size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 0x100000001b3ull; }
    return h;
}
struct HtmlGolden { const char* name; std::string (*make)(std::uint32_t); std::uint32_t n, out_n; std::uint64_t fnv; };
const HtmlGolden kHtml[] = {
    {"markup", MakeMarkup, 3750u, 3610u, 0x5d46526a569fc37bull},
    {"markup", MakeMarkup, 30000u, 28876u, 0x35cf98cf203da82aull},
    {"source", MakeSource, 3750u, 0u, 0u},
    {"source", MakeSource, 30000u, 0u, 0u},
};

void HtmlCase(const HtmlGolden& g) {
    const std::string s = g.make(30000u);
    std::vector<std::uint8_t> in(s.begin(), s.begin() + g.n);
    in.resize(g.n + 64u);
    std::vector<std::uint8_t> out(g.n + 64u), back(g.n + 64u);
    const std::uint32_t r = NzTextTransformHtmlEncode(in.data(), g.n, out.data(), g.n);
    char what[96];
    std::snprintf(what, sizeof(what), "html n=%u -> %u bytes (want %u)", g.n, r, g.out_n);
    Check(g.name, what, r == g.out_n);
    if (g.out_n == 0u) return;
    std::snprintf(what, sizeof(what), "html n=%u output is the original's", g.n);
    Check(g.name, what, Fnv(out.data(), r) == g.fnv);
    const std::uint32_t m = NzTextTransformHtml(out.data(), r, back.data(), g.n + 64u);
    std::snprintf(what, sizeof(what), "html n=%u round trip", g.n);
    Check(g.name, what, m == g.n && std::memcmp(back.data(), s.data(), g.n) == 0);
}

}  // namespace

int main() {
    for (const HtmlGolden& g : kHtml) HtmlCase(g);
    NzCmInitAll();
    for (const LfGolden& g : kLf) {
        InsertLfCase(g, g.size >> 3u, g.side_probe);
        InsertLfCase(g, g.size, g.side_full);
    }
    std::printf("co_texttransform: %d checks, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
