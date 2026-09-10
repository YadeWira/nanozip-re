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
#include "nz_texttransform_num.h"
#include "nz_bwt.h"
#include "nz_optimum_text.h"
#include "nz_lzhd_text.h"
#include "nz_cd_texttransform_dict.h"
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

// number (bit 0x10), and the chain in front of it. FUN_08058580 was captured
// the same way (entry breakpoint, epilogue at 0x080585a1) on the generated
// fixtures. Its INPUT is what the earlier steps made of the text, so each case
// first runs the chain FUN_08059060 would run for the fixture's mask -- insert-LF,
// html, dictionary with the inverse reorder -- and pins that intermediate against
// the captured input before pinning the number pass's output and side stream.
// Everything longer than a few bytes is pinned by size and 64-bit FNV-1a.
struct NumGolden {
    const char* name;
    std::string (*make)(std::uint32_t);
    std::uint32_t n;          // the block: the trial gate's sample or the whole fixture
    unsigned mask;            // what the detector asks for on this fixture
    std::uint32_t in_n; std::uint64_t in_fnv;   // the number pass's input (the chain's output)
    std::uint64_t out_fnv;                      // its output (same size as the input)
    std::uint32_t side_n; std::uint64_t side_fnv;
};
const NumGolden kNum[] = {
    {"source", MakeSource, 3750u, 0x1eu, 2130u, 0x11c4c394f55229e8ull, 0x2af43b4e5c0f4eacull, 31u, 0xed2a67ef50e779d7ull},
    {"source", MakeSource, 30000u, 0x1eu, 17110u, 0xa237813ba14c0fa6ull, 0x47db5359c32f71ebull, 184u, 0x0d71263f8750c2afull},
    {"dotted", MakeDotted, 3750u, 0x1cu, 2169u, 0x5acb1c8fcb3a1721ull, 0xcb454655d6ba0f80ull, 217u, 0xc9464731da3f304dull},
    {"dotted", MakeDotted, 30000u, 0x1cu, 17450u, 0xc75efa0a7defe505ull, 0x8d07158da7ac15faull, 1725u, 0xcbab8a1372da118dull},
};

std::uint32_t InvReorder(std::uint8_t* p, std::uint32_t n) {
    static std::uint8_t inv[256];
    static bool built = false;
    if (!built) { const unsigned char* f = nzr::cd::NzCdReorderAscii(); for (unsigned c = 0; c < 256u; ++c) inv[f[c]] = (std::uint8_t)c; built = true; }
    for (std::uint32_t i = 0; i < n; ++i) p[i] = inv[p[i]];
    return n;
}

void NumCase(const NumGolden& g) {
    const std::string s = g.make(30000u);
    std::vector<std::uint8_t> buf(s.begin(), s.begin() + g.n);
    buf.resize(g.n + 0x1000u);
    std::vector<std::uint8_t> tmp(g.n + 0x1000u), side;
    std::uint32_t n = g.n;
    char what[96];
    // the chain in FUN_08059060's order, each step landing only when it returns non-zero
    if (g.mask & 0x02u) { const std::uint32_t r = NzTextTransformInsertLfEncode(buf.data(), n, tmp.data(), (std::uint32_t)tmp.size(), &side, n); if (r) { buf.swap(tmp); n = r; } }
    if (g.mask & 0x04u) { const std::uint32_t r = NzTextTransformHtmlEncode(buf.data(), n, tmp.data(), n); if (r) { buf.swap(tmp); n = r; } }
    if (g.mask & 0x08u) { const std::uint32_t r = nzr::lzhd_enc::TextDictEncode(buf.data(), n, tmp.data(), n); if (r) { buf.swap(tmp); n = r; InvReorder(buf.data(), n); } }
    std::snprintf(what, sizeof(what), "n=%u chain output is the number pass's captured input", g.n);
    Check(g.name, what, n == g.in_n && Fnv(buf.data(), n) == g.in_fnv);
    std::vector<std::uint8_t> out(n + 64u), back(n + 65600u);
    const std::uint32_t r = NzTextTransformNumberEncode(buf.data(), n, out.data(), n + 64u, &side, 4299161u);
    std::snprintf(what, sizeof(what), "n=%u number pass output is the original's", g.n);
    Check(g.name, what, r == n && Fnv(out.data(), r) == g.out_fnv);
    std::snprintf(what, sizeof(what), "n=%u number side stream is the original's", g.n);
    Check(g.name, what, side.size() == g.side_n && Fnv(side.data(), side.size()) == g.side_fnv);
    const std::uint32_t m = NzTextTransformNumber(side.data(), (std::uint32_t)side.size(), out.data(), r, back.data(), (std::uint32_t)back.size());
    std::snprintf(what, sizeof(what), "n=%u number round trip", g.n);
    Check(g.name, what, m == n && std::memcmp(back.data(), buf.data(), n) == 0);
}

// The forward BWT (the trial gate's first step), against FUN_0805d1e0 captured
// at its call and return in FUN_0808f8e0 on the gate's 3750-byte sample of each
// fixture: the output by size and FNV, and the primary index it returns.
struct BwtGolden { const char* name; std::string (*make)(std::uint32_t); std::uint32_t n; std::uint64_t fnv; std::uint32_t primary; };
const BwtGolden kBwt[] = {
    {"source", MakeSource, 3750u, 0xc62520aacc938d64ull, 216u},
    {"markup", MakeMarkup, 3750u, 0x04cdfda58278660dull, 865u},
};
void BwtCase(const BwtGolden& g) {
    const std::string s = g.make(30000u);
    std::vector<std::uint8_t> in(s.begin(), s.begin() + g.n), out(g.n + 4u);
    const std::uint32_t primary = NzBwtTransform(in.data(), g.n, out.data());
    Check(g.name, "bwt output is the original's", Fnv(out.data(), g.n) == g.fnv);
    Check(g.name, "bwt primary index is the original's", primary == g.primary);
    std::vector<std::uint8_t> back(out.begin(), out.begin() + g.n);
    Check(g.name, "bwt round trip", NzBwtUntransform(back.data(), g.n, primary) && back == in);
}

// The BWT bucket coder (FUN_0806c350), the trial gate's second step: the BWT of
// each fixture's 3750-byte sample coded as the original codes it under -t1 --
// one bucket, the RLE pre-pass, the rank coder -- pinned by size and FNV against
// FUN_0806c350's payload captured at its call and return in the gate, and
// round-tripped through NzBwtDecodeInput.
struct BucketGolden { const char* name; std::string (*make)(std::uint32_t); std::uint32_t n, payload_n; std::uint64_t fnv; };
const BucketGolden kBucket[] = {
    {"source", MakeSource, 3750u, 548u, 0x009a41af1d1a5532ull},
    {"markup", MakeMarkup, 3750u, 462u, 0x300b27808960648full},
    {"prose",  MakeProse,  3750u, 532u, 0x7dc2acf6c90f5ffcull},
};
void BucketCase(const BucketGolden& g) {
    const std::string s = g.make(30000u);
    std::vector<std::uint8_t> in(s.begin(), s.begin() + g.n), bwt(g.n + 4u), payload, back(g.n + 64u);
    NzBwtTransform(in.data(), g.n, bwt.data());
    const std::uint32_t r = NzBwtEncodeInput(bwt.data(), g.n, 0x600487u, payload);
    char what[96];
    std::snprintf(what, sizeof(what), "bucket payload is %u bytes (want %u)", r, g.payload_n);
    Check(g.name, what, r == g.payload_n);
    Check(g.name, "bucket payload is the original's", r != 0u && Fnv(payload.data(), r) == g.fnv);
    Check(g.name, "bucket payload decodes back", r != 0u && NzBwtDecodeInput(payload.data(), r, g.n, back.data()) &&
          std::memcmp(back.data(), bwt.data(), g.n) == 0);
}

// The whole path on the generated fixtures, against what the original wrote
// into its block descriptors for them (`a -co -t1 -m4m`, read back with
// NZOPT_TRACE_TDO / NZOPT_DUMP_TT): the mask the detector asks for, the trial
// gate's verdict, the bits that applied, the transformed size and both side
// streams' sizes.
struct PathGolden { const char* name; std::string (*make)(std::uint32_t); unsigned mask, applied; std::uint32_t out_n, tt2_n, tt16_n; };
const PathGolden kPath[] = {
    {"source", MakeSource, 0x1eu, 0x1au, 17110u, 8u, 184u},
    {"markup", MakeMarkup, 0x0eu, 0x0eu, 17451u, 3u, 0u},
    {"prose",  MakeProse,  0x0cu, 0x08u, 14108u, 0u, 0u},
    {"dotted", MakeDotted, 0x1cu, 0x18u, 17450u, 0u, 1725u},
};
void PathCase(const PathGolden& g) {
    const std::string s = g.make(30000u);
    const std::uint32_t n = 30000u;
    std::vector<std::uint8_t> a(n + 0x2000u, 0), b(n + 0x2000u, 0), scratch(n + 0x2000u, 0);
    std::memcpy(a.data(), s.data(), n);
    bool route = false;
    const std::uint32_t mask = nzr::opt_enc::CoTextFlags(a.data(), n, scratch.data(), false, &route);
    Check(g.name, "path: the mask the detector asks for", mask == g.mask);
    Check(g.name, "path: the trial gate accepts", nzr::opt_enc::CoTrialGate(a.data(), n, mask, true, false));
    std::uint8_t* pa = a.data(); std::uint8_t* pb = b.data(); std::uint8_t applied = 0;
    std::vector<std::uint8_t> tt2, tt16;
    const std::uint32_t r = nzr::opt_enc::CoTextPipeline(mask, pa, n, pb, n + 0x40u, &applied, &tt2, &tt16, true, false);
    Check(g.name, "path: the bits that applied", applied == g.applied);
    Check(g.name, "path: the transformed size", r == g.out_n);
    Check(g.name, "path: the side streams' sizes", tt2.size() == g.tt2_n && tt16.size() == g.tt16_n);
}

}  // namespace

int main() {
    NzCmInitAll();   // kModelInterpolation: every model below reads it, so before anything
    for (const PathGolden& g : kPath) PathCase(g);
    for (const BucketGolden& g : kBucket) BucketCase(g);
    for (const BwtGolden& g : kBwt) BwtCase(g);
    for (const NumGolden& g : kNum) NumCase(g);
    for (const HtmlGolden& g : kHtml) HtmlCase(g);
    for (const LfGolden& g : kLf) {
        InsertLfCase(g, g.size >> 3u, g.side_probe);
        InsertLfCase(g, g.size, g.side_full);
    }
    std::printf("co_texttransform: %d checks, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
