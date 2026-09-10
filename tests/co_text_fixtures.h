// co_text_fixtures.h -- the generated text fixtures the `-co` text tests share.
// Every fixture is produced here by a fixed rule, so the tests carry no data
// files; the goldens they check against were read out of the original binary
// on exactly these bytes (see each test's header for the probes used).
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace co_text_fixtures {

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

}  // namespace co_text_fixtures
