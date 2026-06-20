// Unit tests for the lzpf arith primitives.
//
// The bit reader matches the legacy NanoZip in-memory bit reader at
// FUN_080b1fb0. We validate it against a slow reference implementation
// (BitReaderRef) that reads bits one at a time from a big-endian byte
// stream — same semantics, no caching tricks. Any divergence between the
// two means the port is wrong.

#include "lzpf_arith.h"
#include "nz_cd_tokens.h"
#include "cd_token_fixture.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace {

// Slow reference: pulls one bit at a time MSB-first from a u32-aligned input.
// Matches the legacy big-endian-of-u32 read order: bytes[0..3] are loaded as
// big-endian u32, then bits come out from bit 31 down to bit 0.
struct BitReaderRef {
    const std::uint8_t* base;
    std::size_t total_bits;
    std::size_t pos;
};

std::uint32_t LoadU32BE(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

std::uint32_t RefRead(BitReaderRef& r, std::uint32_t n) {
    std::uint32_t out = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::size_t bit_global = r.pos++;
        const std::size_t word_off = (bit_global >> 5) * 4;
        const std::uint32_t bit_in_word = static_cast<std::uint32_t>(bit_global) & 31u;
        std::uint32_t w = 0;
        if (word_off + 4 <= r.total_bits / 8) {
            w = LoadU32BE(r.base + word_off);
        }
        const std::uint32_t b = (w >> (31u - bit_in_word)) & 1u;
        out = (out << 1) | b;
    }
    return out;
}

int g_failed = 0;
int g_total = 0;

void Expect(bool cond, const char* what, const char* extra = "") {
    ++g_total;
    if (!cond) {
        ++g_failed;
        std::fprintf(stderr, "FAIL: %s %s\n", what, extra);
    }
}

void TestMaskTable() {
    Expect(nzr::lzpf::Mask(0) == 0u, "Mask(0)");
    Expect(nzr::lzpf::Mask(1) == 1u, "Mask(1)");
    Expect(nzr::lzpf::Mask(8) == 0xffu, "Mask(8)");
    Expect(nzr::lzpf::Mask(16) == 0xffffu, "Mask(16)");
    Expect(nzr::lzpf::Mask(31) == 0x7fffffffu, "Mask(31)");
    Expect(nzr::lzpf::Mask(32) == 0xffffffffu, "Mask(32)");
}

void TestCounterInit() {
    nzr::lzpf::RangeCounter c{};
    nzr::lzpf::CounterInit(c, 0);
    Expect(c.total == 0 && c.remaining == 0 && c.leading_bits == 1, "CounterInit(0)");
    nzr::lzpf::CounterInit(c, 1);
    Expect(c.total == 1 && c.remaining == 1 && c.leading_bits == 1, "CounterInit(1)");
    nzr::lzpf::CounterInit(c, 12);
    Expect(c.total == 12 && c.remaining == 12 && c.leading_bits == 4, "CounterInit(12)");
    nzr::lzpf::CounterInit(c, 256);
    Expect(c.total == 256 && c.remaining == 256 && c.leading_bits == 9, "CounterInit(256)");
    nzr::lzpf::CounterInit(c, 0x80000000u);
    Expect(c.leading_bits == 32, "CounterInit(2^31)");
}

void TestBitReaderAgainstRef(const std::vector<std::uint8_t>& data,
                              const std::vector<std::uint32_t>& widths) {
    nzr::lzpf::BitReader r{};
    nzr::lzpf::Init(r, data.data(), data.size());
    BitReaderRef ref{data.data(), data.size() * 8, 0};

    bool tainted = false;  // once any read has refilled past end, cache is junk
    for (std::size_t i = 0; i < widths.size(); ++i) {
        const std::uint32_t w = widths[i];
        const bool would_refill = (r.n_valid < w);
        if (would_refill && (r.cur + 4) > r.end) {
            tainted = true;
        }
        const std::uint32_t got = nzr::lzpf::ReadBits(r, w);
        const std::uint32_t want = RefRead(ref, w);
        if (tainted) {
            continue;  // legacy fills with deterministic-but-undefined bits
        }
        char extra[64];
        std::snprintf(extra, sizeof(extra), "(i=%zu w=%u got=%08x want=%08x)",
                      i, w, got, want);
        Expect(got == want, "ReadBits matches reference", extra);
    }
}

void TestFixedSequences() {
    // Pattern: AABBCCDD EEFF1122 — known big-endian u32s = {0xaabbccdd, 0xeeff1122}.
    const std::vector<std::uint8_t> data = {
        0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x11, 0x22,
    };
    nzr::lzpf::BitReader r{};
    nzr::lzpf::Init(r, data.data(), data.size());

    Expect(nzr::lzpf::ReadBits(r, 4) == 0xa, "first nibble = 0xa");
    Expect(nzr::lzpf::ReadBits(r, 4) == 0xa, "second nibble = 0xa");
    Expect(nzr::lzpf::ReadBits(r, 8) == 0xbb, "next byte = 0xbb");
    Expect(nzr::lzpf::ReadBits(r, 16) == 0xccdd, "next word = 0xccdd");
    // Cache exhausted (32 bits used). Next read forces refill.
    Expect(nzr::lzpf::ReadBits(r, 8) == 0xee, "after-refill byte = 0xee");
    Expect(nzr::lzpf::ReadBits(r, 8) == 0xff, "next = 0xff");
    Expect(nzr::lzpf::ReadBits(r, 16) == 0x1122, "tail word = 0x1122");
}

void TestStraddle() {
    // Verify a read that straddles the 32-bit cache boundary.
    const std::vector<std::uint8_t> data = {
        0x12, 0x34, 0x56, 0x78,  // first u32 = 0x12345678
        0x9a, 0xbc, 0xde, 0xf0,  // second u32 = 0x9abcdef0
    };
    nzr::lzpf::BitReader r{};
    nzr::lzpf::Init(r, data.data(), data.size());

    // Consume 28 bits from the first word.
    Expect(nzr::lzpf::ReadBits(r, 28) == 0x1234567u, "28-bit read = 0x1234567");
    // Now 4 bits remain in cache. Read 16 bits → 4 from cache + 12 from refill.
    // Expected: low 4 of first = 0x8, top 12 of second = 0x9ab. Combined = 0x89ab.
    Expect(nzr::lzpf::ReadBits(r, 16) == 0x89abu, "straddle read = 0x89ab");
    // 20 bits remain in second cache. Read 20 → 0xcdef0.
    Expect(nzr::lzpf::ReadBits(r, 20) == 0xcdef0u, "tail read = 0xcdef0");
}

void TestRandomFuzz() {
    std::mt19937 rng(0xc0ffeeu);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<int> width_dist(1, 31);

    for (int trial = 0; trial < 32; ++trial) {
        std::vector<std::uint8_t> data(64 + (trial * 7) % 257);
        for (auto& b : data) b = static_cast<std::uint8_t>(byte_dist(rng));
        std::vector<std::uint32_t> widths;
        for (int i = 0; i < 100; ++i) {
            widths.push_back(static_cast<std::uint32_t>(width_dist(rng)));
        }
        TestBitReaderAgainstRef(data, widths);
    }
}

// ----------------------------------------------------------------------------
// Huffman round-trip tests.
//
// We encode symbols using a self-implemented canonical Huffman encoder that
// reads first_code[] and base_index[] FROM the same context the decoder will
// use. That way any divergence between encoder and decoder must be in the
// shared table (BuildHuffman) or the bit-stream framing — exactly what we want
// to test.
// ----------------------------------------------------------------------------

class BitWriter {
public:
    void WriteBits(std::uint32_t value, unsigned n) {
        for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
            buf_.push_back(static_cast<std::uint8_t>((value >> i) & 1u));
        }
    }
    std::vector<std::uint8_t> Finish() {
        // Pack MSB-first into bytes, padding with zeros.
        std::vector<std::uint8_t> out((buf_.size() + 7) / 8, 0);
        for (std::size_t i = 0; i < buf_.size(); ++i) {
            if (buf_[i]) {
                out[i / 8] |= static_cast<std::uint8_t>(1u << (7 - (i & 7)));
            }
        }
        return out;
    }
private:
    std::vector<std::uint8_t> buf_;
};

// Encode `symbol` using the tables in `ctx` and the per-symbol code lengths.
// Returns the (code_value, length) pair so the caller can write them.
std::pair<std::uint32_t, unsigned> EncodeSymbol(
    const nzr::lzpf::HuffmanContext& ctx,
    const std::uint8_t* code_lengths,
    std::uint8_t symbol) {
    const unsigned length = code_lengths[symbol];
    // Find the symbol's position in ctx.symbols[].
    unsigned pos = 0;
    while (ctx.symbols[pos] != symbol || code_lengths[ctx.symbols[pos]] != length) {
        ++pos;
    }
    const unsigned base = ctx.base_index[length];
    const unsigned offset_in_length = pos - base;
    const unsigned first = ctx.first_code[length];
    const std::uint32_t code = first + offset_in_length;
    return {code, length};
}

void TestHuffmanFlatLength8() {
    // All 256 symbols, all length 8 — trivial canonical Huffman.
    std::array<std::uint8_t, 256> lengths;
    lengths.fill(8);

    nzr::lzpf::HuffmanContext ctx{};
    nzr::lzpf::BuildHuffman(ctx, lengths.data(), 256);

    // Length-lookup: every entry must be 8.
    bool all_eight = true;
    for (int i = 0; i < 256; ++i) {
        if (ctx.length_table[i] != 8u) {
            all_eight = false;
            break;
        }
    }
    Expect(all_eight, "length_table all = 8 for flat L=8");
    Expect(ctx.first_code[8] == 0u, "first_code[8] = 0");
    Expect(ctx.base_index[8] == 0u, "base_index[8] = 0");
    // Sort is desc by length then desc by symbol → symbols[0]=255, ..., [255]=0.
    Expect(ctx.symbols[0] == 255, "symbols[0] = 255");
    Expect(ctx.symbols[255] == 0, "symbols[255] = 0");

    // Round-trip a fixed message.
    const std::array<std::uint8_t, 12> message = {
        'H', 'e', 'l', 'l', 'o', '!',
        0x00, 0xff, 0x42, 0xa5, 0x10, 0xee
    };
    BitWriter w;
    for (auto s : message) {
        auto [code, len] = EncodeSymbol(ctx, lengths.data(), s);
        w.WriteBits(code, len);
    }
    // Pad with extra bits so DecodeHuffmanBytes can refill the code register
    // after the last symbol without reading garbage.
    w.WriteBits(0, 64);
    auto bytes = w.Finish();

    nzr::lzpf::BitReader br;
    nzr::lzpf::Init(br, bytes.data(), bytes.size());
    nzr::lzpf::RangeCoderPrime(ctx.code_register, br);

    std::array<std::uint8_t, 12> decoded{};
    nzr::lzpf::DecodeHuffmanBytes(ctx, br, decoded.data(), message.size());

    bool ok = true;
    for (std::size_t i = 0; i < message.size(); ++i) {
        if (decoded[i] != message[i]) {
            ok = false;
            char extra[64];
            std::snprintf(extra, sizeof(extra), "(i=%zu got=%02x want=%02x)",
                          i, decoded[i], message[i]);
            Expect(false, "Huffman flat round-trip", extra);
        }
    }
    if (ok) Expect(true, "Huffman flat round-trip");
}

void TestHuffmanSkewed() {
    // Use a Kraft-valid skewed distribution: 1 symbol of length 1,
    // 1 of length 2, 1 of length 3, ..., 1 of length 8, padding with longer
    // lengths to keep Kraft sum = 1.
    //
    // Lengths (sym → len): {0:1, 1:2, 2:3, 3:4, 4:5, 5:6, 6:7, 7:8, 8:8}.
    // Kraft sum = 1/2 + 1/4 + 1/8 + 1/16 + 1/32 + 1/64 + 1/128 + 1/256 + 1/256 = 1.
    std::array<std::uint8_t, 256> lengths{};  // zero-init = symbol absent
    lengths[0] = 1; lengths[1] = 2; lengths[2] = 3; lengths[3] = 4;
    lengths[4] = 5; lengths[5] = 6; lengths[6] = 7;
    lengths[7] = 8; lengths[8] = 8;

    nzr::lzpf::HuffmanContext ctx{};
    nzr::lzpf::BuildHuffman(ctx, lengths.data(), 256);

    // Round-trip: encode every active symbol several times in arbitrary order.
    std::vector<std::uint8_t> message;
    std::mt19937 rng(0xfeedu);
    std::uniform_int_distribution<int> sym_pick(0, 8);
    for (int i = 0; i < 200; ++i) {
        message.push_back(static_cast<std::uint8_t>(sym_pick(rng)));
    }

    BitWriter w;
    for (auto s : message) {
        auto [code, len] = EncodeSymbol(ctx, lengths.data(), s);
        w.WriteBits(code, len);
    }
    w.WriteBits(0, 64);
    auto bytes = w.Finish();

    nzr::lzpf::BitReader br;
    nzr::lzpf::Init(br, bytes.data(), bytes.size());
    nzr::lzpf::RangeCoderPrime(ctx.code_register, br);

    std::vector<std::uint8_t> decoded(message.size());
    nzr::lzpf::DecodeHuffmanBytes(ctx, br, decoded.data(), decoded.size());

    bool ok = (decoded == message);
    Expect(ok, "Huffman skewed round-trip (200 symbols)");
    if (!ok) {
        for (std::size_t i = 0; i < message.size(); ++i) {
            if (decoded[i] != message[i]) {
                std::fprintf(stderr,
                    "  mismatch at %zu: got %u want %u\n",
                    i, decoded[i], message[i]);
                if (i > 5) break;
            }
        }
    }
}

void TestPrimeAndFinalize() {
    // RangeCoderPrime should consume 31 bits and leave n_valid = 1.
    const std::vector<std::uint8_t> data = {
        0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    };
    nzr::lzpf::BitReader r{};
    nzr::lzpf::Init(r, data.data(), data.size());
    std::uint32_t code = 0;
    nzr::lzpf::RangeCoderPrime(code, r);
    Expect(code == 0x7fffffffu, "RangeCoderPrime reads top 31 bits");
    Expect(r.n_valid == 1, "n_valid = 1 after Prime");

    // RangeCoderFinalize matches the legacy semantics: it rewinds to the byte
    // boundary AND tail-calls ReadBits(remaining_bits) to refill cache. So
    // after Finalize, n_valid is whatever the trailing refill produced (not 0).
    // We just check that ReadBits + Finalize doesn't crash and the cursor is
    // sane (within or just past the buffer).
    (void)nzr::lzpf::ReadBits(r, 1);
    (void)nzr::lzpf::ReadBits(r, 16);
    nzr::lzpf::RangeCoderFinalize(r);
    const std::ptrdiff_t cur_off = r.cur - r.start;
    Expect(cur_off >= 0 && cur_off <= static_cast<std::ptrdiff_t>(data.size()) + 4,
           "Finalize cursor in bounds");
}

}  // namespace

void TestRangeBisect() {
    // Encode a sequence of decisions that should bisect to specific values.
    //
    // For hi=7 (range [0..7]): each call consumes up to 3 bits; the decoder
    // ends when lo == mid, i.e. when the range narrows to a single value.
    //
    // We craft bit streams matching the binary-search choices and check the
    // resulting integer.
    auto run = [](std::vector<int> bits, std::uint32_t hi, std::uint32_t expect) {
        // Pack bits MSB-first into a byte buffer (with 32-bit padding for the
        // big-endian refill semantics).
        BitWriter w;
        for (int b : bits) w.WriteBits(b ? 1u : 0u, 1);
        w.WriteBits(0, 64);
        auto bytes = w.Finish();
        nzr::lzpf::BitReader br;
        nzr::lzpf::Init(br, bytes.data(), bytes.size());
        const std::uint32_t got = nzr::lzpf::ReadRangeBisect(br, hi);
        char extra[64];
        std::snprintf(extra, sizeof(extra), "(hi=%u got=%u want=%u)", hi, got, expect);
        Expect(got == expect, "ReadRangeBisect", extra);
    };

    // bit==0 → lo := mid (move toward `hi`); bit==1 → hi := mid (move toward `lo`).
    // hi=7, "000": lo:0→3→5→6, then mid=6 collapses → returns 6.
    run({0, 0, 0}, 7, 6);
    // hi=7, "111": hi:7→3→1→0, return 0.
    run({1, 1, 1}, 7, 0);
    // hi=7, "100": bit1 → hi=3; bit0 → lo=1; bit0 → lo=2; mid=2 collapses → 2.
    run({1, 0, 0}, 7, 2);
    // hi=7, "010": bit0 → lo=3; bit1 → hi=5; bit0 → lo=4; mid=4 collapses → 4.
    run({0, 1, 0}, 7, 4);
    // hi=0: returns 0 immediately, no bits consumed.
    run({}, 0, 0);
    // hi=1: 1 bit. bit=0 → lo=0... wait mid=(0+1)/2=0, lo>=mid, return 0 (no read).
    // Actually for hi=1: mid=0 → return 0. Always returns 0.
    run({}, 1, 0);
}

// ----------------------------------------------------------------------------
// Pass-1 vector tests: feed the same input bytes the legacy nz binary saw
// (captured via gdb at FUN_080a41d0 entry) and assert the meta-Huffman
// code-length array matches the gdb-captured ground truth.
// ----------------------------------------------------------------------------

void TestPass1Vector(const char* label, const std::vector<std::uint8_t>& input,
                     std::uint32_t max_len,
                     const std::vector<std::uint8_t>& expected) {
    nzr::lzpf::BitReader br;
    nzr::lzpf::Init(br, input.data(), input.size());
    std::vector<std::uint8_t> got(max_len + 1u);
    (void)nzr::lzpf::ReadCodeLengthsPass1(br, got.data(), max_len);
    bool ok = (got == expected);
    if (!ok) {
        std::fprintf(stderr, "FAIL [%s] meta_lengths mismatch\n  got=", label);
        for (auto v : got) std::fprintf(stderr, " %u", v);
        std::fprintf(stderr, "\n  want=");
        for (auto v : expected) std::fprintf(stderr, " %u", v);
        std::fprintf(stderr, "\n");
    }
    char extra[64];
    std::snprintf(extra, sizeof(extra), "[%s]", label);
    Expect(ok, "Pass1 meta_lengths", extra);
}

void TestPass1VectorRepeats() {
    // From repeats_256.txt.cf.nz.cf.nz (gdb trace).
    const std::vector<std::uint8_t> input = {
        0x2f, 0x29, 0xfa, 0x9f, 0xfb, 0x47, 0xfe, 0xf7, 0x76, 0x90,
    };
    const std::vector<std::uint8_t> expected = {
        1, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    TestPass1Vector("repeats_256", input, /*max_len=*/12, expected);
}

void TestPass1VectorText() {
    // From text_8k.txt.cf.nz.cf.nz (gdb trace).
    const std::vector<std::uint8_t> input = {
        0x6b, 0x00, 0x80, 0x96, 0xf8, 0xb7, 0xfc, 0xc5, 0xfe, 0x6c,
        0x08, 0x1e, 0xff, 0xc4, 0xcf, 0xf4, 0x39, 0x14, 0x97, 0x91,
        0x52, 0xa5, 0xd1, 0xff, 0xcd, 0xa0, 0x46, 0x64, 0xff, 0xa0,
        0x4c, 0x37, 0xc7, 0x18, 0x50, 0x40, 0x48, 0x90, 0x18, 0x18,
    };
    const std::vector<std::uint8_t> expected = {
        1, 3, 6, 6, 5, 6, 6, 4, 5, 4, 3, 0, 0,
    };
    TestPass1Vector("text_8k", input, /*max_len=*/12, expected);
}

// ----------------------------------------------------------------------------
// Full Pass 1+2 end-to-end vectors. Same input bytes the legacy nz binary
// saw at FUN_080a41d0 entry → assert the 256-byte output matches.
// ----------------------------------------------------------------------------

void TestFullVector(const char* label, const std::vector<std::uint8_t>& input,
                    std::uint32_t max_len,
                    const std::vector<std::uint8_t>& expected) {
    nzr::lzpf::BitReader br;
    nzr::lzpf::Init(br, input.data(), input.size());
    std::vector<std::uint8_t> got(expected.size(), 0);
    bool ok = nzr::lzpf::ReadCodeLengthsHuffman(br, got.data(), got.size(), max_len);
    if (!ok) {
        char extra[64];
        std::snprintf(extra, sizeof(extra), "[%s] returned false", label);
        Expect(false, "ReadCodeLengthsHuffman", extra);
        return;
    }
    bool match = (got == expected);
    if (!match) {
        std::fprintf(stderr, "FAIL [%s] mismatched indices:\n", label);
        for (std::size_t i = 0; i < expected.size(); ++i) {
            if (got[i] != expected[i]) {
                std::fprintf(stderr, "  [%03zu] got=%u want=%u\n",
                             i, got[i], expected[i]);
                if (i > 15 && expected[i] != 0) break;
            }
        }
    }
    char extra[64];
    std::snprintf(extra, sizeof(extra), "[%s]", label);
    Expect(match, "ReadCodeLengthsHuffman full vector", extra);
}

void TestFullRepeats() {
    const std::vector<std::uint8_t> input = {
        0x2f, 0x29, 0xfa, 0x9f, 0xfb, 0x47, 0xfe, 0xf7, 0x76, 0x90,
    };
    std::vector<std::uint8_t> expected(256, 0);
    expected[0]   = 3;
    expected[10]  = 2;
    expected[11]  = 3;
    expected[120] = 2;
    expected[248] = 2;
    TestFullVector("repeats_256", input, 12, expected);
}

void TestFullMixed() {
    // From mixed.cf.nz (gdb trace) — repeating English text with punctuation.
    const std::vector<std::uint8_t> input = {
        0x6c, 0x07, 0x1b, 0x7c, 0xef, 0xf0, 0x05, 0xfc, 0xb1, 0xfa,
        0xff, 0x24, 0xfe, 0x33, 0xe2, 0x09, 0xe4, 0x9e, 0x47, 0xbf,
        0xf8, 0x55, 0x01, 0xf9, 0xdf, 0xe0, 0x0a, 0x17, 0x2c, 0x21,
        0xe4, 0xc8, 0x87,
    };
    std::vector<std::uint8_t> expected(256, 0);
    expected[10]  = 8;
    expected[32]  = 5;
    expected[48]  = 8;
    expected[49]  = 6; expected[50] = 6; expected[51] = 6; expected[52] = 6;
    expected[53]  = 6; expected[54] = 6; expected[55] = 6; expected[56] = 6; expected[57] = 6;
    expected[80]  = 8;
    expected[97]  = 7; expected[98]  = 7; expected[99]  = 7; expected[100] = 7;
    expected[101] = 7; expected[102] = 7; expected[103] = 7; expected[104] = 7;
    expected[105] = 6; expected[106] = 7; expected[107] = 8; expected[108] = 8;
    expected[109] = 8; expected[110] = 8; expected[111] = 7;
    expected[113] = 8; expected[114] = 8; expected[115] = 8; expected[116] = 8;
    expected[117] = 7; expected[118] = 8; expected[119] = 8; expected[120] = 8;
    expected[121] = 8; expected[122] = 8;
    expected[212] = 3; expected[213] = 5;
    expected[225] = 8;
    expected[246] = 2;
    expected[248] = 3;
    expected[252] = 8;
    expected[255] = 3;
    TestFullVector("mixed", input, 12, expected);
}

void TestFullText() {
    const std::vector<std::uint8_t> input = {
        0x6b, 0x00, 0x80, 0x96, 0xf8, 0xb7, 0xfc, 0xc5, 0xfe, 0x6c,
        0x08, 0x1e, 0xff, 0xc4, 0xcf, 0xf4, 0x39, 0x14, 0x97, 0x91,
        0x52, 0xa5, 0xd1, 0xff, 0xcd, 0xa0, 0x46, 0x64, 0xff, 0xa0,
        0x4c, 0x37, 0xc7, 0x18, 0x50, 0x40, 0x48, 0x90, 0x18, 0x18,
    };
    std::vector<std::uint8_t> expected(256, 0);
    // From gdb trace [exit.dst] dump:
    expected[10]  = 8;
    expected[32]  = 7;
    expected[48]  = 7; expected[49] = 5; expected[50] = 5;
    expected[51]  = 6; expected[52] = 6; expected[53] = 6;
    expected[54]  = 6; expected[55] = 6; expected[56] = 6; expected[57] = 6;
    expected[84]  = 8;
    expected[97]  = 0x0a; expected[98]  = 0x0a; expected[99]  = 0x0a; expected[100] = 0x0a;
    expected[101] = 8;    expected[102] = 0x0a; expected[103] = 0x0a; expected[104] = 8;
    expected[105] = 0x0a; expected[106] = 0x0a; expected[107] = 0x0a; expected[108] = 0x0a;
    expected[109] = 0x0a; expected[110] = 0x0a; expected[111] = 8;
    expected[112] = 0x0a; expected[113] = 0x0a; expected[114] = 9;    expected[115] = 0x0a;
    expected[116] = 0x0a; expected[117] = 9;    expected[118] = 0x0a; expected[119] = 0x0a;
    expected[120] = 0x0a; expected[121] = 0x0a; expected[122] = 9;
    expected[217] = 7;    expected[218] = 4;    expected[219] = 3;    expected[220] = 7;
    expected[221] = 9;
    expected[246] = 3;
    expected[248] = 2;
    expected[254] = 4;    expected[255] = 3;
    TestFullVector("text_8k", input, 12, expected);
}

// ----------------------------------------------------------------------------
// DecodeArithBuffer end-to-end vector tests (FUN_080a4ea0 wrapper).
// Each vector captured via gdb at FUN_080a4ea0 entry (input bytes) + exit
// (output bytes + bytes_consumed). See work/reports/trace_080a4ea0.gdb.
// ----------------------------------------------------------------------------

void TestDecodeBufferRepeats() {
    const std::vector<std::uint8_t> input = {
        0x2f, 0x29, 0xfa, 0x9f, 0xfb, 0x47, 0xfe, 0xf7, 0x76, 0x90,
    };
    const std::vector<std::uint8_t> expected_output = {
        0x78, 0x0a, 0x78, 0x0a, 0xf8, 0x00, 0x0b,
    };
    const std::size_t expected_consumed = 10;
    std::vector<std::uint8_t> got(expected_output.size(), 0);
    std::size_t consumed = nzr::lzpf::DecodeArithBuffer(
        input.data(), input.size(), got.data(), got.size(), /*max_len=*/12);
    Expect(consumed == expected_consumed, "DecodeArithBuffer[repeats] consumed");
    bool match = (got == expected_output);
    if (!match) {
        std::fprintf(stderr, "FAIL [repeats wrapper] output mismatch\n  got=");
        for (auto v : got) std::fprintf(stderr, " %02x", v);
        std::fprintf(stderr, "\n  want=");
        for (auto v : expected_output) std::fprintf(stderr, " %02x", v);
        std::fprintf(stderr, "\n");
    }
    Expect(match, "DecodeArithBuffer[repeats] output");
}

void TestDecodeBufferText() {
    // Full 509-byte input captured from FUN_080a4ea0 entry on text_8k.cf.nz.
    const std::vector<std::uint8_t> input = {
        0x6b,0x00,0x80,0x96,0xf8,0xb7,0xfc,0xc5,0xfe,0x6c,0x08,0x1e,0xff,0xc4,0xcf,0xf4,
        0x39,0x14,0x97,0x91,0x52,0xa5,0xd1,0xff,0xcd,0xa0,0x46,0x64,0xff,0xa0,0x4c,0x37,
        0xc7,0x18,0x50,0x40,0x48,0x90,0x18,0x18,0x06,0x82,0x20,0x58,0x90,0x48,0x1a,0x0e,
        0x01,0x01,0x02,0x40,0xf0,0x70,0x04,0x48,0x18,0x0c,0x02,0x40,0x70,0x14,0x48,0x38,
        0x06,0x12,0x0d,0x12,0x02,0x04,0x04,0xb0,0x28,0x13,0x05,0x80,0x02,0x41,0x00,0x70,
        0x38,0x49,0xc2,0xc2,0x82,0x30,0x51,0xa4,0xc3,0x17,0x26,0x18,0xa9,0x30,0xc4,0xc9,
        0x86,0x22,0x4c,0x30,0xf2,0x61,0x86,0x93,0x0c,0x2c,0x98,0x63,0x88,0x0b,0x0a,0xe9,
        0xe7,0x59,0xa7,0x59,0x73,0xac,0xa9,0xd6,0x4c,0xeb,0x22,0x75,0x8f,0x3a,0xc6,0x9d,
        0x62,0xce,0x9a,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,0x53,0xac,0x99,0xd6,0x44,
        0xeb,0x1e,0x75,0x8d,0x3a,0xc5,0x9d,0x2e,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,
        0x53,0xac,0x99,0xd6,0x44,0xeb,0x1e,0x75,0x8d,0x3a,0xc5,0x9d,0x2a,0x4e,0xb3,0xce,
        0xb3,0x4e,0xb2,0xe7,0x59,0x53,0xac,0x99,0xd6,0x44,0xeb,0x1e,0x75,0x8d,0x3a,0xc5,
        0x9d,0x26,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,0x53,0xac,0x99,0xd6,0x44,0xeb,
        0x1e,0x75,0x8d,0x3a,0xc5,0x9d,0x22,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,0x53,
        0xac,0x99,0xd6,0x44,0xeb,0x1e,0x75,0x8d,0x3a,0xc5,0x9d,0x1e,0x4e,0xb3,0xce,0xb3,
        0x4e,0xb2,0xe7,0x59,0x53,0xac,0x99,0xd6,0x44,0xeb,0x1e,0x75,0x8d,0x3a,0xc5,0x9d,
        0x1a,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,0x53,0xac,0x99,0xd6,0x44,0xeb,0x1e,
        0x75,0x8d,0x3a,0xc5,0x9d,0x16,0x4e,0xb3,0xce,0xb3,0x4e,0xb2,0xe7,0x59,0x53,0xac,
        0x99,0xd6,0x44,0xeb,0x1e,0x75,0x8d,0x3a,0xc5,0x9d,0x3c,0x10,0x17,0xd4,0x3c,0xea,
        0x1a,0x75,0x0b,0x9d,0x42,0xa7,0x50,0x99,0xd4,0x22,0x75,0x07,0x9d,0x41,0xa7,0x50,
        0x59,0xa9,0xe4,0xd5,0x9e,0x6a,0xcd,0x87,0x65,0xe1,0xd9,0x58,0x76,0x4e,0x1d,0x91,
        0x87,0x63,0xe1,0xd8,0xd8,0x76,0x2e,0xac,0xc2,0x35,0x43,0xea,0x86,0xd5,0x0b,0xd5,
        0x0a,0xd5,0x09,0xd5,0x08,0xd5,0x07,0xd5,0x06,0xd5,0x05,0xd5,0x96,0x23,0x54,0x3e,
        0xa8,0x6d,0x50,0xbd,0x50,0xad,0x50,0x9d,0x50,0x8d,0x50,0x7d,0x50,0x6d,0x50,0x5d,
        0x59,0x42,0x35,0x43,0xea,0x86,0xd5,0x0b,0xd5,0x0a,0xd5,0x09,0xd5,0x08,0xd5,0x07,
        0xd5,0x06,0xd5,0x05,0xd5,0x92,0x23,0x54,0x3e,0xa8,0x6d,0x50,0xbd,0x50,0xad,0x50,
        0x9d,0x50,0x8d,0x50,0x7d,0x50,0x6d,0x50,0x5d,0x59,0x02,0x35,0x43,0xea,0x86,0xd5,
        0x0b,0xd5,0x0a,0xd5,0x09,0xd5,0x08,0xd5,0x07,0xd5,0x06,0xd5,0x05,0xd5,0x8e,0x23,
        0x54,0x3e,0xa8,0x6d,0x50,0xbd,0x50,0xad,0x50,0x9d,0x50,0x8d,0x50,0x7d,0x50,0x6d,
        0x50,0x5d,0x58,0xc2,0x35,0x43,0xea,0x86,0xd5,0x0b,0xd5,0x0a,0xd5,0x09,0xd5,0x08,
        0xd5,0x07,0xd5,0x06,0xd5,0x05,0xd5,0x8a,0x23,0x54,0x3e,0xa8,0x6d,0x50,0xbd,0x50,
        0xad,0x50,0x9d,0x50,0x8d,0x50,0x7d,0x50,0x6d,0x50,0x5d,0x4d,0x23,
    };
    const std::vector<std::uint8_t> expected_first_256 = {
        0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20,
        0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20,
        0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
        0x20, 0x74, 0x68, 0x65, 0xff, 0x6c, 0x61, 0x7a, 0x79, 0x20,
        0x64, 0x6f, 0x67, 0x20, 0x31, 0x0a, 0x54, 0x68, 0xf8, 0xdd,
        0x32, 0xf6, 0xf6, 0xf8, 0xdc, 0x33, 0xf6, 0xf6, 0xf8, 0xdc,
        0x34, 0xf6, 0xf6, 0xf8, 0xdc, 0x35, 0xf6, 0xf6, 0xf8, 0xdc,
        0x36, 0xf6, 0xf6, 0xf8, 0xdc, 0x37, 0xf6, 0xf6, 0xf8, 0xdc,
        0x38, 0xf6, 0xf6, 0xf8, 0xdc, 0x39, 0xf6, 0xf6, 0xf8, 0xdc,
        0x31, 0x30, 0x0a, 0x54, 0xf8, 0xdb, 0x31, 0xf6, 0xf8, 0xdb,
        0xff, 0x32, 0xf6, 0xf8, 0xdb, 0xff, 0x33, 0xf6, 0xf8, 0xdb,
        0xff, 0x34, 0xf6, 0xf8, 0xdb, 0xff, 0x35, 0xf6, 0xf8, 0xdb,
        0xff, 0x36, 0xf6, 0xf8, 0xdb, 0xff, 0x37, 0xf6, 0xf8, 0xdb,
        0xff, 0x38, 0xf6, 0xf8, 0xdb, 0xff, 0x39, 0xf6, 0xf8, 0xdb,
        0x32, 0xf6, 0xf6, 0xf8, 0xdb, 0xff, 0x31, 0xf6, 0xf8, 0xdb,
        0xff, 0x32, 0xf6, 0xf8, 0xdb, 0xff, 0x33, 0xf6, 0xf8, 0xdb,
        0xff, 0x34, 0xf6, 0xf8, 0xdb, 0xff, 0x35, 0xf6, 0xf8, 0xdb,
        0xff, 0x36, 0xf6, 0xf8, 0xdb, 0xff, 0x37, 0xf6, 0xf8, 0xdb,
        0xff, 0x38, 0xf6, 0xf8, 0xdb, 0xff, 0x39, 0xf6, 0xf8, 0xdb,
        0x33, 0xf6, 0xf6, 0xf8, 0xdb, 0xff, 0x31, 0xf6, 0xf8, 0xdb,
        0xff, 0x32, 0xf6, 0xf8, 0xdb, 0xff, 0x33, 0xf6, 0xf8, 0xdb,
        0xff, 0x34, 0xf6, 0xf8, 0xdb, 0xff, 0x35, 0xf6, 0xf8, 0xdb,
        0xff, 0x36, 0xf6, 0xf8, 0xdb, 0xff, 0x37, 0xf6, 0xf8, 0xdb,
        0xff, 0x38, 0xf6, 0xf8, 0xdb, 0xff, 0x39, 0xf6, 0xf8, 0xdb,
        0x34, 0xf6, 0xf6, 0xf8, 0xdb, 0xff, 0x31, 0xf6, 0xf8, 0xdb,
        0xff, 0x32, 0xf6, 0xf8, 0xdb, 0xff,
    };
    std::vector<std::uint8_t> got(expected_first_256.size(), 0);
    (void)nzr::lzpf::DecodeArithBuffer(input.data(), input.size(), got.data(),
                                        got.size(), /*max_len=*/12);
    bool match = (got == expected_first_256);
    if (!match) {
        std::fprintf(stderr, "FAIL [text wrapper] mismatched bytes:\n");
        int diffs = 0;
        for (std::size_t i = 0; i < expected_first_256.size(); ++i) {
            if (got[i] != expected_first_256[i]) {
                std::fprintf(stderr, "  [%03zu] got=%02x want=%02x\n",
                             i, got[i], expected_first_256[i]);
                if (++diffs >= 8) { std::fprintf(stderr, "  ...\n"); break; }
            }
        }
    }
    Expect(match, "DecodeArithBuffer[text] output[0..255]");
}

// ----------------------------------------------------------------------------
// LZ77 bytecode dispatcher (variant A) tests.
// ----------------------------------------------------------------------------

void TestLz77Repeats256() {
    // Side-stream output for repeats_256.txt.cf.nz: 7 bytes of bytecode that
    // should produce 256 bytes of "x\nx\n" pattern.
    const std::vector<std::uint8_t> bytecode = {
        0x78, 0x0a, 0x78, 0x0a, 0xf8, 0x00, 0x0b,
    };
    // Allocate dict with 4-byte left padding (zero) to support hash_at_minus2.
    std::vector<std::uint8_t> dict_buf(4 + 1024 + 16, 0);
    std::uint8_t* dict = dict_buf.data() + 4;
    std::vector<std::int32_t> hash_table(8192, 0);
    std::int32_t last_lz_dest = -1;
    std::size_t cursor = 0;

    bool ok = nzr::lzpf::DecodeLz77VariantA(
        bytecode.data(), bytecode.size(), dict, 1024,
        &cursor, 256, hash_table.data(), &last_lz_dest);
    Expect(ok, "DecodeLz77VariantA[repeats] returned true");
    Expect(cursor == 256, "DecodeLz77VariantA[repeats] cursor=256");

    // Expected output: "x\n" * 128.
    std::vector<std::uint8_t> expected(256);
    for (int i = 0; i < 128; ++i) {
        expected[2*i]   = 'x';
        expected[2*i+1] = '\n';
    }
    bool match = std::memcmp(dict, expected.data(), 256) == 0;
    if (!match) {
        std::fprintf(stderr, "FAIL [lz77 repeats] mismatch:\n  got=");
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, " %02x", dict[i]);
        std::fprintf(stderr, " ...\n  want=");
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, " %02x", expected[i]);
        std::fprintf(stderr, " ...\n");
    }
    Expect(match, "DecodeLz77VariantA[repeats] output");
}

// Inter-channel LMS predictor (FUN_08096e20, scalar path). Golden vectors and
// checksums captured by calling the real linux32/nz FUN_08096e20 in-process via
// GDB with controlled residuals (DAT_081835b8==0 => scalar path active). The
// LCG residual generator below reproduces the exact inputs that were fed.
void TestLmsInterChannel() {
    auto gen = [](int count, std::uint32_t seed, int mod,
                  std::vector<std::int32_t>& r1, std::vector<std::int32_t>& r2) {
        r1.resize(count); r2.resize(count);
        std::uint32_t x = seed;
        for (int i = 0; i < count; ++i) {
            x = x * 1103515245u + 12345u; x &= 0x7fffffffu; r1[i] = (std::int32_t)(x % (std::uint32_t)mod) - (mod >> 1);
            x = x * 1103515245u + 12345u; x &= 0x7fffffffu; r2[i] = (std::int32_t)(x % (std::uint32_t)mod) - (mod >> 1);
        }
    };
    auto run = [](std::vector<std::int32_t>& r1, std::vector<std::int32_t>& r2) {
        nzr::lzpf::LmsObject o1, o2; o1.Init(); o2.Init();
        nzr::lzpf::ApplyLmsInterChannel(r1.data(), r2.data(), r1.size(), &o1, &o2);
    };
    auto fnv = [](const std::vector<std::int32_t>& v) {
        std::uint32_t h = 2166136261u;
        for (std::int32_t e : v) { h ^= (std::uint32_t)e; h *= 16777619u; }
        return h;
    };
    // Case "s": seed=1 mod=801 count=64 — full golden vectors (byte-exact vs binary).
    static const std::int32_t kS1[64] = {
        -97,189,81,-333,-203,376,-177,-111,171,151,-14,-234,356,-314,-216,337,67,268,-53,281,
        -272,-215,155,52,168,-285,37,-142,-359,383,-117,-382,306,79,179,-13,334,-122,304,162,
        -256,-117,353,149,-228,170,-338,21,107,-356,208,96,-67,-46,-234,-114,187,228,-170,288,
        347,396,273,-108 };
    static const std::int32_t kS2[64] = {
        -388,-306,73,-77,71,-224,253,117,122,211,385,-350,-213,205,249,-181,-176,-173,322,71,
        256,36,-161,183,-83,32,-317,101,-323,301,-217,-251,216,177,-335,-329,-32,159,315,-303,
        362,-394,59,274,391,7,11,332,339,-87,-215,-238,-254,-127,-296,-68,-149,-384,264,392,
        235,291,312,-30 };
    {
        std::vector<std::int32_t> r1, r2; gen(64, 1, 801, r1, r2); run(r1, r2);
        bool ok = true;
        for (int i = 0; i < 64; ++i) if (r1[i] != kS1[i] || r2[i] != kS2[i]) { ok = false; break; }
        Expect(ok, "LMS inter-channel matches binary (64-sample golden)");
    }
    // Case "L": seed=2 mod=801 count=5000 — checksum (exercises ring wrap).
    {
        std::vector<std::int32_t> r1, r2; gen(5000, 2, 801, r1, r2); run(r1, r2);
        Expect(fnv(r1) == 0x02e821afu && fnv(r2) == 0x0210cca6u,
               "LMS inter-channel checksum (5000, ring wrap)");
    }
    // Case "X": seed=5 mod=50001 count=9000 — checksum (coeff saturation + wraps).
    {
        std::vector<std::int32_t> r1, r2; gen(9000, 5, 50001, r1, r2); run(r1, r2);
        Expect(fnv(r1) == 0x47e118feu && fnv(r2) == 0xbbbadd05u,
               "LMS inter-channel checksum (9000, saturation)");
    }
}

// Native -cd token reconstruction (FUN_08099050). Canonical single-token case
// captured from the binary: token {lit_run=5, sel=7, raw_len=991} + literals
// "ABCDA" reconstructs "ABCDABCD" repeated to 1000 bytes (byte-exact vs binary).
void TestCdReconstruct() {
    const std::uint32_t tok[3] = {5u, 7u, 991u};
    const std::uint8_t lit[5] = {'A', 'B', 'C', 'D', 'A'};
    std::uint8_t out[1000 + 16] = {0};
    std::uint32_t n = nzr::cd::NzCdReconstruct(tok, 1, lit, out, 1000);
    bool ok = (n == 1000);
    for (std::uint32_t i = 0; ok && i < 1000; ++i)
        if (out[i] != static_cast<std::uint8_t>("ABCDABCD"[i % 8])) ok = false;
    Expect(ok, "CD recon: token {5,7,991}+\"ABCDA\" -> ABCDABCD x125");
}

// Native -cd token assembler (FUN_080aa070). Replays the captured first 256
// tokens of t.nz batch-0 (3 column streams + shared bitstream + per-field
// slot/model tables) and checks the FNV-1a of the produced token fields against
// the value computed from the REAL binary's token output.
void TestCdTokenAssemble() {
    nzr::cd::NzCdField fl{kCdSlotLit, kCdModelLit, kCdTokThrLit};
    nzr::cd::NzCdField fo{kCdSlotOff, kCdModelOff, kCdTokThrOff};
    nzr::cd::NzCdField fn{kCdSlotLen, kCdModelLen, kCdTokThrLen};
    std::vector<std::uint32_t> toks(kCdTokN * 3);
    nzr::cd::NzCdTokenAssemble(kCdTokN, kCdColLit, kCdColOff, kCdColLen,
                               kCdBitstream, kCdBitstreamLen, fl, fo, fn, toks.data());
    std::uint32_t h = 2166136261u;
    for (std::uint32_t v : toks) { h ^= v; h *= 16777619u; }
    Expect(h == kCdTokGoldenFnv, "CD token assembler matches binary (256-token FNV)");
}

// Native -cd param14 text transform (FUN_080a0ff0). Replays a 1 KB slice of real
// recon output (captured by calling the binary's FUN_080a0ff0 in-process) and
// checks byte-exact reconstruction.
void TestCdParam14() {
    std::vector<std::uint8_t> out(kCdP14InLen * 2 + 64, 0);
    std::uint32_t n = nzr::cd::NzCdParam14(kCdP14In, kCdP14InLen,
                                           out.data(), static_cast<std::uint32_t>(out.size() - 1));
    bool ok = (n == kCdP14OutLen) &&
              (std::memcmp(out.data(), kCdP14Out, kCdP14OutLen) == 0);
    Expect(ok, "CD param14 transform matches binary (1KB slice, byte-exact)");
}

// Native -cd column RLE run-expander (FUN_080acb90). Replays a real column from
// map.txt.nz (arith output + size-region bit stream) and checks byte-exact expand.
void TestCdRleExpand() {
    std::vector<std::uint8_t> out(kCdRleOutLen + 256, 0);
    std::uint32_t n = nzr::cd::NzCdRleExpand(kCdRleSrc, kCdRleCount, out.data(),
                                             static_cast<std::uint32_t>(out.size()),
                                             0u, kCdRleBits, kCdRleBitsLen);
    bool ok = (n == kCdRleOutLen) &&
              (std::memcmp(out.data(), kCdRleOut, kCdRleOutLen) == 0);
    Expect(ok, "CD RLE run-expander matches binary (real column, byte-exact)");
}

// Integrated -cd LZ chunk decoder (NzCdDecodeLzChunk): full pipeline from a real
// raw block (header parse + 3 cols arith/RLE + token assemble + literals + recon).
// Checks the 32 KB LZ window against the binary via FNV (last byte = word-copy edge).
void TestCdDecodeLzChunk() {
    std::vector<std::uint8_t> out(kCdChunkOutLen + 64, 0);
    std::size_t pos = 0;
    std::uint32_t n = nzr::cd::NzCdDecodeLzChunk(kCdBlock, kCdBlockLen, &pos,
                                                 out.data(), kCdChunkOutLen + 64);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i + 1 < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdChunkOutLen && h == kCdChunkFnv,
           "CD integrated LZ chunk decode matches binary (real block, 32KB window)");
}

// Full -cd file decode (NzCdDecodeBlock multi-chunk loop) from a real block ->
// the complete original file. map.txt.nz = 3 chunks, 69689 bytes, no post-filters.
void TestCdDecodeBlock() {
    std::vector<std::uint8_t> out(kCdFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdBlock, kCdBlockLen, out.data(),
                                               kCdFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdFileLen && h == kCdFileFnv,
           "CD full file decode matches original (map.txt, 69689 B, 3 chunks)");
}

// 2nd full-file decode on binary content (image.cat) — confirms NzCdDecodeBlock is
// not text-specific; pure-LZ -cd across content types.
void TestCdDecodeBlockBinary() {
    std::vector<std::uint8_t> out(kCdImgFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdImgBlock, kCdImgBlockLen, out.data(),
                                               kCdImgFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdImgFileLen && h == kCdImgFileFnv,
           "CD full file decode matches original (image.cat binary, 41304 B, 2 chunks)");
}

// 3rd full-file decode exercising the block-RLE post-filter (chunk flag &2) +
// trailing literal flush + cross-chunk recon window (elf.bin, flags=3). Each chunk's
// collapsed LZ window is re-expanded (NzCdRleExpand, thr=1) into the output.
void TestCdDecodeBlockBlockRle() {
    std::vector<std::uint8_t> out(kCdElfFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdElfBlock, kCdElfBlockLen, out.data(),
                                               kCdElfFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdElfFileLen && h == kCdElfFileFnv,
           "CD full file decode matches original (elf.bin block-RLE &2, 94744 B, 3 chunks)");
}

// flag &1-clear raw-store path: a column with b0 even (raw bytes) AND a raw
// (non-arith) literal stream — incompressible data (f21, a PNG; flags=0).
void TestCdDecodeBlockRawStore() {
    std::vector<std::uint8_t> out(kCdRawFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdRawBlock, kCdRawBlockLen, out.data(),
                                               kCdRawFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdRawFileLen && h == kCdRawFileFnv,
           "CD raw-store chunk decode matches original (flags=0 raw col+literals, 8262 B)");
}

// pure-literal chunk: incompressible data => no LZ tokens, the window is one arith
// literal stream of out_size bytes (generator decides via v2==0 / size_field==0).
void TestCdDecodeBlockPureLiteral() {
    std::vector<std::uint8_t> out(kCdPlitFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdPlitBlock, kCdPlitBlockLen, out.data(),
                                               kCdPlitFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdPlitFileLen && h == kCdPlitFileFnv,
           "CD pure-literal chunk decode matches original (no tokens, 5000 B)");
}

// Exe post-filter (chunk flag &4): BCJ-style x86 E8/E9 address un-transform. Replays
// the first 3686 B of play.exe's exe chunk (6 transforms) and checks byte-exact vs the
// binary's own filter output (NzCdExeUnfilter operates in place).
void TestCdExeUnfilter() {
    std::vector<std::uint8_t> buf(kCdExeIn, kCdExeIn + kCdExeLen);
    nzr::cd::NzCdExeUnfilter(buf.data(), kCdExeLen, kCdExePosBase);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < kCdExeLen; ++i) { h ^= buf[i]; h *= 16777619u; }
    Expect(h == kCdExeOutFnv,
           "CD exe filter (&4) matches binary (x86 E8/E9 un-transform, 6 sites)");
}

// Text pipeline (chunk flag &8): line-RLE (FUN_080a2f20) then EOL->CRLF (FUN_080a19b0),
// selected by param 0x21. Replays atoll.fld's &8 chunk recon (20939 B) -> final text
// (32768 B), byte-exact vs the binary. (The stages are validated here even though the
// &8 dispatcher path still bridges pending the multi-chunk window resolution.)
void TestCdTextPipeline() {
    std::vector<std::uint8_t> out(kCdTextOutLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdTextPipeline(kCdTextIn, kCdTextInLen, out.data(),
                                                kCdTextOutLen + 65536, kCdTextParam);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdTextOutLen && h == kCdTextOutFnv,
           "CD text pipeline (&8 line-RLE+CRLF) matches binary (atoll.fld chunk, 32768 B)");
}

// Full multi-chunk decode of a TEXT-PIPELINE (&8) block (atoll/f18) — exercises the
// 64 KB cross-chunk ring: a &8 chunk's recon is compact but the ring base advances by
// the chunk OUTPUT size, so a following chunk's matches resolve into it through the
// wrap. This is the path that a contiguous/compact-advance buffer decodes wrong.
void TestCdDecodeBlockTextPipeline() {
    std::vector<std::uint8_t> out(kCdTextBlockFileLen + 65536, 0);
    std::uint32_t n = nzr::cd::NzCdDecodeBlock(kCdTextBlock, kCdTextBlockLen, out.data(),
                                               kCdTextBlockFileLen + 65536);
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < n; ++i) { h ^= out[i]; h *= 16777619u; }
    Expect(n == kCdTextBlockFileLen && h == kCdTextBlockFileFnv,
           "CD full file decode matches original (atoll &8 text pipeline, 92197 B, ring wrap)");
}

int main() {
    TestMaskTable();
    TestCounterInit();
    TestFixedSequences();
    TestStraddle();
    TestRandomFuzz();
    TestPrimeAndFinalize();
    TestHuffmanFlatLength8();
    TestHuffmanSkewed();
    TestRangeBisect();
    TestPass1VectorRepeats();
    TestPass1VectorText();
    TestFullRepeats();
    TestFullText();
    TestFullMixed();
    TestDecodeBufferRepeats();
    TestDecodeBufferText();
    TestLz77Repeats256();
    TestLmsInterChannel();
    TestCdReconstruct();
    TestCdTokenAssemble();
    TestCdParam14();
    TestCdRleExpand();
    TestCdDecodeLzChunk();
    TestCdDecodeBlock();
    TestCdDecodeBlockBinary();
    TestCdDecodeBlockBlockRle();
    TestCdDecodeBlockRawStore();
    TestCdDecodeBlockPureLiteral();
    TestCdExeUnfilter();
    TestCdTextPipeline();
    TestCdDecodeBlockTextPipeline();
    std::printf("test_lzpf_arith: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
