// dece (the -co exe filter) encoder <-> decoder round trip.
//
// Byte-exactness against the original is checked by the archive comparison in
// tdo/execap (11 of 11 captured blocks identical); what this guards is the
// pair, including the run state: whatever the encoder decides, our own
// NzExeFilter must put the block back together exactly, block after block.
#include "nz_exefilter.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern void NzCmInitAll();

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

void PutDisp(std::vector<std::uint8_t>* v, std::int32_t d) {
    v->push_back((std::uint8_t)d);
    v->push_back((std::uint8_t)(d >> 8));
    v->push_back((std::uint8_t)(d >> 16));
    v->push_back((std::uint8_t)(d >> 24));
}

// Code-shaped bytes: filler, then CALL / JMP / Jcc with displacements drawn
// from a small set of targets so the recent caches get exercised, plus the
// `add esp, imm8` tail the filter folds into its own stream.
std::vector<std::uint8_t> MakeCode(std::size_t n, std::uint32_t seed, int flavour) {
    Rng rng(seed);
    std::vector<std::uint8_t> v;
    v.reserve(n + 16);
    std::int32_t targets[6];
    for (int i = 0; i < 6; ++i) targets[i] = (std::int32_t)(rng() % 0x20000u) - 0x10000;
    while (v.size() < n) {
        const std::uint32_t r = rng() % 100u;
        if (r < 12u) {
            v.push_back(0xe8u);
            PutDisp(&v, targets[rng() % 6u]);
            if (flavour && (rng() & 1u)) {
                v.push_back(0x83u); v.push_back(0xc4u);
                v.push_back((std::uint8_t)(4u + (rng() % 60u)));
            }
        } else if (r < 22u) {
            v.push_back(0xe9u);
            PutDisp(&v, targets[rng() % 6u]);
        } else if (r < 30u) {
            v.push_back(0x0fu);
            v.push_back((std::uint8_t)(0x80u + (rng() % 16u)));
            PutDisp(&v, targets[rng() % 6u]);
        } else if (r < 34u) {
            // displacements too large to touch, and the 0f 8a/8b holes
            v.push_back(0xe8u);
            PutDisp(&v, (std::int32_t)(0x40000000 + (rng() & 0xffff)));
            v.push_back(0x0fu);
            v.push_back((std::uint8_t)(0x8au + (rng() & 1u)));
        } else {
            v.push_back((std::uint8_t)rng());
        }
    }
    v.resize(n);
    return v;
}

// One block through the encoder and straight back through the decoder.
void RoundTrip(NzExeFilterEnc* enc, NzExeFilter* dec,
               const std::vector<std::uint8_t>& in, const std::string& name) {
    std::vector<std::uint8_t> out, side;
    const std::uint32_t m = enc->Encode(in.data(), (std::uint32_t)in.size(), &out, &side);
    if (m == 0u) { enc->Reset(); dec->Reset(); return; }   // declining is a valid answer
    Check(out.size() == m, name + ": the payload is exactly the returned length");

    std::vector<std::uint8_t> back(in.size() + 64u, 0);
    std::uint32_t got = 0;
    const bool ok = dec->Decode(side.data(), (std::uint32_t)side.size(), out.data(), m,
                                back.data(), (std::uint32_t)back.size(), &got);
    Check(ok, name + ": the decoder accepts the stream");
    if (!ok) return;
    Check(got == in.size(), name + ": the decoder restores the block size");
    Check(got == in.size() && std::memcmp(back.data(), in.data(), in.size()) == 0,
          name + ": the decoder reconstructs the block");
    enc->Advance((std::uint32_t)in.size());
}

}  // namespace

int main() {
    NzCmInitAll();

    // Single blocks of every flavour and size.
    for (int flavour = 0; flavour < 2; ++flavour) {
        for (std::size_t n : {0u, 1u, 5u, 64u, 1000u, 20000u, 120000u}) {
            for (std::uint32_t seed : {1u, 99u, 4242u}) {
                NzExeFilterEnc enc;
                NzExeFilter dec;
                char nm[96];
                std::snprintf(nm, sizeof(nm), "code n=%zu seed=%u flavour=%d",
                              (size_t)n, seed, flavour);
                RoundTrip(&enc, &dec, MakeCode(n, seed, flavour), nm);
            }
        }
    }

    // A RUN of consecutive blocks through ONE encoder and one decoder: this is
    // what the recent-target caches and the 23-bit base are for.
    {
        NzExeFilterEnc enc;
        NzExeFilter dec;
        for (int i = 0; i < 8; ++i)
            RoundTrip(&enc, &dec, MakeCode(30000, 7u + (std::uint32_t)i, 1),
                      "run block " + std::to_string(i));
    }

    // A run broken in the middle: both sides must reset together.
    {
        NzExeFilterEnc enc;
        NzExeFilter dec;
        RoundTrip(&enc, &dec, MakeCode(20000, 5, 1), "split a");
        enc.Reset();
        dec.Reset();
        RoundTrip(&enc, &dec, MakeCode(20000, 6, 1), "split b");
    }

    // Blocks that are not code at all: constant, random, and a tail of 0x0f /
    // 0xe8 bytes right at the end (the reference peeks past them).
    {
        for (std::size_t n : {300u, 5000u}) {
            NzExeFilterEnc enc;
            NzExeFilter dec;
            std::vector<std::uint8_t> z(n, 0x0fu);
            RoundTrip(&enc, &dec, z, "all-0f n=" + std::to_string(n));
            std::vector<std::uint8_t> e(n, 0xe8u);
            RoundTrip(&enc, &dec, e, "all-e8 n=" + std::to_string(n));
            Rng rng((std::uint32_t)n + 3u);
            std::vector<std::uint8_t> r(n);
            for (std::size_t i = 0; i < n; ++i) r[i] = (std::uint8_t)rng();
            RoundTrip(&enc, &dec, r, "random n=" + std::to_string(n));
        }
    }

    std::printf("co_dece: %d checks, %d failed\n", checks, failed);
    return failed == 0 ? 0 : 1;
}
