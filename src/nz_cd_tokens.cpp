// Native linux32 `-cd` token pipeline. See nz_cd_tokens.h for the contract and
// the reverse-engineering provenance (FUN_08099050 / FUN_080aa070).
#include "nz_cd_tokens.h"

#include <cstring>

namespace nzr {
namespace cd {

std::uint32_t NzCdReconstruct(const std::uint32_t* tokens, std::uint32_t num_tokens,
                              const std::uint8_t* literals,
                              std::uint8_t* out, std::uint32_t out_size) {
    std::uint32_t rep[4] = {1, 1, 1, 1};
    std::uint32_t pos = 0;
    const std::uint8_t* lp = literals;
    for (std::uint32_t t = 0; t < num_tokens && pos < out_size; ++t) {
        std::uint32_t lit_run = tokens[t * 3 + 0];
        std::uint32_t sel     = tokens[t * 3 + 1];
        std::uint32_t raw_len = tokens[t * 3 + 2];
        std::uint32_t old_rm0 = rep[0];
        std::uint32_t offset, mlen;
        if (sel >= 4) {                       // new match
            offset = sel - 3;
            rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = old_rm0; rep[0] = offset;
            mlen = raw_len + 4 + (offset > 0x63ffu) + (offset > 0x4ffu);
        } else {                              // repeat-match (MTF over rep[])
            offset = rep[sel];
            mlen = raw_len + 2;
            if (sel == 1)      { rep[1] = rep[0]; }
            else if (sel == 2) { rep[2] = rep[1]; rep[1] = rep[0]; }
            else if (sel == 3) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
            rep[0] = offset;
        }
        if (lit_run) {
            if (pos + lit_run > out_size) lit_run = out_size - pos;
            std::memcpy(out + pos, lp, lit_run);
            lp += tokens[t * 3 + 0];  // advance by the full (unclamped) run
            pos += lit_run;
            if (pos >= out_size) break;
        }
        std::uint8_t* dst = out + pos;
        const std::uint8_t* src = out + pos - offset;
        if (pos + mlen > out_size) mlen = out_size - pos;
        for (std::uint32_t i = 0; i < mlen; ++i) dst[i] = src[i];  // overlap-safe
        pos += mlen;
    }
    return pos;
}

namespace {
// MSB-first bit reader over byte-swapped (big-endian) 32-bit words. A word is
// read while the cursor is before the logical end, even if it overruns by up to
// 3 bytes (the buffer carries trailing slack).
struct BitReader {
    const std::uint8_t* base;
    std::size_t orig_bytes;
    std::size_t widx;
    std::uint32_t val;
    std::uint32_t bits;

    BitReader(const std::uint8_t* b, std::size_t orig)
        : base(b), orig_bytes(orig), widx(0), val(0), bits(0) {}

    std::uint32_t word(std::size_t i) const {
        std::uint32_t w;
        std::memcpy(&w, base + i * 4, 4);
        return ((w & 0xff000000u) >> 24) | ((w & 0x00ff0000u) >> 8) |
               ((w & 0x0000ff00u) << 8)  | ((w & 0x000000ffu) << 24);
    }
    std::uint32_t read(std::uint32_t n) {  // n >= 1
        std::uint32_t res;
        if (bits < n) {
            std::uint32_t hi = val << (n - bits);
            std::uint32_t nb = 32 - (n - bits);
            std::uint32_t w = (widx * 4 < orig_bytes) ? word(widx) : nb;
            ++widx;
            val = w;
            res = hi | (val >> nb);
            bits = nb;
        } else {
            bits -= n;
            res = val >> bits;
        }
        return res;
    }
};

inline std::uint32_t DecodeField(std::uint8_t b, const NzCdField& f, BitReader& br) {
    if (b < f.threshold) return b;
    std::uint32_t idx = b - f.threshold;
    std::uint32_t slot = f.slot_tbl[idx];
    std::uint32_t nbits = f.model[slot + 1];
    if (nbits == 0) return b;  // == threshold + idx
    std::uint32_t baseoff = f.model[slot];
    std::uint32_t k = slot >> 1;
    std::uint32_t base = (k == 0) ? 0u : (1u << k);
    std::uint32_t extra = br.read(nbits) & ((1u << nbits) - 1u);
    return (extra | (((idx - baseoff) << nbits) + base)) + f.threshold;
}
}  // namespace

void NzCdTokenAssemble(std::uint32_t num_tokens,
                       const std::uint8_t* col_lit,
                       const std::uint8_t* col_off,
                       const std::uint8_t* col_len,
                       const std::uint8_t* bitstream, std::size_t bitstream_len,
                       const NzCdField& field_lit,
                       const NzCdField& field_off,
                       const NzCdField& field_len,
                       std::uint32_t* out_tokens) {
    BitReader br(bitstream, bitstream_len);
    for (std::uint32_t i = 0; i < num_tokens; ++i) {
        out_tokens[i * 3 + 0] = DecodeField(col_lit[i], field_lit, br);  // lit_run
        out_tokens[i * 3 + 1] = DecodeField(col_off[i], field_off, br);  // sel/offset
        out_tokens[i * 3 + 2] = DecodeField(col_len[i], field_len, br);  // raw_len
    }
}

}  // namespace cd
}  // namespace nzr
