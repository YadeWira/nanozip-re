// nz_postfilter.cpp — NanoZip CM/BWT post-filters, ported from nzdec_v0 NZ.cpp
// (BwtRleExpander) and nz.h (ArithmeticDecoder). Faithful reimplementation.
#include "nz_postfilter.h"
#include <cstring>

namespace {

// ArithmeticDecoder — matches nz.h (12-bit range coder, MSB-first byte cache).
struct ArithDec {
    uint32_t range_hi_, range_lo_, bitbuff_;
    const uint8_t *data_, *data_end_;

    uint32_t ReadByte() { return (data_ != data_end_ ? *data_++ : 0); }
    void InitializeX(const uint8_t* d, const uint8_t* e) {
        data_ = d; data_end_ = e; range_lo_ = 0; range_hi_ = 0xffffffffu; bitbuff_ = 0;
    }
    void FillBuffer() { for (int i = 0; i != 4; ++i) bitbuff_ = (bitbuff_ << 8) | ReadByte(); }
    void Renormalize() {
        while ((range_lo_ ^ range_hi_) < 0x1000000u) {
            range_lo_ <<= 8; range_hi_ = (range_hi_ << 8) + 0xffu;
            bitbuff_ = (bitbuff_ << 8) | ReadByte();
        }
    }
    bool ReadNoShift(uint32_t model) {
        uint32_t compare = range_lo_ + ((range_hi_ - range_lo_) >> 12) * model;
        bool flag = (bitbuff_ <= compare);
        range_hi_ -= flag ? (range_hi_ - compare) : 0u;
        range_lo_ -= flag ? 0u : (range_lo_ - (compare + 1u));
        Renormalize();
        return flag;
    }
    bool Read(uint32_t model) { return ReadNoShift(model >> 4); }
};

struct BwtRleExpander {
    ArithDec adec_;
    uint16_t model_[32];

    BwtRleExpander(const uint8_t* data, const uint8_t* data_end) {
        for (uint32_t i = 0; i < 32; ++i) model_[i] = 0x8000u;
        adec_.InitializeX(data, data_end);
        adec_.FillBuffer();
    }

    uint32_t DecodeInt(uint32_t x) {
        uint32_t result = (x != 0);
        uint32_t n = 1u << (x < 4u ? x : 4u);
        x = x + (x == 0);
        uint32_t i = 1;
        do {
            uint16_t* model_ptr = &model_[i + n];
            bool flag = adec_.Read(*model_ptr);
            *model_ptr = (uint16_t)(*model_ptr + ((0x80u - *model_ptr + ((uint32_t)flag << 16)) >> 8));
            i = i * 2 + flag;
            result = result * 2 + flag;
        } while (i < n);
        if (x > 4u) {
            x -= 4u;
            result <<= x;
            uint32_t lower_bits = 0;
            do { bool flag = adec_.Read(0x8000u); lower_bits = lower_bits * 2 + flag; } while (--x);
            result += lower_bits;
        }
        return result;
    }

    // u32-wise RLE: pairs of equal u32 words introduce a coded run of additional copies.
    bool DecodeU32(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t* out_size_ptr) {
        uint32_t out_size_u32 = *out_size_ptr >> 2;
        uint32_t in_size_u32 = in_size >> 2;
        if (in_size_u32 > out_size_u32) { *out_size_ptr = 0; return false; }
        const uint8_t* in32 = in;                       // byte cursors, read as u32 via memcpy
        const uint8_t* in32_end = in + in_size_u32 * 4u;
        uint8_t* out32 = out;
        uint8_t* out32_end = out + out_size_u32 * 4u;
        auto ld = [](const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; };
        auto st = [](uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); };
        uint32_t v = 0;
        for (;;) {
            uint32_t last_v = v;
            bool brk = false;
            for (int round = 0; round < 6; ++round) {
                if (in32 == in32_end) { brk = true; break; }
                v = ld(in32); st(out32, v); out32 += 4; in32 += 4;
                if (v != last_v) { goto cont; }   // continue outer
            }
            if (brk) break;
            {
                const uint8_t* start_run = in32;
                while (in32 != in32_end && ld(in32) == last_v) in32 += 4;
                uint32_t run_len = (uint32_t)((in32 - start_run) / 4);
                if (run_len > 30u) { *out_size_ptr = 0; return false; }
                uint32_t new_len = DecodeInt(run_len);
                if ((uint32_t)((out32_end - out32) / 4) < (uint32_t)((in32_end - in32) / 4) + new_len) {
                    *out_size_ptr = 0; return false;
                }
                for (uint32_t i = 0; i != new_len; ++i) { st(out32, last_v); out32 += 4; }
            }
            cont:;
        }
        // copy trailing (sub-word) bytes verbatim
        const uint8_t* in_end = in + in_size;
        uint8_t* out_end = out + *out_size_ptr;
        if ((in_end - in32) > (out_end - out32)) { *out_size_ptr = 0; return false; }
        while (in32 != in_end) *out32++ = *in32++;
        *out_size_ptr = (uint32_t)(out32 - out);
        return true;
    }
};

}  // namespace

bool NzBwtRleDecodeU32(const uint8_t* model_data, uint32_t model_len,
                       const uint8_t* in, uint32_t in_size,
                       uint8_t* out, uint32_t* out_size) {
    BwtRleExpander rle(model_data, model_data + model_len);
    return rle.DecodeU32(in, in_size, out, out_size);
}
