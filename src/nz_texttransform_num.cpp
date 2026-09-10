// nz_texttransform_num.cpp — tt16 = TextTransformNumber::Decode, ported
// near-verbatim from nzdec_v0 NZ_TextTransforms.cpp + Tables.h.
#include "nz_texttransform_num.h"
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>

namespace {

typedef uint8_t  u8;
typedef uint16_t u16;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef uint32_t u32;

}  // namespace

// Shared tables built by NzCmInitAll() (nz_cm.cpp).
extern uint16_t kModelInterpolation[4096];
extern uint16_t kModelLutLookup[4096];

namespace {

static inline u32 BSR(u32 v) { return 31u ^ (u32)__builtin_clz(v); }

static void memset32(void* dst, u32 value, size_t n) {
    u32* p = (u32*)dst;
    for (size_t i = 0; i < n; ++i) p[i] = value;
}

// CreateModelLut — identical to reference NZ.cpp.
static void CreateModelLut(u16* out, u32 rows, u32 cols, u32 step, u32 first) {
    out[0] = 0;
    out[cols - 1] = 0xffff;
    const u16* tp = &kModelLutLookup[first];
    for (size_t i = 1; i < cols - 1; ++i, tp += step) out[i] = (u16)(tp[0] << 4);
    u16* dp = &out[cols];
    for (u32 n = cols * (rows - 1); n; --n) *dp++ = *out++;
}

struct ArithDec {
    u32 range_hi_, range_lo_, bitbuff_;
    const u8 *data_, *data_end_;
    u32 ReadByte() { return (data_ != data_end_ ? *data_++ : 0); }
    void InitializeX(const u8* d, const u8* e) {
        data_ = d; data_end_ = e; range_lo_ = 0; range_hi_ = 0xffffffffu; bitbuff_ = 0;
    }
    void FillBuffer() { for (int i = 0; i != 4; ++i) bitbuff_ = (bitbuff_ << 8) | ReadByte(); }
    void Renormalize() {
        while ((range_lo_ ^ range_hi_) < 0x1000000u) {
            range_lo_ <<= 8; range_hi_ = (range_hi_ << 8) + 0xffu;
            bitbuff_ = (bitbuff_ << 8) | ReadByte();
        }
    }
    bool ReadNoShift(u32 model) {
        u32 compare = range_lo_ + ((range_hi_ - range_lo_) >> 12) * model;
        bool flag = (bitbuff_ <= compare);
        range_hi_ -= flag ? (range_hi_ - compare) : 0u;
        range_lo_ -= flag ? 0u : (range_lo_ - (compare + 1u));
        Renormalize();
        return flag;
    }
    bool Read(u32 model) { return ReadNoShift(model >> 4); }
};

template<int Scale>
static inline u32 xInterpolateModel(u16* model_base, u32 value, u32 index, u16** out_ptr) {
    u32 hv = kModelInterpolation[value >> 4] * (Scale - 1);
    u16* model = &model_base[(hv >> 12) + Scale * index];
    u32 interpolated = (model[0] * (0x1000 - (hv & 0xfff)) + model[1] * (hv & 0xfff)) >> 12;
    model += (hv & 0xfff) >> 11;
    *out_ptr = model;
    return interpolated;
}

template<int W, int Scale>
struct InterpolateLut {
    u16 lut[W * Scale];
    void Initialize(int a, int b) { CreateModelLut(lut, W, Scale, a, b); }
    u32 Get(u32 v, u32 idx, u16** out_ptr) { return xInterpolateModel<Scale>(lut, v, idx, out_ptr); }
};

static const u8 kDecpDigitHash[256] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,1,9,6,7,8,6,14,10,10,10,11,12,2,14,3, 0,1,2,3,4,5,6,7,8,9,4,5,13,13,13,15,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,11,14,15,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,12,12,12,14,1,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};
static const u8 kDecpCompactTable[256] = {
  0,0,0,0,0,0,0,0,0,0,1,1,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,
  4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
};
static const u32 kDigitMultipliers[9] = {
  10u,100u,1000u,10000u,100000u,1000000u,10000000u,100000000u,1000000000u
};

static inline u32 Get4bit(const u8* table, u32 idx) {
    return (table[idx >> 1] >> ((idx & 1) * 4)) & 0xf;
}

template<size_t N>
struct Recent {
    u32 recent[N];
    void Initialize() { for (size_t i = 0; i != N; ++i) recent[i] = (u32)i; }
    void Insert(u32 v) { for (size_t i = N - 1; i; --i) recent[i] = recent[i - 1]; recent[0] = v; }
    u32 Get(u32 i) {
        u32 number = recent[i];
        for (; i; --i) recent[i] = recent[i - (size_t)1];
        recent[0] = number;
        return number;
    }
};

struct One {
    u8  model_j_[294912];
    u16 model_e_[0x480 * 2];
    u16 model_small_[16];
    u16 model_big_[172];
    u16 model_f_[128];
    InterpolateLut<0x120, 24> model_g_;
    InterpolateLut<0x2000, 6> model_h_;
    InterpolateLut<8, 6> model_b_;
    InterpolateLut<0x240, 5> model_a_;
    u8  model_d_[73728];
    u16 model_c_[16];
    Recent<128> recent_numbers_[5];
    struct Hash { u32 pred; i8 delta; u8 score; };
    Hash digit_context_hash_[8193];
    u8  unknown_field_[36864];
    void Initialize() {
        memset32(model_e_, 0x80008000u, sizeof(model_e_) / 4);
        memset(model_j_, 0x88, sizeof(model_j_));
        memset32(model_big_, 0x80008000u, sizeof(model_big_) / 4);
        memset32(model_f_, 0x80008000u, sizeof(model_f_) / 4);
        memset32(model_small_, 0x80008000u, sizeof(model_small_) / 4);
        model_g_.Initialize(0xB2, 0xB1);
        model_h_.Initialize(0x333, 0x332);
        model_b_.Initialize(0x333, 0x332);
        model_a_.Initialize(0x400, 0x3FF);
        memset(model_d_, 0x88, sizeof(model_d_));
        memset32(model_c_, 0x80008000u, sizeof(model_c_) / 4);
        memset(digit_context_hash_, 0, sizeof(digit_context_hash_));
        memset(unknown_field_, 0, sizeof(unknown_field_));
        for (size_t j = 0; j != 5; ++j) recent_numbers_[j].Initialize();
    }
};

struct Two {
    u8  small_number_model_[32768];
    u16 big_number_model_[256];
    u16 recent_or_num_model_[8];
    u16 recent_model_[64];
    InterpolateLut<0x20, 12> number_model_;
    Recent<64> recent_numbers_[8];
    void Initialize() {
        memset(small_number_model_, 0x80, sizeof(small_number_model_));
        memset32(big_number_model_, 0x80008000u, sizeof(big_number_model_) / 4);
        memset32(recent_or_num_model_, 0x80008000u, sizeof(recent_or_num_model_) / 4);
        memset32(recent_model_, 0x80008000u, sizeof(recent_model_) / 4);
        number_model_.Initialize(0x174, 0x173);
        for (size_t j = 0; j != 8; ++j) recent_numbers_[j].Initialize();
    }
};

// The range ENCODER the forward pass drives, the mirror of ArithDec: the same
// 12-bit split of the interval, the same carry-less renormalisation, the top
// byte leaving as soon as both bounds agree on it. Bytes go to the block's aux
// stream; past `cap` they are dropped and the pass declines at the end.
struct ArithEnc {
    u32 lo = 0, hi = 0xffffffffu;
    std::vector<u8>* side = nullptr;
    u32 cap = 0;
    void Put(u8 b) { if (side->size() < cap) side->push_back(b); }
    void Encode(bool bit, u32 model) {   // `model` is the 16-bit interpolation
        const u32 mid = lo + ((hi - lo) >> 12) * (model >> 4);
        if (bit) hi = mid; else lo = mid + 1u;
        while ((hi ^ lo) < 0x1000000u) { Put((u8)(hi >> 24)); hi = (hi << 8) | 0xffu; lo <<= 8; }
    }
    void Flush() { Put((u8)(hi >> 24)); }
};

// DAT_081b2f60, the encoder-only class table FUN_080b8300 builds at run time
// (dumped from the original): the hex letters by case, and the three joiners a
// decimal number may run across.
static const u8* HexClass() {
    static u8 t[256];
    static bool built = false;
    if (!built) {
        memset(t, 0, sizeof(t));
        for (int c = 'A'; c <= 'F'; ++c) t[c] = 1;
        for (int c = 'a'; c <= 'f'; ++c) t[c] = 2;
        t[(u8)'-'] = t[(u8)'.'] = t[(u8)':'] = 4;
        built = true;
    }
    return t;
}
static inline bool IsDigit(u32 b) { return (u32)(b - '0') <= 9u; }

struct TextTransformNumber {
    ArithDec adec_;
    One one_;
    Two two_;

    void Decode_0(u8** out_ptr, const u8** in_ptr, const u8* in_ptr_end, u32 digit) {
        const u8* in = *in_ptr;
        u8* out = *out_ptr;
        u32 digit_mask = (digit == 0x31);
        u32 num_digits = 1;
        while (num_digits != 8 && in != in_ptr_end && ((u32)((digit = *in) - 0x31) <= 1u)) {
            digit_mask = digit_mask * 2 + (digit == 0x31);
            num_digits++;
            in++;
        }
        u16* model = &two_.recent_or_num_model_[num_digits - (size_t)1];
        bool literal = adec_.Read(*model);
        *model = (u16)(*model + ((((u32)literal << 16) + 8u - *model) >> 4));
        u32 number = 0;
        if (literal) {
            u32 bits_to_read = num_digits * 4;
            u32 number_low = 1, v;
            u16* big_model = &two_.big_number_model_[(num_digits - 1) * 32 + 4 * num_digits - 1];
            u8* small_model = nullptr;
            do {
                if (number_low >= 0x1000) { v = *big_model; }
                else { small_model = &two_.small_number_model_[(num_digits - 1) * 4096 + number_low]; v = (u32)(*small_model) << 8; }
                u16* inner_model;
                bool numbit = adec_.Read(two_.number_model_.Get(v, bits_to_read - 1, &inner_model));
                *inner_model = (u16)(*inner_model + (((u32)numbit * 0x1007e - *inner_model) >> 7));
                number = number * 2 + numbit;
                if (number_low >= 0x1000) {
                    *big_model = (u16)(*big_model + ((8u - *big_model + (u32)numbit * 65536u) >> 4));
                } else {
                    *small_model = (u8)(*small_model + ((4u - *small_model + (u32)numbit * 256u) >> 3));
                    number_low = number_low * 2 + numbit;
                }
                big_model--;
            } while (--bits_to_read);
            two_.recent_numbers_[num_digits - 1].Insert(number);
        } else {
            u32 n = 6, model_slot = 1, i = 0;
            do {
                u16* m = &two_.recent_model_[model_slot];
                u32 bit = adec_.Read(*m);
                *m = (u16)(*m + ((bit * 65536u + 8u - *m) >> 4));
                model_slot = model_slot * 2 + bit;
                i = i * 2 + bit;
            } while (--n);
            number = two_.recent_numbers_[num_digits - 1].Get(i);
        }
        do {
            u32 d = (number >> (num_digits * 4 - 4)) & 0xf;
            u32 lowercase = (digit_mask >> (num_digits - 1)) & 0x1;
            if (!room(out, 1)) { *out_ptr = out; return; }
            *out++ = (u8)(d + ((d <= 9) ? '0' : ('A' - 10 + lowercase * 0x20)));
        } while (--num_digits);
        *in_ptr = in;
        *out_ptr = out;
    }

    void Decode_1(u8** out_ptr, const u8** in_ptr, const u8* in_ptr_end, u32 digit) {
        const u8 *in = *in_ptr, *in_org = in;
        u8* out = *out_ptr;
        u32 prev_digit = out[-1];
        if (prev_digit == ' ') prev_digit = out[-2];
        u32 num_zeros = 0;
        while (num_zeros != 8 && in != in_ptr_end) {
            digit = *in++;
            if (digit == '0') { num_zeros += 1; }
            else { if (digit != 0x2d && digit != 0x2e && digit != 0x3a) break; }
        }
        if (digit == ' ' && in != in_ptr_end) digit = *in;
        if ((digit >= '0' && digit <= '9') || ((digit | 32) >= 'a' && (digit | 32) <= 'f')) digit = '1';
        u32 hash8 = kDecpDigitHash[digit] + (kDecpDigitHash[prev_digit] << 4);
        u32 hash10 = (digit ^ (8 * prev_digit)) & 0x3ff;
        One::Hash& hashval_ref = one_.digit_context_hash_[hash10 * 8 + num_zeros];
        u32 pred_score = hashval_ref.score;
        i32 hashval_delta = hashval_ref.delta;
        u32 pred_number = hashval_ref.pred + hashval_delta;
        u32 number = pred_number;
        u32 is_predicted = pred_score;
        if (is_predicted) {
            u32 ba = (u32)std::abs(hashval_delta);
            if (ba > 1) ba = 2 + ((ba - 2) ? BSR(ba - 2) : 0);
            u32 min7 = std::min<u32>((hashval_delta < 0) + 2 * ba, 7);
            u32 min3 = std::min<u32>(min7, 3);
            u32 vb = pred_score - 1;
            if (vb > 7) vb = kDecpCompactTable[vb] + 8;
            u32 d_idx = min3 + (vb << 2) + (hash8 << 6) + (num_zeros << 14);
            u32 d_value = Get4bit(one_.model_d_, d_idx);
            u16 *c_ptr = &one_.model_c_[d_value], *b_ptr, *a_ptr;
            u32 b_value = one_.model_b_.Get(*c_ptr, min7, &b_ptr);
            u32 a_value = one_.model_a_.Get(b_value, min3 + vb * 4 + num_zeros * 64, &a_ptr);
            is_predicted = adec_.Read(a_value);
            *a_ptr = (u16)(*a_ptr + ((is_predicted * 0x1001e - *a_ptr) >> 5));
            *b_ptr = (u16)(*b_ptr + ((is_predicted * 0x10006 - *b_ptr) >> 3));
            *c_ptr = (u16)(*c_ptr + ((is_predicted * 0x10000 - *c_ptr + 32) >> 6));
            one_.model_d_[d_idx >> 1] = (u8)(one_.model_d_[d_idx >> 1]
                // Shift performed on the unsigned bit pattern: shifting a
                // negative int is UB, and the optimiser is entitled to act on
                // it (the same class of UB that let gcc delete a loop bound in
                // the BWT port). Bit-identical on two's complement.
                - (i32)((u32)(-(i32)(((u32)0x10 * is_predicted - d_value) >> 1)) << (4 * (d_idx & 1))));
        }
        if (!is_predicted) {
            if (num_zeros >= 4) {
                u16* model_e_ptr = &one_.model_e_[hash8 + num_zeros * 256];
                bool flag_recent = adec_.Read(*model_e_ptr);
                *model_e_ptr = (u16)(*model_e_ptr + (((u32)flag_recent * 65536 + 8 - *model_e_ptr) >> 4));
                if (!flag_recent) {
                    u32 n = 7, model_slot = 1, i = 0;
                    do {
                        u16* m = &one_.model_f_[model_slot];
                        u32 bit = adec_.Read(*m);
                        *m = (u16)(*m + ((bit * 65536u + 8 - *m) >> 4));
                        model_slot = model_slot * 2 + bit;
                        i = i * 2 + bit;
                    } while (--n);
                    number = one_.recent_numbers_[num_zeros - 4].Get(i);
                    goto done;
                }
            }
            {
                u32 number_low = 1;
                u32 lower = 0;
                u32 upper = kDigitMultipliers[num_zeros];
                u32 ii = 0;
                u32 model_j_upper = ((hash8 & 1) + 8 * num_zeros + ((hash8 >> 3) & 6)) * 8192;
                u32 model_j_value = 0;
                u16 *model_ptr, *model_h_ptr, *model_g_ptr;
                while ((number = (lower + upper) >> 1) > lower) {
                    if (number_low >= 0x2000) {
                        model_ptr = &one_.model_big_[ii - 13 + 19 * num_zeros];
                    } else {
                        model_j_value = Get4bit(one_.model_j_, model_j_upper + number_low);
                        model_ptr = &one_.model_small_[model_j_value];
                    }
                    u32 v = one_.model_h_.Get(*model_ptr, hash8 * 32 + ii, &model_h_ptr);
                    v = one_.model_g_.Get(v, num_zeros * 32 + ii, &model_g_ptr);
                    bool latest_bit = adec_.Read(v);
                    *model_g_ptr = (u16)(*model_g_ptr + ((0x1003Eu * latest_bit - *model_g_ptr) >> 6));
                    *model_h_ptr = (u16)(*model_h_ptr + ((0x1003Eu * latest_bit - *model_h_ptr) >> 6));
                    if (number_low >= 0x2000) {
                        *model_ptr = (u16)(*model_ptr + ((0x10000u * latest_bit - *model_ptr + 8u) >> 4));
                    } else {
                        *model_ptr = (u16)(*model_ptr + ((0x10000u * latest_bit - *model_ptr + 32u) >> 6));
                        u32 model_j_idx = model_j_upper + number_low;
                        one_.model_j_[model_j_idx >> 1] = (u8)(one_.model_j_[model_j_idx >> 1]
                            // Unsigned shift, see the matching note above.
                            - (i32)((u32)(-(i32)((22u * latest_bit - model_j_value) >> 3)) << (4 * (model_j_idx & 1))));
                        number_low = number_low * 2 + latest_bit;
                    }
                    if (!latest_bit) lower = number; else upper = number;
                    ii++;
                }
                if (num_zeros >= 4) one_.recent_numbers_[num_zeros - 4].Insert(number);
            }
        }
    done:
        if (pred_score == 0) hashval_ref.delta = (i8)(number - hashval_ref.pred);
        hashval_ref.pred = number;
        hashval_ref.score = (u8)((pred_number == number || pred_score == 0)
            ? pred_score + ((pred_number == number) & (pred_score < 255))
            : pred_score >> 1);
        u8 num_buf[16], *s = num_buf;
        while (number >= 10) { *s++ = (u8)('0' + number % 10); number /= 10; }
        *s++ = (u8)('0' + number);
        while (s <= num_buf + num_zeros && s < num_buf + sizeof(num_buf)) *s++ = '0';
        if (!room(out, 1)) { *in_ptr = in; *out_ptr = out; return; }
        *out++ = *--s;
        u32 ndig = 0;
        for (in = in_org; in != in_ptr_end; ) {
            digit = *in;
            if (digit >= '0' && digit <= '9') {
                if (digit != '0') break;
                if (!room(out, 1)) break;
                *out++ = *--s;
                in++;
                if (++ndig == 8) break;
            } else {
                if (!room(out, 1)) break;
                *out++ = (u8)digit;
                in++;
                if (digit != 0x2d && digit != 0x2e && digit != 0x3a) break;
            }
        }
        *in_ptr = in;
        *out_ptr = out;
    }

    // Output limit. This decoder is driven by both the byte stream and an
    // arithmetic side-stream, and a corrupt or truncated pair can make it emit
    // far more than the caller declared -- out_cap used to be ignored outright,
    // so a 191-byte mutated archive walked off the end of the output buffer and
    // segfaulted. Every write site checks this now; hitting it abandons the
    // transform, and the caller then fails on size or checksum.
    u8* out_end_ = nullptr;
    bool overflow_ = false;
    bool room(const u8* out, u32 n) {
        if (out_end_ != nullptr && static_cast<u32>(out_end_ - out) < n) { overflow_ = true; return false; }
        return true;
    }

    // ------------------------------------------------------------------ forward
    // FUN_08058580 and its two coders, FUN_08056c20 (decimal) and FUN_08057800
    // (hexadecimal), over the same models as Decode_1 and Decode_0: every
    // context, probability and update is the decoder's, only the bit is known
    // instead of read. The pass is size-preserving: a decimal digit becomes '0',
    // each character of a hexadecimal run becomes '1' (lowercase) or '2'
    // (uppercase), and everything else is copied. All the information goes to
    // the side stream.
    ArithEnc enc_;

    // FUN_08056b00: is the digit at p[-1] part of a hexadecimal run? Looks back
    // over at most seven hex letters (never before `lower`, the start of the
    // current copied segment) and forward over digits and letters. A run needs
    // at least four characters, at least one letter, a single case, and at most
    // eight characters -- a ninth ends the matter with 0, not with a cut.
    // Returns (letters before the digit) << 8 | run length * 2 | (1 if uppercase).
    static u32 HexRun(const u8* p, const u8* lower, const u8* end) {
        const u8* hc = HexClass();
        u32 back = 0;
        const u8* q = p - 2;
        if (lower <= q && (hc[*q] & 3u)) {
            const u8* lim = p - 9;
            if (lim < lower) lim = lower;
            do { --q; ++back; if (q < lim) break; } while (hc[*q] & 3u);
        }
        const u8* start = q + 1;
        if (!(start < end)) return 0;
        u32 len = 0, cls = 0;
        bool letter = false;
        for (;;) {
            const u32 b = start[len];
            if (!IsDigit(b)) {
                if ((hc[b] & 3u) == 0u) break;
                if (len == 8u) return 0;
                ++len; cls |= hc[b] & 3u; letter = true;
                if (end <= start + len) break;
                continue;
            }
            if (len == 8u) return 0;
            ++len;
            if (!(start + len < end)) break;
        }
        if (!letter || len < 4u) return 0;
        if (cls == 3u) return 0;
        return (cls & 1u) + len * 2u + back * 0x100u;
    }

    // FUN_08057800: the hexadecimal run starting at *in_ptr.
    void Encode_0(u8** out_ptr, const u8** in_ptr, const u8* in_end, u8 marker) {
        const u8* hc = HexClass();
        const u8* in = *in_ptr;
        u8* out = *out_ptr;
        u32 nd = 0, value = 0;
        while (in < in_end) {
            const u32 b = *in++;
            if (IsDigit(b)) { *out++ = marker; value = value * 16u + (b - '0'); ++nd; }
            else if (hc[b] & 3u) { *out++ = marker; value = value * 16u + ((b - 'A' < 26u) ? b - 0x37u : b - 0x57u); ++nd; }
            else { *out++ = (u8)b; break; }   // the byte that ends the run is copied here
        }
        *in_ptr = in;
        const u32 slot = nd - 1u;
        u32 idx = 0;
        while (idx != 0x40u && two_.recent_numbers_[slot].recent[idx] != value) ++idx;
        const bool notfound = (idx == 0x40u);
        u16* m = &two_.recent_or_num_model_[slot];
        enc_.Encode(notfound, *m);
        *m = (u16)(*m + ((((u32)notfound << 16) + 8u - *m) >> 4));
        if (!notfound) {
            two_.recent_numbers_[slot].Get(idx);          // move to the front, as the decoder will
            u32 node = 1;
            for (int k = 5; k >= 0; --k) {
                const u32 bit = (idx >> k) & 1u;
                u16* rm = &two_.recent_model_[node];
                enc_.Encode(bit != 0u, *rm);
                *rm = (u16)(*rm + ((bit * 65536u + 8u - *rm) >> 4));
                node = node * 2u + bit;
            }
            *out_ptr = out;
            return;
        }
        two_.recent_numbers_[slot].Insert(value);
        u32 number_low = 1;
        u16* big = &two_.big_number_model_[slot * 32u + 4u * nd - 1u];
        for (int k = (int)(nd * 4u) - 1; k >= 0; --k, --big) {
            const u32 bit = (value >> k) & 1u;
            u32 v; u8* small = nullptr;
            if (number_low >= 0x1000u) v = *big;
            else { small = &two_.small_number_model_[slot * 4096u + number_low]; v = (u32)(*small) << 8; }
            u16* inner;
            const u32 pr = two_.number_model_.Get(v, (u32)k, &inner);
            enc_.Encode(bit != 0u, pr);
            *inner = (u16)(*inner + ((bit * 0x1007eu - *inner) >> 7));
            if (number_low >= 0x1000u) *big = (u16)(*big + ((8u - *big + bit * 65536u) >> 4));
            else { *small = (u8)(*small + ((4u - *small + bit * 256u) >> 3)); number_low = number_low * 2u + bit; }
        }
        *out_ptr = out;
    }

    // FUN_08056c20: the decimal number whose first digit is `digit`, *in_ptr
    // just past it. Digits are gathered across '-', '.' and ':' into one value
    // of up to nine digits, and predicted from the context of the byte before
    // and the byte after; a wrong or unscored prediction codes the number by
    // recency or by binary search over its digit-count range.
    void Encode_1(u8** out_ptr, const u8** in_ptr, const u8* in_end, u32 digit) {
        const u8* hc = HexClass();
        const u8* in = *in_ptr;
        u8* out = *out_ptr;
        u32 prev = in[-2];
        if (prev == ' ') prev = in[-3];
        u32 nz = 0, value = digit - '0', last = digit;
        *out++ = '0';
        while (in < in_end) {
            const u32 b = *in++;
            last = b;
            if (IsDigit(b)) { ++nz; *out++ = '0'; value = (b - '0') + value * 10u; if (nz == 8u) break; }
            else { *out++ = (u8)b; if ((hc[b] & 4u) == 0u) break; }
        }
        *in_ptr = in;
        u32 d = last;
        if (d == ' ' && in < in_end) d = *in;
        if (IsDigit(d) || (hc[d] & 3u)) d = '1';
        const u32 hash8 = kDecpDigitHash[d] + (kDecpDigitHash[prev] << 4);
        const u32 hash10 = (d ^ (8u * prev)) & 0x3ffu;
        One::Hash& ctx = one_.digit_context_hash_[hash10 * 8u + nz];
        const u32 score = ctx.score;
        const i32 delta = ctx.delta;
        const u32 pred = ctx.pred + (u32)delta;
        const bool predicted = (value == pred);
        const u32 is_predicted = predicted ? 1u : 0u;
        if (score != 0u) {
            u32 ba = (u32)std::abs(delta);
            if (ba > 1u) ba = 2u + ((ba - 2u) ? BSR(ba - 2u) : 0u);
            const u32 min7 = std::min<u32>((delta < 0) + 2u * ba, 7u);
            const u32 min3 = std::min<u32>(min7, 3u);
            u32 vb = score - 1u;
            if (vb > 7u) vb = kDecpCompactTable[vb] + 8u;
            const u32 d_idx = min3 + (vb << 2) + (hash8 << 6) + (nz << 14);
            const u32 d_value = Get4bit(one_.model_d_, d_idx);
            u16 *c_ptr = &one_.model_c_[d_value], *b_ptr, *a_ptr;
            const u32 b_value = one_.model_b_.Get(*c_ptr, min7, &b_ptr);
            const u32 a_value = one_.model_a_.Get(b_value, min3 + vb * 4u + nz * 64u, &a_ptr);
            enc_.Encode(predicted, a_value);
            *a_ptr = (u16)(*a_ptr + ((is_predicted * 0x1001eu - *a_ptr) >> 5));
            *b_ptr = (u16)(*b_ptr + ((is_predicted * 0x10006u - *b_ptr) >> 3));
            *c_ptr = (u16)(*c_ptr + ((is_predicted * 0x10000u - *c_ptr + 32u) >> 6));
            one_.model_d_[d_idx >> 1] = (u8)(one_.model_d_[d_idx >> 1]
                - (i32)((u32)(-(i32)(((u32)0x10 * is_predicted - d_value) >> 1)) << (4 * (d_idx & 1))));
        }
        if (!predicted || score == 0u) {
            u32 upper = kDigitMultipliers[nz];
            bool coded = false;
            if (nz >= 4u) {
                u32 idx = 0;
                while (idx != 0x80u && one_.recent_numbers_[nz - 4u].recent[idx] != value) ++idx;
                const bool notfound = (idx == 0x80u);
                u16* me = &one_.model_e_[hash8 + nz * 256u];
                enc_.Encode(notfound, *me);
                *me = (u16)(*me + ((((u32)notfound << 16) + 8u - *me) >> 4));
                if (!notfound) {
                    one_.recent_numbers_[nz - 4u].Get(idx);
                    u32 node = 1;
                    for (int k = 6; k >= 0; --k) {
                        const u32 bit = (idx >> k) & 1u;
                        u16* fm = &one_.model_f_[node];
                        enc_.Encode(bit != 0u, *fm);
                        *fm = (u16)(*fm + ((bit * 65536u + 8u - *fm) >> 4));
                        node = node * 2u + bit;
                    }
                    coded = true;
                } else {
                    one_.recent_numbers_[nz - 4u].Insert(value);
                }
            }
            if (!coded) {
                u32 number_low = 1, lower = 0, ii = 0, mid;
                const u32 mj_upper = ((hash8 & 1u) + 8u * nz + ((hash8 >> 3) & 6u)) * 8192u;
                while ((mid = (lower + upper) >> 1) > lower) {
                    u16* mp; u32 mjv = 0;
                    if (number_low >= 0x2000u) mp = &one_.model_big_[ii - 13u + 19u * nz];
                    else { mjv = Get4bit(one_.model_j_, mj_upper + number_low); mp = &one_.model_small_[mjv]; }
                    u16 *hp, *gp;
                    u32 v = one_.model_h_.Get(*mp, hash8 * 32u + ii, &hp);
                    v = one_.model_g_.Get(v, nz * 32u + ii, &gp);
                    const u32 bit = (value < mid) ? 1u : 0u;
                    enc_.Encode(bit != 0u, v);
                    *gp = (u16)(*gp + ((0x1003Eu * bit - *gp) >> 6));
                    *hp = (u16)(*hp + ((0x1003Eu * bit - *hp) >> 6));
                    if (number_low >= 0x2000u) {
                        *mp = (u16)(*mp + ((0x10000u * bit - *mp + 8u) >> 4));
                    } else {
                        *mp = (u16)(*mp + ((0x10000u * bit - *mp + 32u) >> 6));
                        const u32 mj_idx = mj_upper + number_low;
                        one_.model_j_[mj_idx >> 1] = (u8)(one_.model_j_[mj_idx >> 1]
                            - (i32)((u32)(-(i32)((22u * bit - mjv) >> 3)) << (4 * (mj_idx & 1))));
                        number_low = number_low * 2u + bit;
                    }
                    if (!bit) lower = mid; else upper = mid;
                    ++ii;
                }
            }
        }
        if (score == 0u) ctx.delta = (i8)(value - ctx.pred);
        ctx.pred = value;
        ctx.score = (u8)((predicted || score == 0u) ? score + (is_predicted & (score < 255u)) : score >> 1);
        *out_ptr = out;
    }

    // FUN_08058580. `side_cap` is the room the aux stream has; the original's
    // writer stops at half of it, and the pass declines unless it wrote more
    // than four bytes and stayed under that half.
    u32 Encode(const u8* in, u32 n, u8* out, u32 out_cap, std::vector<u8>* side, u32 side_cap) {
        if (n <= 9u || out_cap < n || side == nullptr) return 0;
        one_.Initialize();
        two_.Initialize();
        side->clear();
        enc_ = ArithEnc();
        enc_.side = side;
        enc_.cap = side_cap >> 1;
        const u8* p = in;
        const u8* const end = in + n;
        u8* o = out;
        o[0] = p[0]; o[1] = p[1];
        p += 2; o += 2;
        const u8* seg = p;                       // where the current copied run began
        while (p < end) {
            u32 b;
            for (;;) {
                b = *p++;
                if (IsDigit(b)) break;
                *o++ = (u8)b;
                if (end <= p) goto finish;
            }
            const u32 r = HexRun(p, seg, end);
            if (r == 0u) {
                Encode_1(&o, &p, end, b);
            } else {
                const u32 back = r >> 8;
                p = p - 1 - back;                // the run starts at its first letter
                o -= back;                       // whose copies are replaced by markers
                Encode_0(&o, &p, end, (r & 1u) ? (u8)'2' : (u8)'1');
            }
            seg = p;
        }
    finish:
        enc_.Flush();
        if (!(side->size() < enc_.cap && side->size() > 4u)) return 0;
        return (u32)(o - out);
    }

    u32 Decode(const u8* in_ptr, u32 in_size, u8* out_ptr, u8* out_limit) {
        if (in_size <= 9) return 0;
        out_end_ = out_limit;
        overflow_ = false;
        one_.Initialize();
        two_.Initialize();
        adec_.FillBuffer();
        u8* out_ptr_org = out_ptr;
        const u8* in_ptr_end = in_ptr + in_size;
        if (!room(out_ptr, 2)) return 0;
        *out_ptr++ = *in_ptr++;
        *out_ptr++ = *in_ptr++;
        while (in_ptr != in_ptr_end) {
            u32 digit = *in_ptr++;
            if ((u32)(digit - '0') <= 9) {
                if ((u32)(digit - '1') <= 1) Decode_0(&out_ptr, &in_ptr, in_ptr_end, digit);
                else Decode_1(&out_ptr, &in_ptr, in_ptr_end, digit);
                if (overflow_) return 0;
            } else {
                if (!room(out_ptr, 1)) return 0;
                *out_ptr++ = (u8)digit;
            }
        }
        return (u32)(out_ptr - out_ptr_org);
    }
};

}  // namespace

uint32_t NzTextTransformNumberEncode(const uint8_t* in, uint32_t in_size,
                                     uint8_t* out, uint32_t out_cap,
                                     std::vector<uint8_t>* side, uint32_t side_cap) {
    TextTransformNumber* t = new (std::nothrow) TextTransformNumber();
    if (!t) return 0;
    uint32_t n = t->Encode(in, in_size, out, out_cap, side, side_cap);
    delete t;
    return n;
}

uint32_t NzTextTransformNumber(const uint8_t* side, uint32_t side_len,
                               const uint8_t* in, uint32_t in_size,
                               uint8_t* out, uint32_t out_cap) {
    TextTransformNumber* t = new (std::nothrow) TextTransformNumber();
    if (!t) return 0;
    t->adec_.InitializeX(side, side + side_len);
    uint32_t n = t->Decode(in, in_size, out, out + out_cap);
    delete t;
    return n;
}
