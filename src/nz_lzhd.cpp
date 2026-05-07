// nz_lzhd.cpp — C++17/Linux port of the NanoZip lzhd decoder (DecLZ from
// nzdec_v0 NZ_LZ.cpp by Shelwien).  FUN_080b5240 in the 32-bit ELF.
//
// Tables shared with nz_cm.cpp (built by NzCmInitAll()):
//   kModelInterpolation[4096], kModelLutLookup[4096],
//   kDivideLookup[256], kLzPredSumLookup[256],
//   kLzModelInterpolation[256], kLzModelLNext[512].

#include "nz_lzhd.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>

// ---------------------------------------------------------------------------
// Shared tables built by NzCmInitAll() in nz_cm.cpp
// ---------------------------------------------------------------------------
extern uint16_t kModelInterpolation[4096];
extern uint16_t kModelLutLookup[4096];
extern uint32_t kDivideLookup[256];
extern uint16_t kLzPredSumLookup[256];
extern int16_t  kLzModelInterpolation[256];
extern const uint8_t kLzModelLNext[256 * 2];

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------
static inline void lz_memset32(void* dst, uint32_t value, size_t n) {
    uint32_t* p = static_cast<uint32_t*>(dst);
    for (size_t i = 0; i < n; ++i) p[i] = value;
}

static void lz_create_model_lut(uint16_t* out, uint32_t rows, uint32_t cols,
                                 uint32_t step, uint32_t first) {
    out[0] = 0;
    out[cols - 1] = 0xffffu;
    const uint16_t* tp = &kModelLutLookup[first];
    for (uint32_t i = 1; i < cols - 1; ++i, tp += step)
        out[i] = static_cast<uint16_t>(tp[0] << 4u);
    uint16_t* dp = &out[cols];
    for (uint32_t n = cols * (rows - 1); n; --n)
        *dp++ = *out++;
}

// ---------------------------------------------------------------------------
// ArithmeticDecoder (12-bit range coder matching nzdec_v0 nz.h)
// ---------------------------------------------------------------------------
struct LzArithDec {
    uint32_t range_hi, range_lo, bitbuff;
    const uint8_t* data;
    const uint8_t* data_end;

    uint32_t read_byte() { return (data != data_end) ? *data++ : 0u; }

    void initialize(const uint8_t* p, const uint8_t* end) {
        data = p; data_end = end;
        range_lo = 0; range_hi = 0xffffffffu; bitbuff = 0;
    }

    void fill_buffer() {
        for (int i = 0; i < 4; ++i)
            bitbuff = (bitbuff << 8) | read_byte();
    }

    void renormalize() {
        while ((range_lo ^ range_hi) < 0x1000000u) {
            range_lo <<= 8;
            range_hi = (range_hi << 8) + 0xffu;
            bitbuff  = (bitbuff  << 8) | read_byte();
        }
    }

    bool read_no_shift(uint32_t model) {
        uint32_t cmp = range_lo + ((range_hi - range_lo) >> 12u) * model;
        if (bitbuff <= cmp) range_hi = cmp;
        else                range_lo = cmp + 1u;
        bool flag = (bitbuff <= cmp);
        renormalize();
        return flag;
    }

    bool read(uint32_t model)   { return read_no_shift(model >> 4u); }
    bool read_x(uint32_t model) {
        uint32_t m = model >> 4u;
        return read_no_shift(m + (m < 0x800u ? 1u : 0u));
    }
};

// ---------------------------------------------------------------------------
// Interpolating model helpers (templates matching nzdec_v0)
// ---------------------------------------------------------------------------
template<int Scale>
static uint32_t lz_interpolate(uint16_t* base, uint32_t value,
                                uint32_t index, uint16_t** out_ptr) {
    uint32_t hv = static_cast<uint32_t>(kLzModelInterpolation[value >> 4u] + 0x800) *
                  static_cast<uint32_t>(Scale - 1);
    uint16_t* model = &base[(hv >> 12u) + Scale * index];
    uint32_t interp = (value +
        3u * (((4096u - (hv & 0xfffu)) * model[0] +
                model[1] * (hv & 0xfffu)) >> 16u) + 2u) >> 2u;
    model += (hv & 0xfffu) >> 11u;
    *out_ptr = model;
    return interp;
}

template<int Scale>
static uint32_t lz_interpolate2(uint16_t* base, uint32_t value,
                                 uint32_t index, uint16_t** out_ptr) {
    uint32_t lu = kLzPredSumLookup[value >> 4u];
    uint32_t hv = value * static_cast<uint32_t>(Scale - 1);
    uint16_t* model = &base[(hv >> 12u) + Scale * index];
    uint32_t interp = (lu +
        3u * (((4096u - (hv & 0xfffu)) * model[0] +
                model[1] * (hv & 0xfffu)) >> 16u) + 2u) >> 2u;
    model += (hv & 0xfffu) >> 11u;
    *out_ptr = model;
    return interp;
}

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------
static const uint8_t kLzHistCompress[256] = {
    16,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 11,
    10,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 13,
    12,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 11,
    10,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 15,
    14,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 11,
    10,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 13,
    12,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 11,
    10,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6,  9,
     8,  1,  2,  3,  4,  5,  6,  7,  0,  1,  2,  3,  4,  5,  6, 17,
};

static const uint8_t kLzMatchLenToModel[16] = {
    0, 1, 2, 3, 4, 5, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8
};

// ---------------------------------------------------------------------------
// DecLZ — context-mixing LZ decoder
// ---------------------------------------------------------------------------
struct DecLZ {
    int16_t linear_pred_coeffs[12][8];

    uint8_t  model_h[256][256];
    uint8_t  model_r[768];
    uint8_t  model_i[256][256];
    uint16_t model_d[12 * 1536];
    uint8_t  model_k[65536];
    uint16_t model_j[16];
    uint8_t  model_g[1024];
    uint8_t  model_f[4096];
    uint8_t  model_l[256][256][256];
    uint32_t model_u[256];

    uint16_t matchlen_bits_model[32];
    uint16_t matchlen_model[512];
    uint16_t offs_bits_model_a[288];
    uint16_t offs_bits_model_b[32 * 17];

    struct HiOffsModel  { uint16_t model[4];  };
    struct MidOffsModel { uint16_t model[26]; };
    struct LowOffsModel { uint16_t model[32]; };

    MidOffsModel mid_offs_model[32];
    HiOffsModel  high_offs_model[32];
    LowOffsModel low_offs_model[32];
    uint16_t repmatch_model[2048];

    uint8_t  model_a[2048];
    uint16_t model_b[288 * 5];
    uint16_t model_c[256 * 10];

    uint32_t position_history[65536];

    DecLZ();
    void decode(const uint8_t* in,  uint32_t in_size,
                uint8_t*       out, uint32_t out_size,
                uint8_t*       window_base);
};

DecLZ::DecLZ() {
    std::memset(position_history,   0,    sizeof(position_history));
    std::memset(linear_pred_coeffs, 0,    sizeof(linear_pred_coeffs));
    std::memset(model_h,            0x80, sizeof(model_h));
    std::memset(model_r,            0x80, sizeof(model_r));
    std::memset(model_i,            0x80, sizeof(model_i));
    lz_create_model_lut(model_d, 12, 1536, 372, 371);
    std::memset(model_k,            0x88, sizeof(model_k));
    lz_memset32(model_j,  0x80008000u, sizeof(model_j)  / 4);
    std::memset(model_g,            0x80, sizeof(model_g));
    std::memset(model_f,            0x80, sizeof(model_f));
    std::memset(model_l,            0,    sizeof(model_l));
    lz_memset32(model_u,  0x80000000u, sizeof(model_u)  / 4);
    lz_memset32(matchlen_bits_model, 0x80008000u, sizeof(matchlen_bits_model) / 4);
    lz_memset32(matchlen_model,      0x80008000u, sizeof(matchlen_model)      / 4);
    lz_memset32(offs_bits_model_a,   0x80008000u, sizeof(offs_bits_model_a)   / 4);
    lz_create_model_lut(offs_bits_model_b, 32, 17, 256, 255);
    lz_memset32(repmatch_model, 0x80008000u, sizeof(repmatch_model) / 4);
    std::memset(model_a, 0x80, sizeof(model_a));
    lz_create_model_lut(model_b, 288, 5,  1024, 1023);
    lz_create_model_lut(model_c, 256, 10,  455,  454);
    for (size_t i = 0; i < 32; ++i) {
        lz_memset32(mid_offs_model[i].model,  0x80008000u,
                    sizeof(mid_offs_model[i].model)  / 4);
        lz_memset32(high_offs_model[i].model, 0x80008000u,
                    sizeof(high_offs_model[i].model) / 4);
        lz_memset32(low_offs_model[i].model,  0x80008000u,
                    sizeof(low_offs_model[i].model)  / 4);
    }
}

void DecLZ::decode(const uint8_t* inx, uint32_t in_size,
                   uint8_t* out, uint32_t out_size, uint8_t* window_base) {
    uint32_t repmatch[4];
    uint8_t* out_end = out + out_size;

    repmatch[0] = repmatch[1] = repmatch[2] = repmatch[3] = 1u;
    uint32_t last_lit = 0u;
    uint8_t  lit_or_match_hist = 0xffu;

    LzArithDec adec;
    adec.initialize(inx, inx + in_size);
    adec.fill_buffer();

    while (out < out_end) {
        uint32_t round_bytes = static_cast<uint32_t>(
            std::min<ptrdiff_t>(0x8000, out_end - out));
        uint32_t round_bytes_left = round_bytes;

        do {
            uint8_t* cur_ptr = out;

            uint32_t pos_hash = static_cast<uint16_t>(
                static_cast<uint32_t>(*reinterpret_cast<const uint16_t*>(cur_ptr - 2)) +
                197u * static_cast<uint32_t>(cur_ptr[-3]));

            const uint8_t* rep_ptr = cur_ptr - (repmatch[0] + 1u);

            uint32_t context32 =
                (static_cast<uint32_t>(rep_ptr[0])   << 24u) +
                (static_cast<uint32_t>(cur_ptr[-2])  << 16u) +
                (rep_ptr[-1] == cur_ptr[-1] ? 1u : 0u) +
                (rep_ptr[-2] == cur_ptr[-2] ? 2u : 0u) +
                (rep_ptr[-3] == cur_ptr[-3] ? 4u : 0u) +
                (rep_ptr[-4] == cur_ptr[-4] ? 8u : 0u);

            uint8_t byte_at_minus3 = cur_ptr[-3];

            uint32_t context_0 = (context32 & 7u) + 8u * (context32 >> 24u);
            uint32_t context_1 = (last_lit & 0xfu) + 16u * (context32 & 3u);
            uint32_t context_2 = (context32 & 15u) +
                                  16u * kLzHistCompress[lit_or_match_hist];

            uint8_t*  model_a_ptr = &model_a[context_0];
            uint16_t* model_b_ptr;
            uint16_t* model_c_ptr;
            uint32_t m1 = lz_interpolate<5>(
                model_b, static_cast<uint32_t>(*model_a_ptr) * 16u,
                context_2, &model_b_ptr);
            uint32_t litflag_prob = lz_interpolate<10>(
                model_c, m1, context_1, &model_c_ptr);

            bool litflag = adec.read_no_shift(
                litflag_prob + (litflag_prob <= 0x7ffu ? 1u : 0u));
            *model_a_ptr = static_cast<uint8_t>(
                *model_a_ptr +
                ((4u + (litflag ? 0x100u : 0u) - *model_a_ptr) >> 3u));
            *model_b_ptr = static_cast<uint16_t>(
                *model_b_ptr +
                ((0x1000eu * (litflag ? 1u : 0u) - *model_b_ptr) >> 4u));
            *model_c_ptr = static_cast<uint16_t>(
                *model_c_ptr +
                ((0x1001eu * (litflag ? 1u : 0u) - *model_c_ptr) >> 5u));

            if (litflag) {
                // ---- Literal byte path ----
                uint8_t* model_l_ptr =
                    model_l[static_cast<uint8_t>(context32 >> 16u)]
                           [static_cast<uint8_t>(last_lit)];
                uint32_t model_k_idx =
                    256u * (((last_lit >> 5u) & 7u) +
                             2u * (static_cast<uint8_t>(cur_ptr[-3]) & 0xe0u) +
                             ((static_cast<uint8_t>(context32 >> 0x10u) & 0xe0u) >> 2u));

                uint8_t* model_h_ptr = model_h[static_cast<uint8_t>(last_lit)];
                uint8_t* model_i_ptr =
                    model_i[static_cast<uint8_t>(context32 >> 16u) & 0xffu];

                uint32_t* pos_hash_ptr = &position_history[pos_hash];
                uint32_t  old_pos_hash = *pos_hash_ptr;
                *pos_hash_ptr = static_cast<uint32_t>(out - window_base);
                if (old_pos_hash) {
                    const uint8_t* pp = window_base + old_pos_hash;
                    if (*reinterpret_cast<const uint16_t*>(pp - 2) ==
                            *reinterpret_cast<const uint16_t*>(cur_ptr - 2) &&
                        pp[-3] == byte_at_minus3) {
                        bool x4 = (pp[-4] == cur_ptr[-4]);
                        bool x5 = (pp[-5] == cur_ptr[-5]);
                        context32 +=
                            16u * (static_cast<uint32_t>(x4) +
                                   static_cast<uint32_t>(x4 & x5) + 1u) +
                            (static_cast<uint32_t>(pp[0]) << 8u);
                    }
                }

                uint32_t shifted_value_1 = 256u + static_cast<uint8_t>(context32 >> 24u);
                uint32_t shifted_value_2 = 256u + static_cast<uint8_t>(context32 >>  8u);

                uint32_t model_g_idx =
                    1u + ((shifted_value_1 >> 6u) & 2u) +
                    16u * (round_bytes_left & 3u) + 64u * (context32 & 0xfu);
                uint32_t model_f_idx =
                    1u + ((shifted_value_2 >> 6u) & 2u) +
                    32u * ((context32 >> 4u) & 3u) +
                    128u * (last_lit & 0x1fu);

                uint8_t  param_a = 0, param_b = 0, param_c = 0;
                uint32_t model_r_idx  = 1u;
                uint32_t lit_bit_accum = 1u;
                uint8_t  param_g = 0;
                if (!(lit_or_match_hist & 1u)) {
                    param_g     = static_cast<uint8_t>(last_lit >> 8u);
                    model_r_idx = (param_g >> 7u) + 0x202u;
                }

                last_lit     = 0u;
                uint32_t num_lit_bits = 8u;
                int16_t  predictors[8];

                for (;;) {
                    uint32_t* model_u_ptr = &model_u[*model_l_ptr];
                    uint8_t model_j_idx =
                        (model_k[model_k_idx >> 1u] >>
                         (4u * (model_k_idx & 1u))) & 0xfu;

                    uint8_t* model_r_ptr = &model_r[model_r_idx];
                    uint8_t* model_g_ptr = &model_g[model_g_idx];
                    uint8_t* model_f_ptr = &model_f[model_f_idx];
                    uint32_t coeff_set   =
                        ((model_g_idx >> 6u) & 3u) + 4u * (model_r_idx >> 8u);

                    predictors[0] = kLzModelInterpolation[*model_u_ptr >> 24u];
                    predictors[1] = kLzModelInterpolation[
                        static_cast<uint8_t>(model_j[model_j_idx] >> 8u)];
                    predictors[2] = kLzModelInterpolation[*model_h_ptr];
                    predictors[3] = kLzModelInterpolation[*model_i_ptr];
                    predictors[4] = kLzModelInterpolation[*model_r_ptr];
                    predictors[5] = kLzModelInterpolation[
                        static_cast<uint8_t>((predictors[4] + 2048) >> 4u)];
                    predictors[6] = kLzModelInterpolation[*model_g_ptr];
                    predictors[7] = kLzModelInterpolation[*model_f_ptr];

                    int32_t sum = 0;
                    int16_t* cur_coeffs = linear_pred_coeffs[coeff_set];
                    for (int i = 0; i < 8; ++i)
                        sum += static_cast<int32_t>(predictors[i]) *
                               static_cast<int32_t>(cur_coeffs[i]);

                    uint32_t clamped_sum = static_cast<uint32_t>(
                        std::max(std::min((sum >> 16) + 2048, 4095), 0));

                    uint16_t* model_d_ptr;
                    uint32_t lit_bit_prob = lz_interpolate2<12>(
                        model_d, clamped_sum,
                        param_c + 2u * model_r_idx, &model_d_ptr);
                    lit_bit_prob += (lit_bit_prob < 0x800u ? 1u : 0u);

                    bool lit_bit = adec.read_no_shift(lit_bit_prob);

                    *model_d_ptr = static_cast<uint16_t>(
                        *model_d_ptr +
                        ((0x1003eu * (lit_bit ? 1u : 0u) - *model_d_ptr) >> 6u));

                    int32_t mult = 16 * (4095 * (lit_bit ? 1 : 0) -
                                         static_cast<int32_t>(lit_bit_prob));
                    for (int i = 0; i < 8; ++i) {
                        int32_t v = cur_coeffs[i] +
                            ((((mult * static_cast<int32_t>(predictors[i])) >> 16) + 1) >> 1);
                        cur_coeffs[i] = static_cast<int16_t>(
                            std::max(std::min(v, 32767), -32768));
                    }

                    *model_f_ptr = static_cast<uint8_t>(*model_f_ptr +
                        (((lit_bit ? 0x100u : 0u) + 8u - *model_f_ptr) >> 4u));
                    *model_g_ptr = static_cast<uint8_t>(*model_g_ptr +
                        (((lit_bit ? 0x100u : 0u) + 4u - *model_g_ptr) >> 3u));
                    *model_h_ptr = static_cast<uint8_t>(*model_h_ptr +
                        (((lit_bit ? 0x100u : 0u) + 4u - *model_h_ptr) >> 3u));
                    *model_i_ptr = static_cast<uint8_t>(*model_i_ptr +
                        (((lit_bit ? 0x100u : 0u) + 4u - *model_i_ptr) >> 3u));

                    model_j[model_j_idx] = static_cast<uint16_t>(
                        model_j[model_j_idx] +
                        (((lit_bit ? 0x10000u : 0u) + 32u - model_j[model_j_idx]) >> 6u));

                    // model_k nibble update (signed nibble arithmetic)
                    {
                        uint32_t sh = 4u * (model_k_idx & 1u);
                        uint8_t  byte_val = model_k[model_k_idx >> 1u];
                        int32_t  nibble   = (byte_val >> sh) & 0xfu;
                        int32_t  delta    = (static_cast<int32_t>(18u * (lit_bit ? 1u : 0u)) -
                                             static_cast<int32_t>(model_j_idx)) >> 2;
                        nibble = std::max(std::min(nibble + delta, 15), 0);
                        model_k[model_k_idx >> 1u] = static_cast<uint8_t>(
                            (byte_val & ~(0xfu << sh)) |
                            (static_cast<uint32_t>(nibble) << sh));
                    }

                    *model_l_ptr = kLzModelLNext[
                        static_cast<uint32_t>(*model_l_ptr) * 2u +
                        (lit_bit ? 1u : 0u)];

                    *model_u_ptr =
                        (kDivideLookup[static_cast<uint8_t>(*model_u_ptr)] *
                         ((lit_bit ? (1u << 23u) : 0u) - (*model_u_ptr >> 9u)) & ~0xffu) +
                        (*model_u_ptr +
                         (static_cast<uint8_t>(*model_u_ptr) <= 0x7eu ? 1u : 0u));

                    *model_r_ptr = static_cast<uint8_t>(*model_r_ptr +
                        (((lit_bit ? 0x100u : 0u) + 2u - *model_r_ptr) >> 2u));

                    last_lit = last_lit * 2u + (lit_bit ? 1u : 0u);
                    if (--num_lit_bits == 0u) break;

                    param_c = static_cast<uint8_t>(
                        (((lit_bit ? 0x1000u : 0u) - lit_bit_prob + 1280u) > 2561u) ? 1u : 0u);
                    lit_bit_accum = lit_bit_accum * 2u + (lit_bit ? 1u : 0u);

                    shifted_value_1 <<= 1u;
                    shifted_value_2 <<= 1u;

                    if (++param_a == 4u) {
                        int32_t inc = 15 * static_cast<int32_t>(lit_bit_accum) -
                                      static_cast<int32_t>(param_b) - 225;
                        model_l_ptr  += inc;
                        model_h_ptr  += inc;
                        model_k_idx   = static_cast<uint32_t>(
                                             static_cast<int32_t>(model_k_idx) + inc);
                        model_i_ptr  += inc;
                    } else {
                        // (lit_bit + 1) << ((param_a & 3) - 1)
                        int32_t inc = static_cast<int32_t>(
                            (lit_bit ? 2u : 1u) << ((param_a & 3u) - 1u));
                        param_b     = static_cast<uint8_t>(
                                          static_cast<int32_t>(param_b) + inc);
                        model_h_ptr += inc;
                        model_i_ptr += inc;
                        model_l_ptr += inc;
                        model_k_idx  = static_cast<uint32_t>(
                                           static_cast<int32_t>(model_k_idx) + inc);
                    }

                    model_g_idx =
                        (model_g_idx & 0xfff0u) +
                        (lit_bit_accum == (shifted_value_1 >> 8u) ? 1u : 0u) +
                        ((shifted_value_1 >> 6u) & 2u) +
                        4u * (param_a >> 1u);
                    model_f_idx =
                        (model_f_idx & 0xffe0u) +
                        (lit_bit_accum == (shifted_value_2 >> 8u) ? 1u : 0u) +
                        ((shifted_value_2 >> 6u) & 2u) +
                        4u * static_cast<uint32_t>(param_a);

                    uint32_t old_r = model_r_idx;
                    model_r_idx = (model_r_idx & 0xff00u) + lit_bit_accum;
                    if (old_r >= 0x200u) {
                        model_r_idx = 0x100u + lit_bit_accum;
                        if (static_cast<bool>(lit_bit) == static_cast<bool>(old_r & 1u)) {
                            param_g *= 2u;
                            // (2*lit_bit_accum & (~(int8)lit_bit >> 15)) | ...
                            uint32_t sign_ext = static_cast<uint32_t>(
                                static_cast<int32_t>(
                                    static_cast<int8_t>(lit_bit ? 1 : 0)) >> 15);
                            model_r_idx = (2u * lit_bit_accum & ~sign_ext) +
                                          (param_g >> 7u) + 0x200u;
                        }
                    }
                } // literal bit loop

                *out++ = static_cast<uint8_t>(last_lit);
                lit_or_match_hist =
                    static_cast<uint8_t>(lit_or_match_hist * 2u + 1u);
                round_bytes_left -= 1u;

            } else {
                // ---- Match path ----
                position_history[pos_hash] =
                    static_cast<uint32_t>(out - window_base);

                uint32_t rep_model_idx =
                    8u * ((lit_or_match_hist & 0xfu) +
                           16u * (context32 & 0xfu));
                uint32_t repmatch_index = 0u;
                do {
                    uint16_t* mp = &repmatch_model[
                        (rep_model_idx + repmatch_index) &
                        (repmatch_index == 0u ? 0x3ffu : 0x7ffu)];
                    bool rep_bit = adec.read_x(*mp);
                    *mp = static_cast<uint16_t>(
                        *mp + (((rep_bit ? 65536u : 0u) + 16u - *mp) >> 5u));
                    if (rep_bit) break;
                    ++repmatch_index;
                } while (repmatch_index != 4u);

                uint32_t matchlen_bits = 0u;
                for (;;) {
                    uint16_t* mp = &matchlen_bits_model[
                        ((repmatch_index == 1u) ? 16u : 0u) + matchlen_bits];
                    bool bit = adec.read(*mp);
                    *mp = static_cast<uint16_t>(
                        *mp + (((bit ? 65536u : 0u) + 16u - *mp) >> 5u));
                    if (!bit) break;
                    ++matchlen_bits;
                }

                uint32_t matchlen_bits_lo;
                uint32_t matchlen = (matchlen_bits != 0u) ? 1u : 0u;
                uint16_t* matchlen_model_base = &matchlen_model[32u * matchlen_bits];

                if (matchlen_bits >= 4u) {
                    matchlen_bits_lo = matchlen_bits - 4u;
                    matchlen_bits    = 4u;
                } else {
                    matchlen_bits_lo = 0u;
                    matchlen_bits   += (matchlen_bits == 0u ? 1u : 0u);
                }

                uint32_t matchlen_accum =
                    2u * (repmatch_index == 0u ? 1u : 0u) + 1u;
                do {
                    uint16_t* mp = &matchlen_model_base[matchlen_accum];
                    bool bit = adec.read(*mp);
                    *mp = static_cast<uint16_t>(
                        *mp + (((bit ? 65536u : 0u) + 8u - *mp) >> 4u));
                    matchlen       = matchlen       * 2u + (bit ? 1u : 0u);
                    matchlen_accum = matchlen_accum * 2u + (bit ? 1u : 0u);
                } while (--matchlen_bits);

                for (; matchlen_bits_lo; --matchlen_bits_lo)
                    matchlen = matchlen * 2u + (adec.read(0x8000u) ? 1u : 0u);

                matchlen += 2u;

                uint32_t offset;
                if (repmatch_index != 0u) {
                    offset = repmatch[repmatch_index - 1u];
                    for (; repmatch_index != 1u; --repmatch_index)
                        repmatch[repmatch_index - 1u] = repmatch[repmatch_index - 2u];
                    repmatch[0] = offset;
                } else {
                    uint32_t offs_base_idx =
                        32u * kLzMatchLenToModel[std::min(matchlen - 2u, 15u)];
                    uint32_t offs_accum = 1u, offs_bits = 0u;
                    for (uint32_t n = 5u; n != 0u; --n) {
                        uint16_t* ma  = &offs_bits_model_a[offs_base_idx + offs_accum];
                        uint32_t  mav = *ma >> 4u;
                        uint32_t  mbi = static_cast<uint32_t>(
                            (kLzModelInterpolation[mav >> 4u] + 2048) >> 8u);
                        uint16_t* mb  = &offs_bits_model_b[mbi + 17u * offs_accum];
                        uint32_t prob =
                            (mav + 3u * ((mb[1] + mb[0] + 1u) >> 5u) + 2u) >> 2u;
                        prob += (prob < 0x800u ? 1u : 0u);
                        bool bit = adec.read_no_shift(prob);
                        *ma = static_cast<uint16_t>(
                            *ma + (((bit ? 65536u : 0u) + 16u - *ma) >> 5u));
                        mb[0] = static_cast<uint16_t>(
                            mb[0] + (((bit ? 65550u : 0u) - mb[0]) >> 4u));
                        mb[1] = static_cast<uint16_t>(
                            mb[1] + (((bit ? 65550u : 0u) - mb[1]) >> 4u));
                        offs_accum = offs_accum * 2u + (bit ? 1u : 0u);
                        offs_bits  = offs_bits  * 2u + (bit ? 1u : 0u);
                    }
                    offs_bits ^= 0x1fu;

                    offset = (offs_bits != 0u) ? 1u : 0u;
                    uint32_t offset_accum = 1u;

                    uint32_t n_high =
                        (offs_bits > 2u) ? 2u : offs_bits + (offs_bits == 0u ? 1u : 0u);
                    do {
                        uint16_t* mp = &high_offs_model[offs_bits].model[offset_accum];
                        bool bit = adec.read(*mp);
                        *mp = static_cast<uint16_t>(
                            *mp + (((bit ? 65536u : 0u) + 8u - *mp) >> 4u));
                        offset_accum = offset_accum * 2u + (bit ? 1u : 0u);
                        offset       = offset       * 2u + (bit ? 1u : 0u);
                    } while (--n_high);

                    if (offs_bits > 2u) {
                        uint32_t n_low = std::min(offs_bits - 2u, 4u);
                        offset <<= n_low;
                        uint32_t low_accum = 1u, low_index = 0u;
                        do {
                            uint16_t* mp = &low_offs_model[0].model[low_accum];
                            bool bit = adec.read(*mp);
                            *mp = static_cast<uint16_t>(
                                *mp + (((bit ? 65536u : 0u) + 16u - *mp) >> 5u));
                            low_accum = low_accum * 2u + (bit ? 1u : 0u);
                            offset   |= (bit ? 1u : 0u) << low_index;
                            ++low_index;
                        } while (--n_low);

                        if (offs_bits > 6u) {
                            uint32_t n_mid = offs_bits - 6u, n_mid_left = n_mid;
                            uint32_t offset_mid = 0u;
                            uint16_t* mp = &mid_offs_model[n_mid].model[0];
                            do {
                                bool bit = adec.read(*mp);
                                *mp = static_cast<uint16_t>(
                                    *mp + (((bit ? 65536u : 0u) + 32u - *mp) >> 6u));
                                offset_mid = offset_mid * 2u + (bit ? 1u : 0u);
                                ++mp;
                            } while (--n_mid_left);
                            offset = (offset & 0xfu) + 16u * offset_mid +
                                     ((offset & ~0xfu) << (offs_bits - 6u));
                        }
                    }
                    repmatch[3] = repmatch[2];
                    repmatch[2] = repmatch[1];
                    repmatch[1] = repmatch[0];
                    repmatch[0] = offset;
                }

                auto delta = -static_cast<ptrdiff_t>(offset) - 1;
                for (uint32_t i = 0u; i < matchlen; ++i)
                    out[i] = out[static_cast<ptrdiff_t>(i) + delta];
                lit_or_match_hist =
                    static_cast<uint8_t>(lit_or_match_hist * 2u);
                out             += matchlen;
                round_bytes_left -= matchlen;
                last_lit = static_cast<uint32_t>(out[-1]) +
                           static_cast<uint32_t>(out[delta]) * 256u;
            }
        } while (round_bytes_left != 0u);
    }
}

// ---------------------------------------------------------------------------
// Public API  (NzLzhdDecoder = DecLZ via typedef in nz_lzhd.h)
// ---------------------------------------------------------------------------

NzLzhdDecoder* NzLzhdCreate() {
    void* mem = std::malloc(sizeof(DecLZ));
    if (!mem) return nullptr;
    return ::new (mem) DecLZ();
}

void NzLzhdDestroy(NzLzhdDecoder* dec) {
    if (dec) {
        dec->~DecLZ();
        std::free(dec);
    }
}

void NzLzhdDecode(NzLzhdDecoder* dec,
                  const uint8_t* in,  uint32_t in_size,
                  uint8_t*       out, uint32_t out_size,
                  uint8_t*       window_base) {
    dec->decode(in, in_size, out, out_size, window_base);
}
