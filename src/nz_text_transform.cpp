#include "nz_text_transform.h"
#include "nz_extab.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cstdint>

// kDictionary5to8: maps 5-bit letter code → character (0=terminator, 1='a'..26='z')
// Derived from disassembly of init function at 0x80b70b0 in linux32/nz
static const uint8_t kDictionary5to8[32] = {
    0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// kCharacterTraits_0: character class flags (in .rodata at 0x081332e0 in linux32/nz)
//   0x00=control  0x08=whitespace  0x10=sentence punct  0x04=digit
//   0x41=uppercase  0x21=lowercase  0x80=other punct
static const uint8_t kCharacterTraits_0[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10, 0x80, 0x10, 0x80,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10,
    0x80, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x80, 0x80, 0x80, 0x00, 0x80,
    0x00, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
    0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x80, 0x80, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// kCharacterTraits_1: 1 = continue fast-copy (word char), 0 = word boundary
// Derived from separator string at 0x813c61c in linux32/nz (22 bytes):
// {space,LF,CR,TAB,",',\,/,(,<,[,{,&,-,_,|,=,>,;,.,!,?}
static const uint8_t kCharacterTraits_1[256] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

// Port of InsertLongDict: writes word characters backward into buf, returns new wp
static inline uint8_t* InsertLongDict(uint8_t* wp, uint32_t dict_index) {
    uint8_t* wp_org = wp;
    uint16_t init_val;
    memcpy(&init_val, &kCharDictBig_Initial[dict_index], sizeof(init_val));
    wp -= 2;
    memcpy(wp, &init_val, 2);

    uint32_t dict32 = kCharDictBig_Lo[dict_index];
    do {
        *--wp = kDictionary5to8[(dict32 >> 25) & 0x1fu];
    } while ((dict32 <<= 5) & 0x3E000000u);

    if (wp_org - wp == 8) {
        dict32 = kCharDictBig_Hi[dict_index];
        if (dict32) {
            do {
                *--wp = kDictionary5to8[(dict32 >> 25) & 0x1fu];
            } while ((dict32 <<= 5) & 0x3E000000u);
        }
    }
    return wp;
}

// Port of InsertMidDict
static inline uint8_t* InsertMidDict(uint8_t* wp, uint32_t dict_index) {
    uint16_t init_val;
    memcpy(&init_val, &kCharDictMid_Initial[dict_index], sizeof(init_val));
    wp -= 2;
    memcpy(wp, &init_val, 2);

    uint32_t dict32 = kCharDictMid[dict_index];
    do {
        *--wp = kDictionary5to8[(dict32 >> 25) & 0x1fu];
    } while ((dict32 <<= 5) & 0x3E000000u);
    return wp;
}

// Port of CopyDictEntWithCase
static inline void CopyDictEntWithCase(uint8_t* out, const uint8_t* wp, uint32_t wl, uint32_t case_mode) {
    uint32_t u0, u1, u2, u3;
    memcpy(&u0, wp + 0, 4);
    memcpy(&u1, wp + 4, 4);
    memcpy(out + 0, &u0, 4);
    memcpy(out + 4, &u1, 4);
    if (wl > 8) {
        memcpy(&u2, wp + 8, 4);
        memcpy(&u3, wp + 12, 4);
        memcpy(out + 8, &u2, 4);
        memcpy(out + 12, &u3, 4);
    }
    if (case_mode) {
        out[0] ^= 0x20u;
        if (case_mode == 2) {
            u0 = 0x20202020u;
            memcpy(&u1, out + 1, 4); u1 ^= u0; memcpy(out + 1, &u1, 4);
            memcpy(&u2, out + 5, 4); u2 ^= u0; memcpy(out + 5, &u2, 4);
            if (wl > 9) {
                memcpy(&u3, out + 9,  4); u3 ^= u0; memcpy(out + 9,  &u3, 4);
                uint32_t u4; memcpy(&u4, out + 13, 4); u4 ^= u0; memcpy(out + 13, &u4, 4);
            }
        }
    }
}

// Port of FormatIP
static uint8_t* FormatIP(uint32_t ip, uint8_t* out) {
    uint32_t num_parts = 4;
    do {
        uint32_t part = ip >> 24;
        ip <<= 8;
        if (part >= 100) {
            out[0] = static_cast<uint8_t>(part / 100 + '0');
            out[1] = static_cast<uint8_t>(part / 10 % 10 + '0');
            out[2] = static_cast<uint8_t>(part % 10 + '0');
            out[3] = '.';
            out += 4;
        } else {
            if (part >= 10) {
                *out++ = static_cast<uint8_t>(part / 10 % 10 + '0');
                part %= 10;
            }
            *out = static_cast<uint8_t>(part + '0');
            out[1] = '.';
            out += 2;
        }
    } while (--num_parts);
    return out - 1;
}

// Port of TransformText_1_Dictionary from NZ_TextTransforms.cpp.
// in:        CM-decoded byte stream (word-dictionary encoded), MUST end with 0x20 (space)
// in_size:   byte count including the trailing space
// out:       output buffer (must be >= allocated bytes)
// allocated: capacity of out
// Returns decoded size (stripping trailing space), 0 on error.
uint32_t NzTextTransformDict(const uint8_t* in, uint32_t in_size,
                             uint8_t* out, uint32_t allocated) {
    (void)allocated;
    const uint8_t* out_org = out;
    if (in_size <= 1 || in[in_size - 1] != 0x20u)
        return 0;

    uint32_t recent_ip[20];
    for (uint32_t i = 0; i < 20; i++)
        recent_ip[i] = i;

    uint8_t case_mode = 0;
    const uint8_t* in_end = in + in_size;

    while (in < in_end) {
        uint32_t b = *in++;
        uint32_t c;

        if (b == 127u) {
            c = *in++;
            if (c != 32u) {
                if ((kCharacterTraits_0[c] & 0x20u) && c <= 117u) {
                    uint32_t ip;
                    if (c == 97u) {
                        if (in_end - in < 4) break;
                        ip = (in[3] | ((uint32_t)(in[2] | (uint32_t)((((uint32_t)in[0] << 8) | in[1]) << 8)) << 8)) + 0x1000000u;
                        in += 4;
                        for (int i = 19; i != 0; i--)
                            recent_ip[i] = recent_ip[i - 1];
                        recent_ip[0] = ip;
                    } else {
                        uint32_t idx = c - 98u;
                        ip = recent_ip[idx];
                        if (idx) {
                            do {
                                recent_ip[idx] = recent_ip[idx - 1];
                            } while (--idx);
                            recent_ip[0] = ip;
                        }
                    }
                    if (in >= in_end) break;
                    out = FormatIP(ip, out);
                    c = *in++;
                }
                case_mode = 0;
                goto output_next_char;
            }
            b = *in++;
            if (b == 127u) {
                if (*in++ != 32u) break;
                b = *in++;
                case_mode = 2;
            } else {
                case_mode = 1;
            }
        } else {
            case_mode = 0;
        }

        if (b > 127u) {
            c = *in++;
            // buf layout: [0..13] writable space, [14] = wp_org, always 14 bytes max word.
            // The trailing "+ 16" is pure padding (never written): CopyDictEntWithCase
            // always reads a fixed 8 or 16 bytes starting at wp regardless of the
            // actual word length wl, exactly mirroring the reference's own
            // TransformText_1_Dictionary/CopyDictEntWithCase (which relies on
            // whatever slack its compiler happened to leave after the equivalent
            // stack buffer). Found via ASan while validating tt_flags&0x02 fixtures:
            // for a short word (wl as low as 3) wp sits close to the tail of buf, and
            // the unconditional 8-byte read can run up to 2 bytes past a tightly-sized
            // 17-byte buffer. The extra bytes read are never meaningful (only the
            // first wl bytes of the copy matter; anything past that gets overwritten
            // by the next character(s) in the outer loop), so padding buf costs
            // nothing and removes the UB without changing behavior.
            uint8_t buf[6 + 6 + 2 + 2 + 1 + 16];
            uint8_t* wp = buf + 6 + 6 + 2;
            uint32_t dict_index;
            if (c > 127u) {
                dict_index = c ^ (b << 7) ^ 0x7f7fu;
                c = *in++;
                wp = InsertLongDict(wp, dict_index);
            } else {
                wp = InsertMidDict(wp, b - 128u);
            }
            uint32_t wl = static_cast<uint32_t>((buf + 6 + 6 + 2) - wp);
            out += wl;
            CopyDictEntWithCase(out - wl, wp, wl, case_mode);
        } else {
            uint32_t dict32 = kCharacterDictUltrasmall[b];
            if (dict32 == 0u || (kCharacterTraits_0[c = *in] & 1u)) {
                c = b;
                if (case_mode != 0)
                    c ^= 32u * (kCharacterTraits_0[b] & 1u);
            } else {
                in++;
                uint32_t out32 = dict32;
                memcpy(out, &out32, 4);
                uint8_t* old_out = out;
                out += (dict32 >> 24);
                if (case_mode != 0) {
                    *old_out++ ^= 0x20u;
                    if (case_mode == 2) {
                        while (old_out != out)
                            *old_out++ ^= 0x20u;
                    }
                }
            }
        }

    output_next_char:
        *out++ = static_cast<uint8_t>(c);
        if (kCharacterTraits_1[c]) {
            if (in >= in_end) break;
            for (;;) {
                c = *in++;
                *out++ = static_cast<uint8_t>(c);
                if (!kCharacterTraits_1[c]) break;
                if (case_mode == 2)
                    out[-1] = static_cast<uint8_t>(c ^ (32u * (kCharacterTraits_0[c] & 1u)));
            }
        }
    }

    if (in > in_end || out[-1] != 0x20u)
        return 0;
    return static_cast<uint32_t>(out - 1 - out_org);
}

// Port of TransformText_4 from NZ_TextTransforms.cpp (tt_flags & 0x20).
// Bounds-checked at every write (the reference's unsigned `size_t n_copy`
// do-while can execute its body once even when the computed budget is 0;
// this port turns that edge into a clean decline instead of an OOB write).
uint32_t NzTextTransformRle(const uint8_t* in, uint32_t in_size,
                            uint8_t* out, uint32_t allocated) {
    if (in_size <= 1) return 0;
    const uint8_t* in_end = in + in_size;
    uint8_t* out_end = out + allocated;
    uint8_t* out_org = out;

    const uint8_t escape_char = *in++;
    uint8_t* copy_from = out;

    for (;;) {
        std::ptrdiff_t avail_out = out_end - out;
        std::ptrdiff_t avail_in = in_end - in;
        std::ptrdiff_t n_copy = std::min(avail_out, avail_in);
        if (n_copy <= 0) return 0;  // would be an OOB first write in the reference
        uint8_t v;
        do {
            v = *in++;
            *out++ = v;
        } while (--n_copy && v != escape_char);

        if (in == in_end) break;
        if (n_copy == 0) return 0;  // ran out of budget without an escape hit

        if (*in <= 224u) {
            if (*in == 224u) {
                ++in;
                if (in == in_end) break;
            } else {
                copy_from = out;
            }
        } else {
            std::uint32_t run = static_cast<std::uint32_t>(*in) - 224u;
            if (static_cast<std::ptrdiff_t>(run) > out_end - out) return 0;
            const uint8_t* tmp_copy_from = copy_from;
            copy_from = out;
            do {
                *out++ = *tmp_copy_from++;
            } while (--run);
            ++in;
            if (in == in_end) break;
        }
    }

    return static_cast<uint32_t>(out - out_org);
}

// ---------------------------------------------------------------------------
// tt_flags & 0x02: InsertLF (TransformText_3_InsertLF)
//
// Ported near-verbatim from NZ_TextTransforms.cpp. Reuses the exact same
// ArithDec / InterpolateLut / CreateModelLut idiom already ported for tt16
// in nz_texttransform_num.cpp; transcribed here (rather than shared across
// translation units) since that file keeps the pattern private to an
// anonymous namespace, matching that file's own porting convention.

// kModelInterpolation/kModelLutLookup are built once by NzCmInitAll() /
// Build_kModelInterpolation() (nz_cm.cpp) and shared read-only by every
// text-transform port in this project (see nz_texttransform_num.cpp,
// nz_lzhd.cpp for the same extern-declaration pattern).
extern uint16_t kModelInterpolation[4096];
extern uint16_t kModelLutLookup[4096];

namespace {

// CreateModelLut -- identical to reference NZ.cpp.
void CreateModelLutLf(uint16_t* out, uint32_t rows, uint32_t cols, uint32_t step, uint32_t first) {
    out[0] = 0;
    out[cols - 1] = 0xffffu;
    const uint16_t* tp = &kModelLutLookup[first];
    for (uint32_t i = 1; i < cols - 1; ++i, tp += step)
        out[i] = static_cast<uint16_t>(tp[0] << 4);
    uint16_t* dp = &out[cols];
    for (uint32_t n = cols * (rows - 1); n; --n)
        *dp++ = *out++;
}

struct ArithDecLf {
    uint32_t range_hi_, range_lo_, bitbuff_;
    const uint8_t *data_, *data_end_;

    uint32_t ReadByte() { return (data_ != data_end_ ? *data_++ : 0u); }

    void InitializeX(const uint8_t* d, const uint8_t* e) {
        data_ = d; data_end_ = e;
        range_lo_ = 0; range_hi_ = 0xffffffffu; bitbuff_ = 0;
    }
    void FillBuffer() {
        for (int i = 0; i != 4; ++i) bitbuff_ = (bitbuff_ << 8) | ReadByte();
    }
    void Renormalize() {
        while ((range_lo_ ^ range_hi_) < 0x1000000u) {
            range_lo_ <<= 8;
            range_hi_ = (range_hi_ << 8) + 0xffu;
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

template<int Scale>
inline uint32_t xInterpolateModelLf(uint16_t* model_base, uint32_t value, uint32_t index, uint16_t** out_ptr) {
    uint32_t hv = kModelInterpolation[value >> 4] * (Scale - 1);
    uint16_t* model = &model_base[(hv >> 12) + Scale * index];
    uint32_t interpolated = (model[0] * (0x1000u - (hv & 0xfffu)) + model[1] * (hv & 0xfffu)) >> 12;
    model += (hv & 0xfffu) >> 11;
    *out_ptr = model;
    return interpolated;
}

template<int W, int Scale>
struct InterpolateLutLf {
    uint16_t lut[W * Scale];
    void Initialize(int a, int b) {
        CreateModelLutLf(lut, W, Scale, static_cast<uint32_t>(a), static_cast<uint32_t>(b));
    }
    uint32_t Get(uint32_t v, uint32_t idx, uint16_t** out_ptr) {
        return xInterpolateModelLf<Scale>(lut, v, idx, out_ptr);
    }
};

inline void Memset32Lf(void* dst, uint32_t value, size_t n) {
    uint32_t* p = static_cast<uint32_t*>(dst);
    for (size_t i = 0; i < n; ++i) p[i] = value;
}

// kCharacterTraits_9: 1 if the byte is a "word split" delimiter for the
// look-ahead word-length scan (space and tab only). Verbatim from Tables.h.
const uint8_t kCharacterTraits_9[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

// kCharacterTraits_12: gate on the byte immediately after the candidate
// split point (line_start's next char) -- 1 for most printable bytes.
// Verbatim from Tables.h.
const uint8_t kCharacterTraits_12[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

// kCharacterTraits_14: gate on the byte immediately before the candidate
// split point (the char preceding the copied space/LF). Verbatim from Tables.h.
const uint8_t kCharacterTraits_14[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

// kNextCharToMdl: 3-bit model-index contribution keyed on the next byte
// (*in). Verbatim from Tables.h.
const uint8_t kNextCharToMdl[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 4, 5, 0, 0, 0, 0, 5, 6, 6, 0, 0, 4, 7, 4, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 0, 6, 4,
  0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 6, 0, 6, 0, 0,
  0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 6, 0, 6, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

// kPrevCharToMdl: model-index contribution (bits 3-6, i.e. multiples of 8)
// keyed on the previous byte. Verbatim from Tables.h.
const uint8_t kPrevCharToMdl[256] = {
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x08, 0x78, 0x60, 0x08, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x08, 0x28, 0x38, 0x58, 0x60, 0x58, 0x58, 0x30, 0x40, 0x40, 0x58, 0x58, 0x48, 0x50, 0x20, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x48, 0x48, 0x40, 0x68, 0x40, 0x28,
  0x58, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x40, 0x60, 0x40, 0x70, 0x78,
  0x60, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x40, 0x60, 0x40, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
  0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78, 0x60, 0x68, 0x70, 0x78,
};

// kLineLengthToMdl: 3-bit model-index contribution (bits 7-9 after <<7)
// keyed on how far the projected line length is from the running average.
// Verbatim from Tables.h.
const uint8_t kLineLengthToMdl[128] = {
  1, 2, 3, 4, 5, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

}  // namespace

// Port of TransformText_3_InsertLF from NZ_TextTransforms.cpp (tt_flags & 0x02).
uint32_t NzTextTransformInsertLf(const uint8_t* side, uint32_t side_len,
                                 const uint8_t* in, uint32_t in_size,
                                 uint8_t* out, uint32_t allocated) {
    if (in_size == 0) return 0;
    // Byte-count-preserving transform (see header comment): every write
    // below mirrors a byte already consumed from `in`, so this single
    // upfront check makes every subsequent `*out++` provably in-bounds.
    if (allocated < in_size) return 0;

    const uint8_t* out_org = out;
    uint16_t x_arr[1024];
    Memset32Lf(x_arr, 0x80008000u, sizeof(x_arr) / 4);

    InterpolateLutLf<64, 14> lut_1; lut_1.Initialize(0x13B, 0x13A);
    InterpolateLutLf<8, 11> lut_2;  lut_2.Initialize(0x199, 0x198);
    InterpolateLutLf<128, 11> lut_3; lut_3.Initialize(0x199, 0x198);

    uint8_t linelen_hist[32];
    uint32_t linelen_sum = 70u * 32u;
    uint32_t linelen_pos = 0;
    memset(linelen_hist, 70, sizeof(linelen_hist));

    uint32_t line_len_min = 40u, line_len_max = 96u, line_len_min_hard = 0u;

    ArithDecLf adec;
    adec.InitializeX(side, side + side_len);
    {
        uint32_t x = adec.ReadByte();
        line_len_min_hard = x >> 1;
        if (x & 1u) {
            line_len_min = adec.ReadByte();
            line_len_max = line_len_min + 1u + adec.ReadByte();
        }
    }
    adec.FillBuffer();

    uint8_t c = 0, prev = 0;
    uint8_t* line_start = out;
    for (;;) {
        do {
            prev = c;
            c = *in++;
            *out++ = c;
        } while (--in_size && (c > 32u || (c != 10u && c != 32u)));

        if (!in_size)
            return static_cast<uint32_t>(out - out_org);

        uint32_t linelen = static_cast<uint32_t>(out - line_start);
        if (linelen < line_len_min_hard ||
            in_size <= 1u ||
            !kCharacterTraits_12[*in] ||
            !kCharacterTraits_14[prev]) {
            if (c != 0x20u) line_start = out;
            continue;
        }

        uint32_t wl = 1;
        while (wl < in_size && !kCharacterTraits_9[in[wl - 1]]) wl++;

        uint32_t x_ix =
            (static_cast<uint32_t>(kLineLengthToMdl[(linelen + wl - ((linelen_sum + 16u) >> 5)) & 0x7Fu]) << 7) |
            kPrevCharToMdl[prev] | kNextCharToMdl[*in];

        uint16_t* x_ptr = &x_arr[x_ix];
        uint16_t *lut2_ptr, *lut1_ptr, *lut3_ptr;
        uint32_t v = lut_2.Get(*x_ptr, x_ix >> 7, &lut2_ptr);
        v = lut_1.Get(v, std::min<uint32_t>((linelen - line_len_min_hard) >> 1, 63u), &lut1_ptr);
        v = lut_3.Get(v, x_ix & 0x3Fu, &lut3_ptr);

        bool insert_lf = adec.Read(v);
        *x_ptr = static_cast<uint16_t>(*x_ptr + ((0x10000u * insert_lf + 8u - *x_ptr) >> 4));
        *lut2_ptr = static_cast<uint16_t>(*lut2_ptr + ((0x100FEu * insert_lf - *lut2_ptr) >> 8));
        *lut1_ptr = static_cast<uint16_t>(*lut1_ptr + ((0x1003Eu * insert_lf - *lut1_ptr) >> 6));
        *lut3_ptr = static_cast<uint16_t>(*lut3_ptr + ((0x100FEu * insert_lf - *lut3_ptr) >> 8));

        if (insert_lf) {
            out[-1] = 10;
            if (linelen >= line_len_min && linelen <= line_len_max) {
                uint32_t x = ++linelen_pos & 0x1Fu;
                linelen_sum += linelen - linelen_hist[x];
                linelen_hist[x] = static_cast<uint8_t>(linelen);
            }
            c = 10;
            line_start = out;
        } else {
            if (c != 0x20u) line_start = out;
        }
    }
}

// ---------------------------------------------------------------------------
// tt bit 0x01 -- TransformText_CR_to_CRLF (reference NZ_TextTransforms.cpp:402).
// Faithful transcription, including the deliberate one-byte output slack the
// reference's `out_size++` budget implies (see the header comment): the budget
// counter starts at out_cap + 1 and the overrun is only detected after the
// (out_cap + 1)-th byte has been written, so the caller allocates one spare.
//
// The state machine restores line endings that the encoder collapsed: state 1
// re-expands a bare 10 into 13,10; state 2 rewrites a 10 back to a lone 13.
// ---------------------------------------------------------------------------
uint32_t NzTextTransformCrToCrLf(const uint8_t* in, uint32_t in_size,
                                 uint8_t* out, uint32_t out_cap) {
    uint8_t* const out_org = out;
    if (!(in_size && out_cap)) return 0;

    uint32_t out_size = out_cap + 1u;
    int state = 0;
    uint8_t c = 0, prev = 0;

    for (;;) {
        const uint32_t nn = (in_size < out_size) ? in_size : out_size;
        uint32_t n = nn;
        do {
            prev = c;
            c = *in++;
            *out++ = c;
        } while (--n && (c > 0x13u || (c != 13u && c != 10u)));

        out_size -= (nn - n);
        if (out_size == 0u) return 0;
        in_size -= (nn - n);
        if (in_size == 0u) return (uint32_t)(out - out_org);

        if (state == 1) {
            // A bare 10 becomes 13,10.
            if (c == 10u) {
                out[-1] = 13u;
                *out++ = 10u;
                if (--out_size == 0u) return 0;
            } else {
                out[-1] = *in++;
                if (--in_size == 0u) return (uint32_t)(out - out_org);
                state = 0;
            }
            c = 0;
        } else if (state == 2) {
            // A 10 standing in for a lone 13.
            if (c == 10u) {
                out[-1] = 13u;
            } else {
                out[-1] = 10u;
                state = 0;
            }
            c = 0;
        } else {
            if (c == 10u) {
                if (prev == 13u) state = 1;
            } else if (c == 13u && *in > 13u) {
                // Safe: in_size was just confirmed non-zero above, so this
                // lookahead byte is inside the caller's buffer.
                state = 2;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// tt bit 0x04 -- HtmlTransformer (reference NZ_TextTransforms.cpp:781-899).
//
// The encoder replaces an HTML closing tag with the bare sequence "</", and the
// decoder reconstructs the tag name from a stack of the tags it has seen opened.
// A literal "</" in the source is escaped as "<//".
//
// The stack is deliberately lossy in the same way the original is: only 128
// entries deep (pushes past that overwrite the top slot), names truncated to 16
// bytes, and a small 4-entry "recent tag" ring plus a fixed set of predefined
// tags that are never stacked at all because they never need closing.
// ---------------------------------------------------------------------------
namespace {

static const uint8_t kCharTraitHtml[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
};

// Folds case so <DIV> and <div> hash to the same short tag.
static inline uint32_t NormalizeTagChar(uint8_t b) {
    return (uint32_t)b | (uint32_t)((kCharacterTraits_0[b] & 0x40u) >> 1);
}

// Packs a 1..4 byte tag name into a comparable integer.
static inline uint32_t GetTagShort(const uint8_t* tag, uint32_t taglen) {
    uint32_t rv = NormalizeTagChar(tag[0]);
    if (taglen != 1u) {
        rv = rv * 256u + NormalizeTagChar(tag[1]);
        if (taglen != 2u) {
            rv = rv * 256u + NormalizeTagChar(tag[2]);
            if (taglen != 3u) rv = rv * 256u + NormalizeTagChar(tag[3]);
        }
    }
    return rv;
}

struct HtmlTransformer {
    uint32_t rtag_[4];
    uint8_t rtag_pos_;
    size_t stack_count_;
    uint8_t tagnames_[129][16];
    uint8_t taglens_[129];

    HtmlTransformer() {
        std::memset(rtag_, 0, sizeof(rtag_));
        rtag_pos_ = 0;
        stack_count_ = 0;
        taglens_[0] = 0;
        // The reference leaves tagnames_/taglens_[1..] uninitialised; a decode
        // only ever reads a slot it pushed first, but zero them so a malformed
        // stream cannot read indeterminate stack memory.
        std::memset(tagnames_, 0, sizeof(tagnames_));
        std::memset(taglens_, 0, sizeof(taglens_));
    }

    // Tags that never need a closing partner, so they are never stacked.
    static bool IsPredefinedTag(uint32_t t) {
        return t == 0x6272u || t == 0x696E74u || t == 0x766172u ||
               t == 0x696D67u || t == 0x6D657461u;
    }
    bool IsRecentTag(uint32_t t) const {
        return t == rtag_[0] || t == rtag_[1] || t == rtag_[2] || t == rtag_[3];
    }

    uint32_t TagLen(const uint8_t* tag, const uint8_t* in_end) const {
        const uint32_t cap = (uint32_t)std::min<size_t>((size_t)(in_end - tag), 16u);
        uint32_t n = 0;
        while (n < cap && kCharTraitHtml[tag[n]]) n++;
        return n;
    }

    void AddTag(const uint8_t* tag, const uint8_t* in_end) {
        uint32_t taglen = TagLen(tag, in_end);
        if (taglen == 0u) return;
        if (taglen > 2u) {
            // A self-closing "<foo ... />" needs no stack entry.
            uint32_t i = taglen;
            const uint32_t cap = (uint32_t)std::min<size_t>((size_t)(in_end - tag), 33u);
            while (i < cap && tag[i] != '>') i++;
            if (i == 0u) return;
            if (tag[i - 1u] == '/') return;
        }
        if (taglen < 4u) {
            const uint32_t t = GetTagShort(tag, taglen);
            if (IsRecentTag(t) || IsPredefinedTag(t)) return;
        }
        stack_count_ += (stack_count_ <= 127u);
        taglens_[stack_count_] = (uint8_t)taglen;
        std::memcpy(tagnames_[stack_count_], tag, taglen);
    }

    void EraseTag(const uint8_t* tag, const uint8_t* in_end) {
        const uint32_t taglen = TagLen(tag, in_end);
        if (taglen == 0u) return;
        if (taglen < 4u) {
            const uint32_t t = GetTagShort(tag, taglen);
            if (IsRecentTag(t) || IsPredefinedTag(t)) return;
        }
        while (stack_count_ != 0u) {
            const uint32_t curlen = taglens_[stack_count_];
            if (taglen == curlen &&
                std::memcmp(tagnames_[stack_count_], tag, taglen) == 0) break;
            if (curlen != 0u && curlen <= 4u) {
                const uint32_t t = GetTagShort(tagnames_[stack_count_], curlen);
                if (!IsRecentTag(t)) rtag_[rtag_pos_++ & 0x3u] = t;
            }
            stack_count_--;
        }
    }

    uint32_t Decode(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t allocated) {
        uint8_t* const out_org = out;
        uint8_t* const out_end = out + allocated;
        const uint8_t* const in_end = in + in_size;

        for (;;) {
            uint8_t* out_cur_end =
                out + std::min<size_t>((size_t)(out_end - out), (size_t)(in_end - in));
            while (out != out_cur_end && (*out++ = *in++) != '<') {
                // copy through
            }
            if (out == out_cur_end) return (in == in_end) ? (uint32_t)(out - out_org) : 0u;

            const uint8_t b = *out++ = *in++;
            if (b != '/') {              // "<x" -- an opening tag
                AddTag(in - 1, in_end);
                continue;
            }
            if (in != in_end && in[0] == '/') {   // "<//" -- an escaped literal "</"
                EraseTag(++in, in_end);
                continue;
            }
            // "</" -- expand to the tag on top of the stack.
            const size_t taglen = taglens_[stack_count_];
            if (taglen >= (size_t)(out_end - out)) return 0u;
            std::memcpy(out, tagnames_[stack_count_], taglen);
            out += taglen;
            *out++ = '>';
            stack_count_ -= (stack_count_ != 0u);
        }
    }
};

}  // namespace

uint32_t NzTextTransformHtml(const uint8_t* in, uint32_t in_size,
                             uint8_t* out, uint32_t out_cap) {
    if (in_size == 0u || out_cap == 0u) return 0;
    HtmlTransformer t;
    return t.Decode(in, in_size, out, out_cap);
}
