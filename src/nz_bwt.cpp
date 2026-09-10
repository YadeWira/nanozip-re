// nz_bwt.cpp — NanoZip decr_param == 0 ("BWT") block decoding, ported from the
// community reference decoder (nzdec_v0 NZ.cpp). Faithful reimplementation.
#include "nz_env.h"
#include "nz_trace.h"
#include "nz_bwt.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <atomic>
#include <thread>

namespace {

// NZOPT_TRACE_BWT-gated diagnostics, following this project's existing
// NZOPT_TRACE_* convention (zero cost when the variable is unset).
static bool BwtTrace() {
    static const bool on = (NZ_ENV("NZOPT_TRACE_BWT") != nullptr);
    return on;
}
#define BWT_FAIL(...) do { if (BwtTrace()) std::fprintf(stderr, "[BWT] " __VA_ARGS__); } while (0)

// ---------------------------------------------------------------------------
// Shared primitives. These mirror nz.h and are deliberately kept local to this
// translation unit, matching how nz_cm.cpp / nz_lzhd.cpp / nz_optimum_lz.cpp
// each carry their own copy of the range coder they were ported against.
// ---------------------------------------------------------------------------

// ArithmeticDecoder (nz.h): 12-bit range coder over an MSB-first byte cache.
struct ArithDec {
    uint32_t range_hi_, range_lo_, bitbuff_;
    const uint8_t *data_, *data_end_;

    uint32_t ReadByte() { return (data_ != data_end_ ? *data_++ : 0u); }
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
        const uint32_t compare = range_lo_ + ((range_hi_ - range_lo_) >> 12) * model;
        const bool flag = (bitbuff_ <= compare);
        range_hi_ -= flag ? (range_hi_ - compare) : 0u;
        range_lo_ -= flag ? 0u : (range_lo_ - (compare + 1u));
        Renormalize();
        return flag;
    }
    // A model word keeps the 12-bit probability in its high bits and, for the
    // adaptive-rate models below, an update-shift counter in its low nibble.
    bool Read(uint32_t model) { return ReadNoShift(model >> 4); }
};

static uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }
static uint32_t bitmask(uint32_t nb) { return nb >= 32u ? 0xffffffffu : ((1u << nb) - 1u); }

// BitReader (nz.h), with the same bounded-fetch fix nz_postfilter.cpp carries:
// the reference compares raw byte addresses, so a size that isn't a multiple of
// 4 still triggers one more (partial) word fetch whose trailing bytes can carry
// real bits. This zero-fills past the true end instead of reading out of the
// caller's buffer, which is bit-for-bit equivalent for every position that can
// matter.
struct BitReader {
    uint32_t bitcount_, bitbuff_;
    const uint8_t *ptr_, *ptr_end_;
    void Initialize(const uint8_t* data, size_t size) {
        bitcount_ = 0; bitbuff_ = 0;
        ptr_ = data;
        ptr_end_ = data + size;
    }
    uint32_t FetchWord() {
        if (ptr_ >= ptr_end_) return 0u;
        const size_t avail = (size_t)(ptr_end_ - ptr_);
        uint32_t v;
        if (avail >= 4u) {
            std::memcpy(&v, ptr_, 4);
            ptr_ += 4;
        } else {
            uint8_t buf[4] = {0, 0, 0, 0};
            std::memcpy(buf, ptr_, avail);
            std::memcpy(&v, buf, 4);
            ptr_ += avail;
        }
        return bswap32(v);
    }
    uint32_t GetBits(uint32_t nb) {
        uint32_t bits = bitbuff_, bitcount = bitcount_;
        if (nb > bitcount) {
            bitbuff_ = FetchWord();
            const uint32_t new_bitcount = 32u - (nb - bitcount);
            bits = (bitbuff_ >> new_bitcount) | (bits << (nb - bitcount));
            bitcount = new_bitcount;
        } else {
            bitcount -= nb;
            bits >>= bitcount;
        }
        bitcount_ = bitcount;
        return bitmask(nb) & bits;
    }
};

// BackwardsByteStream (nz.h): the per-bucket size table is written at the tail
// of the payload and read backwards, terminator-bit first.
struct BackwardsByteStream {
    const uint8_t *ptr_, *ptr_end_;
    BackwardsByteStream(const uint8_t* data, size_t data_size)
        : ptr_(data), ptr_end_(data + data_size) {}
    uint32_t ReadBackwardsByte() { return (ptr_end_ > ptr_) ? *--ptr_end_ : 0x80u; }
    uint32_t ReadBackwardsVarint() {
        uint32_t result = 0, v;
        do {
            v = ReadBackwardsByte();
            result = (result << 7) ^ v;
        } while (!(v & 0x80u));
        return result ^ 0x80u;
    }
    uint32_t BytesLeft() const { return (uint32_t)(ptr_end_ - ptr_); }
};

static uint32_t BSR(uint32_t n) {
    uint32_t r = 0;
    while (n >>= 1) ++r;
    return r;
}

// BwtRleExpander (reference NZ.cpp). Only the byte-wise Decode1 variant is
// needed here; the u32-wise DecodeU32 used by the param2 post-filter lives in
// nz_postfilter.cpp.
struct BwtRleExpander {
    ArithDec adec_;
    uint16_t model_[32];

    BwtRleExpander(const uint8_t* data, const uint8_t* data_end) {
        for (uint32_t i = 0; i < 32u; ++i) model_[i] = 0x8000u;
        adec_.InitializeX(data, data_end);
        adec_.FillBuffer();
    }

    uint32_t DecodeInt(uint32_t x) {
        uint32_t result = (x != 0u);
        const uint32_t n = 1u << (x < 4u ? x : 4u);
        x = x + (x == 0u);
        uint32_t i = 1;
        do {
            uint16_t* model_ptr = &model_[i + n];
            const bool flag = adec_.Read(*model_ptr);
            *model_ptr = (uint16_t)(*model_ptr + ((0x80u - *model_ptr + ((uint32_t)flag << 16)) >> 8));
            i = i * 2u + flag;
            result = result * 2u + flag;
        } while (i < n);
        if (x > 4u) {
            x -= 4u;
            result <<= x;
            uint32_t lower_bits = 0;
            do {
                lower_bits = lower_bits * 2u + adec_.Read(0x8000u);
            } while (--x);
            result += lower_bits;
        }
        return result;
    }

    // Byte-wise run expansion: a byte repeated twice introduces a run, whose
    // length is the arithmetic-coded expansion of the literal repeat count.
    bool Decode1(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t* out_size_ptr) {
        if (!in_size || in_size > *out_size_ptr) { *out_size_ptr = 0; return false; }
        const uint8_t* in_end = in + in_size;
        uint8_t* out_end = out + *out_size_ptr;
        uint8_t* out_org = out;
        uint8_t v = 0;
        for (;;) {
            const uint8_t last_v = v;
            if (in == in_end) break;
            *out++ = v = *in++;
            if (v != last_v) continue;
            if (in == in_end) break;
            *out++ = v = *in++;
            if (v != last_v) continue;
            const uint8_t* start_run = in;
            while (in != in_end && *in == last_v) in++;
            const uint32_t run_len = (uint32_t)(in - start_run);
            if (run_len > 30u) { *out_size_ptr = 0; return false; }
            const uint32_t new_len = DecodeInt(run_len);
            if ((uint32_t)(out_end - out) < (uint32_t)(in_end - in) + new_len) {
                *out_size_ptr = 0; return false;
            }
            std::memset(out, last_v, new_len);
            out += new_len;
        }
        *out_size_ptr = (uint32_t)(out - out_org);
        return true;
    }
};

// BwtIntModel (reference NZ.cpp): an adaptive Elias-gamma-shaped integer coder
// used for the per-bucket C/B tables.
struct BwtIntModel {
    uint32_t bits_to_read_;
    uint16_t model_[32];
    BwtIntModel() : bits_to_read_(31) {
        for (uint32_t i = 0; i != 32u; ++i) model_[i] = 0x8000u;
    }
    uint32_t Read(ArithDec* adec) {
        uint32_t nb = 0xffffffffu;
        while (++nb != bits_to_read_) {
            const bool v = adec->Read(model_[nb]);
            model_[nb] = (uint16_t)(model_[nb] +
                (((uint32_t)v * 65536u + 8u - model_[nb]) >> 4));
            if (!v) break;
        }
        const uint32_t res = nb ? (1u << nb) : 0u;
        uint32_t n = nb + (nb == 0u);
        uint32_t res2 = 0;
        do {
            res2 = res2 * 2u + adec->Read(0x8000u);
        } while (--n);
        return res + res2;
    }
};

// ReadSomeValue (reference NZ.cpp): reads an index into a shrinking alphabet.
static uint32_t ReadSomeValue(ArithDec* adec, uint32_t n) {
    uint32_t sum1 = 0;
    uint32_t numbits;
    for (;;) {
        if (n == 1u) return sum1;
        numbits = 1;
        uint32_t mm = (n - 1u) >> 1;
        if (mm == 0u) break;
        while (mm >>= 1) numbits++;
        n &= (1u << numbits) - 1u;
        if (!n) { numbits++; break; }
        const bool flag = adec->Read(n << (15u - numbits));
        if (!flag) break;
        sum1 += (1u << numbits);
    }
    uint32_t sum2 = 0;
    do {
        sum2 = sum2 * 2u + adec->Read(0x8000u);
    } while (--numbits);
    return sum1 + sum2;
}

static const uint8_t kSomeLut2[256] = {
    5, 4, 3, 2, 2, 2, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0,
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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const uint8_t kSomeLut[384] = {
    0, 0, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
};

// BwtUnpackInput (reference NZ.cpp): one symbol bucket's move-to-front rank
// stream. `Decode` returns 0 on success and non-zero on a detected
// inconsistency, mirroring the reference's own convention.
struct BwtUnpackInput {
    uint16_t model_a_[6146];
    uint16_t model_b_[512];
    struct ModelC { uint32_t x, y; };
    ModelC model_c_[256];

    static void FillUp(uint32_t in_size, uint32_t ents_used, uint8_t* P, uint32_t* C) {
        bool bytes_used[256];
        std::memset(bytes_used, 0, sizeof(bytes_used));
        for (uint32_t i = 0; i != ents_used; ++i) bytes_used[P[i]] = true;
        for (uint32_t k = 0; ents_used + k < 256u; ++k) {
            uint32_t j = 0;
            while (bytes_used[j]) j++;
            bytes_used[j] = true;
            P[ents_used + k] = (uint8_t)j;
            C[j] = k + in_size;
        }
    }

    static void MoveUpItem(uint8_t* P, uint32_t* C, uint32_t size, uint32_t ents_used) {
        const uint8_t value = P[0];
        for (uint32_t i = 0; i != 255u; ++i) P[i] = P[i + 1];
        P[255] = value;
        C[value] = size + 255u - ents_used;
    }

    uint32_t Decode(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t out_size,
                    BitReader* bitreader) {
        ArithDec adec;
        adec.InitializeX(in, in + in_size);
        adec.FillBuffer();

        uint8_t permutation[256];
        for (uint32_t i = 0; i < 256u; ++i) permutation[i] = (uint8_t)i;

        uint8_t P[256];
        uint8_t* P_ptr = P;
        uint32_t C[256];
        uint32_t B[256];
        std::memset(P, 0, sizeof(P));
        std::memset(C, 0, sizeof(C));
        std::memset(B, 0, sizeof(B));

        // Which byte values this bucket uses, in first-appearance order.
        uint32_t out_size_tmp = out_size;
        uint32_t end_idx = 256;
        do {
            const uint32_t cur_idx = ReadSomeValue(&adec, end_idx + (end_idx != 256u));
            if (cur_idx == end_idx) break;
            if (cur_idx > end_idx) do { BWT_FAIL("decode: cur_idx>end_idx\n"); return 3; } while (0);
            *P_ptr++ = permutation[cur_idx];
            permutation[cur_idx] = permutation[--end_idx];
        } while (end_idx != 0u && --out_size_tmp != 0u);

        uint32_t ents_used = 256u - end_idx;
        if (ents_used == 0u) do { BWT_FAIL("decode: ents_used==0\n"); return 4; } while (0);
        if (ents_used < 256u) FillUp(out_size, ents_used, P, C);

        BwtIntModel int_model;

        // C: cumulative first-occurrence offsets per used symbol.
        C[P[0]] = 0;
        for (uint32_t j = 1; j < ents_used; ++j) {
            const uint32_t prev = C[P[j - 1]];
            if (j + out_size < ents_used + prev) do { BWT_FAIL("decode: C underflow\n"); return 5; } while (0);
            const uint32_t n = j + out_size - ents_used - prev;
            int_model.bits_to_read_ = n ? BSR(n) : 0u;
            C[P[j]] = int_model.Read(&adec) + prev + 1u;
        }

        // B: per-symbol run boundaries.
        int_model.bits_to_read_ = (out_size - ents_used) != 0u ? BSR(out_size - ents_used) : 0u;
        for (uint32_t bi = 0, bsum = 0; bi != ents_used; bi++, bsum++) {
            bsum += int_model.Read(&adec);
            if (bsum >= out_size) { BWT_FAIL("decode: B bsum %u >= out_size %u\n", bsum, out_size); return 1; }
            B[bi] = bsum;
        }

        if (BwtTrace()) {
            // Is P sorted by C right after the tables are read? If not, the
            // divergence is upstream (symbol-set or C/B entropy decode); if it
            // only breaks later, it is the move-to-front update.
            uint32_t bad = 0;
            for (uint32_t j = 1; j < ents_used; ++j)
                if (C[P[j]] < C[P[j - 1]]) bad++;
            std::fprintf(stderr, "[BWT] tables: ents_used=%u out_size=%u nonmonotonic=%u C[P0]=%u C[P1]=%u C[P2]=%u B0=%u B1=%u\n",
                         ents_used, out_size, bad, C[P[0]], C[P[1]], C[P[2]], B[0], ents_used > 1 ? B[1] : 0);
        }
        std::memset(model_c_, 0, sizeof(model_c_));
        for (uint32_t i = 0; i != 6146u; ++i) model_a_[i] = 0x8002u;
        for (uint32_t i = 0; i != 512u; ++i) model_b_[i] = 0x8000u;

        uint8_t* out_cur = out;
        uint32_t countdown = B[0] + 1u;
        uint32_t* B_cur = B;

        for (;;) {
            for (;;) {
                uint32_t num_rle = C[P[1]] - C[P[0]];
                // The reference splats this run 4 bytes at a time, relying on
                // the caller's 3x over-allocation to absorb up to 3 bytes of
                // overshoot that the next run then overwrites. Writing exactly
                // num_rle bytes is equivalent and needs no slack.
                if (num_rle == 0u || num_rle > (uint32_t)(out + out_size - out_cur)) {
                    BWT_FAIL("decode: num_rle %u remaining %u\n", num_rle, (uint32_t)(out + out_size - out_cur));
                    return 2;
                }
                std::memset(out_cur, P[0], num_rle);
                out_cur += num_rle;

                if (--countdown == 0u) break;

                const uint32_t hash1 = (uint32_t)(C[P[4]] - C[P[1]] < 4u) +
                                       (uint32_t)(C[P[3]] - C[P[1]] < 3u) +
                                       kSomeLut2[(C[P[2]] + ~C[P[1]]) & 0xffu];
                const uint32_t hash2 = hash1 * 2u + (uint32_t)(C[P[1]] - C[P[0]] < 2u);

                ModelC* c_ptr = &model_c_[P[0]];

                const uint32_t c_shifted = (c_ptr->x + 0x80u) >> 8;
                uint16_t* a_ptr = &model_a_[0x20u * hash2 +
                    0x200u * ((uint32_t)(c_ptr->x != 0u) + (uint32_t)(c_shifted > 0x800u) +
                              kSomeLut[std::min<uint32_t>(c_shifted, 0x17Fu)])];

                const bool a_flag = adec.Read(*a_ptr);
                {
                    const uint32_t a = *a_ptr;
                    const uint32_t rate = a & 0xfu;
                    *a_ptr = (uint16_t)(rate + (rate <= 6u) +
                        (((((uint32_t)a_flag * 65536u + 0x40u - a) >> rate) + a) & 0xfff0u));
                }

                uint32_t upper_bits = 0;
                if (!a_flag) {
                    uint32_t ik = 0;
                    for (;;) {
                        ++a_ptr;
                        if (a_ptr >= model_a_ + 6146u) do { BWT_FAIL("decode: a_ptr overflow\n"); return 6; } while (0);
                        const bool aa_flag = adec.Read(*a_ptr);
                        const uint32_t a = *a_ptr;
                        const uint32_t rate = a & 0xfu;
                        *a_ptr = (uint16_t)(rate + (rate <= 7u) +
                            (((((uint32_t)aa_flag * 65536u + 0x80u - a) >> rate) + a) & 0xfff0u));
                        if (!aa_flag || ++ik == 31u) break;
                    }

                    // The unary prefix length: its tail is what a rank delta above
                    // 2^30 would need (see the note below), so record the large ones.
                    if (ik >= 20u) nz_trace::Construct("bwt_rank_ik=%u", ik);
                    uint16_t* b_ptr = &model_b_[ik * 16u + hash2];
                    const bool b_flag = adec.Read(*b_ptr);
                    *b_ptr = (uint16_t)(*b_ptr +
                        ((((uint32_t)b_flag << 16) + 512u - *b_ptr) >> 10));
                    upper_bits = (uint32_t)(ik != 0u) * 2u + (uint32_t)b_flag;
                    if (ik > 1u)
                        upper_bits = (upper_bits << (ik - 1u)) + bitreader->GetBits(ik - 1u);
                    upper_bits += 1u;

                    // upper_bits is a rank delta that gets added to a C[] entry,
                    // so it can never legitimately exceed this bucket's output
                    // size. Reaching ik = 31 (the unary prefix saturates there)
                    // would mean a delta above 2^30, i.e. a single BWT bucket
                    // over a gigabyte. MEASURED (2026-09-04) that the encoder
                    // does not go anywhere near it: over every -co/-cO archive
                    // in the verification package plus a 221 MB text input
                    // compressed at -m256m and at -m2g (the largest memory the
                    // original accepts), the biggest bucket is 440 054 bytes
                    // and the biggest ik is 18 -- and the bucket size does not
                    // grow with -m, so it is the codec's own bucket split that
                    // bounds it, not the memory budget. A 32-bit encoder could
                    // not hold such a block anyway (the BWT needs several bytes
                    // of suffix array per symbol). So this is an unreachable
                    // corner of the format rather than a gap in the port, and
                    // declining here keeps a garbage C[] entry from surfacing
                    // later as a confusing num_rle underflow.
                    if (upper_bits > out_size) {
                        BWT_FAIL("decode: rank delta %u > out_size %u (ik=%u, no encoder emits this)\n",
                                 upper_bits, out_size, ik);
                        return 7;
                    }
                }

                const uint32_t y = (3u * c_ptr->y + 5u * c_ptr->x + 259u) >> 3;
                c_ptr->y = y;
                c_ptr->x = (upper_bits * 1024u + 12u * y + 8u) >> 4;

                // Move the just-emitted symbol back to its new rank.
                const uint8_t last_rle = P[0];
                P[0] = P[1];

                upper_bits += C[P[1]];
                uint32_t new_c = upper_bits + 8u;
                size_t k = 1;
                // The reference writes these as `new_c >= C[P[k+8]] && k != 249`
                // (and `... P[k+1] ... && k != 255`), which reads P[257]/P[256]
                // on the final probe -- past its own `uint8 P[256]`, landing in
                // whatever the stack puts next. The value is always discarded
                // (the k check ends the loop on that same iteration either way),
                // so *semantically* testing the bound first changes nothing.
                //
                // It changes everything in practice. Because P[k+8] is UB, gcc
                // -O2 is entitled to assume it is in bounds, i.e. k <= 247, and
                // therefore that `k != 249` is always true -- so it deletes that
                // test and the loop loses its upper bound. k was observed
                // reaching 2313, after which `P[k] = last_rle` writes far past
                // P[255] and corrupts C[] (which the compiler had placed right
                // after P), surfacing later as an absurd num_rle. Testing the
                // bound first removes the UB and restores the intended loop.
                // Found with ASAN (which flagged only the read, since at -O1 it
                // does not exploit the UB) plus an A/B revert: with the
                // reference form a real 1.5 MB BWT block fails, with this form
                // it decodes byte-exact. The reference decoder is presumably
                // miscompiled the same way at -O2, which may be part of why it
                // is known to get some -co/-cO edges wrong.
                for (; k + 8u <= 255u && new_c >= C[P[k + 8]] && k != 249u; k += 8, new_c += 8)
                    std::memmove(P + k, P + k + 1, 8);
                new_c = (uint32_t)(upper_bits + k);
                for (; k + 1u <= 255u && new_c >= C[P[k + 1]] && k != 255u; k += 1, new_c += 1)
                    P[k] = P[k + 1];
                P[k] = last_rle;
                C[last_rle] = new_c;
            }
            if (--ents_used == 0u) break;
            countdown = B_cur[1] - B_cur[0];
            B_cur++;
            MoveUpItem(P, C, out_size, ents_used);
        }
        return 0;
    }

    // BwtUnpackMain (reference NZ.cpp). Works in place inside a scratch region
    // of 3 * out_size bytes whose first `data_size` bytes hold this bucket's
    // compressed input; on success the first `out_size` bytes hold the result.
    uint32_t BwtUnpackMain(uint8_t* data, uint32_t data_size, uint32_t out_size) {
        if (!data_size) return 0;
        BackwardsByteStream bs(data, data_size);
        uint32_t pp_in_size = bs.ReadBackwardsVarint();
        uint32_t pp_datasize = 0;
        if (pp_in_size) {
            if (pp_in_size > out_size) { BWT_FAIL("unpack: pp_in_size %u > out_size %u\n", pp_in_size, out_size); return 0; }
            pp_in_size = out_size - pp_in_size;
            pp_datasize = pp_in_size ? bs.ReadBackwardsVarint() : 0u;
        }
        uint32_t bits_size = bs.ReadBackwardsVarint();
        const bool do_rle = (bits_size != 0u);
        bits_size -= (uint32_t)do_rle;
        const uint32_t bytes_left = bs.BytesLeft();
        if (bits_size > bytes_left || pp_datasize > bytes_left - bits_size) {
            BWT_FAIL("unpack: bits_size %u pp_datasize %u vs bytes_left %u\n", bits_size, pp_datasize, bytes_left);
            return 0;
        }
        if (bits_size + pp_datasize >= bytes_left) {
            BWT_FAIL("unpack: bits+pp %u >= bytes_left %u\n", bits_size + pp_datasize, bytes_left);
            return 0;
        }

        uint8_t* out_ptr = data + out_size;
        BitReader bitreader;
        bitreader.Initialize(data + pp_datasize, bits_size);
        uint8_t* in_ptr = data + (bits_size + pp_datasize);
        BwtRleExpander rle_expander(data, data + pp_datasize);
        if (do_rle) {
            if (Decode(in_ptr, bytes_left - (bits_size + pp_datasize), out_ptr,
                       pp_in_size ? pp_in_size : out_size, &bitreader)) {
                BWT_FAIL("unpack: Decode failed (in=%u out=%u)\n",
                         bytes_left - (bits_size + pp_datasize), pp_in_size ? pp_in_size : out_size);
                return 0;
            }
            in_ptr = data + out_size;
            out_ptr = data + out_size + out_size;
        }
        if (pp_in_size) {
            uint32_t tmp_out = out_size;
            if (!rle_expander.Decode1(in_ptr, pp_in_size, out_ptr, &tmp_out)) {
                BWT_FAIL("unpack: Decode1 failed (pp_in_size=%u out_size=%u)\n", pp_in_size, out_size);
                return 0;
            }
            if (tmp_out != out_size) {
                BWT_FAIL("unpack: Decode1 size %u != %u\n", tmp_out, out_size);
                return 0;
            }
            in_ptr = out_ptr;
        }
        if (data != in_ptr) std::memmove(data, in_ptr, out_size);
        return out_size;
    }
};

}  // namespace


// BwtUntransform (reference NZ.cpp:645). The reference has two code paths --
// one for data_size >= 0x1000000 that keeps a separate copy of the input and a
// table of plain indices, one below that which packs the byte and the index
// into a single u32 (byte | index << 8). They compute the same permutation;
// the packed form is only an allocation optimisation, and it silently caps the
// addressable index at 2^24. This port always uses the general form.
//
// The reference also aliases its index table onto the bytes just past `data`
// (`(uint32*)((data + data_size + 3) & ~3)`), which requires every caller to
// have over-allocated by 4*data_size + 3. That coupling is not worth
// replicating: this port owns its scratch buffers, so a caller only has to
// provide the block's own bytes.
// The inverse BWT walk is one dependent chain of random accesses -- a cache
// miss per output byte on a large block. The original (FUN_0809d370 for blocks
// of 0x40000 bytes and more, walker FUN_0809d160) breaks it into many chains:
// pick K start indices, walk each until it meets another chain's start, then
// stitch the pieces in cycle order from the primary index. The pieces are the
// same bytes in the same order, so the output is identical; the win is that K
// independent misses are in flight instead of one. Its start-detection trick is
// kept: a chain's start index has the chain's id in its low byte, so "is this
// index a start" is one L1 lookup (starts[idx & 0xff] == idx); the primary index
// takes the chain slot its own low byte selects. The byte for a position comes
// from the 256-entry cumulative count table (largest c with C[c] <= pos), as in
// the original, so no second random access is needed.
namespace {

constexpr uint32_t kBwtChainThreshold = 0x40000u;   // the original's cut-over
constexpr uint32_t kBwtChains = 128u;               // walked round-robin, split over threads
std::atomic<unsigned> g_bwt_threads{0};             // 0 = decide from the hardware
constexpr uint32_t kBwtPage = 1u << 16;             // scratch page per piece

inline uint32_t BwtSymOf(const uint32_t* C, uint32_t pos) {
    uint32_t s = 0;
    for (uint32_t k = 128; k; k >>= 1) if (pos >= C[s + k]) s += k;
    return s;
}

struct BwtChain {
    uint32_t start = 0, idx = 0, next_start = 0, len = 0;
    std::vector<uint32_t> pages;   // page indices into the scratch pool
    uint32_t page_fill = kBwtPage; // bytes used in the last page (full = need a new one)
    bool done = false;
};

bool BwtUntransformChains(uint8_t* data, uint32_t n, uint32_t bwt_pos,
                          const uint32_t* C, const std::vector<uint32_t>& table) {
    // Chain k starts at a spaced index whose low byte is k; the primary index
    // replaces the chain its low byte selects (or is added as one more chain).
    uint32_t nchains = kBwtChains;
    std::vector<BwtChain> chains(nchains + 1u);
    uint32_t starts[256];
    int16_t chain_of[256];
    for (uint32_t i = 0; i < 256u; ++i) { starts[i] = 0xffffffffu; chain_of[i] = -1; }
    const uint32_t step = n / nchains;
    for (uint32_t k = 0; k < nchains; ++k) {
        uint32_t s = ((k * step) & 0xffffff00u) | k;
        if (s >= n) s = k;   // n >= 0x40000 here, so k < n always
        chains[k].start = s; starts[k] = s; chain_of[k] = (int16_t)k;
    }
    const uint32_t plow = bwt_pos & 0xffu;
    uint32_t primary;
    if (plow < nchains) { chains[plow].start = bwt_pos; starts[plow] = bwt_pos; primary = plow; }
    else { primary = nchains; chains[primary].start = bwt_pos; starts[plow] = bwt_pos; chain_of[plow] = (int16_t)primary; ++nchains; }
    chains.resize(nchains);
    // Two chains can only collide if a spaced start equals the primary index;
    // that slot was replaced above, and low bytes are distinct by construction.

    // Scratch pool: every byte lands in exactly one page, plus one partial page
    // per chain.
    const uint64_t npages = (uint64_t)((n + kBwtPage - 1u) / kBwtPage) + nchains;
    std::vector<uint8_t> pool((size_t)npages * kBwtPage);
    for (uint32_t k = 0; k < nchains; ++k) chains[k].idx = chains[k].start;

    // The chains are independent: split them over threads, each walking its
    // subset round-robin (one step of every live chain per round, so the
    // independent loads overlap). Pages come from a shared counter; every chain
    // writes only its own pages.
    unsigned nthreads = g_bwt_threads.load(std::memory_order_relaxed);
    if (nthreads == 0u) nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0u) nthreads = 1u;
    if (nthreads > 16u) nthreads = 16u;
    if (nthreads > nchains / 8u) nthreads = nchains / 8u;
    if (nthreads == 0u) nthreads = 1u;
    std::atomic<uint32_t> next_page_atomic{0};
    std::atomic<bool> walk_ok{true};
    auto walk = [&](uint32_t first, uint32_t last) {
        std::vector<uint32_t> active;
        for (uint32_t k = first; k < last; ++k) active.push_back(k);
        uint64_t steps = 0;
        while (!active.empty()) {
            for (size_t a = 0; a < active.size();) {
                BwtChain& c = chains[active[a]];
                const uint32_t pos = c.idx;
                const uint32_t sym = BwtSymOf(C, pos);
                const uint32_t nxt = table[pos];
                ++steps;
                if (c.page_fill == kBwtPage) { c.pages.push_back(next_page_atomic.fetch_add(1u)); c.page_fill = 0; }
                pool[(size_t)c.pages.back() * kBwtPage + c.page_fill++] = (uint8_t)sym;
                ++c.len;
                if (starts[nxt & 0xffu] == nxt) {
                    c.next_start = nxt; c.done = true;
                    active[a] = active.back(); active.pop_back();
                } else {
                    c.idx = nxt; ++a;
                }
            }
            // Chains never overlap (two on one cycle stop at each other's start,
            // chains on different cycles never meet), so a valid permutation takes
            // at most n steps in all; a corrupt one is not a permutation and
            // would walk forever.
            if (steps > (uint64_t)n) { walk_ok = false; return; }
        }
    };
    if (nthreads <= 1u) {
        walk(0u, nchains);
    } else {
        std::vector<std::thread> pool_threads;
        const uint32_t per = (nchains + nthreads - 1u) / nthreads;
        for (unsigned t = 0; t < nthreads; ++t) {
            const uint32_t first = t * per, last = std::min(nchains, first + per);
            if (first >= last) break;
            pool_threads.emplace_back(walk, first, last);
        }
        for (auto& th : pool_threads) th.join();
    }
    if (!walk_ok) {
        BWT_FAIL("chain walk did not terminate: corrupt permutation\n");
        return false;
    }

    // Stitch from the primary index, following each piece to the chain that
    // starts where it ended, until n bytes are out. A periodic block has a
    // permutation of several cycles: the plain walk then repeats the primary's
    // cycle, and so does this (the same chain comes round again). The pieces
    // must end exactly at n and the last link must lead back to the primary
    // index -- the plain walk's "ends where it began" check.
    uint64_t total = 0;
    uint32_t cur = primary;
    uint8_t* out = data;
    while (total < n) {
        const BwtChain& c = chains[cur];
        if (c.len == 0u || total + c.len > n) { BWT_FAIL("chain stitch: piece does not fit\n"); return false; }
        uint32_t left = c.len;
        for (size_t p = 0; p < c.pages.size() && left; ++p) {
            const uint32_t take = left < kBwtPage ? left : kBwtPage;
            std::memcpy(out, pool.data() + (size_t)c.pages[p] * kBwtPage, take);
            out += take; left -= take;
        }
        total += c.len;
        const int16_t nk = chain_of[c.next_start & 0xffu];
        if (nk < 0 || chains[(uint32_t)nk].start != c.next_start) { BWT_FAIL("chain stitch: bad link\n"); return false; }
        cur = (uint32_t)nk;
    }
    if (total != n || cur != primary) {
        BWT_FAIL("chain stitch: total %llu of %u, back at primary: %d\n",
                 (unsigned long long)total, n, (int)(cur == primary));
        return false;
    }
    return true;
}

}  // namespace

void NzBwtSetThreadCount(unsigned n) { g_bwt_threads.store(n, std::memory_order_relaxed); }

bool NzBwtUntransform(uint8_t* data, uint32_t data_size, uint32_t bwt_pos) {
    if (data_size == 0u) return true;
    // The reference reads table[bwt_pos] unchecked on the first iteration; a
    // corrupt or misparsed header would walk off the table. Decline instead.
    if (bwt_pos >= data_size) return false;

    uint32_t byte_count[256];
    std::memset(byte_count, 0, sizeof(byte_count));
    for (uint32_t i = 0; i != data_size; ++i) byte_count[data[i]]++;
    uint32_t C[257];   // C[c] = first sorted position of symbol c
    uint32_t sum = 0;
    for (uint32_t i = 0; i != 256u; ++i) {
        const uint32_t t = byte_count[i];
        C[i] = sum; byte_count[i] = sum;
        sum += t;
    }
    C[256] = sum;

    std::vector<uint32_t> table(data_size);
    for (uint32_t i = 0; i != data_size; ++i) table[byte_count[data[i]]++] = i;

    if (data_size >= kBwtChainThreshold)
        return BwtUntransformChains(data, data_size, bwt_pos, C, table);

    // Small block: the plain single-chain walk; the byte at a position is its
    // symbol in the sorted column (largest c with C[c] <= pos), which equals
    // the BWT byte the reference reads through the table.
    const uint32_t start = bwt_pos;
    for (uint32_t i = 0; i != data_size; ++i) {
        data[i] = (uint8_t)BwtSymOf(C, bwt_pos);
        bwt_pos = table[bwt_pos];
    }
    // A genuine BWT is one cycle of length data_size, so the walk ends where it
    // began. Corrupt input (a flipped byte changes the symbol counts) breaks the
    // permutation into several cycles and the walk ends elsewhere: the original
    // reports such a block as "Error decoding (code 100)" without writing it.
    if (bwt_pos != start) return false;
    return true;
}

// ---------------------------------------------------------------------------
// The FORWARD Burrows-Wheeler transform, for the encoder: sort the n cyclic
// rotations of `in`, write the byte before each rotation's start, and return
// the row the unrotated block landed on -- which is exactly what
// NzBwtUntransform takes back. The output is canonical, so any correct
// rotation sort produces the original's bytes; this one is prefix doubling
// with two counting sorts per round, O(n log n), early out once every rank is
// distinct. Rotations that are byte-for-byte equal (a periodic block) stay in
// index order, and the row of rotation 0 is reported.
// ---------------------------------------------------------------------------
uint32_t NzBwtTransform(const uint8_t* in, uint32_t n, uint8_t* out) {
    if (n == 0u) return 0;
    if (n == 1u) { out[0] = in[0]; return 0; }
    std::vector<uint32_t> sa(n), tmp(n), rank(n), rank2(n), cnt;
    bool distinct = false;
    {   // round 0: by the first byte
        cnt.assign(257u, 0u);
        for (uint32_t i = 0; i < n; ++i) ++cnt[in[i] + 1u];
        for (uint32_t c = 1; c <= 256u; ++c) cnt[c] += cnt[c - 1u];
        for (uint32_t i = 0; i < n; ++i) sa[cnt[in[i]]++] = i;
        uint32_t r = 0;
        rank[sa[0]] = 0;
        for (uint32_t j = 1; j < n; ++j) {
            if (in[sa[j]] != in[sa[j - 1u]]) ++r;
            rank[sa[j]] = r;
        }
        distinct = (r + 1u == n);
    }
    for (uint32_t k = 1; !distinct && k < n; k <<= 1) {
        // sort by (rank[i], rank[i + k]) with two stable counting passes
        cnt.assign(n + 1u, 0u);
        for (uint32_t i = 0; i < n; ++i) ++cnt[rank[(i + k) % n] + 1u];
        for (uint32_t c = 1; c <= n; ++c) cnt[c] += cnt[c - 1u];
        for (uint32_t i = 0; i < n; ++i) tmp[cnt[rank[(i + k) % n]]++] = i;
        cnt.assign(n + 1u, 0u);
        for (uint32_t i = 0; i < n; ++i) ++cnt[rank[i] + 1u];
        for (uint32_t c = 1; c <= n; ++c) cnt[c] += cnt[c - 1u];
        for (uint32_t j = 0; j < n; ++j) { const uint32_t i = tmp[j]; sa[cnt[rank[i]]++] = i; }
        uint32_t r = 0;
        rank2[sa[0]] = 0;
        for (uint32_t j = 1; j < n; ++j) {
            const uint32_t a = sa[j], b = sa[j - 1u];
            if (rank[a] != rank[b] || rank[(a + k) % n] != rank[(b + k) % n]) ++r;
            rank2[a] = r;
        }
        rank.swap(rank2);
        distinct = (r + 1u == n);
    }
    uint32_t primary = 0;
    for (uint32_t j = 0; j < n; ++j) {
        const uint32_t i = sa[j];
        if (i == 0u) primary = j;
        out[j] = in[(i + n - 1u) % n];
    }
    return primary;
}

// ---------------------------------------------------------------------------
// The BWT bucket ENCODER (FUN_0806c350 and its per-bucket coder FUN_0806d370 /
// FUN_0806cc70 / FUN_0806e050), for the -co family's compressor: the mirror of
// NzBwtDecodeInput and BwtUnpackInput above, over the same models, tables and
// framing. It is what the -co trial gate compresses its sample with (before
// and after the text transform, comparing the two sizes) and what a BWT block's
// payload is.
//
// Per bucket (one per leading symbol of the sorted rotations, i.e. one per
// byte value, a contiguous slice of the BWT output):
//   - 8 bytes or fewer: stored raw (FUN_0806d780 never hands them to the coder).
//   - the RLE pre-pass (FUN_0808fe30), kept only if it saves bytes;
//   - the rank coder (FUN_0806cc70): the symbol set, the C table of first
//     occurrences and the B table of exhaustion points through the adaptive
//     integer model, then one move-to-front rank per run, whose raw bits go to
//     a separate MSB-first bit stream -- kept only if arith + bits beats the
//     data by more than 0x200 bytes;
//   - otherwise the pre-pass output alone, or the bucket raw.
// The bucket stream is [pp data][bits][arith][varints: bits+1 or 0, pp side
// bytes, size - pp size], and the payload is the buckets in symbol order
// followed by their [in][out] table, empties as [extra empties][0] and raw
// buckets as [0][count]. FUN_0806c350 returns the payload size, or 0 when it is
// not below the input (the caller then stores).
//
// The original queues its decisions and codes them in a batch; coding them as
// they arise gives the same bytes, so this does that.
// ---------------------------------------------------------------------------
namespace {

// The range ENCODER the decoders' ArithDec reads: 12-bit probability of a one,
// carry-less, the top byte leaving as soon as the two bounds agree on it.
struct BwtArithEnc {
    uint32_t lo = 0, hi = 0xffffffffu;
    uint8_t* cur; uint8_t* end;
    bool overflow = false;
    void Put(uint8_t b) { if (cur < end) *cur++ = b; else overflow = true; }
    void Encode(bool bit, uint32_t p12) {
        const uint32_t mid = lo + ((hi - lo) >> 12) * p12;
        if (bit) hi = mid; else lo = mid + 1u;
        while ((hi ^ lo) < 0x1000000u) { Put((uint8_t)(hi >> 24)); hi = (hi << 8) | 0xffu; lo <<= 8; }
    }
    void EncodeModel(bool bit, uint32_t model16) { Encode(bit, model16 >> 4); }
    void EncodeRaw(uint32_t v, uint32_t nbits) {   // p = 1/2 decisions, MSB first
        while (nbits--) Encode(((v >> nbits) & 1u) != 0u, 0x800u);
    }
    void Flush() { Put((uint8_t)(hi >> 24)); }
};

// The MSB-first bit stream BitReader fetches as big-endian words (FUN_0806e050's
// writer, flushed byte-wise by FUN_080b2030).
struct BwtBitWriter {
    uint8_t* base; uint8_t* cur; uint8_t* end;
    uint32_t buf = 0, count = 0;
    bool overflow = false;
    void Put(uint32_t v, uint32_t nb) {
        if (nb == 0u) return;
        if (count + nb <= 32u) { buf = (buf << nb) | v; count += nb; return; }
        const uint32_t fit = 32u - count;          // bits that complete the word
        const uint32_t rest = nb - fit;
        const uint32_t word = (buf << fit) | (v >> rest);
        if (cur + 4 <= end) { const uint32_t w = bswap32(word); std::memcpy(cur, &w, 4); cur += 4; }
        else overflow = true;
        buf = v & bitmask(rest);
        count = rest;
    }
    void Flush() {                                  // FUN_080b2030
        while (count != 0u) {
            if (cur >= end) { overflow = true; return; }
            if (count < 8u) { *cur++ = (uint8_t)(buf << (8u - count)); count = 0; }
            else { count -= 8u; *cur++ = (uint8_t)(buf >> count); }
        }
    }
    uint32_t Bytes() const { return (uint32_t)(cur - base); }
};

// FUN_080b1e70: a varint written forward, the FIRST byte carrying the 0x80 flag,
// which BackwardsByteStream::ReadBackwardsVarint reads from the tail.
void PutTableVarint(std::vector<uint8_t>& out, uint32_t v) {
    if (v < 0x80u) { out.push_back((uint8_t)(v | 0x80u)); return; }
    out.push_back((uint8_t)((v & 0x7fu) | 0x80u));
    v >>= 7;
    while (v >= 0x80u) { out.push_back((uint8_t)(v & 0x7fu)); v >>= 7; }
    out.push_back((uint8_t)v);
}

// WriteSomeValue: the inverse of ReadSomeValue, step for step.
void WriteSomeValue(BwtArithEnc& enc, uint32_t value, uint32_t n) {
    uint32_t sum1 = 0, numbits;
    for (;;) {
        if (n == 1u) return;
        numbits = 1;
        uint32_t mm = (n - 1u) >> 1;
        if (mm == 0u) break;
        while (mm >>= 1) numbits++;
        n &= (1u << numbits) - 1u;
        if (!n) { numbits++; break; }
        const bool flag = (value - sum1) >= (1u << numbits);
        enc.EncodeModel(flag, n << (15u - numbits));
        if (!flag) break;
        sum1 += (1u << numbits);
    }
    enc.EncodeRaw(value - sum1, numbits);
}

// The inverse of BwtIntModel::Read.
struct BwtIntModelEnc {
    uint32_t bits_to_read_ = 31;
    uint16_t model_[32];
    BwtIntModelEnc() { for (uint32_t i = 0; i != 32u; ++i) model_[i] = 0x8000u; }
    void Write(BwtArithEnc& enc, uint32_t v) {
        const uint32_t nb = v ? BSR(v) : 0u;
        for (uint32_t i = 0; i < nb; ++i) {
            enc.EncodeModel(true, model_[i]);
            model_[i] = (uint16_t)(model_[i] + ((65536u + 8u - model_[i]) >> 4));
        }
        if (nb != bits_to_read_) {
            enc.EncodeModel(false, model_[nb]);
            model_[nb] = (uint16_t)(model_[nb] + ((8u - model_[nb]) >> 4));
        }
        const uint32_t res = nb ? (1u << nb) : 0u;
        enc.EncodeRaw(v - res, nb + (nb == 0u));
    }
};

// One bucket's rank coder: BwtUnpackInput::Decode run backwards over the data,
// every decision known.
struct BwtBucketEncoder {
    uint16_t model_a_[6146];
    uint16_t model_b_[512];
    BwtUnpackInput::ModelC model_c_[256];

    // Returns the arithmetic stream's size (0 = declined: it overflowed), with the
    // raw rank bits in `bits`.
    uint32_t Encode(const uint8_t* d, uint32_t n, uint8_t* arith, uint32_t arith_cap,
                    BwtBitWriter& bits) {
        if (n == 0u) return 0;
        BwtArithEnc enc; enc.cur = arith; enc.end = arith + arith_cap;

        // The symbol set in first-appearance order, and C = first occurrences.
        uint32_t C[256], B[256];
        uint8_t P[256];
        bool seen[256] = {false};
        uint32_t ents_used = 0;
        for (uint32_t i = 0; i < n; ++i) {
            const uint8_t c = d[i];
            if (!seen[c]) { seen[c] = true; C[c] = i; P[ents_used++] = c; }
        }
        {   // ReadSomeValue's shrinking alphabet, from the writer's side
            uint8_t perm[256];
            for (uint32_t i = 0; i < 256u; ++i) perm[i] = (uint8_t)i;
            uint32_t end_idx = 256;
            uint32_t left = n;
            for (uint32_t j = 0; j < ents_used; ++j) {
                uint32_t cur_idx = 0;
                while (perm[cur_idx] != P[j]) ++cur_idx;
                WriteSomeValue(enc, cur_idx, end_idx + (end_idx != 256u));
                perm[cur_idx] = perm[--end_idx];
                --left;
                if (end_idx == 0u || left == 0u) break;
            }
            // The decoder keeps reading while symbols and bytes remain: the set
            // ends with the terminator, the index equal to the count left.
            if (end_idx != 0u && left != 0u) WriteSomeValue(enc, end_idx, end_idx + 1u);
        }
        if (ents_used < 256u) BwtUnpackInput::FillUp(n, ents_used, P, C);

        BwtIntModelEnc int_model;
        for (uint32_t j = 1; j < ents_used; ++j) {
            const uint32_t prev = C[P[j - 1u]];
            const uint32_t range = j + n - ents_used - prev;
            int_model.bits_to_read_ = range ? BSR(range) : 0u;
            int_model.Write(enc, C[P[j]] - prev - 1u);
        }

        // B: the run count at which each symbol runs out, in the order they do.
        // Found by walking the runs the way the decoder will emit them.
        uint32_t nb_ = 0;
        {
            uint32_t Cw[256]; uint8_t Pw[256];
            std::memcpy(Cw, C, sizeof(Cw)); std::memcpy(Pw, P, sizeof(Pw));
            uint32_t used = ents_used, runs = 0;
            uint32_t pos = 0;
            while (used != 0u) {
                const uint8_t sym = Pw[0];
                const uint32_t run_end = (used > 1u) ? Cw[Pw[1]] : n;
                pos = run_end;
                ++runs;
                // next occurrence of sym at or after run_end
                uint32_t next = pos;
                while (next < n && d[next] != sym) ++next;
                if (next >= n) {
                    B[nb_++] = runs - 1u;
                    --used;
                    BwtUnpackInput::MoveUpItem(Pw, Cw, n, used);
                    continue;
                }
                Reinsert(Pw, Cw, next, sym);
            }
        }
        int_model.bits_to_read_ = (n - ents_used) != 0u ? BSR(n - ents_used) : 0u;
        for (uint32_t bi = 0, prev = 0; bi != ents_used; ++bi) {
            int_model.Write(enc, B[bi] - prev);
            prev = B[bi] + 1u;
        }

        // The ranks.
        std::memset(model_c_, 0, sizeof(model_c_));
        for (uint32_t i = 0; i != 6146u; ++i) model_a_[i] = 0x8002u;
        for (uint32_t i = 0; i != 512u; ++i) model_b_[i] = 0x8000u;
        uint32_t used = ents_used;
        for (;;) {
            const uint8_t sym = P[0];
            const uint32_t run_end = (used > 1u) ? C[P[1]] : n;
            uint32_t next = run_end;
            while (next < n && d[next] != sym) ++next;
            if (next >= n) {
                if (--used == 0u) break;
                BwtUnpackInput::MoveUpItem(P, C, n, used);
                continue;
            }
            // context, as the decoder computes it before it moves anything
            const uint32_t hash1 = (uint32_t)(C[P[4]] - C[P[1]] < 4u) +
                                   (uint32_t)(C[P[3]] - C[P[1]] < 3u) +
                                   kSomeLut2[(C[P[2]] + ~C[P[1]]) & 0xffu];
            const uint32_t hash2 = hash1 * 2u + (uint32_t)(C[P[1]] - C[P[0]] < 2u);
            BwtUnpackInput::ModelC* c_ptr = &model_c_[sym];
            const uint32_t c_shifted = (c_ptr->x + 0x80u) >> 8;
            const uint32_t ctx = (uint32_t)(c_ptr->x != 0u) + (uint32_t)(c_shifted > 0x800u) +
                                 kSomeLut[std::min<uint32_t>(c_shifted, 0x17Fu)];
            // move sym to its new rank; delta is what the decoder adds back
            const uint32_t k = Reinsert(P, C, next, sym);
            const uint32_t delta = (next - C[P[0]]) - k;
            CodeRank(enc, bits, sym, hash2, ctx, delta);
            const uint32_t y = (3u * c_ptr->y + 5u * c_ptr->x + 259u) >> 3;
            c_ptr->y = y;
            c_ptr->x = (delta * 1024u + 12u * y + 8u) >> 4;
        }
        enc.Flush();
        if (enc.overflow) return 0;
        return (uint32_t)(enc.cur - arith);
    }

    // FUN_0806cc70's move: P[0] leaves, everything with a next occurrence before
    // `next` closes up, and the symbol lands at rank k with C[sym] = next.
    static uint32_t Reinsert(uint8_t* P, uint32_t* C, uint32_t next, uint8_t sym) {
        P[0] = P[1];
        uint32_t k = 1;
        for (; k + 8u != 0xf9u; k += 8u) {
            if (next < C[P[k + 8u]]) break;
            std::memmove(P + k, P + k + 1u, 8);
        }
        for (; k + 1u != 0xffu; ++k) {
            if (next < C[P[k + 1u]]) break;
            P[k] = P[k + 1u];
        }
        P[k] = sym;
        C[sym] = next;
        return k;
    }

    // FUN_0806e050: one rank. a_flag says "delta is zero"; otherwise the unary
    // length of delta - 1 through model_a, its second-highest bit through
    // model_b, and the rest raw.
    void CodeRank(BwtArithEnc& enc, BwtBitWriter& bits, uint8_t /*sym*/, uint32_t hash2,
                  uint32_t ctx, uint32_t delta) {
        uint16_t* a_ptr = &model_a_[0x20u * hash2 + 0x200u * ctx];
        const bool a_flag = (delta == 0u);
        {
            const uint32_t a = *a_ptr;
            enc.EncodeModel(a_flag, a);
            const uint32_t rate = a & 0xfu;
            *a_ptr = (uint16_t)(rate + (rate <= 6u) +
                (((((uint32_t)a_flag * 65536u + 0x40u - a) >> rate) + a) & 0xfff0u));
        }
        if (a_flag) return;
        const uint32_t v = delta - 1u;
        // unary: one flag per bit of v above the lowest, capped at 31
        uint32_t ik = 0;
        {
            uint32_t rest = v;
            for (;;) {
                ++a_ptr;
                rest >>= 1;
                const bool more = (rest != 0u);
                const uint32_t a = *a_ptr;
                enc.EncodeModel(more, a);
                const uint32_t rate = a & 0xfu;
                *a_ptr = (uint16_t)(rate + (rate <= 7u) +
                    (((((uint32_t)more * 65536u + 0x80u - a) >> rate) + a) & 0xfff0u));
                if (!more) break;
                if (++ik == 31u) break;
            }
        }
        const uint32_t nbits = ik + (ik == 0u);            // bits of v below its top one
        const uint32_t shifted = v << ((32u - nbits) & 31u); // v's top bit at bit 31...
        const bool b_flag = ((int32_t)shifted < 0);
        uint16_t* b_ptr = &model_b_[ik * 16u + hash2];
        enc.EncodeModel(b_flag, *b_ptr);
        *b_ptr = (uint16_t)(*b_ptr + ((((uint32_t)b_flag << 16) + 512u - *b_ptr) >> 10));
        if (ik > 1u) bits.Put((shifted << 1) >> ((32u - (nbits - 1u)) & 31u), nbits - 1u);
    }
};

}  // namespace

namespace {

// The RLE pre-pass (FUN_0808fe30 -> FUN_08090100), the inverse of
// BwtRleExpander::Decode1: three equal bytes in a row are written as they are,
// the run beyond them (L more) as BSR(L) further copies -- the class the
// decoder turns back into DecodeInt's bit-tree -- with L itself coded into a
// side stream of its own. The comparison starts against a phantom zero, as the
// decoder's does. Returns the collapsed size, 0 when the side stream ran out of
// its room.
struct BwtRleSideEnc {
    BwtArithEnc enc;
    uint16_t model_[32];
    BwtRleSideEnc(uint8_t* base, uint8_t* end) { enc.cur = base; enc.end = end; for (uint32_t i = 0; i < 32u; ++i) model_[i] = 0x8000u; }
    // DecodeInt backwards: `x` is the class, L the value it has to yield.
    void EncodeInt(uint32_t L, uint32_t x) {
        const uint32_t k = x < 4u ? x : 4u;
        const uint32_t n = 1u << k;
        const uint32_t xx = x + (x == 0u);
        const uint32_t high = (xx > 4u) ? (L >> (xx - 4u)) : L;   // what the tree codes
        uint32_t i = 1;
        // the tree reads k flags (one for x = 0), MSB of `high` below its top bit first
        const uint32_t nflags = (x == 0u) ? 1u : k;
        for (uint32_t j = 0; j < nflags; ++j) {
            const bool flag = ((high >> (nflags - 1u - j)) & 1u) != 0u;
            uint16_t* m = &model_[i + n];
            enc.EncodeModel(flag, *m);
            *m = (uint16_t)(*m + ((0x80u - *m + ((uint32_t)flag << 16)) >> 8));
            i = i * 2u + flag;
        }
        if (xx > 4u) enc.EncodeRaw(L & bitmask(xx - 4u), xx - 4u);
    }
};

uint32_t BwtRleCollapse(const uint8_t* in, uint32_t n, uint8_t* out, BwtRleSideEnc& side) {
    if (n == 0u) return 0;
    const uint8_t* p = in;
    const uint8_t* const end = in + n;
    uint8_t* o = out;
    uint32_t prev = 0;                               // the phantom zero
    while (p < end) {
        const uint8_t c = *p++;
        *o++ = c;
        if (c != prev) { prev = c; continue; }
        // a pair: the third byte is written whatever it is
        if (p >= end) break;
        const uint8_t c1 = *p++;
        *o++ = c1;
        if (c1 != c) { prev = c1; continue; }
        // three in a row: count the rest of the run
        const uint8_t* q = p;
        while (q < end && *q == c) ++q;
        const uint32_t L = (uint32_t)(q - p);
        p = q;
        uint32_t x = 0;
        if (L > 1u) { uint32_t t = L >> 1; do { ++x; *o++ = c; t >>= 1; } while (t != 0u); }
        side.EncodeInt(L, x);
        prev = c;
    }
    side.enc.Flush();
    if (side.enc.overflow) return 0;
    return (uint32_t)(o - out);
}

// FUN_0806d370: one bucket's stream, or empty when the bucket is stored raw.
// `alloc` is the room FUN_0806c350 gave the bucket.
void BwtEncodeBucket(const uint8_t* data, uint32_t cnt, uint32_t alloc, std::vector<uint8_t>& stream) {
    stream.clear();
    if (cnt <= 8u) return;
    // the pre-pass: its side stream has `cnt` bytes of room
    std::vector<uint8_t> ppout(cnt + 8u), ppside(cnt + 8u);
    BwtRleSideEnc side(ppside.data(), ppside.data() + cnt);
    uint32_t pp = BwtRleCollapse(data, cnt, ppout.data(), side);
    const uint32_t aux = (uint32_t)(side.enc.cur - ppside.data());
    const bool use_pp = (pp != 0u) && (aux + pp < cnt);
    const uint8_t* body = use_pp ? ppout.data() : data;
    const uint32_t size = use_pp ? pp : cnt;
    const uint32_t room = use_pp ? alloc - aux : alloc;
    // the rank coder: bits area past the work array, arith output at body + size
    const uint32_t hdr = (((size + 0x400u) + 3u) & ~3u) + size * 4u;
    bool ranked = false;
    std::vector<uint8_t> bitsbuf, arith;
    uint32_t asz = 0, bsz = 0;
    if (room > hdr) {
        bitsbuf.assign(room - hdr + 8u, 0);
        arith.assign(size + 8u, 0);
        BwtBitWriter bits; bits.base = bits.cur = bitsbuf.data(); bits.end = bitsbuf.data() + (room - hdr);
        BwtBucketEncoder be;
        asz = be.Encode(body, size, arith.data(), size, bits);
        bits.Flush();
        bsz = bits.Bytes();
        ranked = (asz != 0u) && !bits.overflow && (asz + bsz + 0x200u < size);
        static const bool force = (NZ_ENV("NZOPT_BWTENC_FORCE") != nullptr);
        if (force && asz != 0u && !bits.overflow) ranked = true;
        if (BwtTrace())
            std::fprintf(stderr, "[BWTENC] count=%u pp=%u aux=%u use_pp=%d arith=%u bits=%u -> %s\n",
                         cnt, pp, aux, (int)use_pp, asz, bsz, ranked ? "ranked" : (use_pp ? "pp only" : "raw"));
    }
    if (!ranked && !use_pp) return;                  // stored raw
    if (use_pp) stream.insert(stream.end(), ppside.data(), ppside.data() + aux);
    if (ranked) {
        stream.insert(stream.end(), bitsbuf.data(), bitsbuf.data() + bsz);
        stream.insert(stream.end(), arith.data(), arith.data() + asz);
        PutTableVarint(stream, bsz + 1u);
    } else {
        stream.insert(stream.end(), body, body + size);
        PutTableVarint(stream, 0);
    }
    if (use_pp) PutTableVarint(stream, aux);
    PutTableVarint(stream, cnt - (use_pp ? pp : 0u));
}

}  // namespace

// FUN_0806c350 with FUN_0806d370's per-bucket decisions. `cap` is the room the
// caller has (the gate passes 0x600487); it shapes the per-bucket allocations
// whose overflow makes a bucket fall back. Returns the payload size written to
// `out`, or 0 when the payload would not be below `n`.
uint32_t NzBwtEncodeInput(const uint8_t* bwt, uint32_t n, uint32_t cap, std::vector<uint8_t>& out,
                          unsigned threads) {
    out.clear();
    if (n < 8u) return 0;
    if (cap < n * 5u + 0x41000u) return 0;
    // Single-threaded (DAT_08183620 == 0, every -t1 run) the whole block is ONE
    // bucket, symbol 0; the split by leading symbol is the multi-threaded
    // layout and is not written yet.
    uint32_t count[256] = {0};
    if (threads <= 1u) {
        count[0] = n;
    } else {
        return 0;
    }
    uint32_t nonempty = 0;
    for (uint32_t c = 0; c < 256u; ++c) nonempty += (count[c] != 0u);

    // FUN_0806c350's per-bucket room: what is left of `cap` beyond five bytes per
    // input byte, shared out among the buckets still to come.
    uint32_t alloc[256] = {0};
    {
        uint32_t room = cap - n * 5u, left = nonempty;
        for (uint32_t c = 0; c < 256u; ++c) {
            if (count[c] == 0u) continue;
            const uint32_t share = room / left;
            --left;
            alloc[c] = (share + count[c] * 5u) & ~7u;
            room -= share;
        }
    }

    std::vector<uint8_t> streams, stream;
    uint32_t coded[256] = {0};                      // 0 = stored raw
    const uint8_t* src = bwt;
    for (uint32_t c = 0; c < 256u; ++c) {
        const uint32_t cnt = count[c];
        if (cnt == 0u) continue;
        const uint8_t* data = src;
        src += cnt;
        BwtEncodeBucket(data, cnt, alloc[c], stream);
        if (stream.empty()) { streams.insert(streams.end(), data, data + cnt); continue; }
        coded[c] = (uint32_t)stream.size();
        streams.insert(streams.end(), stream.begin(), stream.end());
    }

    // The bucket table, in symbol order, read back from the tail.
    std::vector<uint8_t> table;
    for (uint32_t c = 0; c < 256u; ) {
        if (count[c] == 0u) {
            uint32_t extra = 0;
            while (c + 1u + extra < 256u && count[c + 1u + extra] == 0u) ++extra;
            PutTableVarint(table, extra);
            PutTableVarint(table, 0);
            c += 1u + extra;
            continue;
        }
        PutTableVarint(table, coded[c]);
        PutTableVarint(table, count[c]);
        ++c;
    }
    out.swap(streams);
    out.insert(out.end(), table.begin(), table.end());
    if (out.size() >= n) { out.clear(); return 0; }
    return (uint32_t)out.size();
}

// BwtDecodeInput (reference NZ.cpp:591). The BWT output is split into 256
// buckets keyed by leading symbol; each bucket's (in_bytes, out_bytes) pair is
// stored as a backwards varint pair at the tail of the payload, with runs of
// empty buckets collapsed into a single zero-marker plus a repeat count.
//
// The reference decodes each bucket in place inside a scratch region strided at
// 3 * out_bytes[i] (BwtUnpackMain needs two extra out_size-sized staging areas),
// then compacts all buckets down to the front of the same buffer. This port
// keeps that layout -- it is load-bearing for BwtUnpackMain -- but owns the
// scratch buffer rather than borrowing the caller's over-allocated one.
bool NzBwtDecodeInput(const uint8_t* payload, uint32_t payload_size,
                      uint32_t out_size, uint8_t* out) {
    if (out_size == 0u) return false;

    uint32_t out_bytes[256];
    uint32_t in_bytes[256];
    bool stored_raw[256] = {false};

    BackwardsByteStream byte_stream(payload, payload_size);
    uint32_t n = 255;
    int32_t nzeros = 0;
    uint64_t in_pos = 0, out_pos = 0;
    do {
        uint32_t round_in = 0, round_out = 0;
        if (--nzeros < 0) {
            round_out = byte_stream.ReadBackwardsVarint();
            if (round_out) {
                round_in = byte_stream.ReadBackwardsVarint();
            } else {
                nzeros = (int32_t)byte_stream.ReadBackwardsVarint();
            }
        }
        // round_in == 0 for a non-empty bucket means the encoder could not
        // compress it and stored it verbatim: its input length IS its output
        // length, and there is no per-bucket header to parse. Reading it as a
        // literal zero left the bucket's bytes unaccounted for, so every later
        // bucket was distributed from the wrong offset and the first one to
        // carry a header parsed garbage out of its neighbour's data.
        stored_raw[n] = (round_out != 0u && round_in == 0u);
        if (stored_raw[n]) round_in = round_out;
        if (BwtTrace() && round_out != 0u)
            std::fprintf(stderr, "[BWT]   bucket %u: out=%u in=%u%s\n",
                         n, round_out, round_in, stored_raw[n] ? " (stored raw)" : "");
        in_bytes[n] = round_in;
        out_bytes[n] = round_out;
        in_pos += round_in;
        out_pos += round_out;
        if (in_pos > payload_size || out_pos > out_size) {
            BWT_FAIL("table: bucket %u in_pos %llu out_pos %llu vs payload %u out %u\n",
                     n, (unsigned long long)in_pos, (unsigned long long)out_pos, payload_size, out_size);
            return false;
        }
    } while ((int32_t)--n != -1);

    if (BwtTrace()) {
        uint32_t nz = 0, mx = 0;
        for (uint32_t i = 0; i < 256u; ++i) { if (out_bytes[i]) ++nz; if (out_bytes[i] > mx) mx = out_bytes[i]; }
        std::fprintf(stderr, "[BWT] table: %u non-empty buckets, largest out=%u, out_pos=%llu/%u in_pos=%llu\n",
                     nz, mx, (unsigned long long)out_pos, out_size, (unsigned long long)in_pos);
    }
    // The bucket table must account for exactly the declared output size, and
    // the per-bucket inputs must fit in what's left of the payload after it.
    if (out_pos != out_size) {
        BWT_FAIL("table: out_pos %llu != out_size %u\n", (unsigned long long)out_pos, out_size);
        return false;
    }
    if (in_pos > byte_stream.BytesLeft()) {
        BWT_FAIL("table: in_pos %llu > bytes_left %u\n", (unsigned long long)in_pos, byte_stream.BytesLeft());
        return false;
    }

    // Per-bucket scratch: 3 * out_bytes[i], as BwtUnpackMain requires.
    uint64_t scratch_size = 0;
    for (uint32_t i = 0; i != 256u; ++i) scratch_size += (uint64_t)out_bytes[i] * 3u;
    if (scratch_size == 0u) return false;
    std::vector<uint8_t> scratch(scratch_size);

    uint8_t* offsets[256];
    {
        uint8_t* cur = scratch.data();
        for (uint32_t i = 0; i != 256u; ++i) {
            offsets[i] = cur;
            cur += (size_t)out_bytes[i] * 3u;
        }
    }

    // Distribute each bucket's compressed bytes, highest bucket first so a
    // bucket's destination never clobbers a lower bucket's unread source.
    const uint8_t* cur_src = byte_stream.ptr_end_;
    for (uint32_t i = 256; i-- != 0;) {
        cur_src -= in_bytes[i];
        if (in_bytes[i]) std::memcpy(offsets[i], cur_src, in_bytes[i]);
    }

    // Each bucket is decoded by its own unpacker in its own scratch region, so
    // the buckets are independent; the original (FUN_0809a890 under FUN_0809d370's
    // thread group) decodes them in parallel on large blocks and so does this.
    auto decode_bucket = [&](uint32_t i) -> bool {
        BwtUnpackInput unpacker;
        if (unpacker.BwtUnpackMain(offsets[i], in_bytes[i], out_bytes[i]) != out_bytes[i]) {
            BWT_FAIL("bucket %u failed (in=%u out=%u)\n", i, in_bytes[i], out_bytes[i]);
            return false;
        }
        return true;
    };
    unsigned nthreads = 1u;
    if (out_size >= kBwtChainThreshold) {
        nthreads = g_bwt_threads.load(std::memory_order_relaxed);
        if (nthreads == 0u) nthreads = std::thread::hardware_concurrency();
        if (nthreads == 0u) nthreads = 1u;
        if (nthreads > 16u) nthreads = 16u;
    }
    if (nthreads <= 1u) {
        for (uint32_t i = 0; i != 256u; ++i) {
            if (out_bytes[i] == 0u || stored_raw[i]) continue;   // raw: already in place
            if (!decode_bucket(i)) return false;
        }
    } else {
        // Largest buckets first so the tail of the schedule is short.
        std::vector<uint32_t> order;
        for (uint32_t i = 0; i != 256u; ++i) if (out_bytes[i] != 0u && !stored_raw[i]) order.push_back(i);
        std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) { return out_bytes[a] > out_bytes[b]; });
        std::atomic<size_t> next{0};
        std::atomic<bool> ok{true};
        auto worker = [&]() {
            for (;;) {
                const size_t k = next.fetch_add(1u);
                if (k >= order.size() || !ok.load(std::memory_order_relaxed)) return;
                if (!decode_bucket(order[k])) ok = false;
            }
        };
        std::vector<std::thread> threads;
        for (unsigned t = 0; t < nthreads && t < order.size(); ++t) threads.emplace_back(worker);
        for (auto& th : threads) th.join();
        if (!ok) return false;
    }

    uint8_t* dst = out;
    for (uint32_t i = 0; i != 256u; ++i) {
        if (out_bytes[i]) std::memcpy(dst, offsets[i], out_bytes[i]);
        dst += out_bytes[i];
    }
    return (uint32_t)(dst - out) == out_size;
}

// ---------------------------------------------------------------------------
// param14 (reference NZ_LZ.cpp:543, DecodeLZ_Param14) and param15 (reference
// NZ.cpp:843, DecodeParam15): two BWT-only follow-on transforms that run after
// the inverse BWT and before the shared param2/param1/text-transform/dece
// chain.
//
// Both are LZ77 passes driven by their own arithmetic-coded side stream, and
// both find their matches by scanning the *byte* stream for a two-byte escape
// tag rather than by coding literal/match flags. They differ in how a match
// names its source:
//   param14  tag 0xfe 0xf1, then a selector byte: 1 = the tag was a literal
//            (emit it, continue), 0 = a match. Offset is coded relative to the
//            current output position, with 4 repeat-offset slots.
//   param15  tag 0xfe 0xf0, then a selector byte: 0 = literal. Otherwise the
//            match length is coded, and the source is a 4-byte BIG-ENDIAN
//            one's-complement ABSOLUTE offset from the base of the whole
//            accumulated output stream -- so a match can reach back into
//            earlier blocks, not just this one.
//
// NOTE: param14 here is NOT the same transform as nz_cd_tokens.cpp's
// NzCdParam14 (the -cd char-class space-insertion text transform). Same name,
// different algorithm; do not conflate them.
//
// The reference bounds-checks neither the relative offset nor the absolute one,
// so a corrupt stream walks off the front of its buffer. Both ports decline
// instead, matching this project's safety invariant.
// ---------------------------------------------------------------------------

namespace {

// Shared length decoder: a unary bit-count in `model_hi`, then that many bits
// through the binary tree in `model_lo`, then any remaining low bits raw.
struct Param1415LenDecoder {
    static uint32_t Decode(ArithDec* adec, uint16_t* model_hi, uint16_t* model_lo,
                           uint32_t lo_accum_init) {
        uint32_t lenbits = 0;
        for (;; lenbits++) {
            uint16_t* mp = &model_hi[lenbits];
            const bool flag = adec->Read(*mp);
            *mp = (uint16_t)(*mp + ((((uint32_t)flag << 16) + 8u - *mp) >> 4));
            if (!flag) break;
        }
        uint32_t matchlen = (lenbits != 0u);
        const uint32_t base = lenbits * 8u;
        uint32_t n_len_lower;
        if (lenbits >= 2u) {
            n_len_lower = lenbits - 2u;
            lenbits = 2u;
        } else {
            lenbits += (lenbits == 0u);
            n_len_lower = 0u;
        }
        uint32_t accum = lo_accum_init;
        do {
            uint16_t* mp = &model_lo[base + accum];
            const bool flag = adec->Read(*mp);
            *mp = (uint16_t)(*mp + ((((uint32_t)flag << 16) + 8u - *mp) >> 4));
            matchlen = matchlen * 2u + flag;
            accum = accum * 2u + flag;
        } while (--lenbits);
        while (n_len_lower) {
            matchlen = matchlen * 2u + adec->Read(0x8000u);
            n_len_lower--;
        }
        return matchlen;
    }
};

}  // namespace

bool NzBwtParam14(const uint8_t* model_data, uint32_t model_len,
                  const uint8_t* in, uint32_t in_size,
                  uint8_t* out, uint32_t out_cap, uint32_t* out_size) {
    if (out_size == nullptr) return false;
    *out_size = 0;

    ArithDec adec;
    adec.InitializeX(model_data, model_data + model_len);
    adec.FillBuffer();

    uint16_t model_a[4], model_b[64], model_c[256], model_d[32];
    for (uint32_t i = 0; i != 4u; ++i) model_a[i] = 0x8000u;
    for (uint32_t i = 0; i != 64u; ++i) model_b[i] = 0x8000u;
    for (uint32_t i = 0; i != 256u; ++i) model_c[i] = 0x8000u;
    for (uint32_t i = 0; i != 32u; ++i) model_d[i] = 0x8000u;

    const uint8_t* in_end = in + in_size;
    uint8_t* const out_org = out;
    uint8_t* const out_end = out + out_cap;

    uint32_t repmatch[4] = {1u, 1u, 1u, 1u};

    for (;;) {
        const size_t room_in = (size_t)(in_end - in);
        const size_t room_out = (size_t)(out_end - out);
        const uint8_t* scan_max = in + (room_in < room_out ? room_in : room_out);
        uint32_t prev_byte = 0;
        for (;;) {
            if (in == scan_max) {
                if (in != in_end) {
                    BWT_FAIL("param14: ran out of output room with %ld input left\n",
                             (long)(in_end - in));
                    return false;
                }
                *out_size = (uint32_t)(out - out_org);
                return true;
            }
            if (prev_byte == 0xfef1u && *in <= 1u) break;
            prev_byte = (uint32_t)((uint8_t)prev_byte << 8) | *in++;
            *out++ = (uint8_t)prev_byte;
        }

        // Selector byte: 1 means the tag itself was literal data.
        if (*in++ != 0u) continue;

        // A match: drop the two tag bytes that were already emitted.
        if ((size_t)(out - out_org) < 2u) {
            BWT_FAIL("param14: match tag with fewer than 2 bytes emitted\n");
            return false;
        }
        out -= 2;

        uint32_t repmatch_index = 0, trace_slot = 0;
        for (; repmatch_index != 4u; repmatch_index++) {
            uint16_t* mp = &model_a[repmatch_index];
            const bool flag_a = adec.Read(*mp);
            *mp = (uint16_t)(*mp + ((((uint32_t)flag_a << 16) + 4u - *mp) >> 3));
            if (flag_a) break;
        }

        uint32_t offset, matchlen;
        if (repmatch_index == 0u) {
            uint32_t offs_bits = 0;
            for (; offs_bits != 31u; offs_bits++) {
                uint16_t* mp = &model_d[offs_bits];
                const bool flag = adec.Read(*mp);
                *mp = (uint16_t)(*mp + ((((uint32_t)flag << 16) + 8u - *mp) >> 4));
                if (!flag) break;
            }
            const uint32_t upper_bits = offs_bits ? (1u << offs_bits) : 0u;
            uint32_t numbits = offs_bits + (offs_bits == 0u);
            uint32_t lowbits = 0;
            do {
                lowbits = lowbits * 2u + adec.Read(0x8000u);
            } while (--numbits);
            offset = upper_bits + lowbits;
            repmatch[3] = repmatch[2];
            repmatch[2] = repmatch[1];
            repmatch[1] = repmatch[0];
            repmatch[0] = offset;
            matchlen = Param1415LenDecoder::Decode(&adec, model_b, model_c, 1u) + 7u;
        } else {
            trace_slot = repmatch_index;
            offset = repmatch[repmatch_index - 1u];
            if (repmatch_index != 1u) {
                for (; repmatch_index != 1u; repmatch_index--)
                    repmatch[repmatch_index - 1u] = repmatch[repmatch_index - 2u];
                repmatch[0] = offset;
            }
            matchlen = Param1415LenDecoder::Decode(&adec, model_b + 32, model_c, 3u) + 7u;
        }

        if (NZ_ENV("NZOPT_TRACE_P14") != nullptr)
            std::fprintf(stderr, "P14 pos=%ld len=%u off=%u slot=%u rep=[%u,%u,%u,%u]\n",
                         (long)(out - out_org), matchlen, offset, trace_slot,
                         repmatch[0], repmatch[1], repmatch[2], repmatch[3]);
        if (offset == 0u || offset > (uint32_t)(out - out_org)) {
            BWT_FAIL("param14: offset %u out of range (emitted %ld)\n",
                     offset, (long)(out - out_org));
            return false;
        }
        if (matchlen > (uint32_t)(out_end - out)) {
            BWT_FAIL("param14: matchlen %u exceeds output room %ld\n",
                     matchlen, (long)(out_end - out));
            return false;
        }
        const uint8_t* src = out - offset;
        for (uint32_t i = 0; i != matchlen; i++) out[i] = src[i];
        out += matchlen;
    }
}

bool NzBwtParam15(const uint8_t* model_data, uint32_t model_len,
                  const uint8_t* in, uint32_t in_size,
                  const uint8_t* window_base, size_t window_len,
                  uint8_t* out, uint32_t out_cap, uint32_t* out_size,
                  uint32_t window_cap) {
    if (out_size == nullptr) return false;
    *out_size = 0;

    ArithDec adec;
    adec.InitializeX(model_data, model_data + model_len);
    adec.FillBuffer();

    uint16_t model_a[64], model_b[256];
    for (uint32_t i = 0; i != 64u; ++i) model_a[i] = 0x8000u;
    for (uint32_t i = 0; i != 256u; ++i) model_b[i] = 0x8000u;

    const uint8_t* in_end = in + in_size;
    uint8_t* const out_org = out;
    uint8_t* const out_end = out + out_cap;

    for (;;) {
        const size_t room_in = (size_t)(in_end - in);
        const size_t room_out = (size_t)(out_end - out);
        const uint8_t* scan_max = in + (room_in < room_out ? room_in : room_out);
        uint32_t prev_byte = 0;
        for (;;) {
            if (in == scan_max) {
                if (in != in_end) {
                    BWT_FAIL("param15: ran out of output room with %ld input left\n",
                             (long)(in_end - in));
                    return false;
                }
                *out_size = (uint32_t)(out - out_org);
                return true;
            }
            if (prev_byte == 0xfef0u) break;
            prev_byte = (uint32_t)((uint8_t)prev_byte << 8) | *in++;
            *out++ = (uint8_t)prev_byte;
        }

        if (in == in_end) { BWT_FAIL("param15: truncated selector\n"); return false; }
        if (*in == 0u) { in++; continue; }

        // Length first, then the absolute source offset as 4 raw big-endian
        // bytes (one's complement) taken from the byte stream, not the coder.
        const uint32_t matchlen =
            Param1415LenDecoder::Decode(&adec, model_a + 32, model_b, 3u);

        if ((size_t)(in_end - in) < 4u) {
            BWT_FAIL("param15: truncated absolute offset\n");
            return false;
        }
        uint32_t offs_from_start = ~(((uint32_t)in[0] << 24) |
                                           ((uint32_t)in[1] << 16) |
                                           ((uint32_t)in[2] << 8) |
                                            (uint32_t)in[3]);
        const uint64_t need = (uint64_t)matchlen + 8u;
        // The offset is a position in the LZ ring, so on a stream whose window
        // has already scrolled past the ring capacity the source lies one or
        // more capacities further along the accumulated bytes. Take the latest
        // congruent position that still fits before the window's end -- exactly
        // what the ring holds. MEASURED on a 200 MB -co archive of 16 slices:
        // its 12th slice reaches 10.9 MB of window with an 8 MB ring, and six
        // of that slice's matches read 8 MB too early without this (the p15
        // stage check byte caught it: status 105).
        if (window_cap != 0u && (uint64_t)offs_from_start + need <= (uint64_t)window_len) {
            const uint64_t limit = (uint64_t)window_len - need;
            if (offs_from_start <= limit) {
                const uint64_t k = (limit - (uint64_t)offs_from_start) / (uint64_t)window_cap;
                offs_from_start = (uint32_t)((uint64_t)offs_from_start + k * (uint64_t)window_cap);
            }
        }
        if ((uint64_t)offs_from_start + need > (uint64_t)window_len) {
            BWT_FAIL("param15: window offset %u + %llu exceeds window %zu\n",
                     offs_from_start, (unsigned long long)need, window_len);
            return false;
        }
        if ((size_t)(out - out_org) < 2u) {
            BWT_FAIL("param15: match tag with fewer than 2 bytes emitted\n");
            return false;
        }
        out -= 2;
        if (need > (uint64_t)(out_end - out)) {
            BWT_FAIL("param15: matchlen+8 %llu exceeds output room %ld\n",
                     (unsigned long long)need, (long)(out_end - out));
            return false;
        }
        const uint8_t* src = window_base + offs_from_start;
        static const bool watch_p15 = (NZ_ENV("NZ_WATCH_P15") != nullptr);
        if (watch_p15)
            std::fprintf(stderr, "[p15m] out_at=%ld len=%u need=%llu src_off=%u window=%zu\n",
                         (long)(out - out_org), matchlen, (unsigned long long)need,
                         offs_from_start, window_len);
        for (uint32_t i = 0; i != (uint32_t)need; i++) out[i] = src[i];
        out += (uint32_t)need;
        in += 4;
    }
}

// ---------------------------------------------------------------------------
// The param14 ENCODER (reference FUN_080bb3a0 -> FUN_080b9990). Its format is
// NzBwtParam14 above, read backwards; what is new here is the search: a hash
// chain with an adaptive probe budget, four repeat-offset slots, and a rarity
// gate that vetoes a match whose bytes are too common to be worth a tag.
// ---------------------------------------------------------------------------
namespace {

inline uint32_t P14Load32(const uint8_t* p) {
    uint32_t v; std::memcpy(&v, p, 4); return v;
}
inline uint32_t P14Hash(uint32_t v) { return ((v >> 0x13) ^ v); }

// Both thresholds live in one .bss table the reference fills at start-up; the
// second index is simply six further along. Generated, not embedded:
// verified 249/249 and 250/250 against a dump from a live process.
inline uint32_t P14Threshold(uint32_t len) {          // DAT_081b3280[len]
    return (len < 5u) ? 0u : (len - 3u) * (len - 3u) * ((len - 5u) / 3u);
}
inline uint32_t P14SkipLen(uint32_t len) {            // DAT_081b36a0[len]
    return (len < 6u) ? 1u : ((len - 4u) / 2u);
}
const uint32_t kP14RarityCut = 15059u;                // DAT_081b37a0

struct P14Encoder {
    const uint8_t* in = nullptr;
    uint32_t n = 0;
    uint32_t hash_mask = 0, chain_mask = 0, off_mask = 0, tag_mask = 0;
    std::vector<uint32_t> head, chain;
    uint32_t budget = 0;                              // st[8]
    const uint16_t* stats = nullptr;

    BwtArithEnc enc;
    uint16_t model_a[4], model_b[64], model_c[256], model_d[32];

    void InsertHash(uint32_t pos) {
        const uint32_t v = P14Load32(in + pos);
        const uint32_t h = P14Hash(v) & hash_mask;
        const uint32_t old = head[h];
        head[h] = pos | (v & tag_mask);
        chain[pos & chain_mask] = old;
    }

    // FUN_080bc490: the offset's bit count through model_d, then its low bits raw.
    void PutOffset(uint32_t value) {
        uint32_t nbits = 0xffffffffu, rest = value;
        for (;;) {
            ++nbits;
            if (nbits == 31u) break;
            uint16_t* m = &model_d[nbits];
            rest >>= 1;
            const bool flag = (rest != 0u);
            enc.EncodeModel(flag, *m);
            *m = (uint16_t)(*m + ((((uint32_t)flag << 16) + 8u - *m) >> 4));
            if (!flag) break;
        }
        uint32_t count = nbits + (nbits == 0u ? 1u : 0u);
        uint32_t bits = value << ((32u - count) & 31u);
        do {
            enc.Encode(((int32_t)bits < 0), 0x800u);
            bits <<= 1;
        } while (--count);
    }

    // The inverse of Param1415LenDecoder::Decode.
    void PutLen(uint32_t value, uint16_t* model_hi, uint32_t lo_accum_init) {
        uint32_t lenbits = 0, rest = value;
        for (;;) {
            uint16_t* m = &model_hi[lenbits];
            rest >>= 1;
            const bool flag = (rest != 0u);
            enc.EncodeModel(flag, *m);
            *m = (uint16_t)(*m + ((((uint32_t)flag << 16) + 8u - *m) >> 4));
            if (!flag) break;
            ++lenbits;
        }
        const uint32_t base = lenbits * 8u;
        uint32_t tree_bits, n_low;
        if (lenbits >= 2u) { tree_bits = 2u; n_low = lenbits - 2u; }
        else { tree_bits = (lenbits == 0u) ? 1u : lenbits; n_low = 0u; }
        uint32_t bits = value << ((32u - (lenbits ? lenbits : 1u)) & 31u);
        uint32_t accum = lo_accum_init;
        for (uint32_t i = 0; i < tree_bits; ++i) {
            const bool flag = ((int32_t)bits < 0);
            bits <<= 1;
            uint16_t* m = &model_c[base + accum];
            enc.EncodeModel(flag, *m);
            *m = (uint16_t)(*m + ((((uint32_t)flag << 16) + 8u - *m) >> 4));
            accum = accum * 2u + (flag ? 1u : 0u);
        }
        for (uint32_t i = 0; i < n_low; ++i) {
            enc.Encode(((int32_t)bits < 0), 0x800u);
            bits <<= 1;
        }
    }

    uint32_t Run(uint8_t* out, uint32_t out_cap, uint8_t* side, uint32_t side_limit);
};

}  // namespace

void NzBwtParam14Stats(const uint8_t* data, uint32_t n, std::vector<uint16_t>* stats) {
    stats->assign(0x40000u, 0);
    if (n < 4u) return;
    for (uint32_t i = 0; i + 3u < n; ++i)
        (*stats)[P14Hash(P14Load32(data + i)) & 0x3ffffu] += 1u;
}

namespace {

uint32_t P14Encoder::Run(uint8_t* out, uint32_t out_cap, uint8_t* side, uint32_t side_limit) {
    (void)out_cap;
    enc.cur = side; enc.end = side + side_limit;
    enc.lo = 0; enc.hi = 0xffffffffu; enc.overflow = false;
    for (uint32_t i = 0; i != 4u; ++i) model_a[i] = 0x8000u;
    for (uint32_t i = 0; i != 64u; ++i) model_b[i] = 0x8000u;
    for (uint32_t i = 0; i != 256u; ++i) model_c[i] = 0x8000u;
    for (uint32_t i = 0; i != 32u; ++i) model_d[i] = 0x8000u;

    // The reference keeps the four repeat offsets NEGATED, so `inp + rep[i]`
    // is the candidate source; they start at -1.
    int32_t rep[4] = {-1, -1, -1, -1};

    const uint8_t* const in_end = in + n;
    uint8_t* const out_lim = out + n - 0x10;
    const uint8_t* inp = in;
    uint8_t* outp = out;
    uint32_t prev16 = 0;

    if (inp < in_end && outp < out_lim) {
        InsertHash(0);
        const uint8_t first = *inp++;
        *outp++ = first;
        prev16 = first;

        while (inp < in_end && outp < out_lim) {
            if (prev16 == 0xfef1u && *inp < 2u) *outp++ = 1u;

            const uint32_t rem = (uint32_t)(in_end - inp);
            const uint32_t pos = (uint32_t)(inp - in);
            const uint32_t v = P14Load32(inp);
            const uint32_t tag = v & tag_mask;
            const uint32_t h = P14Hash(v) & hash_mask;
            uint32_t link = head[h];
            head[h] = pos | tag;
            chain[pos & chain_mask] = link;

            uint32_t match_len = 0, slot = 4, score = 0;
            uint32_t cand = link & off_mask;

            if (cand < pos && tag == (link & tag_mask)) {
                const uint32_t budget_old = budget;
                budget += (budget < 8u) ? 1u : 0u;
                const uint8_t* p = in + cand;
                if (P14Load32(p) == v && rem > 3u) {
                    uint32_t probes = (budget_old >> 2) + 1u;
                    uint32_t best = 0, best_dist = 0, cur = 0;
                    for (;;) {                                   // outer
                        cur = 4u;
                        while (cur < rem && p[cur] == inp[cur]) ++cur;
                        if (cur <= best) {
                            --probes;
                            cur = best;
                            if (probes == 0u) { match_len = best; slot = best_dist + 4u; score = best * 4u; break; }
                            goto walk;
                        }
                        {
                            const uint32_t adj = (best > 6u) ? ((cur - best) & 3u) : 0u;
                            budget = (adj + budget) & 0x3ffu;
                            if (cur > 0x40u) probes -= probes >> 1;
                            best_dist = (uint32_t)(inp - p);
                            if (cur > 0x80u) { slot = best_dist + 4u; score = cur * 4u; match_len = cur; break; }
                        }
                        for (;;) {                               // inner
                            --probes;
                            best = cur;
                            if (probes == 0u) { match_len = best; slot = best_dist + 4u; score = best * 4u; goto decided; }
                        walk:
                            link = chain[link & chain_mask];
                            cand = link & off_mask;
                            if (cand >= pos) { slot = best_dist + 4u; score = cur * 4u; match_len = cur; goto decided; }
                            if (tag != (link & tag_mask)) {
                                budget -= budget >> 4;
                                slot = best_dist + 4u; score = cur * 4u; match_len = cur; goto decided;
                            }
                            p = in + cand;
                            if (P14Load32(p + cur - 3u) == P14Load32(inp + cur - 3u)) break;
                        }
                        best = cur;
                        if (v != P14Load32(p)) {
                            budget >>= 1;
                            slot = best_dist + 4u; score = cur * 4u; match_len = cur;
                            goto decided;
                        }
                    }
                }
            }
        decided:
            // The four repeat slots: a two-byte probe, then extend.
            {
                uint32_t packed = 0, rep_score = 4u;
                for (uint32_t i = 0; i != 4u; ++i) {
                    const uint8_t* rp = inp + rep[i];
                    if (rp < in || (uint16_t)(rp[0] | (rp[1] << 8)) != (uint16_t)(inp[0] | (inp[1] << 8)))
                        continue;
                    uint32_t k = 1;
                    do { ++k; if (rem <= k) break; } while (rp[k] == inp[k]);
                    packed = i + k * 4u;
                    rep_score = packed + 4u;
                    break;
                }
                if (score <= rep_score) { slot = packed & 3u; match_len = packed >> 2; }
            }

            uint32_t rarity = 0;
            bool take = false;
            // NZOPT_TRACE_P14POS logs EVERY evaluated position, which is what
            // diffing against a GDB log of the reference's own decisions needs;
            // NZOPT_TRACE_P14 logs only the matches it emits.
            const char* dbg = NZ_ENV("NZOPT_TRACE_P14POS");
            if (match_len > 6u) {
                if (match_len > 0xfeu) {
                    take = true;
                } else {
                    for (uint32_t i = 0; i != match_len; ++i)
                        rarity += stats[P14Hash(P14Load32(inp + i)) & 0x3ffffu];
                    take = (rarity < P14Threshold(match_len)) ||
                           (slot < 4u && rarity < P14Threshold(match_len + 6u));
                }
            }

            if (dbg != nullptr)
                std::fprintf(stderr, "EV len=%u slot=%u p=%u\n", match_len, slot, pos);
            if (take) {
                const uint32_t tr_off = slot > 3u ? (slot - 4u) : (uint32_t)(-rep[slot]);
                const uint32_t tr_slot = slot > 3u ? 0u : slot + 1u;
                const long tr_pos = (long)(inp - in);
                // The reference feeds the chain for offsets 1..len-1 inclusive;
                // stopping one short silently reorders every later chain walk.
                for (uint32_t i = 1; i < match_len; ++i) InsertHash(pos + i);
                inp += match_len;
                *outp++ = 0xfeu; *outp++ = 0xf1u; *outp++ = 0u;
                if (slot > 3u) {
                    const uint32_t dist = slot - 4u;
                    uint16_t* m = &model_a[0];
                    enc.EncodeModel(true, *m);
                    *m = (uint16_t)(*m + ((0x10000u + 4u - *m) >> 3));
                    PutOffset(dist);
                    PutLen(match_len - 7u, model_b, 1u);
                    rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0];
                    rep[0] = -(int32_t)dist;
                } else {
                    uint16_t* m = &model_a[0];
                    enc.EncodeModel(false, *m);
                    *m = (uint16_t)(*m + ((4u - *m) >> 3));
                    for (uint32_t i = 1; i <= 3u; ++i) {
                        const bool flag = (slot == i - 1u);
                        uint16_t* mm = &model_a[i];
                        enc.EncodeModel(flag, *mm);
                        *mm = (uint16_t)(*mm + ((((uint32_t)flag << 16) + 4u - *mm) >> 3));
                        if (flag) break;
                    }
                    const int32_t keep = rep[slot];
                    for (uint32_t i = slot; i != 0u; --i) rep[i] = rep[i - 1u];
                    rep[0] = keep;
                    PutLen(match_len - 7u, model_b + 32, 3u);
                }
                if (NZ_ENV("NZOPT_TRACE_P14") != nullptr)
                    std::fprintf(stderr, "P14 pos=%ld len=%u off=%u slot=%u rep=[%u,%u,%u,%u]\n",
                                 tr_pos, match_len, tr_off, tr_slot,
                                 (uint32_t)(-rep[0]), (uint32_t)(-rep[1]),
                                 (uint32_t)(-rep[2]), (uint32_t)(-rep[3]));
                prev16 = 0;
                continue;
            }

            // No match: copy `skip` literal bytes, keeping the hash chain fed.
            uint32_t skip;
            if (rarity < kP14RarityCut) {
                skip = P14SkipLen(match_len);
            } else {
                skip = match_len - 1u;
                budget -= budget >> 2;
            }
            uint8_t b = *inp;
            for (;;) {
                ++inp;
                prev16 = ((prev16 & 0xffu) << 8) | b;
                *outp++ = b;
                if (--skip == 0u) break;
                InsertHash((uint32_t)(inp - in));
                if (inp >= in_end || outp >= out_lim) goto finish;
                if (prev16 == 0xfef1u && *inp < 2u) { *outp++ = 1u; }
                b = *inp;
            }
        }
    }
finish:
    enc.Flush();
    if (!(enc.cur < enc.end)) return 0;
    const uint32_t side_len = (uint32_t)(enc.cur - side);
    const uint32_t body = (uint32_t)(outp - out);
    if (!(out + body + side_len < out_lim)) return 0;
    return body;
}

}  // namespace

uint32_t NzBwtParam14Encode(const uint8_t* in, uint32_t n,
                            const std::vector<uint16_t>& stats,
                            std::vector<uint8_t>* out,
                            std::vector<uint8_t>* side,
                            uint32_t side_cap) {
    out->clear();
    side->clear();
    if (in == nullptr || n < 0x80u || stats.size() < 0x40000u) return 0;

    P14Encoder e;
    e.in = in;
    e.n = n;
    e.stats = stats.data();

    // FUN_080bb3a0's setup: the offset mask covers the block, the hash is
    // sized from n/2 with a floor of 2^19 entries.
    const uint32_t nm1 = n - 1u;
    const uint32_t hi = nm1 ? (31u - (uint32_t)__builtin_clz(nm1)) : 0u;
    e.off_mask = (1u << ((hi + 1u) & 31u)) - 1u;
    e.tag_mask = ~e.off_mask;
    const uint32_t half = n >> 1;
    const uint32_t hb = half ? (31u - (uint32_t)__builtin_clz(half)) : 0u;
    const uint32_t bits = (hb + 1u > 0x14u) ? hb : 0x13u;
    e.hash_mask = (1u << bits) - 1u;
    e.chain_mask = (1u << (bits - 1u)) - 1u;
    e.head.assign((size_t)e.hash_mask + 1u, 0);
    e.chain.assign((size_t)e.chain_mask + 1u, 0);
    // The reference's hash table is scratch past the block buffer's 2n mark and
    // is never cleared, so it arrives holding whatever that memory last had
    // (22 211 live entries on the first call of a run, measured). It does not
    // matter: a stale entry still has to pass the position and tag checks and
    // then a four-byte verification, so it can only ever name a real match --
    // seeding ours from a dump of the reference's own table changes nothing.
    e.budget = 0;

    // The reference writes into the block buffer's tail and copies back; the
    // acceptance test is `filtered + side < n - 0x10`, so n is room enough.
    out->assign((size_t)n + 0x20u, 0);
    side->assign(side_cap, 0);
    const uint32_t r = e.Run(out->data(), (uint32_t)out->size(),
                             side->data(), side_cap >> 1);
    if (r == 0u) { out->clear(); side->clear(); return 0; }
    out->resize(r);
    side->resize((size_t)(e.enc.cur - side->data()));
    return r;
}
