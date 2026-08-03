// nz_bwt.cpp — NanoZip decr_param == 0 ("BWT") block decoding, ported from the
// community reference decoder (nzdec_v0 NZ.cpp). Faithful reimplementation.
#include "nz_bwt.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// NZOPT_TRACE_BWT-gated diagnostics, following this project's existing
// NZOPT_TRACE_* convention (zero cost when the variable is unset).
static bool BwtTrace() {
    static const bool on = (std::getenv("NZOPT_TRACE_BWT") != nullptr);
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
                    // size. It does exceed it when ik saturates at 31: the
                    // shift by ik-1 then yields ~3.2e9. The reference computes
                    // `numbits = max(ik, 1)` at exactly this point and never
                    // uses it, which suggests its large-ik path is incomplete
                    // rather than that this port mis-transcribed it -- the
                    // reference is already known to get some -co/-cO edges
                    // wrong. Pinning down what the real binary does here needs
                    // GDB against linux32/nz, so decline at the true cause
                    // instead of letting a garbage C[] entry surface later as a
                    // confusing num_rle underflow.
                    if (upper_bits > out_size) {
                        BWT_FAIL("decode: rank delta %u > out_size %u (ik=%u, reference large-ik path incomplete)\n",
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
bool NzBwtUntransform(uint8_t* data, uint32_t data_size, uint32_t bwt_pos) {
    if (data_size == 0u) return true;
    // The reference reads table[bwt_pos] unchecked on the first iteration; a
    // corrupt or misparsed header would walk off the table. Decline instead.
    if (bwt_pos >= data_size) return false;

    uint32_t byte_count[256];
    std::memset(byte_count, 0, sizeof(byte_count));
    for (uint32_t i = 0; i != data_size; ++i) byte_count[data[i]]++;
    uint32_t sum = 0;
    for (uint32_t i = 0; i != 256u; ++i) {
        const uint32_t t = byte_count[i];
        byte_count[i] = sum;
        sum += t;
    }

    std::vector<uint8_t> source(data, data + data_size);
    std::vector<uint32_t> table(data_size);
    for (uint32_t i = 0; i != data_size; ++i) table[byte_count[source[i]]++] = i;

    for (uint32_t i = 0; i != data_size; ++i) {
        const uint32_t v = table[bwt_pos];
        data[i] = source[v];
        bwt_pos = v;
    }
    return true;
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

    for (uint32_t i = 0; i != 256u; ++i) {
        if (out_bytes[i] == 0u) continue;
        BwtUnpackInput unpacker;
        if (unpacker.BwtUnpackMain(offsets[i], in_bytes[i], out_bytes[i]) != out_bytes[i]) {
            BWT_FAIL("bucket %u failed (in=%u out=%u)\n", i, in_bytes[i], out_bytes[i]);
            return false;
        }
    }

    uint8_t* dst = out;
    for (uint32_t i = 0; i != 256u; ++i) {
        if (out_bytes[i]) std::memcpy(dst, offsets[i], out_bytes[i]);
        dst += out_bytes[i];
    }
    return (uint32_t)(dst - out) == out_size;
}
