// nz_audio.cpp — NanoZip decr_param == 2 ("audio") block decoding, ported from
// the community reference decoder (nzdec_v0 NZ_Audio.cpp). Faithful
// reimplementation.
#include "nz_audio.h"
#include "lzpf_arith.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Built once by NzCmInitAll() (nz_cm.cpp), shared with the CM decoder and the
// tt16 text transform. The bit-count model below is seeded from it.
extern uint16_t kModelLutLookup[4096];

namespace nzr {
namespace audio {
namespace {

// NZOPT_TRACE_AUDIO-gated diagnostics, following this project's existing
// NZOPT_TRACE_* convention (zero cost when the variable is unset).
static bool AudioTrace() {
    static const bool on = (std::getenv("NZOPT_TRACE_AUDIO") != nullptr);
    return on;
}
#define AUD_FAIL(...) do { if (AudioTrace()) std::fprintf(stderr, "[AUD] " __VA_ARGS__); } while (0)

static uint32_t BSR(uint32_t n) {
    uint32_t r = 0;
    while (n >>= 1) ++r;
    return r;
}

// ---------------------------------------------------------------------------
// ArithmeticDecoder (nz.h): the same 12-bit range coder the CM/BWT/post-filter
// ports each carry their own copy of.
// ---------------------------------------------------------------------------
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
    bool Read(uint32_t model) { return ReadNoShift(model >> 4); }
};

static uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }
static uint32_t bitmask(uint32_t nb) { return nb >= 32u ? 0xffffffffu : ((1u << nb) - 1u); }

// ---------------------------------------------------------------------------
// BitReader (nz.h).
//
// Unlike the copy in nz_postfilter.cpp, this one must advance its cursor by a
// FULL 4 bytes on every fetch even when fewer than 4 bytes remain. The
// reference walks the stream as `uint32 *ptr_` and increments it whenever
// `ptr_ < ptr_end_` (a raw byte-address comparison), so a trailing partial word
// still moves the cursor a whole word. BytesRead() is derived from that cursor
// and its result is fed straight back into the chunk's input-consumption
// accounting (`in += bit_reader.BytesRead()`), so clamping the advance the way
// the post-filter copy does would silently desynchronise the next chunk.
//
// The bytes past the true end are zero-filled rather than read, which keeps the
// port inside its own buffer while staying bit-for-bit equivalent for every
// position a valid stream can actually consume.
// ---------------------------------------------------------------------------
struct BitReader {
    uint32_t bitcount_, bitbuff_;
    const uint8_t *ptr_, *ptr_start_, *ptr_end_;

    void Initialize(const uint8_t* data, size_t size) {
        bitcount_ = 0; bitbuff_ = 0;
        ptr_ = data; ptr_start_ = data; ptr_end_ = data + size;
    }
    uint32_t FetchWord() {
        if (ptr_ >= ptr_end_) return 0u;
        const size_t avail = (size_t)(ptr_end_ - ptr_);
        uint8_t buf[4] = {0, 0, 0, 0};
        std::memcpy(buf, ptr_, avail < 4u ? avail : 4u);
        ptr_ += 4;  // a whole word, exactly as the reference's uint32*++
        uint32_t v;
        std::memcpy(&v, buf, 4);
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
    uint32_t BytesRead() const {
        return ((7u - bitcount_) + (uint32_t)(ptr_ - ptr_start_) * 8u) >> 3;
    }
};

// ---------------------------------------------------------------------------
// AudioStereoDecoder: an adaptive sign-LMS cross-channel predictor.
//
// Sizing note: the reference's Part carries history_[1024 + 128] and
// factors_[128], with hist_ptr_ starting at &history_[1024] and wrapping to
// &history_[1152 - order_]. That is exact only while order_ and hist_order_
// stay <= 128. Both are fixed by construction here (AudioPred always builds
// this with order 4, param 8, giving orders 8 and 4), never stream-controlled,
// so no bound can be driven out of range by input. Reset() is still written to
// tolerate the general case.
// ---------------------------------------------------------------------------
struct AudioStereoDecoder {
    struct Part {
        uint8_t order_, hist_order_;
        int32_t* hist_ptr_;
        int32_t factors_[128];
        int32_t history_[1024 + 128];

        void SetOrder(int order) {
            order_ = (uint8_t)order;
            hist_order_ = (uint8_t)std::max(order, 4);
        }
        void Reset() {
            hist_ptr_ = &history_[1024];
            // Decode() reads and writes hist_ptr_[0 .. hist_order_), which is
            // >= order_ whenever order_ < 4, so clear the wider span. Identical
            // to the reference for every order AudioPred actually constructs
            // (8 and 4, where the two are equal), just not uninitialised in the
            // general case.
            const uint32_t order = order_;
            const uint32_t hist = hist_order_ > order ? hist_order_ : order;
            std::memset(hist_ptr_, 0, sizeof(int32_t) * hist);
            std::memset(factors_, 0, sizeof(int32_t) * order);
        }
    };

    struct Chan {
        uint8_t shift_;
        Part one_, two_;

        explicit Chan(int order) {
            shift_ = 0;
            two_.order_ = one_.order_ = 4;
            two_.hist_order_ = one_.hist_order_ = (uint8_t)std::max(order, 4);
            one_.hist_ptr_ = &one_.history_[1024];
            two_.hist_ptr_ = &two_.history_[1024];
        }

        void SetOrder(int o1, int o2) { one_.SetOrder(o1); two_.SetOrder(o2); }

        // All of the int32 lanes below are written with explicit unsigned
        // wraparound. The reference lets them overflow as signed ints, which is
        // UB: on a stream this port cannot yet decode correctly the values do
        // blow past INT32_MAX (UBSan confirms it), and leaving that UB in place
        // is what let the optimiser delete a loop bound in the sibling BWT
        // port. Wrapping explicitly keeps the exact same bit pattern while
        // making the behaviour defined.
        static inline int32_t WrapAdd(int32_t a, int32_t b) {
            return (int32_t)((uint32_t)a + (uint32_t)b);
        }
        static inline int32_t WrapSub(int32_t a, int32_t b) {
            return (int32_t)((uint32_t)a - (uint32_t)b);
        }

        int32_t Decode(int32_t value, int32_t other_value) {
            two_.hist_ptr_[0] = other_value;
            for (uint32_t i = 1, e = two_.hist_order_; i < e; i++)
                two_.hist_ptr_[i] = WrapSub(other_value, two_.hist_ptr_[i]);

            uint64_t usum = 0;
            for (uint32_t i = 0, e = one_.order_; i != e; i++)
                usum += (uint64_t)((int64_t)one_.factors_[i] * one_.hist_ptr_[i]);
            for (uint32_t i = 0, e = two_.order_; i != e; i++)
                usum += (uint64_t)((int64_t)two_.factors_[i] * two_.hist_ptr_[i]);
            const int64_t sum = (int64_t)usum;

            const int64_t sum_sign64 = (sum >> 63);
            const int32_t sum_sign = (int32_t)sum_sign64;
            const int64_t mag = (int64_t)(((uint64_t)sum ^ (uint64_t)sum_sign64) - (uint64_t)sum_sign64);
            const int32_t shifted = (int32_t)(((uint32_t)(int32_t)(mag >> shift_)) ^ (uint32_t)sum_sign);
            const int32_t new_value = WrapAdd(value, WrapSub(shifted, sum_sign));

            if (value < 0) {
                for (uint32_t i = 0, e = one_.order_; i != e; i++)
                    one_.factors_[i] = WrapSub(one_.factors_[i], one_.hist_ptr_[i]);
            } else if (value > 0) {
                for (uint32_t i = 0, e = one_.order_; i != e; i++)
                    one_.factors_[i] = WrapAdd(one_.factors_[i], one_.hist_ptr_[i]);
            }

            one_.hist_ptr_--;
            if (one_.hist_ptr_ < one_.history_) {
                one_.hist_ptr_ = &one_.history_[1152 - one_.order_];
                std::memcpy(one_.hist_ptr_ + 1, one_.history_,
                            sizeof(int32_t) * (one_.order_ - 1));
            }
            one_.hist_ptr_[0] = new_value;
            for (uint32_t i = 1, e = one_.hist_order_; i < e; i++)
                one_.hist_ptr_[i] = WrapSub(new_value, one_.hist_ptr_[i]);

            if (value < 0) {
                for (uint32_t i = 0, e = two_.order_; i != e; i++)
                    two_.factors_[i] = WrapSub(two_.factors_[i], two_.hist_ptr_[i]);
            } else if (value > 0) {
                for (uint32_t i = 0, e = two_.order_; i != e; i++)
                    two_.factors_[i] = WrapAdd(two_.factors_[i], two_.hist_ptr_[i]);
            }

            two_.hist_ptr_--;
            if (two_.hist_ptr_ < two_.history_) {
                two_.hist_ptr_ = &two_.history_[1152 - two_.order_];
                std::memcpy(two_.hist_ptr_ + 1, two_.history_,
                            sizeof(int32_t) * (two_.order_ - 1));
            }
            return new_value;
        }
    };

    Chan left_, right_;

    AudioStereoDecoder(int order, int param) : left_(order), right_(order) {
        SetBits(23, 23);
        if (param) {
            left_.SetOrder(4, 4);
            right_.SetOrder(4, 4);
            if (param > 4) {
                left_.SetOrder(param, param - 4);
                right_.SetOrder(param, param - 4);
            }
        }
        Reset();
    }

    void SetBits(uint32_t c0, uint32_t c1) {
        left_.shift_ = (uint8_t)c0;
        right_.shift_ = (uint8_t)c1;
    }

    void Reset() {
        left_.one_.Reset(); left_.two_.Reset();
        right_.one_.Reset(); right_.two_.Reset();
    }

    void Decode(int32_t* lp, int32_t* rp, uint32_t frames) {
        int32_t new_right_value = 0, new_left_value = 0;
        for (uint32_t i = 0; i != frames; i++) {
            lp[i] = new_left_value = left_.Decode(lp[i], new_right_value);
            rp[i] = new_right_value = right_.Decode(rp[i], new_left_value);
        }
    }
};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GDB GROUND TRUTH, 2026-09-01 -- what the real binary actually does for a
// `decr_param == 2` block, and why this AudioPred transcription only agrees with
// it under `-cO`.
//
// Captured against `linux32/nz` on the three archives in ~/.cache/nzre_aud by
// watchpointing the residual array the real decoder hands to its reconstruction
// call (`FUN_080a50c0`, 3rd argument), then watching one element of it to get the
// sequence of stages that write it:
//
//   -cO :  FUN_0809bbf0  ->  FUN_08095d90  ->  FUN_08096160
//   -co :  FUN_0809bbf0  ->  FUN_080958d0  ->  FUN_08095d90  ->  FUN_08096e20
//   (-cc takes the -co shape)
//
// So the audio path is NOT a separate algorithm family: it is assembled from the
// SAME primitives as the lzpf prefilter, three of which this tree already has
// byte-exact --
//   FUN_0809bbf0 = nzr::lzpf::DecodeResidualsStereo  (in-tree, and its comment
//                  calls it speculative/never-the-real-path -- true for lzpf,
//                  FALSE for audio: this is its real caller)
//   FUN_08095d90 = nzr::lzpf::LpcPredictor / PrefilterPlane
//   FUN_08096e20 = nzr::lzpf::LmsObject (the LMS)
// -- plus two that are NOT ported: FUN_080958d0 (an extra predictor stage that
// only -co/-cc run) and FUN_08096160 (-cO's inter-channel stage, where -co/-cc
// use the LMS instead).
//
// Measured consequences, so nobody re-derives them:
//   * The residual array handed to the reconstruction is BYTE-IDENTICAL across
//     -co, -cO and -cc (md5 7d4ca807c2b0fdcc6f57ac92291a82f9, 32000 int32).
//   * This port reproduces it byte-exactly for -cO (0 diffs) and gets it wrong
//     for -co (from element 0) and -cc (from element 2). The reconstruction
//     stage is therefore fine; the defect is entirely in residual production.
//   * The real decoder writes resid[0] exactly ONCE, so its predictor stages do
//     not touch the first element.
//
// REFUTED here, do not retry: reading the small header the reconstruction call
// receives (`01 01 02 02 2c 00 00 00 ...`, where [4..7] is header_bytes = 44 and
// [2]/[3] drive FUN_080a50c0's branch) as the six predictor-enable flags -- no
// bit offset in -120..+120 reproduces it and forcing it does not match; and
// re-routing the payload straight into DecodePrefilterStream (best of 64 offsets
// x orders x nstages x mono/stereo left 63725 of 64044 bytes wrong).
//
// fresh capture. NZOPT_DUMP_AUDCOUNTS dumps the per-sample bit-count array where
// FUN_0809bbf0 receives it, NZOPT_DUMP_AUDPOST the residuals where it returns, and
// NZOPT_DUMP_AUDPLANE=<prefix> one file per FUN_08095d90 call. Those three split the
// pipeline at exactly the points the GDB captures in ~/.cache/nzre_tools/audio_gdb/
// were taken, so each half can be checked independently.
//
// SECOND ROUND OF GROUND TRUTH (2026-09-01). The two remaining codecs fail for two
// DIFFERENT reasons, and both are now localised:
//
// -co: its BIT-COUNT DECODER IS A DIFFERENT CLASS, and it is unported. The two
//   per-channel decoders are reached through a vtable at obj+0x38700/+0x38704, and
//   the vtable pointer differs per codec:
//        -cO, -cc :  vtable 0x0813c848, decode = FUN_0809c070
//        -co      :  vtable 0x0813c860, decode = FUN_0809bdc0
//   The AudioBitcountDecoder below is a transcription of FUN_0809c070 -- which is why
//   -cO's and -cc's bit-count arrays come out BYTE-EXACT and -co's is garbage from
//   element 0 (near-constant ~26 where the real values range 0..45). Per
//   work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md, vtable 0x0813c860 is
//   a Fenwick-tree/frequency-count coder whose slot0 (FUN_080bd760) is its
//   build/rebalance routine; FUN_0809bdc0 has never been read line by line and there
//   is no decompile for it. Porting it is what -co needs.
//
// -cc: bit-counts byte-exact AND the post-residual-decode array byte-exact, so its
//   defect is in the PREDICTOR stages. The real per-plane call order for it is
//   5, 2, 3, 0, 1 on channels ch2, ch1, ch2, ch1, ch2 -- which this file's loop
//   already reproduces exactly. Stage 0 (linpred[5], shift 8) is byte-exact; stage 1
//   (linpred[2], shift 13) first diverges at element 2, where the real predictor
//   contributes 0 and this one contributes -1. So the SUM differs, not the rounding.
//   Re-confirmed with per-stage evidence (not just end-to-end, as before): switching
//   RunSmall to UpdateBig's magnitude-shift-then-re-sign convention breaks stage 0,
//   which was exact. The arithmetic shift is right; do not retry that.
// ---------------------------------------------------------------------------

// LinearPredictor: sign-LMS over a 512-stride dual history (samples in the low
// half, log-magnitudes in the high half). hist_[3072] is exactly sized for the
// wrap target &hist_[2560 - order] plus the +512 stride, for order <= 512.
// Orders are fixed by AudioPred's constructor (0x60 and 8), never from input.
// ---------------------------------------------------------------------------
static inline int32_t Clamp16(int32_t v) {
    return ((int16_t)v != v) ? ((v >> 31) ^ 0x7fff) : v;
}

static inline void CopyHist(int16_t* dst, const int16_t* src, uint32_t n) {
    for (; n; n--) *dst++ = *src++;
}

struct LinearPredictor {
    int32_t predicted_value_;
    uint16_t order_;
    uint8_t shift_;
    int16_t* cur_ptr_;
    int16_t factors_[512];
    int16_t hist_[3072];

    LinearPredictor() : predicted_value_(0), order_(0), shift_(0), cur_ptr_(hist_) {
        std::memset(factors_, 0, sizeof(factors_));
        std::memset(hist_, 0, sizeof(hist_));
    }

    void Initialize(uint32_t order) { order_ = (uint16_t)order; Reset(); }
    void SetBits(int c) { shift_ = (uint8_t)c; }

    void Reset() {
        predicted_value_ = 0;
        cur_ptr_ = &hist_[2048];
        std::memset(cur_ptr_, 0, sizeof(int16_t) * order_);
        std::memset(cur_ptr_ + 512, 0, sizeof(int16_t) * order_);
        std::memset(factors_, 0, sizeof(int16_t) * order_);
    }

    void UpdateBig(int32_t sample, int32_t delta) {
        const uint32_t order = order_;
        int16_t* cur_ptr = cur_ptr_;
        if (delta < 0) {
            for (uint32_t i = 0; i != order; i++)
                factors_[i] = (int16_t)Clamp16((int32_t)((uint32_t)factors_[i] - (uint32_t)cur_ptr[i + (size_t)512]));
        } else if (delta > 0) {
            for (uint32_t i = 0; i != order; i++)
                factors_[i] = (int16_t)Clamp16((int32_t)((uint32_t)factors_[i] + (uint32_t)cur_ptr[i + (size_t)512]));
        }
        cur_ptr_ = cur_ptr - 1;
        if (cur_ptr_ < hist_) {
            cur_ptr_ = &hist_[2560 - order];
            CopyHist(cur_ptr_ + 1, hist_, order - 1);
            CopyHist(cur_ptr_ + 1 + 512, hist_ + 512, order - 1);
        }

        const int32_t clamped_sample = Clamp16(sample);
        cur_ptr_[0] = (int16_t)clamped_sample;
        const int32_t log = (clamped_sample ? (int32_t)BSR((uint32_t)std::abs(clamped_sample)) : 0) + 1;
        cur_ptr_[512] = (int16_t)(((clamped_sample >> 31) ^ log) - (clamped_sample >> 31));

        uint32_t usum = 0;
        for (uint32_t i = 0; i != order; i++)
            usum += (uint32_t)((int32_t)cur_ptr_[i] * (int32_t)factors_[i]);
        const int32_t sum = (int32_t)usum;
        predicted_value_ = ((sum >> 31) ^ (int32_t)((uint32_t)std::abs(sum) >> shift_)) - (sum >> 31);
    }

    void RunBig(int32_t* samples, uint32_t n) {
        for (; n; n--) {
            const int32_t delta = *samples;
            const int32_t sample = (int32_t)((uint32_t)delta + (uint32_t)predicted_value_);
            *samples++ = sample;
            UpdateBig(sample, delta);
        }
    }

    void RunSmall(int32_t* samples, uint32_t n) {
        const uint32_t order = order_;
        for (; n; n--) {
            const int32_t delta = *samples;
            const int32_t outvalue = (int32_t)((uint32_t)delta + (uint32_t)predicted_value_);
            *samples++ = outvalue;

            int16_t* cur_ptr = cur_ptr_;
            if (delta <= 0) {
                for (uint32_t i = 0; i != order; i++)
                    factors_[i] = (int16_t)((uint32_t)factors_[i] + (uint32_t)cur_ptr[i + (size_t)512]);
            } else {
                for (uint32_t i = 0; i != order; i++)
                    factors_[i] = (int16_t)((uint32_t)factors_[i] - (uint32_t)cur_ptr[i + (size_t)512]);
            }
            cur_ptr_ = cur_ptr - 1;
            if (cur_ptr_ < hist_) {
                cur_ptr_ = &hist_[2560 - order];
                CopyHist(cur_ptr_ + 1, hist_, order - 1);
                CopyHist(cur_ptr_ + 1 + 512, hist_ + 512, order - 1);
            }

            cur_ptr_[0] = (int16_t)outvalue;
            cur_ptr_[512] = (int16_t)((int16_t)outvalue ? (((outvalue >> 14) & 2) - 1) : 0);

            uint32_t usum = 0;
            for (uint32_t i = 0; i != order; i++)
                usum += (uint32_t)((int32_t)cur_ptr_[i] * (int32_t)factors_[i]);
            predicted_value_ = (int32_t)usum >> shift_;
        }
    }

    void Run(int32_t* samples, uint32_t n) {
        if (order_ <= 8) RunSmall(samples, n);
        else RunBig(samples, n);
    }
};

// ---------------------------------------------------------------------------
// AudioBitcountDecoder: arithmetic-coded per-sample magnitude classes, with a
// run-length escape once seven consecutive zero classes have been seen.
// ---------------------------------------------------------------------------
struct AudioBitcountDecoder {
    uint16_t model_a_[64];
    uint16_t model_b_[576];
    uint16_t model_c_[32];

    AudioBitcountDecoder() { Reset(); }

    void Reset() {
        for (uint32_t i = 0; i != 64u; ++i) model_a_[i] = 0x8000u;
        for (uint32_t i = 0; i != 32u; ++i) model_c_[i] = 0x8000u;
        model_b_[0] = 0;
        model_b_[8] = 0xffffu;  // reference writes -1 into a uint16
        for (uint32_t i = 1; i != 8u; i++)
            model_b_[i] = (uint16_t)(16u * kModelLutLookup[512u * i - 1u]);
        // Cascading replication of the 9-entry seed across all 64 groups: each
        // write reads an entry this same loop may already have produced.
        for (uint32_t i = 0; i != 9u * 63u; i++)
            model_b_[i + 9] = model_b_[i];
    }

    // Returns the number of input bytes consumed, or 0 on failure.
    uint32_t Decode(const uint8_t* in, const uint8_t* in_end, uint8_t* out, uint32_t outsize) {
        if (outsize == 0u || in_end - in <= 1) {
            AUD_FAIL("bitcount: outsize=%u avail=%ld\n", outsize, (long)(in_end - in));
            return 0;
        }
        uint16_t insize16;
        std::memcpy(&insize16, in, 2);
        uint32_t insize = insize16;
        in += 2;
        if (insize > (uint32_t)(in_end - in)) {
            AUD_FAIL("bitcount: insize=%u > avail=%ld\n", insize, (long)(in_end - in));
            return 0;
        }

        ArithDec adec;
        adec.InitializeX(in, in + insize);
        adec.FillBuffer();

        const uint32_t outsize_bits = BSR(outsize);
        uint32_t num_zeros = 0;

        for (;;) {
            uint32_t accum = 1;
            do {
                uint16_t* model_a_ptr = &model_a_[accum];
                uint16_t* model_b_ptr = &model_b_[(*model_a_ptr >> 13) + 9u * accum];

                const bool flag = adec.Read(((uint32_t)model_b_ptr[0] + model_b_ptr[1] + 1u) >> 1);

                *model_a_ptr = (uint16_t)(*model_a_ptr +
                    ((((uint32_t)flag * 0x10000u) + 4u - *model_a_ptr) >> 3));
                model_b_ptr[0] = (uint16_t)(model_b_ptr[0] +
                    ((((uint32_t)flag * 0x1007eu) - model_b_ptr[0]) >> 7));
                model_b_ptr[1] = (uint16_t)(model_b_ptr[1] +
                    ((((uint32_t)flag * 0x1007eu) - model_b_ptr[1]) >> 7));

                accum = accum * 2u + flag;
            } while (accum <= 63u);

            accum = ~accum & 0x3fu;
            num_zeros = (accum == 0u) ? num_zeros + 1u : 0u;
            *out++ = (uint8_t)accum;
            outsize -= 1u;
            if (outsize == 0u) break;

            if (num_zeros > 6u) {
                uint32_t num_zero_bits = 0xffffffffu;
                while (++num_zero_bits != outsize_bits) {
                    uint16_t* model_c_ptr = &model_c_[num_zero_bits];
                    const bool flag = adec.Read(*model_c_ptr);
                    *model_c_ptr = (uint16_t)(*model_c_ptr +
                        ((((uint32_t)flag * 0x10000u) + 16u - *model_c_ptr) >> 5));
                    if (!flag) break;
                }
                const uint32_t num_zero_upper = num_zero_bits ? (1u << num_zero_bits) : 0u;
                uint32_t nn = num_zero_bits + (num_zero_bits == 0u);
                uint32_t num_zero_lower = 0;
                do {
                    num_zero_lower = num_zero_lower * 2u + adec.Read(0x8000u);
                } while (--nn);
                uint32_t num_zero = std::min(num_zero_upper + num_zero_lower, outsize);
                outsize -= num_zero;
                while (num_zero) { *out++ = 0; num_zero--; }
                if (outsize == 0u) break;
            }
        }
        return 2u + insize;
    }
};

// ---------------------------------------------------------------------------
// Sample reconstruction.
// ---------------------------------------------------------------------------
struct AudioFormat {
    bool stereo_filter;
    bool little_endian;
    uint8_t sample_size;
    uint8_t channels;
};

static void StoreU16LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void CopyOutSamples(uint8_t* out, uint32_t nframes, const int32_t* samples,
                           AudioFormat fmt) {
    uint32_t left_sum = 0, right_sum = 0;
    const int32_t* right_part = samples + nframes;

    if (fmt.channels == 1 && fmt.stereo_filter && fmt.sample_size == 2 && fmt.little_endian) {
        for (uint32_t i = 0; i != nframes; i++) {
            left_sum += (uint32_t)samples[i];
            right_sum += (uint32_t)right_part[i];
            StoreU16LE(out + i * 4, left_sum);
            StoreU16LE(out + i * 4 + 2, right_sum);
        }
        return;
    }

    if (fmt.channels == 2 && fmt.stereo_filter && fmt.sample_size == 2 && fmt.little_endian) {
        for (uint32_t i = 0; i != nframes; i++) {
            left_sum += (uint32_t)samples[i];
            right_sum += (uint32_t)right_part[i];
            const uint32_t tt = right_sum - (uint32_t)((int32_t)left_sum >> 1);
            StoreU16LE(out + i * 4, tt + left_sum);
            StoreU16LE(out + i * 4 + 2, tt);
        }
        return;
    }

    const uint32_t nchannels = fmt.channels ? 2u : 1u;

    for (uint32_t n = nframes; n; n--) {
        int32_t values[2] = {0, 0};

        left_sum += (uint32_t)(*samples++);
        values[0] = (int32_t)left_sum;

        if (fmt.channels) {
            right_sum += (uint32_t)(*right_part++);
            values[1] = (int32_t)right_sum;
            if (fmt.channels == 2) {
                values[1] = (int32_t)(right_sum - (uint32_t)((int32_t)left_sum >> 1));
                values[0] = (int32_t)(left_sum + (uint32_t)values[1]);
            }
        }

        for (uint32_t i = 0; i < nchannels; i++) {
            const int32_t value = values[i];
            if (fmt.sample_size == 1) {
                *out++ = (uint8_t)value;
            } else if (fmt.sample_size == 2) {
                if (fmt.little_endian) {
                    *out++ = (uint8_t)value;
                    *out++ = (uint8_t)(value >> 8);
                } else {
                    *out++ = (uint8_t)(value >> 8);
                    *out++ = (uint8_t)value;
                }
            } else {
                if (fmt.little_endian) {
                    *out++ = (uint8_t)value;
                    *out++ = (uint8_t)(value >> 8);
                    *out++ = (uint8_t)(value >> 16);
                } else {
                    *out++ = (uint8_t)(value >> 16);
                    *out++ = (uint8_t)(value >> 8);
                    *out++ = (uint8_t)value;
                }
            }
        }
    }
}

static const uint8_t kAudioInt32Idx[64] = {
    0, 0, 2, 2, 4, 4, 4, 4, 6, 6, 6, 6, 8, 8, 8, 8,
    10, 10, 10, 10, 12, 12, 12, 12, 14, 14, 14, 14, 16, 16, 16, 16,
    18, 18, 18, 18, 20, 20, 20, 20, 22, 22, 22, 22, 24, 26, 28, 30,
    32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62
};

static const uint8_t kAudioInt32Tab[64] = {
    0, 0, 2, 0, 4, 0, 8, 1, 12, 2, 16, 3, 20, 4, 24, 5,
    28, 6, 32, 7, 36, 8, 40, 10, 44, 12, 45, 13, 46, 14, 47, 15,
    48, 16, 49, 17, 50, 18, 51, 19, 52, 20, 53, 21, 54, 22, 55, 23,
    56, 24, 57, 25, 58, 26, 59, 27, 60, 28, 61, 29, 62, 30, 63, 31
};

static const uint32_t kAudioInt32Base[32] = {
    1u, 2u, 4u, 8u, 16u, 32u, 64u, 128u, 256u, 512u, 1024u, 2048u,
    4096u, 8192u, 16384u, 32768u, 65536u, 131072u, 262144u, 524288u,
    1048576u, 2097152u, 4194304u, 8388608u, 16777216u, 33554432u,
    67108864u, 134217728u, 268435456u, 536870912u, 1073741824u, 2147483648u
};

// bitcount classes are produced by AudioBitcountDecoder as `~accum & 0x3f`, so
// they are always 0..63 and every table index below stays in range.
static bool DecodeInt32Array(int32_t* samples, uint32_t size, const uint8_t* bitcount,
                             BitReader* bit_reader) {
    while (size) {
        int32_t value = *bitcount++;
        // AudioBitcountDecoder only ever emits `~accum & 0x3f`, so a class
        // above 63 means the bit-count buffer is stale or corrupt. Left
        // unchecked it walks kAudioInt32Idx/Tab/Base out of range and hands
        // GetBits() a shift count >= 32 (UB) -- the same "index is obviously
        // fine so the compiler may assume it" shape as the BWT P[257] bug.
        if ((uint32_t)value > 63u) {
            AUD_FAIL("int32: bitcount class %d out of range\n", value);
            return false;
        }
        if (value) {
            const uint32_t vm = (uint32_t)value - 1u;
            const uint32_t t = kAudioInt32Idx[vm];
            const uint32_t numbits = kAudioInt32Tab[t + 1];
            if (numbits) {
                const uint32_t base =
                    kAudioInt32Base[t >> 1] + ((vm - kAudioInt32Tab[t]) << numbits);
                value = (int32_t)((base | bit_reader->GetBits(numbits)) + 1u);
            } else {
                value = (int32_t)(vm + 1u);
            }
            const uint32_t b = bit_reader->GetBits(1);
            value = (int32_t)((0u - (b & 1u)) ^ (uint32_t)value) + (int32_t)(b & 1u);
        }
        *samples++ = value;
        size--;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------

struct NzAudioPred::Impl {
    AudioBitcountDecoder bitcount_decoder_[2];
    AudioStereoDecoder stereo_dec_;
    // The FUN_08096e20 alternative to stereo_dec_, selected by context bit 4.
    nzr::lzpf::LmsObject lms_[2];
    uint8_t ctx_flags_{0x03};
    LinearPredictor linpred_[6];
    // The reference puts these on the stack (uint8[65536] + int32[65536],
    // 320 KB per call). They are members here so a deep call chain cannot blow
    // the stack; the contents are fully rewritten on every chunk.
    std::vector<uint8_t> bitcount_;
    std::vector<int32_t> samples_;

    Impl() : stereo_dec_(4, 8), bitcount_(0x10000), samples_(0x10000) {
        linpred_[0].Initialize(0x60);
        linpred_[1].Initialize(0x60);
        linpred_[2].Initialize(8);
        linpred_[3].Initialize(8);
        linpred_[4].Initialize(8);
        linpred_[5].Initialize(8);
    }

    void Reset() {
        bitcount_decoder_[0].Reset();
        bitcount_decoder_[1].Reset();
        stereo_dec_.Reset();
        lms_[0].Init();
        lms_[1].Init();
        for (uint32_t i = 0; i != 6u; i++) linpred_[i].Reset();
    }

    // Returns input bytes consumed, or 0 on failure.
    uint32_t DecodeChunk(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t outsize) {
        const uint8_t* in_start = in;
        uint8_t* out_end = out + outsize;
        const uint8_t* in_end = in + in_size;
        if (in >= in_end) { AUD_FAIL("chunk: empty input\n"); return 0; }

        uint32_t type = *in++;

        AudioFormat fmt;
        fmt.stereo_filter = (type & 1u) != 0u;
        type /= 2u;
        fmt.channels = (uint8_t)(type % 3u);
        type /= 3u;
        const uint32_t f = type % 5u;
        type /= 5u;
        fmt.little_endian = false;
        fmt.sample_size = 1;
        if (f) {
            fmt.little_endian = ((f - 1u) & 1u) != 0u;
            fmt.sample_size = (uint8_t)(2u + ((f - 1u) >> 1));
        }
        uint32_t header_bytes = type;
        if (header_bytes == 6u) {
            if (in >= in_end) { AUD_FAIL("chunk: truncated ext header_bytes\n"); return 0; }
            header_bytes = 6u + *in++;
        }

        if (header_bytes > (uint32_t)(out_end - out)) {
            AUD_FAIL("chunk: header_bytes=%u > out room %u\n",
                     header_bytes, (uint32_t)(out_end - out));
            return 0;
        }
        for (; header_bytes; header_bytes--) {
            if (in >= in_end) { AUD_FAIL("chunk: truncated header bytes\n"); return 0; }
            *out++ = *in++;
        }

        uint32_t sample_count = (uint32_t)(out_end - out) / fmt.sample_size;
        if (fmt.channels) sample_count &= ~1u;

        const uint32_t databytes = sample_count * fmt.sample_size;
        const uint32_t pad_bytes = (uint32_t)(out_end - out) - databytes;
        for (uint32_t i = 0; i < pad_bytes; i++) {
            if (in >= in_end) { AUD_FAIL("chunk: truncated pad bytes\n"); return 0; }
            out[databytes + i] = *in++;
        }

        const uint32_t nsamples = databytes / fmt.sample_size;
        uint32_t nframes = nsamples;
        if (fmt.channels) {
            if (nsamples & 1u) { AUD_FAIL("chunk: odd nsamples=%u\n", nsamples); return 0; }
            nframes = nsamples >> 1;
        }
        if (nsamples > samples_.size()) {
            AUD_FAIL("chunk: nsamples=%u exceeds buffer\n", nsamples);
            return 0;
        }

        uint8_t* bitcount = bitcount_.data();
        int32_t* samples = samples_.data();

        if (fmt.channels) {
            const uint32_t u0 = bitcount_decoder_[0].Decode(in, in_end, bitcount, nframes);
            if (u0 == 0u) return 0;
            in += u0;
            const uint32_t u1 = bitcount_decoder_[1].Decode(in, in_end, bitcount + nframes, nframes);
            if (u1 == 0u) return 0;
            in += u1;
        } else {
            const uint32_t u0 = bitcount_decoder_[0].Decode(in, in_end, bitcount, nframes);
            if (u0 == 0u) return 0;
            in += u0;
        }

        if (AudioTrace()) std::fprintf(stderr, "[AUD] bitcount consumed: cursor now at +%u\n",
                                       (uint32_t)(in - in_start));
        // GDB ground truth (2026-09-01) says this whole stage list is WRONG for
        // -co/-cc: see the comment block at the top of NzAudioPred for the real
        // per-codec stage sequence and which primitives it is actually built from.
        BitReader bit_reader;
        bit_reader.Initialize(in, (size_t)(in_end - in));

        // FUN_080a5330 lines 195-210. The leading bit gates the inter-channel
        // stage; when it is set, WHICH stage runs (and therefore how many side
        // bits are consumed) depends on context bit 4 -- 4+4 bits biased +0x10
        // for FUN_08096160, or 3+3 bits biased +7 for FUN_08096e20. When it is
        // clear, BOTH objects are reset (FUN_080be670 + FUN_080beb60).
        bool use_stereo_dec = false;
        bool use_lms = false;
        const bool lms_variant = (ctx_flags_ & 0x10u) != 0u;
        if (fmt.channels) {
            if (bit_reader.GetBits(1)) {
                if (!lms_variant) {
                    const uint32_t c0 = bit_reader.GetBits(4);
                    const uint32_t c1 = bit_reader.GetBits(4);
                    stereo_dec_.SetBits(16u + c0, 16u + c1);
                    use_stereo_dec = true;
                } else {
                    const uint32_t s0 = bit_reader.GetBits(3);
                    const uint32_t s1 = bit_reader.GetBits(3);
                    lms_[0].shift = (uint8_t)(7u + s0);
                    lms_[1].shift = (uint8_t)(7u + s1);
                    use_lms = true;
                }
            } else {
                stereo_dec_.Reset();
                lms_[0].Init();
                lms_[1].Init();
            }
        }

        uint8_t use_lp[3][2] = {{0, 0}, {0, 0}, {0, 0}};
        for (int i = 0; i != 3; i++) {
            for (int j = 0; j < (fmt.channels ? 2 : 1); j++) {
                const uint8_t flag = (uint8_t)bit_reader.GetBits(1);
                use_lp[i][j] = flag;
                if (flag) linpred_[i * 2 + j].SetBits((int)bit_reader.GetBits(3) + 8);
                else linpred_[i * 2 + j].Reset();
            }
        }

        if (AudioTrace()) {
            std::fprintf(stderr,
                "[AUD] chunk: sf=%d ch=%u le=%d ss=%u hdr_out=%u nsamples=%u nframes=%u "
                "stereo_dec=%d lp=%u%u%u%u%u%u\n",
                (int)fmt.stereo_filter, fmt.channels, (int)fmt.little_endian, fmt.sample_size,
                (uint32_t)(outsize - (uint32_t)(out_end - out)), nsamples, nframes,
                (int)use_stereo_dec,
                use_lp[0][0], use_lp[0][1], use_lp[1][0], use_lp[1][1], use_lp[2][0], use_lp[2][1]);
        }
        if (const char* dp = getenv("NZOPT_DUMP_AUDCOUNTS")) {
            // Dump the per-sample bit-count array exactly where the real decoder
            // passes it to FUN_0809bbf0 (its 3rd argument), so a GDB capture of
            // that call splits "our bit-count decode is wrong" from "our residual
            // decode is wrong".
            static int seq = 0;
            char nm[512];
            std::snprintf(nm, sizeof(nm), "%s.%d", dp, seq++);
            FILE* f = std::fopen(nm, "wb");
            if (f) { std::fwrite(bitcount, 1, nsamples, f); std::fclose(f); }
            std::fprintf(stderr, "[AUD] dumped %u bit-counts to %s\n", nsamples, nm);
        }
        if (!DecodeInt32Array(samples, nsamples, bitcount, &bit_reader)) return 0;

        if (const char* dp = getenv("NZOPT_DUMP_AUDPOST")) {
            // Dump the residual array immediately after the residual decode, i.e.
            // exactly where FUN_0809bbf0 returns in the real decoder -- the
            // remaining split point between "residual decode wrong" and
            // "predictor / inter-channel stage wrong".
            static int seq = 0;
            char nm[512];
            std::snprintf(nm, sizeof(nm), "%s.%d", dp, seq++);
            FILE* f = std::fopen(nm, "wb");
            if (f) { std::fwrite(samples, 4, nsamples, f); std::fclose(f); }
            std::fprintf(stderr, "[AUD] dumped %u post-residual int32 to %s\n", nsamples, nm);
        }

        in += bit_reader.BytesRead();

        const char* pdump = getenv("NZOPT_DUMP_AUDPLANE");
        int pseq = 0;
        for (int i = 2; i >= 0; i--) {
            for (int j = 0; j < (fmt.channels ? 2 : 1); j++) {
                if (use_lp[i][j]) {
                    linpred_[i * 2 + j].Run(samples + j * nframes, nframes);
                    if (pdump) {
                        char nm[512];
                        std::snprintf(nm, sizeof(nm), "%s_%d.bin", pdump, pseq);
                        FILE* f = std::fopen(nm, "wb");
                        if (f) { std::fwrite(samples, 4, nsamples, f); std::fclose(f); }
                        std::fprintf(stderr, "[AUD] plane call #%d = linpred[%d] ch%d -> %s\n",
                                     pseq, i * 2 + j, j, nm);
                        ++pseq;
                    }
                }
            }
        }

        if (use_stereo_dec) stereo_dec_.Decode(samples, samples + nframes, nframes);
        else if (use_lms)
            nzr::lzpf::ApplyLmsInterChannel(samples, samples + nframes, nframes,
                                            &lms_[0], &lms_[1]);

        if (const char* dp = getenv("NZOPT_DUMP_AUDRESID")) {
            // Dump the residual array exactly where the real decoder hands it to
            // FUN_080a50c0 (its 3rd argument), so a GDB capture of that call can be
            // diffed against this port stage by stage.
            static int seq = 0;
            char nm[512];
            std::snprintf(nm, sizeof(nm), "%s.%d", dp, seq++);
            FILE* f = std::fopen(nm, "wb");
            if (f) { std::fwrite(samples, 4, nsamples, f); std::fclose(f); }
            std::fprintf(stderr, "[AUD] dumped %u residual int32 to %s\n", nsamples, nm);
        }
        CopyOutSamples(out, nframes, samples, fmt);

        // NOTE: `in` can legitimately end up a few bytes past in_end here.
        // BytesRead() counts whole 4-byte words, so a trailing partial word
        // reports up to 3 bytes more than physically existed. The reference has
        // the same behaviour and it is harmless: it only happens on the final
        // chunk, after which Decode's loop has no output left and stops. Decode
        // re-checks the cursor before starting any further chunk.
        return (uint32_t)(in - in_start);
    }

    bool Decode(const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t outsize) {
        const uint8_t* in_end = in + in_size;
        while (outsize != 0u) {
            if (in > in_end) { AUD_FAIL("decode: cursor past end with %u left\n", outsize); return false; }
            const uint32_t n = std::min<uint32_t>(outsize, 0x10000u);
            const uint32_t in_used = DecodeChunk(in, (uint32_t)(in_end - in), out, n);
            if (in_used == 0u) return false;
            in += in_used;
            out += n;
            outsize -= n;
        }
        return true;
    }
};

void NzAudioPred::SetContextFlags(std::uint8_t flags) { impl_->ctx_flags_ = flags; }

NzAudioPred::NzAudioPred() : impl_(new Impl()) {}
NzAudioPred::~NzAudioPred() = default;
void NzAudioPred::Reset() { impl_->Reset(); }

bool NzAudioPred::Decode(const std::uint8_t* in, std::uint32_t in_size,
                         std::uint8_t* out, std::uint32_t out_size) {
    return impl_->Decode(in, in_size, out, out_size);
}

}  // namespace audio
}  // namespace nzr
