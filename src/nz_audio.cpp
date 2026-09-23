// nz_audio.cpp — NanoZip decr_param == 2 ("audio") block decoding, ported from
// the community reference decoder (nzdec_v0 NZ_Audio.cpp). Faithful
// reimplementation.
#include "nz_env.h"
#if defined(__SSE2__)
#include <emmintrin.h>
#endif
#include "nz_trace.h"
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
static bool BcTrace() {
    static const bool t = (NZ_ENV("NZ_BCTRACE") != nullptr);
    return t;
}

static bool AudioTrace() {
    static const bool on = (NZ_ENV("NZOPT_TRACE_AUDIO") != nullptr);
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

        Part() = default;
        // hist_ptr_ walks this object's own history_, so a copy has to rebase it.
        Part(const Part& o)
            : order_(o.order_), hist_order_(o.hist_order_),
              hist_ptr_(history_ + (o.hist_ptr_ - o.history_)) {
            std::memcpy(factors_, o.factors_, sizeof(factors_));
            std::memcpy(history_, o.history_, sizeof(history_));
        }
        Part& operator=(const Part& o) {
            if (this != &o) {
                order_ = o.order_;
                hist_order_ = o.hist_order_;
                std::memcpy(factors_, o.factors_, sizeof(factors_));
                std::memcpy(history_, o.history_, sizeof(history_));
                hist_ptr_ = history_ + (o.hist_ptr_ - o.history_);
            }
            return *this;
        }

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

        // One inter-channel step, both ways: `encoding` makes `in_value` the
        // sample and returns the residual, exactly inverting the decode.
        int32_t Step(int32_t in_value, int32_t other_value, bool encoding) {
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
            const int32_t pred = WrapSub(shifted, sum_sign);
            const int32_t value = encoding ? WrapSub(in_value, pred) : in_value;
            const int32_t new_value = encoding ? in_value : WrapAdd(value, pred);

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
            return encoding ? value : new_value;
        }

        int32_t Decode(int32_t value, int32_t other_value) { return Step(value, other_value, false); }
        int32_t Encode(int32_t sample, int32_t other_value) { return Step(sample, other_value, true); }
    };

    Chan left_, right_;

    AudioStereoDecoder(int order, int param) : left_(order), right_(order) {
        Configure(param);
    }

    // `param` is a per-CODEC constant, not a fixed 8. GDB-read from the real
    // object's order fields (+0x1404 / +0x2814 relative to obj+0xa870):
    //     -co : 4, 4   => param 4      (the `param > 4` refinement is skipped)
    //     -cO : 8, 4   => param 8
    //     -cc : 16, 12 => param 16
    // The hardcoded 8 was -cO's value, which is why only -cO agreed with the
    // binary here. SetOrder recomputes hist_order_, so re-running this is enough
    // to reconfigure -- the constructor's `order` argument does not survive it.
    void Configure(int param) {
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

    uint32_t PartOrderOne() const { return left_.one_.order_; }
    uint32_t PartOrderTwo() const { return left_.two_.order_; }

    void Decode(int32_t* lp, int32_t* rp, uint32_t frames) {
        int32_t new_right_value = 0, new_left_value = 0;
        for (uint32_t i = 0; i != frames; i++) {
            lp[i] = new_left_value = left_.Decode(lp[i], new_right_value);
            rp[i] = new_right_value = right_.Decode(rp[i], new_left_value);
        }
    }

    // The same walk with the samples going in and the residuals coming out.
    void Encode(int32_t* lp, int32_t* rp, uint32_t frames) {
        int32_t new_right_value = 0, new_left_value = 0;
        for (uint32_t i = 0; i != frames; i++) {
            const int32_t l = lp[i], r = rp[i];
            lp[i] = left_.Encode(l, new_right_value);
            new_left_value = l;
            rp[i] = right_.Encode(r, new_left_value);
            new_right_value = r;
        }
    }
};

// ---------------------------------------------------------------------------
// Second bit-count decoder class (vtable 0x0813c860, slot 2 = FUN_0809bdc0).
//
// `-co` selects this instead of the 64-symbol bit-tree coder AudioBitcountDecoder
// implements (vtable 0x0813c848, FUN_0809c070); `-cO` and `-cc` select that one.
// Transcribed from the raw disassembly at 0x0809bdc0 (207 instructions, no calls) --
// there is no decompile for it, and the architecture notes' description of it as a
// "Fenwick-tree cumulative frequency" coder does not survive reading the code: the
// cumulative search is a plain LINEAR scan in groups of four with a back-off, and
// the adaptive model is an EXACT SLIDING WINDOW, not a decayed frequency table.
//
// Layout of the state object, all confirmed by the addressing in the asm:
//   +0x0004                     "dirty" flag, set to 1 on entry
//   +0x0010 + sel*0x900 + 4*i   freq[sel][i], i in 0..63   (u32)
//   +0x0110 + sel*0x900         ring[sel][0..0x7f7]        (u8, 2040 recent symbols)
//   +0x0908 + sel*0x900         ring write cursor          (u32)
//   +0x12010                    the persistent context     (u32)
// 32 contexts x 0x900 = 0x12000, which is exactly why the context field lands at
// +0x12010 -- the strongest confirmation that the table count is 32.
//
// Model invariant: freq[sel][s] == 8 * (number of times s appears in ring[sel]).
// Every decode does freq[new] += 8 and freq[evicted] -= 8, so the per-context total
// is a constant 2040*8 = 16320 (0x3fc0), which is what keeps the 14-bit cumulative
// target in range. A fresh object therefore starts with an all-zero ring and
// freq[0] = 0x3fc0.
class AudioBitcountDecoderB {
 public:
    AudioBitcountDecoderB() { Reset(); }

    // Initial state, GDB-read from the real object and then reduced to its rule
    // (the object is built by the class's slot-0 routine, FUN_080bd760, for which
    // there is no decompile either -- so this was derived from the state it leaves).
    // Per context `sel`, with `center = 2 * sel`:
    //   * the ring's first entries are a symmetric ramp: for d = 4 down to 0, write
    //     2^(4-d) copies of (center-d) and (center+d), interleaved left-then-right
    //     and clipped to [0,63]; the write cursor ends where that ramp ends;
    //   * every remaining slot k holds `k % 64`;
    //   * freq[s] = 1 + 8 * (occurrences of s in the WHOLE ring).
    // That last identity is what makes the totals come out at exactly
    // 64 + 8*2040 = 16384 = 0x4000, matching the coder's 14-bit precision.
    // Verified against the binary's own tables for sel = 0, 1 and 31: cursor lands
    // on 31, 43 and 39 respectively, and every one of the 64 frequencies matches.
    void Reset() {
        std::memset(freq_, 0, sizeof(freq_));
        for (uint32_t sel = 0; sel < kCtx; sel++) {
            const int center = (int)(2u * sel);
            uint32_t w = 0;
            for (int d = 4; d >= 0; --d) {
                const uint32_t reps = 1u << (4 - d);
                for (uint32_t r = 0; r < reps; ++r) {
                    const int a = center - d, b = center + d;
                    if (a >= 0 && a < (int)kSym && w < kWindow) ring_[sel][w++] = (uint8_t)a;
                    if (d != 0 && b >= 0 && b < (int)kSym && w < kWindow)
                        ring_[sel][w++] = (uint8_t)b;
                }
            }
            cursor_[sel] = w;
            for (uint32_t k = w; k < kWindow; ++k) ring_[sel][k] = (uint8_t)(k % kSym);
            for (uint32_t k = 0; k < kWindow; ++k) freq_[sel][ring_[sel][k]] += 8u;
            for (uint32_t i = 0; i < kSym; ++i) freq_[sel][i] += 1u;
        }
        ctx_ = 0;
    }

    // Returns input bytes consumed (the u16 length header plus that many bytes), or
    // 0 on malformed input. Mirrors FUN_0809bdc0's own return of `len + 2`.
    uint32_t Decode(const uint8_t* in, const uint8_t* in_end, uint8_t* dst, uint32_t count) {
        const size_t avail = (size_t)(in_end - in);
        if (avail <= 1u || count == 0u) return 0u;
        const uint32_t len = (uint32_t)in[0] | ((uint32_t)in[1] << 8);
        if (len > avail - 2u) return 0u;
        const uint8_t* cur = in + 2;
        const uint8_t* end = cur + len;

        auto next_byte = [&]() -> uint32_t {
            // The original reads *cur unconditionally and masks the result when
            // cur == end (`movzbl (%ebx),%ebx; sbb; and`). Bounded here; the masked
            // value is zero either way.
            if (cur < end) return *cur++;
            return 0u;
        };

        uint32_t code = 0;
        for (int k = 0; k < 4; k++) code = (code << 8) | next_byte();

        uint32_t lo = 0;
        uint32_t range = 0xffffffffu;
        uint32_t scale = range >> 14;
        uint32_t target = (uint32_t)(((uint64_t)(code - lo)) / scale) & 0x3fffu;

        for (uint32_t i = 0;;) {
            const uint32_t sel = ((ctx_ + 0x80u) >> 9) & (kCtx - 1u);
            uint32_t* f = freq_[sel];

            // Cumulative scan: four at a time until the running sum passes the
            // target, then back off one entry at a time (up to four).
            uint32_t acc = 0, idx = 0;
            do {
                acc += f[idx] + f[idx + 1] + f[idx + 2] + f[idx + 3];
                idx += 4;
            } while (acc <= target && idx + 4u <= kSym);
            uint32_t sym_freq = 0;
            for (int back = 0; back < 4; back++) {
                sym_freq = f[idx - 1];
                acc -= sym_freq;
                idx -= 1;
                if (acc <= target) break;
            }
            const uint32_t sym = idx;
            const uint32_t cum_low = acc;

            f[sym] += 8u;
            const uint32_t pos = cursor_[sel];
            const uint8_t evicted = ring_[sel][pos];
            f[evicted] -= 8u;
            ring_[sel][pos] = (uint8_t)sym;
            cursor_[sel] = (pos < kWindow - 1u) ? pos + 1u : 0u;

            dst[i] = (uint8_t)sym;

            // ctx = (15*ctx + 256*sym + 8) >> 4  -- exponential decay toward 16*sym.
            ctx_ = ((ctx_ * 16u + sym * 256u + 8u) - ctx_) >> 4;

            lo += cum_low * scale;
            range = scale * sym_freq;

            // Carryless renormalize: shift a byte in while the top byte of lo and
            // lo+range agree, with the classic underflow squeeze when range gets
            // smaller than the 14-bit precision.
            for (;;) {
                if (((lo + range) ^ lo) > 0xffffffu) {
                    if (range > 0x3fffu) break;
                    range = (0u - lo) & 0x3fffu;
                }
                if (range == 0u) return 0u;
                code = (code << 8) | next_byte();
                lo <<= 8;
                range <<= 8;
            }

            // Safety net the original does not need: with a mis-modelled table a
            // zero symbol frequency makes range 0, and the renormalize loop above
            // would then spin forever. Decline instead.
            if (range == 0u) return 0u;
            scale = range >> 14;
            if (++i == count) break;
            target = (uint32_t)(((uint64_t)(code - lo)) / scale) & 0x3fffu;
        }
        return len + 2u;
    }

 private:
    static constexpr uint32_t kCtx = 32u;
    static constexpr uint32_t kSym = 64u;
    static constexpr uint32_t kWindow = 0x7f8u;   // 2040
    uint32_t freq_[kCtx][kSym];
    uint8_t  ring_[kCtx][kWindow];
    uint32_t cursor_[kCtx];
    uint32_t ctx_;
};

// ---------------------------------------------------------------------------
// The audio path (decr_param == 2) is fully ported and byte-exact for -co, -cO
// and -cc. Getting there took three separate findings, kept here in one
// paragraph because each is a rule the code below depends on rather than a
// historical note: the -co bit-count decoder is a whole second CLASS
// (FUN_0809bdc0, SetBitcountVariantB) and not a parameter of the -cO one;
// FUN_080958d0 is an extra predictor stage that only -co and -cc run;
// FUN_08096160 is the inter-channel stage only -cO runs. The measurement
// recipe that produced them -- GDB on the real binary, one stage at a time,
// with the object's own state as the oracle -- is written up in
// ~/.cache/nzre_tools/audio_gdb/ together with the captured ground truth and
// the hypotheses it refuted.
// ---------------------------------------------------------------------------
static inline int32_t Clamp16(int32_t v) {
    return ((int16_t)v != v) ? ((v >> 31) ^ 0x7fff) : v;
}

static inline void CopyHist(int16_t* dst, const int16_t* src, uint32_t n) {
    for (; n; n--) *dst++ = *src++;
}

// The real predictor (FUN_08095d90) runs these three loops in MMX, 16 taps per
// iteration: paddsw/psubsw for the saturating factor update, pmaddwd + paddd for
// the dot product. SSE2 does the same eight lanes at a time; the results are
// bit-identical (saturation is saturation, and the int32 partial sums wrap the
// same way in any order). The scalar tails handle order % 8 and non-SSE2 builds.
static inline void FactorsUpdateSat(int16_t* factors, const int16_t* logs, uint32_t order, bool add) {
    uint32_t i = 0;
#if defined(__SSE2__)
    for (; i + 8u <= order; i += 8u) {
        const __m128i f = _mm_loadu_si128(reinterpret_cast<const __m128i*>(factors + i));
        const __m128i l = _mm_loadu_si128(reinterpret_cast<const __m128i*>(logs + i));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(factors + i),
                         add ? _mm_adds_epi16(f, l) : _mm_subs_epi16(f, l));
    }
#endif
    if (add) for (; i != order; i++) factors[i] = (int16_t)Clamp16((int32_t)((uint32_t)factors[i] + (uint32_t)logs[i]));
    else     for (; i != order; i++) factors[i] = (int16_t)Clamp16((int32_t)((uint32_t)factors[i] - (uint32_t)logs[i]));
}
static inline void FactorsUpdateWrap(int16_t* factors, const int16_t* logs, uint32_t order, bool add) {
    uint32_t i = 0;
#if defined(__SSE2__)
    for (; i + 8u <= order; i += 8u) {
        const __m128i f = _mm_loadu_si128(reinterpret_cast<const __m128i*>(factors + i));
        const __m128i l = _mm_loadu_si128(reinterpret_cast<const __m128i*>(logs + i));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(factors + i),
                         add ? _mm_add_epi16(f, l) : _mm_sub_epi16(f, l));
    }
#endif
    if (add) for (; i != order; i++) factors[i] = (int16_t)((uint32_t)factors[i] + (uint32_t)logs[i]);
    else     for (; i != order; i++) factors[i] = (int16_t)((uint32_t)factors[i] - (uint32_t)logs[i]);
}
static inline uint32_t DotI16(const int16_t* a, const int16_t* b, uint32_t order) {
    uint32_t usum = 0, i = 0;
#if defined(__SSE2__)
    if (order >= 8u) {
        __m128i acc = _mm_setzero_si128();
        for (; i + 8u <= order; i += 8u) {
            const __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i));
            const __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i));
            acc = _mm_add_epi32(acc, _mm_madd_epi16(x, y));
        }
        alignas(16) uint32_t lanes[4];
        _mm_store_si128(reinterpret_cast<__m128i*>(lanes), acc);
        usum = lanes[0] + lanes[1] + lanes[2] + lanes[3];
    }
#endif
    for (; i != order; i++) usum += (uint32_t)((int32_t)a[i] * (int32_t)b[i]);
    return usum;
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

    // `cur_ptr_` walks this object's own hist_, so a default copy would leave the
    // copy reading and writing the ORIGINAL's history -- which is exactly what a
    // trial must not do. Rebase it.
    LinearPredictor(const LinearPredictor& o)
        : predicted_value_(o.predicted_value_), order_(o.order_), shift_(o.shift_),
          cur_ptr_(hist_ + (o.cur_ptr_ - o.hist_)) {
        std::memcpy(factors_, o.factors_, sizeof(factors_));
        std::memcpy(hist_, o.hist_, sizeof(hist_));
    }
    LinearPredictor& operator=(const LinearPredictor& o) {
        if (this != &o) {
            predicted_value_ = o.predicted_value_;
            order_ = o.order_;
            shift_ = o.shift_;
            std::memcpy(factors_, o.factors_, sizeof(factors_));
            std::memcpy(hist_, o.hist_, sizeof(hist_));
            cur_ptr_ = hist_ + (o.cur_ptr_ - o.hist_);
        }
        return *this;
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
        if (delta != 0) FactorsUpdateSat(factors_, cur_ptr + 512, order, delta > 0);
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

        const int32_t sum = (int32_t)DotI16(cur_ptr_, factors_, order);
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
            FactorsUpdateWrap(factors_, cur_ptr + 512, order, delta <= 0);
            cur_ptr_ = cur_ptr - 1;
            if (cur_ptr_ < hist_) {
                cur_ptr_ = &hist_[2560 - order];
                CopyHist(cur_ptr_ + 1, hist_, order - 1);
                CopyHist(cur_ptr_ + 1 + 512, hist_ + 512, order - 1);
            }

            cur_ptr_[0] = (int16_t)outvalue;
            cur_ptr_[512] = (int16_t)((int16_t)outvalue ? (((outvalue >> 14) & 2) - 1) : 0);

            predicted_value_ = (int32_t)DotI16(cur_ptr_, factors_, order) >> shift_;
        }
    }

    // Encoder side: the same two loops with the subtraction the other way round.
    // The state updates see exactly the pair (sample, delta) the decoder sees.
    void RunForwardBig(int32_t* samples, uint32_t n) {
        for (; n; n--) {
            const int32_t sample = *samples;
            const int32_t delta = (int32_t)((uint32_t)sample - (uint32_t)predicted_value_);
            *samples++ = delta;
            UpdateBig(sample, delta);
        }
    }

    void RunForwardSmall(int32_t* samples, uint32_t n) {
        const uint32_t order = order_;
        for (; n; n--) {
            const int32_t outvalue = *samples;
            const int32_t delta = (int32_t)((uint32_t)outvalue - (uint32_t)predicted_value_);
            *samples++ = delta;

            int16_t* cur_ptr = cur_ptr_;
            FactorsUpdateWrap(factors_, cur_ptr + 512, order, delta <= 0);
            cur_ptr_ = cur_ptr - 1;
            if (cur_ptr_ < hist_) {
                cur_ptr_ = &hist_[2560 - order];
                CopyHist(cur_ptr_ + 1, hist_, order - 1);
                CopyHist(cur_ptr_ + 1 + 512, hist_ + 512, order - 1);
            }

            cur_ptr_[0] = (int16_t)outvalue;
            cur_ptr_[512] = (int16_t)((int16_t)outvalue ? (((outvalue >> 14) & 2) - 1) : 0);

            predicted_value_ = (int32_t)DotI16(cur_ptr_, factors_, order) >> shift_;
        }
    }

    void RunForward(int32_t* samples, uint32_t n) {
        if (order_ <= 8) RunForwardSmall(samples, n);
        else RunForwardBig(samples, n);
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
            if (BcTrace()) std::fprintf(stderr, "S %u\n", accum);
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
                if (BcTrace()) std::fprintf(stderr, "R %u k=%u low=%u\n", num_zero, num_zero_bits, num_zero_lower);
                outsize -= num_zero;
                while (num_zero) { *out++ = 0; num_zero--; }
                if (outsize == 0u) break;
            }
        }
        return 2u + insize;
    }
};

// ---------------------------------------------------------------------------
// Encoder side: the bit-count coder run backwards (variant A, FUN_0809c070's
// mirror). Same models, same update order; the arithmetic coder is the usual
// carry-less range coder this codebase already writes for the post-filters.
// ---------------------------------------------------------------------------
struct ArithEncA {
    uint32_t lo_ = 0, hi_ = 0xffffffffu;
    std::vector<uint8_t>* out_ = nullptr;

    void Put(uint8_t b) { out_->push_back(b); }
    // `model` is the 16-bit probability the decoder passes to ArithDec::Read,
    // which shifts it right by 4 before use.
    void EncodeModel(bool bit, uint32_t model) { Encode(bit, model >> 4); }
    void Encode(bool bit, uint32_t p12) {
        const uint32_t compare = lo_ + ((hi_ - lo_) >> 12) * p12;
        if (bit) hi_ = compare; else lo_ = compare + 1u;
        while ((lo_ ^ hi_) < 0x1000000u) {
            Put((uint8_t)(hi_ >> 24));
            lo_ <<= 8;
            hi_ = (hi_ << 8) | 0xffu;
        }
    }
    void Flush() { Put((uint8_t)(hi_ >> 24)); }
};

// Variant B's encoder (the `-co` coder, FUN_0809bdc0's mirror): a 64-symbol
// carry-less range coder over the same sliding-window frequency tables.
class AudioBitcountEncoderB {
 public:
    AudioBitcountEncoderB() { Reset(); }

    // Identical to AudioBitcountDecoderB::Reset.
    void Reset() {
        std::memset(freq_, 0, sizeof(freq_));
        for (uint32_t sel = 0; sel < kCtx; sel++) {
            const int center = (int)(2u * sel);
            uint32_t w = 0;
            for (int d = 4; d >= 0; --d) {
                const uint32_t reps = 1u << (4 - d);
                for (uint32_t r = 0; r < reps; ++r) {
                    const int a = center - d, b = center + d;
                    if (a >= 0 && a < (int)kSym && w < kWindow) ring_[sel][w++] = (uint8_t)a;
                    if (d != 0 && b >= 0 && b < (int)kSym && w < kWindow)
                        ring_[sel][w++] = (uint8_t)b;
                }
            }
            cursor_[sel] = w;
            for (uint32_t k = w; k < kWindow; ++k) ring_[sel][k] = (uint8_t)(k % kSym);
            for (uint32_t k = 0; k < kWindow; ++k) freq_[sel][ring_[sel][k]] += 8u;
            for (uint32_t i = 0; i < kSym; ++i) freq_[sel][i] += 1u;
        }
        ctx_ = 0;
    }

    bool Encode(const uint8_t* counts, uint32_t n, std::vector<uint8_t>* out) {
        if (n == 0u) return false;
        std::vector<uint8_t> body;
        uint32_t lo = 0;
        uint32_t range = 0xffffffffu;
        uint32_t scale = range >> 14;

        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t sym = counts[i];
            if (sym >= kSym) return false;
            const uint32_t sel = ((ctx_ + 0x80u) >> 9) & (kCtx - 1u);
            uint32_t* f = freq_[sel];

            uint32_t cum_low = 0;
            for (uint32_t j = 0; j < sym; ++j) cum_low += f[j];
            const uint32_t sym_freq = f[sym];

            f[sym] += 8u;
            const uint32_t pos = cursor_[sel];
            const uint8_t evicted = ring_[sel][pos];
            f[evicted] -= 8u;
            ring_[sel][pos] = (uint8_t)sym;
            cursor_[sel] = (pos < kWindow - 1u) ? pos + 1u : 0u;

            ctx_ = ((ctx_ * 16u + sym * 256u + 8u) - ctx_) >> 4;

            lo += cum_low * scale;
            range = scale * sym_freq;

            for (;;) {
                if (((lo + range) ^ lo) > 0xffffffu) {
                    if (range > 0x3fffu) break;
                    range = (0u - lo) & 0x3fffu;
                }
                if (range == 0u) return false;
                body.push_back((uint8_t)(lo >> 24));
                lo <<= 8;
                range <<= 8;
            }
            if (range == 0u) return false;
            scale = range >> 14;
        }
        // FUN_0806bf40: up to FOUR bytes of `lo`, stopping as soon as what is
        // left is zero -- so a stream whose `lo` ends in zero bytes writes fewer.
        // A flat three matched two fixtures by luck and came out one byte short
        // on the first five-chunk one.
        for (int k = 0; k < 4 && lo != 0u; ++k) { body.push_back((uint8_t)(lo >> 24)); lo <<= 8; }

        if (body.size() > 0xffffu) return false;
        out->push_back((uint8_t)(body.size() & 0xffu));
        out->push_back((uint8_t)(body.size() >> 8));
        out->insert(out->end(), body.begin(), body.end());
        return true;
    }

 private:
    static constexpr uint32_t kCtx = 32u;
    static constexpr uint32_t kSym = 64u;
    static constexpr uint32_t kWindow = 0x7f8u;
    uint32_t freq_[kCtx][kSym];
    uint8_t  ring_[kCtx][kWindow];
    uint32_t cursor_[kCtx];
    uint32_t ctx_;
};

struct AudioBitcountEncoder {
    uint16_t model_a_[64];
    uint16_t model_b_[576];
    uint16_t model_c_[32];

    AudioBitcountEncoder() { Reset(); }

    // Identical to AudioBitcountDecoder::Reset.
    void Reset() {
        for (uint32_t i = 0; i != 64u; ++i) model_a_[i] = 0x8000u;
        for (uint32_t i = 0; i != 32u; ++i) model_c_[i] = 0x8000u;
        model_b_[0] = 0;
        model_b_[8] = 0xffffu;
        for (uint32_t i = 1; i != 8u; i++)
            model_b_[i] = (uint16_t)(16u * kModelLutLookup[512u * i - 1u]);
        for (uint32_t i = 0; i != 9u * 63u; i++) model_b_[i + 9] = model_b_[i];
    }

    void EncodeSymbol(ArithEncA& enc, uint32_t value) {
        // The decoder ends its 6-step descent on accum in [64,127] and answers
        // `~accum & 0x3f`, so the flags are the complement's bits, top first.
        const uint32_t bits = (~value) & 0x3fu;
        uint32_t accum = 1;
        for (int k = 5; k >= 0; --k) {
            const bool flag = ((bits >> k) & 1u) != 0u;
            uint16_t* model_a_ptr = &model_a_[accum];
            uint16_t* model_b_ptr = &model_b_[(*model_a_ptr >> 13) + 9u * accum];
            enc.EncodeModel(flag, ((uint32_t)model_b_ptr[0] + model_b_ptr[1] + 1u) >> 1);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 4u - *model_a_ptr) >> 3));
            model_b_ptr[0] = (uint16_t)(model_b_ptr[0] +
                ((((uint32_t)flag * 0x1007eu) - model_b_ptr[0]) >> 7));
            model_b_ptr[1] = (uint16_t)(model_b_ptr[1] +
                ((((uint32_t)flag * 0x1007eu) - model_b_ptr[1]) >> 7));
            accum = accum * 2u + flag;
        }
    }

    // Writes the u16 length prefix and the coded body. Returns false only if the
    // body does not fit a 16-bit length, which the format cannot express.
    bool Encode(const uint8_t* counts, uint32_t n, std::vector<uint8_t>* out) {
        if (n == 0u) return false;
        std::vector<uint8_t> body;
        ArithEncA enc;
        enc.out_ = &body;

        const uint32_t outsize_bits = BSR(n);
        uint32_t remaining = n, num_zeros = 0, i = 0;
        for (;;) {
            const uint32_t v = counts[i++];
            if (BcTrace()) std::fprintf(stderr, "S %u\n", v);
            EncodeSymbol(enc, v);
            num_zeros = (v == 0u) ? num_zeros + 1u : 0u;
            remaining -= 1u;
            if (remaining == 0u) break;

            if (num_zeros > 6u) {
                // How many zeros follow right here: the decoder emits them in one
                // run and does NOT feed them back into num_zeros.
                uint32_t z = 0;
                while (z < remaining && counts[i + z] == 0u) ++z;
                const uint32_t k = (z < 2u) ? 0u : BSR(z);
                uint32_t j = 0;
                for (; j < k; ++j) {
                    uint16_t* m = &model_c_[j];
                    enc.EncodeModel(true, *m);
                    *m = (uint16_t)(*m + (((0x10000u) + 16u - *m) >> 5));
                }
                if (k != outsize_bits) {
                    uint16_t* m = &model_c_[k];
                    enc.EncodeModel(false, *m);
                    *m = (uint16_t)(*m + ((16u - *m) >> 5));
                }
                const uint32_t upper = k ? (1u << k) : 0u;
                uint32_t nn = k + (k == 0u);
                const uint32_t lower = z - upper;
                while (nn) {
                    --nn;
                    enc.Encode(((lower >> nn) & 1u) != 0u, 0x8000u >> 4);
                }
                if (BcTrace()) std::fprintf(stderr, "R %u k=%u low=%u\n", z, k, lower);
                i += z;
                remaining -= z;
                if (remaining == 0u) break;
            }
        }
        enc.Flush();
        if (body.size() > 0xffffu) return false;
        out->push_back((uint8_t)(body.size() & 0xffu));
        out->push_back((uint8_t)(body.size() >> 8));
        out->insert(out->end(), body.begin(), body.end());
        return true;
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

// The inverse of CopyOutSamples: raw bytes back to the per-channel delta planes
// the predictors work on. The accumulators are the decoder's, run backwards, so
// the deltas it will add up reproduce these very bytes.
static void UnpackSamples(const uint8_t* in, uint32_t nframes, int32_t* samples,
                          AudioFormat fmt) {
    const uint32_t nchannels = fmt.channels ? 2u : 1u;
    int32_t* right_part = samples + nframes;
    uint32_t left_prev = 0, right_prev = 0;

    for (uint32_t i = 0; i < nframes; ++i) {
        int32_t values[2] = {0, 0};
        for (uint32_t c = 0; c < nchannels; ++c) {
            int32_t v = 0;
            // The probe's `signed_` flag (the payload's `sf` bit) says how wide a
            // sample is to be READ: sign-extended or not. The decoder never needs
            // it -- it writes back the low byte(s) either way -- but it decides
            // every delta here, and the two readings differ by a whole 2^width on
            // any sample past the halfway point. A .SOU (sf=0) and a .ss (sf=1),
            // both 8-bit mono, pick opposite ways, and each was byte-exact only
            // under its own.
            if (fmt.sample_size == 1) {
                const uint32_t raw = *in++;
                v = fmt.stereo_filter ? (int32_t)(int8_t)(uint8_t)raw : (int32_t)raw;
            } else if (fmt.sample_size == 2) {
                const uint32_t b0 = *in++, b1 = *in++;
                const uint32_t raw = fmt.little_endian ? (b0 | (b1 << 8)) : (b1 | (b0 << 8));
                v = fmt.stereo_filter ? (int32_t)(int16_t)(uint16_t)raw : (int32_t)raw;
            } else {
                const uint32_t b0 = *in++, b1 = *in++, b2 = *in++;
                const uint32_t raw = fmt.little_endian ? (b0 | (b1 << 8) | (b2 << 16))
                                                       : (b2 | (b1 << 8) | (b0 << 16));
                v = (int32_t)((raw ^ 0x800000u) - 0x800000u);
            }
            values[c] = v;
        }

        uint32_t left_sum, right_sum;
        if (fmt.channels == 2) {
            // values[1] is `tt`; values[0] = left_sum + tt, right_sum = tt + (left_sum >> 1)
            const uint32_t tt = (uint32_t)values[1];
            left_sum = (uint32_t)values[0] - tt;
            right_sum = tt + (uint32_t)((int32_t)left_sum >> 1);
        } else {
            left_sum = (uint32_t)values[0];
            right_sum = (uint32_t)values[1];
        }

        samples[i] = (int32_t)(left_sum - left_prev);
        left_prev = left_sum;
        if (fmt.channels) {
            right_part[i] = (int32_t)(right_sum - right_prev);
            right_prev = right_sum;
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
// ---------------------------------------------------------------------------
// Encoder side: the bit writer and the residual coder, mirrors of BitReader and
// DecodeInt32Array.
// ---------------------------------------------------------------------------
struct BitWriter {
    std::vector<uint8_t>* out_ = nullptr;
    uint32_t buff_ = 0;     // bits waiting, left-aligned in the low `count_` bits
    uint32_t count_ = 0;    // how many bits `buff_` holds

    void PutBits(uint32_t value, uint32_t nb) {
        while (nb) {
            const uint32_t take = (nb < 32u - count_) ? nb : (32u - count_);
            const uint32_t chunk = (value >> (nb - take)) & bitmask(take);
            buff_ = (count_ + take >= 32u) ? ((buff_ << take) | chunk)
                                           : ((buff_ << take) | chunk);
            count_ += take;
            nb -= take;
            if (count_ == 32u) FlushWord();
        }
    }
    void FlushWord() {
        // The reader fetches whole big-endian 32-bit words.
        out_->push_back((uint8_t)(buff_ >> 24));
        out_->push_back((uint8_t)(buff_ >> 16));
        out_->push_back((uint8_t)(buff_ >> 8));
        out_->push_back((uint8_t)buff_);
        buff_ = 0;
        count_ = 0;
    }
    // The last word goes out only as far as it carries bits: the reader fetches
    // four bytes and zero-fills whatever the stream does not have, so the
    // reference stops at the last byte that holds a bit and the payload ends
    // there (measured: a whole trailing word makes the chunk three bytes long).
    void Finish() {
        if (count_ == 0u) return;
        const uint32_t nbytes = (count_ + 7u) >> 3;
        uint32_t w = buff_ << (32u - count_);
        for (uint32_t k = 0; k < nbytes; ++k) { out_->push_back((uint8_t)(w >> 24)); w <<= 8; }
        buff_ = 0;
        count_ = 0;
    }
};

// The inverse of the class tables. The groups OVERLAP -- `kAudioInt32Tab[23]`
// says ten bits where four classes over an octave want nine, so classes 42 and
// 43 cover values that class 44 covers as well and a search for "a class that
// can carry x" finds the wrong one. The rule that reproduces the reference is
// the octave: k = BSR(x) picks the group at t = 2k (its base IS 2^k), and the
// class is that group's first plus the top bits of the offset. Classes 42 and 43
// are therefore never emitted, which is what the original's own streams show.
struct AudioInt32Classes {
    // magnitude-1 -> class index (vm) and the extra bits to write
    void Split(uint32_t x, uint32_t* vm, uint32_t* extra, uint32_t* nbits) const {
        if (x == 0u) { *vm = 0; *extra = 0; *nbits = 0; return; }
        uint32_t k = BSR(x);
        if (k > 31u) k = 31u;
        const uint32_t t = 2u * k;
        const uint32_t nb = kAudioInt32Tab[t + 1];
        if (nb == 0u) { *vm = x; *extra = 0; *nbits = 0; return; }
        const uint32_t off = x - kAudioInt32Base[k];
        *vm = kAudioInt32Tab[t] + (off >> nb);
        *extra = off & bitmask(nb);
        *nbits = nb;
    }
};

static const AudioInt32Classes& Int32Classes() {
    static const AudioInt32Classes c;
    return c;
}

// Writes the per-sample classes into `counts` and the magnitude/sign bits into
// the writer. The inverse of DecodeInt32Array: class 0 is a zero sample, and
// every other class carries `nbits` magnitude bits and then one sign bit.
static bool EncodeInt32Array(const int32_t* samples, uint32_t n,
                             uint8_t* counts, BitWriter* bw) {
    const AudioInt32Classes& tab = Int32Classes();
    for (uint32_t i = 0; i < n; ++i) {
        const int32_t v = samples[i];
        if (v == 0) { counts[i] = 0; continue; }
        const uint32_t mag = (uint32_t)(v < 0 ? -(int64_t)v : (int64_t)v);
        uint32_t vm = 0, extra = 0, nbits = 0;
        tab.Split(mag - 1u, &vm, &extra, &nbits);
        if (vm > 62u) return false;   // past what a 6-bit class can carry
        counts[i] = (uint8_t)(vm + 1u);
        if (nbits) bw->PutBits(extra, nbits);
        bw->PutBits(v < 0 ? 1u : 0u, 1);
    }
    return true;
}

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
    AudioBitcountDecoderB bitcount_b_[2];
    bool bitcount_variant_b_{false};
    uint8_t ctx_flags_{0x03};
    LinearPredictor linpred_[6];
    // The reference puts these on the stack (uint8[65536] + int32[65536],
    // 320 KB per call). They are members here so a deep call chain cannot blow
    // the stack; the contents are fully rewritten on every chunk.
    std::vector<uint8_t> bitcount_;
    std::vector<int32_t> samples_;

    Impl() : stereo_dec_(4, 8), bitcount_(0x10000), samples_(0x10000) {
        SetPlaneOrders(0x60u, 8u, 8u);   // -cO's profile; the historical hardcoding
    }

    // The six linear predictors' orders are NOT fixed -- they are a per-CODEC
    // constant, read out of the real decoder's plane objects (field +0x1c08) with
    // GDB. One order per PAIR:
    //     -co :  64, 8,  8
    //     -cO :  96, 8,  8
    //     -cc : 384, 16, 8
    // This file used to hardcode 0x60/8/8 for every codec, i.e. -cO's profile --
    // which is exactly why -cO was byte-exact and the other two were not. With the
    // wrong order a plane can even take the wrong code path: -cc's planes 2 and 3
    // are order 16, so they belong in RunBig, and the port was running them through
    // RunSmall.
    void SetStereoParam(uint32_t param) { stereo_dec_.Configure((int)param); }

    void SetBitcountVariantB(bool b) { bitcount_variant_b_ = b; }

    void SetPlaneOrders(uint32_t pair0, uint32_t pair1, uint32_t pair2) {
        linpred_[0].Initialize(pair0);
        linpred_[1].Initialize(pair0);
        linpred_[2].Initialize(pair1);
        linpred_[3].Initialize(pair1);
        linpred_[4].Initialize(pair2);
        linpred_[5].Initialize(pair2);
    }

    void Reset() {
        bitcount_decoder_[0].Reset();
        bitcount_decoder_[1].Reset();
        bitcount_b_[0].Reset();
        bitcount_b_[1].Reset();
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

        // Which bit-count decoder CLASS runs is per-codec: a virtual call through
        // obj+0x38700/+0x38704 in the real decoder, vtable 0x0813c848
        // (FUN_0809c070 = AudioBitcountDecoder) for -cO/-cc and 0x0813c860
        // (FUN_0809bdc0 = AudioBitcountDecoderB) for -co.
        auto decode_counts = [&](int which, uint8_t* out_counts, uint32_t n) -> uint32_t {
            return bitcount_variant_b_
                ? bitcount_b_[which].Decode(in, in_end, out_counts, n)
                : bitcount_decoder_[which].Decode(in, in_end, out_counts, n);
        };
        if (fmt.channels) {
            const uint32_t u0 = decode_counts(0, bitcount, nframes);
            if (u0 == 0u) return 0;
            in += u0;
            const uint32_t u1 = decode_counts(1, bitcount + nframes, nframes);
            if (u1 == 0u) return 0;
            in += u1;
        } else {
            const uint32_t u0 = decode_counts(0, bitcount, nframes);
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
                    if (BcTrace()) std::fprintf(stderr, "GATE 1 stereo c0=%u c1=%u\n", c0, c1);
                    stereo_dec_.SetBits(16u + c0, 16u + c1);
                    use_stereo_dec = true;
                } else {
                    const uint32_t s0 = bit_reader.GetBits(3);
                    const uint32_t s1 = bit_reader.GetBits(3);
                    if (BcTrace()) std::fprintf(stderr, "GATE 1 lms s0=%u s1=%u\n", s0, s1);
                    lms_[0].shift = (uint8_t)(7u + s0);
                    lms_[1].shift = (uint8_t)(7u + s1);
                    use_lms = true;
                }
            } else {
                if (BcTrace()) std::fprintf(stderr, "GATE 0\n");
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
                if (flag) {
                    const uint32_t sb = bit_reader.GetBits(3);
                    if (BcTrace()) std::fprintf(stderr, "LP %d %d flag=1 bits=%u\n", i, j, sb);
                    linpred_[i * 2 + j].SetBits((int)sb + 8);
                } else {
                    if (BcTrace()) std::fprintf(stderr, "LP %d %d flag=0\n", i, j);
                    linpred_[i * 2 + j].Reset();
                }
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
        if (const char* dp = NZ_ENV("NZOPT_DUMP_AUDCOUNTS")) {
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

        if (const char* dp = NZ_ENV("NZOPT_DUMP_AUDPOST")) {
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

        const char* pdump = NZ_ENV("NZOPT_DUMP_AUDPLANE");
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

        if (const char* dp = NZ_ENV("NZOPT_DUMP_AUDRESID")) {
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

bool NzAudioEncodeResiduals(const std::int32_t* samples, std::uint32_t n,
                            std::uint8_t* counts, std::vector<std::uint8_t>* bits,
                            const std::uint32_t* prefix, std::uint32_t prefix_n) {
    BitWriter bw;
    bw.out_ = bits;
    for (std::uint32_t k = 0; k < prefix_n; ++k) bw.PutBits(prefix[2 * k], prefix[2 * k + 1]);
    if (!EncodeInt32Array(samples, n, counts, &bw)) return false;
    bw.Finish();
    return true;
}

bool NzAudioDecodeResiduals(const std::uint8_t* bits, std::size_t bits_size,
                            const std::uint8_t* counts, std::uint32_t n,
                            std::int32_t* samples) {
    BitReader br;
    br.Initialize(bits, bits_size);
    return DecodeInt32Array(samples, n, counts, &br);
}

std::uint32_t NzAudioDecodeBitcounts(const std::uint8_t* in, std::size_t in_size,
                                     std::uint8_t* out, std::uint32_t n, bool variant_b) {
    if (variant_b) {
        AudioBitcountDecoderB dec;
        return dec.Decode(in, in + in_size, out, n);
    }
    AudioBitcountDecoder dec;
    return dec.Decode(in, in + in_size, out, n);
}

// ---------------------------------------------------------------------------
// NzAudioEncoder -- one decr_param==2 chunk, written. The decisions (format,
// inter-channel gate, per-plane predictor flags) come in from the caller for
// now; picking them the way the reference does is the next piece.
// ---------------------------------------------------------------------------
struct NzAudioEncoder::Impl {
    AudioBitcountEncoder bc_a_[2];
    AudioBitcountEncoderB bc_b_[2];
    bool variant_b_{false};
    uint8_t ctx_flags_{0x03};
    LinearPredictor linpred_[6];
    AudioStereoDecoder stereo_dec_;
    nzr::lzpf::LmsObject lms_[2];
    std::vector<int32_t> samples_;
    std::vector<uint8_t> counts_;

    Impl() : stereo_dec_(4, 8), samples_(0x10000), counts_(0x10000) {}

    void SetPlaneOrders(uint32_t p0, uint32_t p1, uint32_t p2) {
        linpred_[0].Initialize(p0); linpred_[1].Initialize(p0);
        linpred_[2].Initialize(p1); linpred_[3].Initialize(p1);
        linpred_[4].Initialize(p2); linpred_[5].Initialize(p2);
    }
    void Reset() {
        bc_a_[0].Reset(); bc_a_[1].Reset();
        bc_b_[0].Reset(); bc_b_[1].Reset();
        stereo_dec_.Reset();
        lms_[0].Init(); lms_[1].Init();
        for (int i = 0; i < 6; ++i) linpred_[i].Reset();
    }

    uint64_t class_sum_ = 0;     // sum of the per-sample classes of the last chunk
    uint64_t abs_sum_ = 0;       // and the sum of |residual|

    // ---------------------------------------------------------------------
    // The reference's decisions (FUN_08081c40 and its two helpers), ported.
    // ---------------------------------------------------------------------

    // The cost every decision here is made on: the sum of the residuals' bit
    // lengths, `BSR(|v| + 1)` (FUN_08080690 inlined).
    static uint64_t BitCost(const int32_t* v, uint32_t n) {
        uint64_t c = 0;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t m = (uint32_t)((v[i] ^ (v[i] >> 31)) - (v[i] >> 31)) + 1u;
            c += m ? BSR(m) : 0u;
        }
        return c;
    }

    // FUN_080535e0: try the shifts in [lo, hi] on three windows of up to 0x800
    // samples taken at 0, n/3 and 2n/3, and keep the cheapest. Gives up once a
    // candidate is two past the best so far.
    uint64_t ShiftSearchSmall(LinearPredictor& pred, const int32_t* samples, uint32_t n,
                              uint32_t lo, uint32_t hi) {
        const uint32_t win = n < 0x800u ? n : 0x800u;
        uint64_t best = ~0ull;
        uint32_t best_shift = 0;
        std::vector<int32_t> scratch(0x1800u);
        const bool trace = NZ_ENV("NZOPT_TRACE_PLANES") != nullptr;
        if (const char* dp = NZ_ENV("NZOPT_DUMP_PLANEIN")) {
            static int seq = 0; char nm[512];
            std::snprintf(nm, sizeof(nm), "%s.%d", dp, seq++);
            if (FILE* f = std::fopen(nm, "wb")) { std::fwrite(samples, 4, n, f); std::fclose(f); }
        }
        if (trace) std::fprintf(stderr, "SS n=%u lo=%u hi=%u first=%d %d %d %d %d %d  [100]=%d [500]=%d [1000]=%d [2000]=%d [6159]=%d [12318]=%d\n", n, lo, hi,
                                samples[0], samples[1], samples[2], samples[3], samples[4], samples[5],
                                n > 100u ? samples[100] : 0, n > 500u ? samples[500] : 0,
                                n > 1000u ? samples[1000] : 0, n > 2000u ? samples[2000] : 0,
                                n > 6159u ? samples[6159] : 0, n > 12318u ? samples[12318] : 0);
        for (uint32_t cand = lo; cand <= hi; ++cand) {
            std::fill(scratch.begin(), scratch.end(), 0);
            for (uint32_t w = 0; w < 3u; ++w) {
                const uint32_t off = (n / 3u) * w;
                for (uint32_t k = 0; k < win && off + k < n; ++k) scratch[w * 0x800u + k] = samples[off + k];
            }
            LinearPredictor clone = pred;
            clone.SetBits((int)cand);
            const uint32_t run = n < 0x1800u ? n : 0x1800u;
            clone.RunForward(scratch.data(), run);
            const uint64_t cost = BitCost(scratch.data(), 0x1800u);
            if (trace) std::fprintf(stderr, "SS   cand=%u cost=%llu out=%d %d %d %d %d %d (order=%u)\n", cand, (unsigned long long)cost,
                                     scratch[0], scratch[1], scratch[2], scratch[3], scratch[4], scratch[5], clone.order_);
            if (cost < best) {
                best = cost;
                best_shift = cand;
                if (cost == 0u) break;
            } else if (cand + 2u <= best_shift) {
                break;
            }
        }
        pred.SetBits((int)best_shift);
        return best;
    }

    // FUN_08053780: the same idea for the long predictor, over candidates 12..14
    // and with the chosen one INCREMENTED by one before it is stored -- which is
    // why the side bits the reference writes are 5, 6 or 7 and never lower.
    uint64_t ShiftSearchBig(LinearPredictor& pred, const int32_t* samples, uint32_t n,
                            uint32_t win_in) {
        if (pred.order_ == 8u) return ShiftSearchSmall(pred, samples, n, 8u, 0xfu);
        if (pred.order_ >= 0x100u) { pred.SetBits(15); return 0; }
        const uint32_t win = win_in < n ? win_in : n;
        const uint32_t stride = n / 3u;
        uint64_t best = ~0ull;
        uint32_t best_shift = 0;
        std::vector<int32_t> scratch(win ? win : 1u);
        for (uint32_t cand = 12u; cand != 15u; ++cand) {
            LinearPredictor clone = pred;
            clone.SetBits((int)cand);
            uint64_t cost = 0;
            for (uint32_t w = 0; w < 3u; ++w) {
                const uint32_t off = stride * w;
                if (off >= n) break;
                const uint32_t take = (off + win <= n) ? win : (n - off);
                scratch.assign(samples + off, samples + off + take);
                clone.RunForward(scratch.data(), take);
                cost += BitCost(scratch.data(), take);
            }
            if (cost < best) {
                best = cost;
                best_shift = cand;
                if (cost == 0u) break;
            }
        }
        if (best_shift < 15u) best_shift += 1u;
        pred.SetBits((int)best_shift);
        return best;
    }

    // FUN_08081b70: does this plane pay? Run a clone over up to 0x2000 samples
    // and compare the cost before and after with the caller's ratio.
    bool PlanePays(const LinearPredictor& pred, const int32_t* samples, uint32_t n,
                   uint32_t a, uint32_t b) {
        const uint32_t take = n < 0x2000u ? n : 0x2000u;
        std::vector<int32_t> scratch(samples, samples + take);
        const uint64_t before = BitCost(scratch.data(), take);
        LinearPredictor clone = pred;
        clone.RunForward(scratch.data(), take);
        const uint64_t after = BitCost(scratch.data(), take);
        return after * a < before * b;
    }


    // The whole block: chunks of 0x10000 output bytes, the models carried across
    // them, and the probe's `prefix` updated at each boundary exactly as the
    // reference does -- after a chunk it holds the ALIGNMENT CARRY, the bytes the
    // next chunk has to copy verbatim before its samples begin
    // (`(channels ? 2 : 1) * width - pad`).
    bool Encode(const uint8_t* in, uint32_t size, NzAudioChunkParams p,
                std::vector<uint8_t>* out) {
        uint32_t off = 0;
        bool first = true;
        while (off < size) {
            const uint32_t n = (size - off < 0x10000u) ? (size - off) : 0x10000u;
            if (!first) p.gate = false;      // decided again below
            NzAudioChunkParams cp = p;
            ChoosePlanes(in + off, n, &cp, 0);
            if (!EncodeChunk(in + off, n, cp, out)) return false;
            // the carry for the next chunk
            const uint32_t nch = cp.channels ? 2u : 1u;
            const uint32_t body = n - cp.header_bytes;
            uint32_t sample_count = body / cp.sample_size;
            if (cp.channels) sample_count &= ~1u;
            const uint32_t pad = body - sample_count * cp.sample_size;
            p.header_bytes = pad ? (nch * cp.sample_size - pad) : 0u;
            first = false;
            off += n;
        }
        return true;
    }

    // Debug hook: the per-channel arrays as they reach the plane decisions, for
    // diffing against a GDB capture of the reference at FUN_08053780.
    void PreparedPlanes(const uint8_t* in, uint32_t outsize, const NzAudioChunkParams& p,
                        std::vector<int32_t>* out) {
        AudioFormat fmt;
        fmt.stereo_filter = p.stereo_filter;
        fmt.channels = p.channels;
        fmt.sample_size = p.sample_size;
        fmt.little_endian = p.little_endian;
        const uint8_t* body = in + p.header_bytes;
        const uint32_t body_size = outsize - p.header_bytes;
        uint32_t sample_count = body_size / fmt.sample_size;
        if (fmt.channels) sample_count &= ~1u;
        const uint32_t nframes = fmt.channels ? (sample_count >> 1) : sample_count;
        out->assign(sample_count, 0);
        UnpackSamples(body, nframes, out->data(), fmt);
        if (fmt.channels && p.gate) {
            // The stage has to run with the very parameters the payload will
            // carry, or everything downstream of it sees different residuals.
            if ((ctx_flags_ & 0x10u) != 0u) {
                lms_[0].shift = (uint8_t)(7u + p.gate_a);
                lms_[1].shift = (uint8_t)(7u + p.gate_b);
                nzr::lzpf::InverseLmsInterChannel(out->data(), out->data() + nframes, nframes, &lms_[0], &lms_[1]);
            } else {
                stereo_dec_.SetBits(16u + p.gate_a, 16u + p.gate_b);
                stereo_dec_.Encode(out->data(), out->data() + nframes, nframes);
            }
        }
        Reset();
    }

    // The reference's plane decisions (FUN_08081c40). Its outer loop is over the
    // three STAGES and the inner one over the channels, and the stage index is
    // what selects both the shift rule and the acceptance ratio:
    //   stage 0  every plane is used, no trial at all;
    //   stage 1  the trial runs with the 0x40/0x41 ratio (about 1.5 %);
    //   stage 2  the trial runs with a plain "must be cheaper".
    void ChoosePlanes(const uint8_t* in, uint32_t outsize, NzAudioChunkParams* p, int /*unused*/) {
        AudioFormat fmt;
        fmt.stereo_filter = p->stereo_filter;
        fmt.channels = p->channels;
        fmt.sample_size = p->sample_size;
        fmt.little_endian = p->little_endian;
        const uint8_t* body = in + p->header_bytes;
        const uint32_t body_size = outsize - p->header_bytes;
        uint32_t sample_count = body_size / fmt.sample_size;
        if (fmt.channels) sample_count &= ~1u;
        const uint32_t nsamples = sample_count;
        const uint32_t nframes = fmt.channels ? (nsamples >> 1) : nsamples;
        if (nframes == 0u) return;

        std::vector<int32_t> cur(nsamples);
        UnpackSamples(body, nframes, cur.data(), fmt);

        // Everything below measures on COPIES: the live models belong to the
        // chunk that is actually written, and they have to carry across chunks.
        LinearPredictor lp_copy[6] = {linpred_[0], linpred_[1], linpred_[2],
                                      linpred_[3], linpred_[4], linpred_[5]};
        AudioStereoDecoder sd_copy = stereo_dec_;
        nzr::lzpf::LmsObject lms_copy[2] = {lms_[0], lms_[1]};

        // FUN_08081af0: the inter-channel stage is used unless one channel is
        // far cheaper than the other -- costs of 100 + sum BSR(|v| + 1), and the
        // stage is skipped when min * 7 < max * 3. Its two parameters are not
        // searched: the stereo predictor takes them from its own part orders and
        // the LMS variant from a pair of constants.
        if (fmt.channels) {
            const uint64_t cl = 100u + BitCost(cur.data(), nframes);
            const uint64_t cr = 100u + BitCost(cur.data() + nframes, nframes);
            const uint64_t lo = cl < cr ? cl : cr;
            const uint64_t hi = cl < cr ? cr : cl;
            p->gate = !(lo * 7u < hi * 3u);
            if (p->gate) {
                if ((ctx_flags_ & 0x10u) != 0u) {
                    p->gate_a = 0xcu - 7u;
                    p->gate_b = ((fmt.channels == 2u) ? 0xbu : 0xcu) - 7u;
                } else {
                    p->gate_a = ((stereo_dec_.PartOrderOne() >> 2) + 0x14u) - 0x10u;
                    p->gate_b = ((stereo_dec_.PartOrderTwo() >> 2) + 0x14u) - 0x10u;
                }
            }
        }
        if (fmt.channels && p->gate) {
            // Same parameters the payload will carry (missing them made every
            // decision downstream read different residuals).
            if ((ctx_flags_ & 0x10u) != 0u) {
                lms_copy[0].shift = (uint8_t)(7u + p->gate_a);
                lms_copy[1].shift = (uint8_t)(7u + p->gate_b);
                nzr::lzpf::InverseLmsInterChannel(cur.data(), cur.data() + nframes, nframes, &lms_copy[0], &lms_copy[1]);
            } else {
                sd_copy.SetBits(16u + p->gate_a, 16u + p->gate_b);
                sd_copy.Encode(cur.data(), cur.data() + nframes, nframes);
            }
        }

        const uint32_t nch = fmt.channels ? 2u : 1u;
        const bool long_order = linpred_[1].order_ > 0x40u;   // the field at obj+0x1c18
        const uint32_t trial_win = long_order ? nframes : std::min<uint32_t>(nframes, 0x1000u);
        for (int i = 0; i <= 2; ++i) {
            for (uint32_t j = 0; j < nch; ++j) {
                LinearPredictor& lp = lp_copy[i * 2 + (int)j];
                int32_t* chan = cur.data() + j * nframes;

                if ((ctx_flags_ & 1u) == 0u) {
                    const uint32_t ord = lp.order_;
                    lp.SetBits((int)(ord > 8u ? std::min<uint32_t>(ord / 20u + 12u, 15u) : 8u));
                } else if (lp.order_ < 9u) {
                    if (!long_order) lp.SetBits((int)(8u + (i == 1 ? 1u : 0u)));
                    else ShiftSearchSmall(lp, chan, nframes, 8u, i == 1 ? 0xbu : 0xau);
                } else {
                    ShiftSearchBig(lp, chan, nframes,
                                   i == 0 ? (((ctx_flags_ & 8u) != 0u) ? 0x800u : 0x100u) : 0x800u);
                }

                bool use = true;
                if (i == 1) use = PlanePays(lp, chan, trial_win, 0x40u, 0x41u);
                else if (i == 2) use = PlanePays(lp, chan, trial_win, 1u, 1u);
                p->lp_flag[i][j] = use ? 1u : 0u;
                p->lp_bits[i][j] = (uint8_t)(use ? (lp.shift_ >= 8u ? lp.shift_ - 8u : 0u) : 0u);
                if (use) lp.RunForward(chan, nframes);
                else lp.Reset();
            }
        }
    }

    bool EncodeChunk(const uint8_t* in, uint32_t outsize, const NzAudioChunkParams& p,
                     std::vector<uint8_t>* out) {
        const size_t chunk_start = out->size();
        AudioFormat fmt;
        fmt.stereo_filter = p.stereo_filter;
        fmt.channels = p.channels;
        fmt.sample_size = p.sample_size;
        fmt.little_endian = p.little_endian;

        // The type byte, built the way DecodeChunk takes it apart.
        uint32_t f = 0;
        if (p.sample_size != 1u) f = 1u + (((uint32_t)p.sample_size - 2u) << 1) + (p.little_endian ? 1u : 0u);
        const uint32_t hdr_code = (p.header_bytes >= 6u) ? 6u : p.header_bytes;
        if (p.header_bytes >= 6u && p.header_bytes - 6u > 0xffu) return false;
        const uint32_t type = ((hdr_code * 5u + f) * 3u + p.channels) * 2u + (p.stereo_filter ? 1u : 0u);
        if (type > 0xffu) return false;
        out->push_back((uint8_t)type);
        if (p.header_bytes >= 6u) out->push_back((uint8_t)(p.header_bytes - 6u));

        if (p.header_bytes > outsize) return false;
        out->insert(out->end(), in, in + p.header_bytes);
        const uint8_t* body = in + p.header_bytes;
        uint32_t body_size = outsize - p.header_bytes;

        uint32_t sample_count = body_size / fmt.sample_size;
        if (fmt.channels) sample_count &= ~1u;
        const uint32_t databytes = sample_count * fmt.sample_size;
        const uint32_t pad_bytes = body_size - databytes;
        out->insert(out->end(), body + databytes, body + databytes + pad_bytes);

        const uint32_t nsamples = databytes / fmt.sample_size;
        uint32_t nframes = nsamples;
        if (fmt.channels) {
            if (nsamples & 1u) return false;
            nframes = nsamples >> 1;
        }
        if (nsamples > samples_.size()) return false;
        int32_t* samples = samples_.data();
        uint8_t* counts = counts_.data();

        UnpackSamples(body, nframes, samples, fmt);

        // The side bits, in the order the decoder reads them.
        std::vector<uint32_t> prefix;
        const bool lms_variant = (ctx_flags_ & 0x10u) != 0u;
        if (fmt.channels) {
            prefix.push_back(p.gate ? 1u : 0u); prefix.push_back(1u);
            if (p.gate) {
                if (!lms_variant) {
                    prefix.push_back(p.gate_a); prefix.push_back(4u);
                    prefix.push_back(p.gate_b); prefix.push_back(4u);
                    stereo_dec_.SetBits(16u + p.gate_a, 16u + p.gate_b);
                } else {
                    prefix.push_back(p.gate_a); prefix.push_back(3u);
                    prefix.push_back(p.gate_b); prefix.push_back(3u);
                    lms_[0].shift = (uint8_t)(7u + p.gate_a);
                    lms_[1].shift = (uint8_t)(7u + p.gate_b);
                }
            } else {
                stereo_dec_.Reset();
                lms_[0].Init();
                lms_[1].Init();
            }
        }
        for (int i = 0; i != 3; i++) {
            for (int j = 0; j < (fmt.channels ? 2 : 1); j++) {
                const uint8_t flag = p.lp_flag[i][j];
                prefix.push_back(flag ? 1u : 0u); prefix.push_back(1u);
                if (flag) {
                    prefix.push_back(p.lp_bits[i][j]); prefix.push_back(3u);
                    linpred_[i * 2 + j].SetBits((int)p.lp_bits[i][j] + 8);
                } else {
                    linpred_[i * 2 + j].Reset();
                }
            }
        }

        // The inter-channel stage, inverted, then the predictors forward in the
        // order the decoder undoes them (it runs 2, 1, 0).
        if (fmt.channels && p.gate) {
            if (lms_variant)
                nzr::lzpf::InverseLmsInterChannel(samples, samples + nframes, nframes, &lms_[0], &lms_[1]);
            else
                stereo_dec_.Encode(samples, samples + nframes, nframes);
        }
        for (int i = 0; i <= 2; i++) {
            for (int j = 0; j < (fmt.channels ? 2 : 1); j++) {
                if (p.lp_flag[i][j]) linpred_[i * 2 + j].RunForward(samples + j * nframes, nframes);
            }
        }

        std::vector<uint8_t> bits;
        BitWriter bw;
        bw.out_ = &bits;
        for (size_t k = 0; k + 1 < prefix.size(); k += 2) bw.PutBits(prefix[k], prefix[k + 1]);
        if (!EncodeInt32Array(samples, nsamples, counts, &bw)) return false;
        bw.Finish();
        class_sum_ = 0;
        abs_sum_ = 0;
        for (uint32_t k = 0; k < nsamples; ++k) {
            class_sum_ += counts[k];
            const int32_t r = samples[k];
            abs_sum_ += (uint64_t)(r < 0 ? -(int64_t)r : (int64_t)r);
        }

        // The bit-count arrays come first in the payload, one per channel.
        const uint32_t per = nframes;
        for (int ch = 0; ch < (fmt.channels ? 2 : 1); ++ch) {
            const bool ok = variant_b_ ? bc_b_[ch].Encode(counts + (uint32_t)ch * per, per, out)
                                       : bc_a_[ch].Encode(counts + (uint32_t)ch * per, per, out);
            if (!ok) return false;
        }
        out->insert(out->end(), bits.begin(), bits.end());
        // FUN_08081c40's own gate (`pcVar16 <= written`): a chunk whose payload
        // does not come out BELOW the aligned sample bytes is refused, and one
        // refused chunk takes the whole block with it (FUN_08082d00 returns 0).
        // Without it this port wrote audio blocks the original declines -- a
        // speech+noise .wav came out as decr_param 2 against the original's LZ.
        if (out->size() - chunk_start >= (size_t)databytes) return false;
        return true;
    }
};

NzAudioEncoder::NzAudioEncoder() : impl_(new Impl()) {}
NzAudioEncoder::~NzAudioEncoder() = default;
void NzAudioEncoder::SetContextFlags(std::uint8_t flags) { impl_->ctx_flags_ = flags; }
void NzAudioEncoder::SetPlaneOrders(std::uint32_t a, std::uint32_t b, std::uint32_t c) {
    impl_->SetPlaneOrders(a, b, c);
}
void NzAudioEncoder::SetStereoParam(std::uint32_t param) { impl_->stereo_dec_.Configure((int)param); }
void NzAudioEncoder::SetBitcountVariantB(bool b) { impl_->variant_b_ = b; }
void NzAudioEncoder::Reset() { impl_->Reset(); }
bool NzAudioEncoder::EncodeChunk(const std::uint8_t* in, std::uint32_t outsize,
                                 const NzAudioChunkParams& params,
                                 std::vector<std::uint8_t>* out) {
    return impl_->EncodeChunk(in, outsize, params, out);
}

bool NzAudioEncoder::Encode(const std::uint8_t* in, std::uint32_t size,
                            const NzAudioChunkParams& params,
                            std::vector<std::uint8_t>* out) {
    return impl_->Encode(in, size, params, out);
}

void NzAudioEncoder::PreparedPlanes(const std::uint8_t* in, std::uint32_t outsize,
                                    const NzAudioChunkParams& params,
                                    std::vector<std::int32_t>* out) {
    impl_->PreparedPlanes(in, outsize, params, out);
}

void NzAudioEncoder::ChoosePlanes(const std::uint8_t* in, std::uint32_t outsize,
                                  NzAudioChunkParams* params, int metric) {
    impl_->ChoosePlanes(in, outsize, params, metric);
}

std::uint64_t NzAudioEncoder::LastClassSum() const { return impl_->class_sum_; }
std::uint64_t NzAudioEncoder::LastAbsSum() const { return impl_->abs_sum_; }

struct NzBitcountEncoderSet::Impl {
    AudioBitcountEncoder a_[4];
    AudioBitcountEncoderB b_[4];
    bool variant_b_ = false;
};

NzBitcountEncoderSet::NzBitcountEncoderSet() : impl_(new Impl()) {}
NzBitcountEncoderSet::~NzBitcountEncoderSet() = default;
void NzBitcountEncoderSet::Reset() {
    for (int k = 0; k < 4; ++k) { impl_->a_[k].Reset(); impl_->b_[k].Reset(); }
}
void NzBitcountEncoderSet::SetVariantB(bool b) { impl_->variant_b_ = b; }
bool NzBitcountEncoderSet::Encode(unsigned ch, const std::uint8_t* counts, std::uint32_t n,
                                  std::vector<std::uint8_t>* out) {
    if (ch >= 4u) return false;
    return impl_->variant_b_ ? impl_->b_[ch].Encode(counts, n, out)
                             : impl_->a_[ch].Encode(counts, n, out);
}

bool NzAudioEncodeBitcounts(const std::uint8_t* counts, std::uint32_t n,
                            std::vector<std::uint8_t>* out, bool variant_b) {
    if (variant_b) {
        AudioBitcountEncoderB enc;
        return enc.Encode(counts, n, out);
    }
    AudioBitcountEncoder enc;
    return enc.Encode(counts, n, out);
}

void NzAudioPred::SetContextFlags(std::uint8_t flags) { impl_->ctx_flags_ = flags; }

void NzAudioPred::SetPlaneOrders(std::uint32_t pair0, std::uint32_t pair1, std::uint32_t pair2) {
    impl_->SetPlaneOrders(pair0, pair1, pair2);
}

void NzAudioPred::SetStereoParam(std::uint32_t param) { impl_->SetStereoParam(param); }

void NzAudioPred::SetBitcountVariantB(bool b) { impl_->SetBitcountVariantB(b); }

NzAudioPred::NzAudioPred() : impl_(new Impl()) {}
NzAudioPred::~NzAudioPred() = default;
void NzAudioPred::Reset() { impl_->Reset(); }

bool NzAudioPred::Decode(const std::uint8_t* in, std::uint32_t in_size,
                         std::uint8_t* out, std::uint32_t out_size) {
    return impl_->Decode(in, in_size, out, out_size);
}

// ===========================================================================
// NzImageModel -- decr_param == 3 (FUN_080a9ca0 / FUN_080a90c0 and callees).
// Ported from the Ghidra decompile + asm of work/linux32/nz; offsets in the
// comments are the real object's, for cross-reference with GDB.
// ===========================================================================
namespace {

inline bool ImgTrace() {
    static const bool t = (NZ_ENV("NZ_IMG_TRACE") != nullptr);
    return t;
}
#define IMG_TRACE(...) do { if (ImgTrace()) std::fprintf(stderr, "[IMG] " __VA_ARGS__); } while (0)

// One 4-tap sign-sign stage of the cascade (obj+0x8c60 + stage*0x80 + ch*0x20):
// [0..3] = coefficients, [4..7] = the neighbour values FUN_080b6820 loads.
struct ImgCascade {
    int32_t coef[4]{};
    int32_t hist[4]{};
};

// FUN_080b5ed0 (regparm: eax=left, edx=above, ecx=above_left): the neighbour
// closest to the gradient left+above-above_left, ties left, then above.
inline uint32_t ImgGradientPick(uint32_t a, uint32_t b, uint32_t c) {
    auto uabs = [](uint32_t x) { const uint32_t s = (uint32_t)((int32_t)x >> 31); return (x ^ s) - s; };
    const uint32_t g = a + b - c;
    const uint32_t da = uabs(g - a), db = uabs(g - b), dc = uabs(g - c);
    if (da <= dc && da <= db) return a;
    return (db <= dc) ? b : c;
}

}  // namespace

struct NzImageModel::Impl {
    uint8_t flags_{0};                       // obj+0x52940
    bool variant_b_{false};
    nzr::lzpf::LpcBigPredictor plane_[5];    // obj+0x10 + k*0x1c10 (FUN_080bddc0 core)
    ImgCascade casc_[4][4];                  // [stage][channel]
    std::vector<int16_t> ring0_;             // *obj      : 4 shorts per sample, index & 0xfffff
    std::vector<int16_t> ring1_;             // *(obj+4)  : 1 short per sample, index & 0x7fff
    uint32_t r0_{0}, r1_{0};                 // obj+0x52910 / +0x52914
    uint16_t width_{1};                      // obj+0x5291a
    uint16_t row_{0};                        // obj+0x5291e
    uint16_t col_{0};                        // obj+0x52918
    uint8_t align_{0}, nch_{1}, grp_{1}, endian_{0};   // +0x52921 / 22 / 23 / 25
    uint8_t casc_shift_[16];                 // obj+0x52926 (16 bytes)
    uint8_t plane_shift_[5];                 // obj+0x52936 (u16 stride, low bytes)
    AudioBitcountDecoder bc_a_[4];           // obj+0x50f00 + k*0x680  (vtable 0x0813c848)
    AudioBitcountDecoderB bc_b_[4];          // obj+0x8e60  + k*0x12020 (vtable 0x0813c860)
    bool have_ = true;                       // obj+0x52920: set by the ctor and at every chunk commit
    std::vector<uint8_t> bitcount_;          // auStack_100e0
    std::vector<int32_t> resid_;             // auStack_500fc

    Impl() : ring0_(0x100000u + 16u, 0), ring1_(0x8000u + 4u, 0),
             bitcount_(0x10000u), resid_(0x10000u + 8u) {
        std::memset(casc_shift_, 0x0c, sizeof(casc_shift_));
        for (auto& s : plane_shift_) s = 0x0f;
        Configure(0x0fu, 32u, 48u, false);
    }

    void Configure(uint8_t flags, uint32_t order03, uint32_t order4, bool vb) {
        flags_ = flags; variant_b_ = vb;
        for (int k = 0; k < 4; ++k) { plane_[k].order = order03; plane_[k].Reset(); }
        plane_[4].order = order4; plane_[4].Reset();
    }

    // FUN_080b6170 (see the header). The flag bit 1 branch (LMS planes and the
    // cascade coefficients) is written from the decompile but exercised by no
    // codec's reset yet: only lzpf (flags 0) and the -cd/-co families call it.
    void Reset() {
        width_ = 1; col_ = 0; row_ = 0; align_ = 0; grp_ = 1; nch_ = 1; endian_ = 0;
        if (!have_) return;
        have_ = false;
        r0_ = 0; r1_ = 0;
        if (flags_ & 4u) std::fill(ring0_.begin(), ring0_.end(), 0);
        std::fill(ring1_.begin(), ring1_.end(), 0);
        std::memset(casc_shift_, 0x0c, sizeof(casc_shift_));
        for (auto& s : plane_shift_) s = 0x0f;
        if (flags_ & 2u) {
            for (int k = 0; k < 5; ++k) plane_[k].Reset();
            for (auto& row : casc_) for (auto& st : row) { std::memset(st.coef, 0, sizeof(st.coef)); std::memset(st.hist, 0, sizeof(st.hist)); }
        }
        // flag bit 0: the four per-channel bit-count models go back to their
        // initial state (the class's slot-0 routine through the object's vtable)
        if (flags_ & 1u) {
            for (int k = 0; k < 4; ++k) { if (variant_b_) bc_b_[k].Reset(); else bc_a_[k].Reset(); }
        }
    }

    // FUN_080bdb20: clear a plane's sample/sign windows and its prediction; the
    // coefficients and the shift survive.
    static void PlaneResetWindow(nzr::lzpf::LpcBigPredictor& p) {
        p.ring_off = 0x1000;
        std::memset(p.area + 0x1000, 0, p.order * 2u);
        std::memset(p.area + 0x1400, 0, p.order * 2u);
        p.pred = 0;
    }
    // FUN_080bddc0(plane, value, residual) with value == plane.pred + residual.
    static void PlaneStep(nzr::lzpf::LpcBigPredictor& p, int32_t residual) {
        int32_t r = residual;
        p.Run(&r, 1u);
    }

    void ZeroSampleGroup() {
        for (uint32_t k = 0; k < nch_; ++k) {
            for (uint32_t j = 0; j < 4; ++j) ring0_[r0_ + k * 4u + j] = 0;
            ring1_[r1_ + k] = 0;
        }
    }

    // FUN_080b6340: a chunk below 0x180 bytes is stored verbatim; the model only
    // advances its rings/counters as if `n` zero bytes had been decoded.
    void SmallAdvance(uint32_t n) {
        if (n == 0u) return;
        uint8_t a = align_;
        if (a != 0u) {
            const uint8_t g = grp_;
            for (;;) {
                ++a; --n;
                if (a == g) { align_ = 0; if (n == 0u) return; break; }
                if (n == 0u) { align_ = a; return; }
            }
        }
        const uint32_t g = grp_;
        align_ = (uint8_t)(n % g);
        uint32_t cnt = (g - 1u + n) / g;
        do {
            ZeroSampleGroup();
            r0_ = (r0_ + nch_ * 4u) & 0xfffffu;
            r1_ = (r1_ + nch_) & 0x7fffu;
            const uint16_t c = (uint16_t)(col_ + 1u);
            col_ = c;
            if (c == width_) { col_ = 0; ++row_; }
        } while (--cnt);
    }

    // FUN_080b64d0: after a chunk that ended mid-pixel, account for the split
    // pixel with one zero sample group.
    void EndChunk() {
        if (align_ == 0u) return;
        ZeroSampleGroup();
        r1_ = (r1_ + nch_) & 0x7fffu;
        r0_ = (r0_ + nch_ * 4u) & 0xfffffu;
        const uint16_t c = (uint16_t)(col_ + 1u);
        col_ = (width_ == c) ? (uint16_t)0 : c;
    }

    // FUN_080b6820: load the four cascade stages' neighbour values from ring0.
    // Stage 0 tracks the pixel above-and-three-to-the-right (value level 0) as a
    // shift register; stages 1..3 take the four rows above at level 1 (straight
    // up), level 2 (up-right diagonal) and level 3 (up-left diagonal).
    void CascadeLoad(uint32_t stride, uint32_t nch) {
        const uint32_t idx0 = (r0_ - 4u * (stride - 3u * nch)) & 0xfffffu;
        for (uint32_t c = 0; c < 4; ++c) {
            ImgCascade& st = casc_[0][c];
            st.hist[3] = st.hist[2]; st.hist[2] = st.hist[1]; st.hist[1] = st.hist[0];
            st.hist[0] = ring0_[idx0 + c * 4u];
        }
        uint32_t idx = r0_ + 1u;
        for (uint32_t i = 0; i < 4; ++i) {
            idx = (idx - 4u * stride) & 0xfffffu;
            for (uint32_t c = 0; c < 4; ++c) casc_[1][c].hist[i] = ring0_[idx + c * 4u];
        }
        idx = r0_ + 2u;
        for (uint32_t i = 0; i < 4; ++i) {
            idx = (idx - 4u * (stride - nch)) & 0xfffffu;
            for (uint32_t c = 0; c < 4; ++c) casc_[2][c].hist[i] = ring0_[idx + c * 4u];
        }
        idx = r0_ + 3u;
        for (uint32_t i = 0; i < 4; ++i) {
            idx = (idx - 4u * (stride + nch)) & 0xfffffu;
            for (uint32_t c = 0; c < 4; ++c) casc_[3][c].hist[i] = ring0_[idx + c * 4u];
        }
    }

    // FUN_080b65b0: turn `pr` (entering as the previous pixel's values) into the
    // 2D prediction. Always operates on 4 lanes; lanes >= nch are harmless.
    // 32-bit wrap-around add (the original's x86 arithmetic); UBSan-clean on corrupt input.
    static inline int32_t WrapAdd(int32_t a, int32_t b) { return static_cast<int32_t>(static_cast<uint32_t>(a) + static_cast<uint32_t>(b)); }
    void Predict2D(uint32_t* pr, uint32_t stride, uint32_t mode, uint32_t nch) {
        if (mode == 0u) return;
        const int16_t* above = &ring1_[(r1_ - stride) & 0x7fffu];
        const int16_t* aleft = &ring1_[(r1_ - stride - nch) & 0x7fffu];
        if (mode <= 4u) {
            for (int c = 0; c < 4; ++c) pr[c] += 1u + (uint16_t)above[c];
            if (mode >= 3u) for (int c = 0; c < 4; ++c) pr[c] += (uint16_t)aleft[c];
        } else if (mode == 5u) {
            for (int c = 0; c < 4; ++c) pr[c] += (uint16_t)aleft[c];
        }
        switch (mode) {
        case 1: for (int c = 0; c < 4; ++c) pr[c] = (uint16_t)above[c]; break;
        case 2: case 5: for (int c = 0; c < 4; ++c) pr[c] = (uint32_t)((int32_t)pr[c] >> 1); break;
        case 3: for (int c = 0; c < 4; ++c) pr[c] = (uint32_t)((int32_t)pr[c] / 3); break;
        case 4: {
            const int16_t* aright = &ring1_[(r1_ - stride + nch) & 0x7fffu];
            for (int c = 0; c < 4; ++c) pr[c] = (uint32_t)((int32_t)(pr[c] + 1u + (uint16_t)aright[c]) >> 2);
            break;
        }
        case 6: for (int c = 0; c < 4; ++c) pr[c] = ImgGradientPick(pr[c], (uint16_t)above[c], (uint16_t)aleft[c]); break;
        default: break;   // 7: keep the left pixel
        }
    }

    // FUN_080a90c0. Returns 0 on success, 1 on truncated input, 2 on a zero width.
    int DecodeChunk(const uint8_t* in, size_t* consumed, size_t* remaining,
                    uint8_t* out, uint32_t chunk) {
        if (chunk < 0x180u) {
            if (chunk <= *remaining) {
                SmallAdvance(chunk);
                std::memcpy(out, in, chunk);
                *consumed += chunk; *remaining -= chunk;
                IMG_TRACE("small chunk=%u (verbatim)\n", chunk);
                return 0;
            }
            return 1;
        }
        if (*remaining < 2u) return 1;
        const uint8_t h = in[0];
        *consumed += 1; *remaining -= 1;
        if (*remaining == 0u) return 1;
        const uint8_t* p = in + 1;
        uint32_t prefix = h >> 5;
        if (prefix > 5u) {
            if (prefix == 7u) {
                if (*remaining < 3u) return 1;
                prefix = (uint32_t)(p[0] | (p[1] << 8)) + 0xfau;
                p += 2; *consumed += 2; *remaining -= 2;
            } else {
                const uint8_t b = p[0];
                *consumed += 1; *remaining -= 1;
                if (*remaining == 0u) return 1;
                prefix = (uint32_t)b + 6u;
                p += 1;
            }
        }
        uint32_t W;
        if ((h & 1u) == 0u) {
            if (*remaining < 3u) return 1;
            W = (uint32_t)(p[0] | (p[1] << 8)) + 1u;
            p += 2; *consumed += 2; *remaining -= 2;
        } else {
            W = width_;
            if (W == 0u) return 2;
        }
        // Raw prefix (the BMP header on the first chunk), byte by byte.
        if (prefix != 0u) {
            if (prefix > chunk) return 1;   // (the original would overrun; be safe)
            for (uint32_t i = 0; i < prefix; ++i) {
                out[i] = p[i];
                *consumed += 1; *remaining -= 1;
                if (*remaining == 0u) return 1;
            }
            p += prefix;
        }
        uint8_t* outp = out + prefix;
        const uint32_t nch = ((h >> 3) & 3u) + 1u;
        const uint32_t bps = ((h >> 2) & 1u) + 1u;
        const uint32_t rem_mod = (chunk - prefix) % (bps * nch);
        const uint32_t aligned = (chunk - prefix) - rem_mod;
        // Misaligned tail bytes: raw, stored at the END of the chunk.
        if (rem_mod != 0u) {
            uint8_t* dst = outp + aligned;
            for (uint32_t i = 0; i < rem_mod; ++i) {
                dst[i] = p[i];
                *consumed += 1; *remaining -= 1;
                if (*remaining == 0u) return 1;
            }
            p += rem_mod;
        }
        // LAB_080a92cb: commit the chunk's format into the object.
        have_ = true;
        align_ = (uint8_t)rem_mod;
        grp_ = (uint8_t)(bps * nch);
        nch_ = (uint8_t)nch;
        endian_ = (h >> 1) & 1u;
        width_ = (uint16_t)W;
        const uint32_t per_ch = (aligned / nch) / bps;
        if (per_ch * nch > bitcount_.size()) return 1;
        // Per-channel bit-count streams (planar).
        uint8_t* bc = bitcount_.data();
        for (uint32_t c = 0; c < nch; ++c) {
            size_t n;
            if ((flags_ & 1u) == 0u) {
                n = nzr::lzpf::DecodeArithBuffer(p, *remaining, bc, per_ch, 12u);
            } else if (variant_b_) {
                n = bc_b_[c].Decode(p, p + *remaining, bc, per_ch);
            } else {
                n = bc_a_[c].Decode(p, p + *remaining, bc, per_ch);
            }
            if (n == 0u || n > *remaining) { IMG_TRACE("bitcount ch%u failed (n=%zu)\n", c, n); return 1; }
            p += n; *consumed += n; *remaining -= n;
            bc += per_ch;
        }
        // Side-bit header (FUN_080b1fb0 reads) then the residual stream.
        nzr::lzpf::BitReader br;
        nzr::lzpf::Init(br, p, *remaining);
        const uint32_t mode = nzr::lzpf::ReadBits(br, 3u);
        if (nzr::lzpf::ReadBits(br, 1u)) {
            for (int k = 0; k < 5; ++k) plane_shift_[k] = (uint8_t)(nzr::lzpf::ReadBits(br, 4u) + 0x0bu);
        }
        for (int k = 0; k < 5; ++k) plane_[k].shift = plane_shift_[k];
        uint8_t casc[16];
        if (nzr::lzpf::ReadBits(br, 1u) == 0u) {
            std::memcpy(casc, casc_shift_, 16);
        } else {
            std::memcpy(casc, casc_shift_, 16);
            for (int s = 0; s < 4; ++s)
                for (uint32_t c = 0; c < nch; ++c)
                    casc[s * 4 + c] = (uint8_t)(nzr::lzpf::ReadBits(br, 4u) + 0x0cu);
            std::memcpy(casc_shift_, casc, 16);
        }
        const uint32_t count = aligned / bps;
        if (count > resid_.size()) return 1;
        {
            nzr::lzpf::SideBitState sb;
            sb.ignored = br.start; sb.end = br.end; sb.cur = br.cur; sb.cache = br.cache; sb.n_valid = br.n_valid;
            if ((flags_ & 1u) == 0u) nzr::lzpf::DecodeResidualsMono(resid_.data(), count, bitcount_.data(), &sb);
            else                     nzr::lzpf::DecodeResidualsStereo(resid_.data(), count, bitcount_.data(), &sb);
            br.cur = sb.cur; br.cache = sb.cache; br.n_valid = sb.n_valid;
        }
        {
            const uint32_t used_bytes = (uint32_t)(((7u - br.n_valid) + (uint32_t)(br.cur - br.start) * 8u) >> 3);
            const size_t n = (used_bytes < *remaining) ? used_bytes : *remaining;
            *consumed += n; *remaining -= n;
        }
        nz_trace::Construct("image_mode=%u nch=%u bps=%u", mode, nch, bps);
        IMG_TRACE("chunk=%u h=%02x prefix=%u W=%u nch=%u bps=%u tail=%u per_ch=%u mode=%u pshift=%u,%u,%u,%u,%u r0=%u r1=%u col=%u row=%u\n",
                  chunk, h, prefix, W, nch, bps, rem_mod, per_ch, mode,
                  plane_shift_[0], plane_shift_[1], plane_shift_[2], plane_shift_[3], plane_shift_[4],
                  r0_, r1_, col_, row_);
        // Pixel loop.
        const int32_t* rp[4] = {nullptr, nullptr, nullptr, nullptr};
        for (uint32_t c = 0; c < nch; ++c) rp[c] = resid_.data() + c * per_ch;
        const uint32_t stride = W * nch;
        uint32_t left[4] = {0, 0, 0, 0};
        uint32_t pr[4] = {0, 0, 0, 0};
        uint32_t done = 0;
        while (done < per_ch) {
            uint32_t run = per_ch - done; if (run > W) run = W;
            const uint16_t colc = col_;
            if (colc == 0u) {
                ++row_;
                col_ = (W == run) ? (uint16_t)0 : (uint16_t)run;
                if (flags_ & 2u) for (int k = 0; k < 5; ++k) PlaneResetWindow(plane_[k]);
            } else {
                col_ = 0;
                const uint32_t left_in_row = W - colc;
                if (run > left_in_row) run = left_in_row;
            }
            {
                const uint32_t ai = (r1_ - stride) & 0x7fffu;
                for (int c = 0; c < 4; ++c) left[c] = (uint16_t)ring1_[ai + c];
            }
            done += run;
            for (; run != 0u; --run) {
                int32_t d[4] = {0, 0, 0, 0};          // aiStack_d0: what gets added to the prediction
                int32_t lvl[4][4] = {};              // cascade levels 0..3 (aiStack_c0/b0/a0/90)
                if ((flags_ & 2u) == 0u) {
                    for (uint32_t c = 0; c < nch; ++c) d[c] = *rp[c]++;
                } else {
                    int32_t lms4[4] = {0, 0, 0, 0};  // aiStack_80: plane-4 output per channel
                    for (uint32_t c = 0; c < nch; ++c) {
                        const int32_t r = *rp[c]++;
                        lms4[c] = WrapAdd(plane_[4].pred, r);   // 32-bit wrap on corrupt input (UBSan)
                        PlaneStep(plane_[4], r);
                    }
                    if (flags_ & 4u) {
                        CascadeLoad(stride, nch);
                        int32_t nxt[4];
                        for (uint32_t c = 0; c < nch; ++c) nxt[c] = lms4[c];
                        for (int s = 3; s >= 0; --s) {
                            for (uint32_t c = 0; c < nch; ++c) {
                                ImgCascade& st = casc_[s][c];
                                const int64_t dot = (int64_t)st.coef[0] * st.hist[0] + (int64_t)st.coef[1] * st.hist[1]
                                                  + (int64_t)st.coef[2] * st.hist[2] + (int64_t)st.coef[3] * st.hist[3];
                                const int64_t sg = dot >> 63;
                                const uint64_t mag = (uint64_t)((dot ^ sg) - sg);
                                const uint32_t q = (uint32_t)(mag >> (casc[s * 4 + c] & 0x1fu));
                                const int32_t pred = (int32_t)((q ^ (uint32_t)sg) - (uint32_t)sg);
                                const int32_t in_v = nxt[c];
                                lvl[s][c] = WrapAdd(pred, in_v);
                                if (in_v != 0) {
                                    const int32_t sgn = in_v >> 31;
                                    for (int k = 0; k < 4; ++k) st.coef[k] = WrapAdd(st.coef[k], (int32_t)(((uint32_t)st.hist[k] ^ (uint32_t)sgn) - (uint32_t)sgn));
                                }
                            }
                            for (uint32_t c = 0; c < nch; ++c) nxt[c] = lvl[s][c];
                        }
                    } else {
                        for (uint32_t c = 0; c < nch; ++c) lvl[0][c] = lms4[c];
                    }
                    for (uint32_t c = 0; c < nch; ++c) {
                        d[c] = WrapAdd(plane_[c].pred, lvl[0][c]);
                        PlaneStep(plane_[c], lvl[0][c]);
                    }
                }
                for (uint32_t c = 0; c < nch; ++c) pr[c] = left[c];
                Predict2D(pr, stride, mode, nch);
                for (uint32_t c = 0; c < nch; ++c) {
                    const uint32_t v = pr[c] + (uint32_t)d[c];
                    left[c] = v;
                    if (bps == 1u) {
                        *outp++ = (uint8_t)v;
                    } else {
                        if (endian_ == 0u) { outp[1] = (uint8_t)v; outp[0] = (uint8_t)(v >> 8); }
                        else               { outp[0] = (uint8_t)v; outp[1] = (uint8_t)(v >> 8); }
                        outp += 2;
                    }
                }
                if ((flags_ & 2u) == 0u) {
                    for (uint32_t c = 0; c < nch; ++c) ring1_[r1_ + c] = (int16_t)left[c];
                    r1_ = (r1_ + nch) & 0x7fffu;
                } else {
                    for (uint32_t c = 0; c < nch; ++c) {
                        ring1_[r1_ + c] = (int16_t)left[c];
                        ring0_[r0_ + c * 4u + 0u] = (int16_t)lvl[0][c];
                        ring0_[r0_ + c * 4u + 1u] = (int16_t)lvl[1][c];
                        ring0_[r0_ + c * 4u + 2u] = (int16_t)lvl[2][c];
                        ring0_[r0_ + c * 4u + 3u] = (int16_t)lvl[3][c];
                    }
                    r0_ = (r0_ + nch * 4u) & 0xfffffu;
                    r1_ = (r1_ + nch) & 0x7fffu;
                }
            }
        }
        EndChunk();
        return 0;
    }

    // FUN_080a9ca0.
    size_t Decode(const uint8_t* in, size_t in_size, uint8_t* out, size_t out_size) {
        if (out_size == 0u || in_size == 0u) return 0;
        size_t consumed = 0, remaining = in_size;
        for (;;) {
            const uint32_t chunk = (out_size < 0x10000u) ? (uint32_t)out_size : 0x10000u;
            const int rc = DecodeChunk(in + consumed, &consumed, &remaining, out, chunk);
            if (rc != 0) { IMG_TRACE("chunk failed rc=%d consumed=%zu remaining=%zu\n", rc, consumed, remaining); return 0; }
            out_size -= chunk;
            if (out_size == 0u) return consumed;
            if (remaining == 0u) return 0;
            out += chunk;
        }
    }
};

NzImageModel::NzImageModel() = default;
NzImageModel::~NzImageModel() = default;

NzImageModel::Impl& NzImageModel::Get() {
    if (!impl_) {
        impl_.reset(new Impl());
        for (const PendingOp& op : pending_) {
            if (op.is_reset) impl_->Reset();
            else impl_->Configure(op.flags, op.order03, op.order4, op.variant_b);
        }
        pending_.clear();
        pending_.shrink_to_fit();
    }
    return *impl_;
}
void NzImageModel::Reset() {
    if (impl_) { impl_->Reset(); return; }
    if (pending_.empty() || !pending_.back().is_reset) pending_.push_back(PendingOp{true, 0u, 0u, 0u, false});
}
void NzImageModel::Configure(std::uint8_t flags, std::uint32_t order03, std::uint32_t order4, bool vb) {
    if (impl_) { impl_->Configure(flags, order03, order4, vb); return; }
    pending_.push_back(PendingOp{false, flags, order03, order4, vb});
}
std::size_t NzImageModel::Decode(const std::uint8_t* in, std::size_t in_size,
                                 std::uint8_t* out, std::size_t out_size) {
    return Get().Decode(in, in_size, out, out_size);
}

}  // namespace audio
}  // namespace nzr
