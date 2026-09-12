// nz_exefilter.cpp — the `dece` post-filter: x86 CALL/JMP address
// un-relativiser, ported from the community reference decoder (nzdec_v0
// NZ_x86.cpp). Faithful reimplementation.
#include "nz_env.h"
#include "nz_exefilter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

// Built once by NzCmInitAll() (nz_cm.cpp) and shared read-only by the CM
// decoder, the text transforms and this filter.
extern uint16_t kModelInterpolation[4096];
extern uint16_t kModelLutLookup[4096];

namespace {

static bool ExeTrace() {
    static const bool on = (NZ_ENV("NZOPT_TRACE_DECE") != nullptr);
    return on;
}
#define EXE_FAIL(...) do { if (ExeTrace()) std::fprintf(stderr, "[DECE] " __VA_ARGS__); } while (0)

// ArithmeticDecoder (nz.h) -- the same 12-bit range coder the sibling ports
// each carry a copy of.
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

// The encoder side of the same range coder (reference: the inlined coder in
// FUN_08090c00 / FUN_08090de0 / FUN_08091100). `end` is the descriptor's limit
// (base + cap/2); past it the reference keeps coding and drops the bytes.
struct ArithEnc {
    uint32_t lo = 0, hi = 0xffffffffu;
    uint8_t* cur = nullptr;
    uint8_t* end = nullptr;
    void Put(uint8_t b) { if (cur < end) *cur++ = b; }
    void Encode(bool bit, uint32_t p12) {
        const uint32_t mid = lo + ((hi - lo) >> 12) * p12;
        if (bit) hi = mid; else lo = mid + 1u;
        while ((hi ^ lo) < 0x1000000u) { Put((uint8_t)(hi >> 24)); hi = (hi << 8) | 0xffu; lo <<= 8; }
    }
    void EncodeModel(bool bit, uint32_t model16) { Encode(bit, model16 >> 4); }
    void Flush() { Put((uint8_t)(hi >> 24)); }
};

// FUN_080b1e70, the varint the decoder's ReadBackwardsVarint undoes: the FIRST
// byte carries the low 7 bits with 0x80 set, the rest the higher bits without.
static void PutBackwardsVarint(std::vector<uint8_t>* out, uint32_t v) {
    if (v < 0x80u) { out->push_back((uint8_t)(v | 0x80u)); return; }
    out->push_back((uint8_t)((v & 0x7fu) | 0x80u));
    v >>= 7;
    while (v >= 0x80u) { out->push_back((uint8_t)(v & 0x7fu)); v >>= 7; }
    out->push_back((uint8_t)v);
}

// BackwardsByteStream (nz.h): the two counts sit at the tail of the side
// stream and are read backwards; whatever is left in front is the arith stream.
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
};

// NOTE: this interpolation formula is NOT the same as xInterpolateModelLf in
// nz_text_transform.cpp. That one returns a plain two-point interpolation;
// this one folds in (value >> 4) and averages. Reusing the other would decode
// subtly wrong -- they only look alike.
template <int Scale>
static inline uint32_t ExeInterpolateModel(uint16_t* model_base, uint32_t value,
                                          uint32_t index, uint16_t** out_ptr) {
    const uint32_t hv = (uint32_t)kModelInterpolation[value >> 4] * (uint32_t)(Scale - 1);
    uint16_t* model = &model_base[(hv >> 12) + (uint32_t)Scale * index];
    const uint32_t frac = hv & 0xfffu;
    const uint32_t interpolated =
        ((value >> 4) + 3u * (((4096u - frac) * model[0] + (uint32_t)model[1] * frac) >> 16) + 2u) >> 2;
    model += frac >> 11;
    *out_ptr = model;
    return interpolated;
}

struct ExeModeModel {
    uint32_t history_;
    uint16_t model_a_[1024];
    uint16_t model_b_[512];

    ExeModeModel() {
        history_ = 0;
        for (uint32_t i = 0; i != 1024u; ++i) model_a_[i] = 0x8000u;
        model_b_[0] = 0;
        model_b_[7] = 0xffffu;  // reference stores -1 into a uint16
        for (uint32_t i = 1; i != 7u; ++i)
            model_b_[i] = (uint16_t)(16u * kModelLutLookup[i * 585u - 1u]);
        // Cascading replication: each write may read an entry this same loop
        // already produced.
        for (uint32_t i = 0; i != 504u; ++i) model_b_[i + 8] = model_b_[i];
    }

    // Returns 0, 1 or 2 -- the "mode" of the following instruction.
    uint32_t Get(ArithDec* adec, uint32_t context) {
        history_ *= 4u;
        uint32_t count = 0;
        for (;;) {
            uint16_t* model_a_ptr = &model_a_[4u * context + count];
            uint16_t* model_b_ptr = nullptr;
            const uint32_t b_value =
                ExeInterpolateModel<8>(model_b_, *model_a_ptr, history_ + count, &model_b_ptr);
            const bool flag = adec->ReadNoShift(b_value);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_a_ptr) >> 4));
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x1000eu) - *model_b_ptr) >> 4));
            if (!flag || ++count == 2u) break;
        }
        history_ = (history_ + count) & 0xFu;
        return count;
    }

    // FUN_08090c00, the inverse of Get: the flag is "the value is not reached
    // yet", so 0 costs one bit, 1 two and 2 two.
    void Put(ArithEnc* aenc, uint32_t context, uint32_t value) {
        history_ *= 4u;
        uint32_t count = 0;
        for (;;) {
            uint16_t* model_a_ptr = &model_a_[4u * context + count];
            uint16_t* model_b_ptr = nullptr;
            const uint32_t b_value =
                ExeInterpolateModel<8>(model_b_, *model_a_ptr, history_ + count, &model_b_ptr);
            const bool flag = (value != count);
            aenc->Encode(flag, b_value);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_a_ptr) >> 4));
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x1000eu) - *model_b_ptr) >> 4));
            if (!flag || ++count == 2u) break;
        }
        history_ = (history_ + value) & 0xFu;
    }
};

struct ExeOffsetModel {
    uint16_t model_a_[32];
    uint16_t model_b_[1922];
    uint16_t model_c_[18];

    ExeOffsetModel() {
        for (uint32_t i = 0; i != 32u; ++i) model_a_[i] = 0x8000u;
        for (uint32_t i = 0; i != 1922u; ++i) model_b_[i] = 0x8000u;
        for (uint32_t i = 0; i != 18u; ++i) model_c_[i] = 0x8000u;
    }

    // Returns false if the bit-count saturates: the reference lets `nbits`
    // reach 31, which makes model_base 62*31 == 1922 and indexes model_b_
    // exactly one past its own 1922 entries. The value is then written, so
    // this is a genuine out-of-bounds WRITE on a corrupt stream, not a benign
    // read. Decline instead.
    bool Get(ArithDec* adec, uint32_t type, uint32_t* out_value) {
        uint16_t* model_c_ptr = &model_c_[type];
        const bool sign = adec->Read(*model_c_ptr);
        *model_c_ptr = (uint16_t)(*model_c_ptr +
            ((((uint32_t)sign * 0x10000u) + 8u - *model_c_ptr) >> 4));

        uint32_t nbits = 0xffffffffu;
        while (++nbits != 31u) {
            uint16_t* model_a_ptr = &model_a_[nbits];
            const bool flag = adec->Read(*model_a_ptr);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 4u - *model_a_ptr) >> 3));
            if (!flag) break;
        }
        if (nbits >= 31u) {
            EXE_FAIL("offset model: nbits saturated at 31 (would index model_b_[1922])\n");
            return false;
        }

        const uint32_t isign = (uint32_t)(-(int32_t)sign);
        const uint32_t model_base = 62u * nbits;
        uint32_t result = (nbits != 0u);
        nbits += (nbits == 0u);
        uint32_t last = isign & 1u;
        for (uint32_t i = 0; i < nbits; i++) {
            uint16_t* model_b_ptr = &model_b_[model_base + last + i * 2u];
            const bool flag = adec->Read(*model_b_ptr);
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_b_ptr) >> 4));
            result = result * 2u + flag;
            last = flag;
        }
        *out_value = isign ^ result;
        return true;
    }

    // FUN_08090de0. The reference stops the bit-count unary at 30 where the
    // decoder's loop would still read a flag at 30 -- unreachable, since the
    // caller only offers displacements that fit in 25 bits (bsr <= 23).
    void Put(ArithEnc* aenc, uint32_t type, uint32_t value) {
        const uint32_t isign = (uint32_t)((int32_t)value >> 31);
        const bool sign = (isign != 0u);
        uint16_t* model_c_ptr = &model_c_[type];
        aenc->EncodeModel(sign, *model_c_ptr);
        *model_c_ptr = (uint16_t)(*model_c_ptr +
            ((((uint32_t)sign * 0x10000u) + 8u - *model_c_ptr) >> 4));

        const uint32_t mag = isign ^ value;
        uint32_t nbits = 0xffffffffu;
        uint32_t rest = mag;
        for (;;) {
            ++nbits;
            if (nbits == 30u) break;
            uint16_t* model_a_ptr = &model_a_[nbits];
            rest >>= 1;
            const bool flag = (rest != 0u);
            aenc->EncodeModel(flag, *model_a_ptr);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 4u - *model_a_ptr) >> 3));
            if (!flag) break;
        }

        const uint32_t count = nbits + (nbits == 0u ? 1u : 0u);
        const uint32_t model_base = 62u * nbits;
        uint32_t bits = mag << ((32u - count) & 31u);
        uint32_t last = isign & 1u;
        for (uint32_t i = 0; i < count; ++i) {
            uint16_t* model_b_ptr = &model_b_[model_base + last + i * 2u];
            const bool flag = ((int32_t)bits < 0);
            bits <<= 1;
            aenc->EncodeModel(flag, *model_b_ptr);
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_b_ptr) >> 4));
            last = flag ? 1u : 0u;
        }
    }
};

struct ExeJumpRecentModel {
    uint16_t model_a_[8];
    uint16_t model_b_[512];

    ExeJumpRecentModel() {
        for (uint32_t i = 0; i != 8u; ++i) model_a_[i] = 0x8000u;
        for (uint32_t i = 0; i != 512u; ++i) model_b_[i] = 0x8000u;
    }

    // Returns a recent-jump slot index in [0, 255].
    uint32_t Get(ArithDec* adec) {
        uint32_t nbits = 0xffffffffu;
        while (++nbits != 7u) {
            uint16_t* model_a_ptr = &model_a_[nbits];
            const bool flag = adec->Read(*model_a_ptr);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_a_ptr) >> 4));
            if (flag) break;
        }
        const uint32_t model_base = 1u << nbits;
        uint32_t result = (nbits != 0u);
        nbits += (nbits == 0u);
        do {
            uint16_t* model_b_ptr = &model_b_[model_base + result];
            const bool flag = adec->Read(*model_b_ptr);
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_b_ptr) >> 4));
            result = result * 2u + flag;
        } while (--nbits);
        return result;
    }

    // FUN_08091100. Note the polarity: here the unary flag means STOP, the
    // opposite of ExeOffsetModel's.
    void Put(ArithEnc* aenc, uint32_t slot) {
        uint32_t nbits = 0xffffffffu;
        uint32_t rest = slot;
        for (;;) {
            ++nbits;
            if (nbits == 7u) break;
            uint16_t* model_a_ptr = &model_a_[nbits];
            rest >>= 1;
            const bool flag = (rest == 0u);
            aenc->EncodeModel(flag, *model_a_ptr);
            *model_a_ptr = (uint16_t)(*model_a_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_a_ptr) >> 4));
            if (flag) break;
        }
        const uint32_t model_base = 1u << nbits;
        uint32_t result = (nbits != 0u) ? 1u : 0u;
        uint32_t count = nbits + (nbits == 0u ? 1u : 0u);
        uint32_t bits = slot << ((32u - count) & 31u);
        for (;;) {
            uint16_t* model_b_ptr = &model_b_[model_base + result];
            const bool flag = ((int32_t)bits < 0);
            bits <<= 1;
            aenc->EncodeModel(flag, *model_b_ptr);
            *model_b_ptr = (uint16_t)(*model_b_ptr +
                ((((uint32_t)flag * 0x10000u) + 8u - *model_b_ptr) >> 4));
            if (--count == 0u) return;
            result = (flag ? 1u : 0u) + result * 2u;
        }
    }
};

// ~63 KB of models; heap-allocated rather than left on the stack the way the
// reference does, since this runs at the bottom of a deep decode chain.
struct ExeModels {
    ExeModeModel jump_mode, call_mode, call_recent;
    ExeModeModel jcc_mode[16];
    ExeOffsetModel jump_offset;
    ExeJumpRecentModel jump_recent;
};

static void StoreU32LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

}  // namespace


// ---------------------------------------------------------------------------
// Run state. Only the recent-target caches and the base persist across a run of
// consecutive dece blocks; the probability models above are rebuilt per block,
// exactly as the reference's Decode-locals are.
// ---------------------------------------------------------------------------
struct NzExeFilter::Impl {
    uint32_t recent_call[3];
    uint32_t recent_jump[256];
    uint32_t carry;   // the reference's exe_base_: output bytes this run has made

    Impl() { Reset(); }

    void Reset() {
        for (uint32_t i = 0; i != 3u; ++i) recent_call[i] = i;
        for (uint32_t i = 0; i != 256u; ++i) recent_jump[i] = i;
        carry = 0;
    }

    bool Decode(const uint8_t* side, uint32_t side_len,
                const uint8_t* in, uint32_t in_size,
                uint8_t* out, uint32_t out_cap, uint32_t* out_size) {
        auto m = std::unique_ptr<ExeModels>(new ExeModels());

        BackwardsByteStream backwards(side, side_len);
        const uint32_t num_call_offs = backwards.ReadBackwardsVarint();
        const uint32_t num_call = backwards.ReadBackwardsVarint() + num_call_offs;

        const uint8_t* const in_true_end = in + in_size;
        const uint8_t* in_end = in_true_end;
        uint8_t* const out_org = out;
        uint8_t* const out_end = out + out_cap;

        // The tail of the input carries the raw side data: `num_call` add-esp
        // immediates, then `num_call_offs` big-endian 32-bit call targets.
        // Computed in uint64 so a 32-bit size_t cannot wrap the guard.
        const uint64_t end_bytes = (uint64_t)num_call_offs * 4u + num_call;
        if (end_bytes >= (uint64_t)(in_end - in)) {
            EXE_FAIL("end_bytes %llu >= input %u\n", (unsigned long long)end_bytes, in_size);
            return false;
        }
        in_end -= end_bytes;

        const uint8_t* addesp_stream = in_end;
        const uint8_t* const addesp_end = addesp_stream + num_call;
        const uint8_t* offs_stream = addesp_end;
        const uint8_t* const offs_end = offs_stream + (size_t)num_call_offs * 4u;

        ArithDec adec;
        adec.InitializeX(backwards.ptr_, backwards.ptr_end_);
        adec.FillBuffer();

        // The reference works in truncated pointer values:
        //     base   = (uint32)out_org - exe_base_
        //     stored = offs + base - (uint32)out
        //     offs   = model + (uint32)out - base       (non-recent jump)
        // The absolute addresses cancel exactly, leaving the RUN-RELATIVE
        // output position P = carry + (out - out_org). Working in offsets is
        // bit-identical and, unlike casting a 64-bit pointer down to uint32,
        // well defined. The algebra also collapses the non-recent jump case to
        // "stored == the model value".
        uint32_t jump_mode = 0, jump_type = 0, offs = 0;

        for (;;) {
            const uint8_t prev_byte = (out > out_org) ? out[-1] : 0u;

            if (in >= in_end || out >= out_end) break;

            const uint8_t b = *in++;
            *out++ = b;

            bool handle_jump = false;

            if (b == 0xe8u) {
                const uint32_t call_mode = m->call_mode.Get(&adec, prev_byte);
                if (call_mode >= 1u) {
                    uint32_t coffs;
                    if (call_mode == 1u) {
                        uint32_t recent = m->call_recent.Get(&adec, prev_byte);  // 0..2
                        coffs = recent_call[recent];
                        if (recent) {
                            do {
                                recent_call[recent] = recent_call[recent - 1u];
                            } while (--recent);
                            recent_call[0] = coffs;
                        }
                    } else {
                        if ((size_t)(offs_end - offs_stream) < 4u) {
                            EXE_FAIL("call target stream exhausted\n");
                            return false;
                        }
                        coffs = (uint32_t)offs_stream[3] |
                                ((uint32_t)offs_stream[2] << 8) |
                                ((uint32_t)offs_stream[1] << 16) |
                                ((uint32_t)offs_stream[0] << 24);
                        offs_stream += 4;
                        recent_call[2] = recent_call[1];
                        recent_call[1] = recent_call[0];
                        recent_call[0] = coffs;
                    }
                    // The reference writes these 4 bytes (and the 3 add-esp
                    // bytes) with no room check at all -- the loop only tests
                    // out >= out_end at the top, so it can run up to 7 bytes
                    // past the buffer.
                    if ((size_t)(out_end - out) < 4u) {
                        EXE_FAIL("no room for call displacement\n");
                        return false;
                    }
                    StoreU32LE(out, coffs - (carry + (uint32_t)(out - out_org)));
                    out += 4;

                    if (addesp_stream >= addesp_end) {
                        EXE_FAIL("add-esp stream exhausted\n");
                        return false;
                    }
                    const uint8_t sp_val = *addesp_stream++;
                    if (sp_val) {
                        if ((size_t)(out_end - out) < 3u) {
                            EXE_FAIL("no room for add-esp\n");
                            return false;
                        }
                        out[0] = 0x83u; out[1] = 0xc4u; out[2] = sp_val;
                        out += 3;
                    }
                }
            } else if (b == 0xe9u) {
                jump_mode = m->jump_mode.Get(&adec, prev_byte);
                jump_type = 0;
                handle_jump = true;
            } else if (b == 0x0fu) {
                // The reference peeks past its own reduced in_end into the
                // side-stream tail, which is still inside the caller's buffer,
                // so bound the peek by the TRUE input end: faithful and
                // in-bounds both.
                if (in < in_true_end) {
                    const uint8_t b2 = *in;
                    if ((b2 & 0xF0u) == 0x80u && !(b2 >= 0x8Au && b2 <= 0x8Bu)) {
                        if (out >= out_end) break;
                        *out++ = b2;
                        in++;
                        jump_type = (uint32_t)(b2 & 0xFu) + 1u;
                        jump_mode = m->jcc_mode[b2 & 0xFu].Get(&adec, 0x80u | (uint32_t)(prev_byte >> 4));
                        handle_jump = true;
                    }
                }
            }

            if (handle_jump && jump_mode >= 1u) {
                if (jump_mode == 1u) {
                    uint32_t recent = m->jump_recent.Get(&adec);  // 0..255
                    offs = recent_jump[recent];
                    if (recent) {
                        do {
                            recent_jump[recent] = recent_jump[recent - 1u];
                        } while (--recent);
                        recent_jump[0] = offs;
                    }
                } else {
                    uint32_t model_value = 0;
                    if (!m->jump_offset.Get(&adec, jump_type, &model_value)) return false;
                    offs = model_value + carry + (uint32_t)(out - out_org);
                    for (size_t i = 255; i != 0; i--) recent_jump[i] = recent_jump[i - 1];
                    recent_jump[0] = offs;
                }
                if ((size_t)(out_end - out) < 4u) {
                    EXE_FAIL("no room for jump displacement\n");
                    return false;
                }
                StoreU32LE(out, offs - (carry + (uint32_t)(out - out_org)));
                out += 4;
            }
        }

        // Both raw side streams must end up EXACTLY consumed. On every real
        // archive they do, so a leftover means the instruction stream and the
        // side data disagree -- i.e. we decoded garbage that happened not to
        // trip any other check. Turning that into a decline converts a
        // silent-wrong-output path into a clean failure (the arithmetic stream
        // has no equivalent gate: once exhausted its reader just returns zero
        // bytes forever, and only the entry checksum catches that).
        if (addesp_stream != addesp_end || offs_stream != offs_end) {
            EXE_FAIL("side streams not fully consumed: addesp %ld left, offs %ld left\n",
                     (long)(addesp_end - addesp_stream), (long)(offs_end - offs_stream));
            return false;
        }

        const uint32_t produced = (uint32_t)(out - out_org);
        // FUN_080b98e0 masks the accumulated base to 23 bits; a run whose
        // output passes 8 MB therefore restarts its reference frame, and a
        // decoder that does not mask would disagree with the compressor's
        // recent-target cache from that point on.
        carry = (carry + produced) & 0x7fffffu;
        *out_size = produced;
        return true;
    }
};

NzExeFilter::NzExeFilter() : impl_(new Impl()) {}
NzExeFilter::~NzExeFilter() = default;
void NzExeFilter::Reset() { impl_->Reset(); }

bool NzExeFilter::Decode(const std::uint8_t* side, std::uint32_t side_len,
                         const std::uint8_t* in, std::uint32_t in_size,
                         std::uint8_t* out, std::uint32_t out_cap,
                         std::uint32_t* out_size) {
    if (out_size == nullptr) return false;
    return impl_->Decode(side, side_len, in, in_size, out, out_cap, out_size);
}

std::uint64_t NzExeFilter::DecodedSizeBound(const std::uint8_t* side, std::uint32_t side_len,
                                            std::uint32_t in_size) {
    // Every output byte is one of:
    //   - an instruction byte copied 1:1            (at most in_size of them)
    //   - a restored JUMP/Jcc displacement, 4 bytes. These are driven by the
    //     ARITHMETIC decoder and consume NO side-stream byte, so nothing in the
    //     side stream counts them -- only the input does, since each needs its
    //     own opcode byte. That is what makes 5 * in_size the leading term.
    //   - a restored CALL displacement, 4 bytes, plus an optional 3-byte add-esp
    //     -- one `addesp_stream` byte each, so `num_call` of them at most.
    // Hence in_size + 4*in_size + 7*num_call. Loose, but sound, and still a
    // small multiple of the BLOCK where the alternative is the whole rest of
    // the stream's output.
    const std::uint64_t n = in_size;
    if (side == nullptr || side_len == 0u) return n * 5u + 16u;
    BackwardsByteStream backwards(side, side_len);
    const std::uint32_t num_call_offs = backwards.ReadBackwardsVarint();
    const std::uint32_t num_call = backwards.ReadBackwardsVarint() + num_call_offs;
    return n * 5u + static_cast<std::uint64_t>(num_call) * 7u + 16u;
}


// ---------------------------------------------------------------------------
// The encoder (reference FUN_08090360). Its decisions are: which of the three
// instruction shapes this byte starts, whether the displacement is small
// enough to touch, and whether the resulting target is already in a recent
// cache. Everything else is bookkeeping the decoder mirrors exactly.
// ---------------------------------------------------------------------------
namespace {

// (&DAT_081b3180)[b] & 8 -- dumped from a live process: set for 0x80..0x89
// and 0x8c..0x8f, i.e. exactly the Jcc rel32 opcodes, which is the predicate
// the decoder already spells out.
static inline bool IsJccSecondByte(uint8_t b) {
    return (b & 0xF0u) == 0x80u && !(b >= 0x8Au && b <= 0x8Bu);
}

static inline uint32_t LoadU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// (disp >> 24) + 1 < 2 unsigned, i.e. the sign-extended top byte is 0 or -1:
// a displacement that fits in 25 bits.
static inline bool DispFits(int32_t disp) {
    return (uint32_t)((disp >> 24) + 1) < 2u;
}

}  // namespace

struct NzExeFilterEnc::EncImpl {
    uint32_t recent_call[3];
    uint32_t recent_jump[256];
    uint32_t carry;

    EncImpl() { Reset(); }

    void Reset() {                                     // FUN_080b98a0
        for (uint32_t i = 0; i != 3u; ++i) recent_call[i] = i;
        for (uint32_t i = 0; i != 256u; ++i) recent_jump[i] = i;
        carry = 0;
    }
    void Advance(uint32_t n) { carry = (carry + n) & 0x7fffffu; }   // FUN_080b98e0

    uint32_t Encode(const uint8_t* in, uint32_t n,
                    std::vector<uint8_t>* out_v, std::vector<uint8_t>* side_v) {
        out_v->clear();
        side_v->clear();
        if (n == 0u) return 0;

        auto m = std::unique_ptr<ExeModels>(new ExeModels());

        // The reference reads up to 4 bytes past the block when it looks at a
        // displacement before checking that the instruction fits (and one past
        // it for the byte after a trailing 0x0f); in the compressor those bytes
        // are the rest of its own block allocation. A zero-padded copy gives
        // the same answer without touching memory we do not own.
        std::vector<uint8_t> padded((size_t)n + 8u, 0);
        std::memcpy(padded.data(), in, n);
        const uint8_t* const base = padded.data();
        const uint8_t* const in_end = base + n;

        // Room for the worst case: every transformed call with a NEW target
        // costs the payload 4 bytes but adds 1 add-esp byte and 4 target
        // bytes, so the total can exceed n by one byte per such call (at most
        // one per five input bytes). The reference writes into its own block
        // buffer and relies on that buffer's slack.
        out_v->assign((size_t)n + (size_t)n / 4u + 64u, 0);
        // The two raw areas the reference carves out of the scratch past the
        // block buffers: the add-esp bytes get n/8 (overflowing it is what
        // makes the filter decline), the call targets whatever follows.
        const uint32_t addesp_cap = ((n >> 3) + 3u) & ~3u;
        std::vector<uint8_t> addesp((size_t)addesp_cap + (size_t)n / 4u + 8u, 0);
        std::vector<uint8_t> offs((size_t)n + 8u, 0);

        std::vector<uint8_t> side;
        side.assign(kSideCap >> 1, 0);
        ArithEnc aenc;
        aenc.cur = side.data();
        aenc.end = side.data() + (kSideCap >> 1);

        const uint8_t* p = base;
        uint8_t* o = out_v->data();
        uint8_t* ae = addesp.data();
        uint8_t* of = offs.data();
        bool addesp_overflow = false;

        for (;;) {
            if (p >= in_end) break;
            const uint32_t prev = (p > base) ? (uint32_t)p[-1] : 0u;
            const uint8_t* const at = p;
            const uint8_t b = *p++;
            *o++ = b;

            if (b == 0xe8u) {
                const int32_t disp = (int32_t)LoadU32LE(p);
                const uint32_t target =
                    (uint32_t)disp + carry + (uint32_t)(p - base);
                if (DispFits(disp) && at + 8 <= in_end) {
                    uint32_t slot = 3;
                    if (target == recent_call[0]) slot = 0;
                    else if (target == recent_call[1]) slot = 1;
                    else if (target == recent_call[2]) slot = 2;
                    p += 4;
                    m->call_mode.Put(&aenc, prev, slot == 3u ? 2u : 1u);
                    uint8_t sp = 0;
                    if (p[0] == 0x83u && p[1] == 0xc4u && p[2] != 0u) { sp = p[2]; p += 3; }
                    if (ae < addesp.data() + addesp.size()) *ae = sp;
                    ++ae;
                    if (ae > addesp.data() + addesp_cap) addesp_overflow = true;
                    if (slot == 3u) {
                        const uint32_t t1 = recent_call[1];
                        recent_call[1] = recent_call[0];
                        recent_call[2] = t1;
                        recent_call[0] = target;
                        of[0] = (uint8_t)(target >> 24); of[1] = (uint8_t)(target >> 16);
                        of[2] = (uint8_t)(target >> 8);  of[3] = (uint8_t)target;
                        of += 4;
                    } else {
                        if (slot != 0u) {
                            for (uint32_t k = slot; k != 0u; --k) recent_call[k] = recent_call[k - 1u];
                            recent_call[0] = target;
                        }
                        m->call_recent.Put(&aenc, prev, slot);
                    }
                } else {
                    m->call_mode.Put(&aenc, prev, 0);
                }
            } else if (b == 0xe9u) {
                const int32_t disp = (int32_t)LoadU32LE(p);
                const uint32_t target =
                    (uint32_t)disp + carry + (uint32_t)(p - base);
                if (DispFits(disp) && at + 5 <= in_end) {
                    p += 4;
                    uint32_t slot = 0x100;
                    if (target == recent_jump[0]) slot = 0;
                    else {
                        for (uint32_t k = 1; k != 0x100u; ++k)
                            if (target == recent_jump[k]) { slot = k; break; }
                    }
                    if (slot != 0x100u) {
                        m->jump_mode.Put(&aenc, prev, 1);
                        if (slot != 0u) {
                            for (uint32_t k = slot; k != 0u; --k) recent_jump[k] = recent_jump[k - 1u];
                            recent_jump[0] = target;
                        }
                        m->jump_recent.Put(&aenc, slot);
                    } else {
                        m->jump_mode.Put(&aenc, prev, 2);
                        for (uint32_t k = 255; k != 0u; --k) recent_jump[k] = recent_jump[k - 1u];
                        recent_jump[0] = target;
                        m->jump_offset.Put(&aenc, 0, (uint32_t)disp);
                    }
                } else {
                    m->jump_mode.Put(&aenc, prev, 0);
                }
            } else if (b == 0x0fu) {
                const uint8_t b2 = *p;                 // the over-read above
                if (IsJccSecondByte(b2)) {
                    if (p >= in_end) break;            // nothing but the 0x0f left
                    const uint32_t lo4 = b2 & 0xfu;
                    *o++ = b2;
                    ++p;                               // both opcode bytes consumed
                    const int32_t disp = (int32_t)LoadU32LE(p);
                    const uint32_t target =
                        (uint32_t)disp + carry + (uint32_t)(p - base);
                    const uint32_t ctx = (prev >> 4) ^ (uint32_t)(b2 & 0xf0u);
                    if (DispFits(disp) && at + 6 <= in_end) {
                        p += 4;
                        uint32_t slot = 0x100;
                        if (target == recent_jump[0]) slot = 0;
                        else {
                            for (uint32_t k = 1; k != 0x100u; ++k)
                                if (target == recent_jump[k]) { slot = k; break; }
                        }
                        if (slot != 0x100u) {
                            m->jcc_mode[lo4].Put(&aenc, ctx, 1);
                            if (slot != 0u) {
                                for (uint32_t k = slot; k != 0u; --k)
                                    recent_jump[k] = recent_jump[k - 1u];
                                recent_jump[0] = target;
                            }
                            m->jump_recent.Put(&aenc, slot);
                        } else {
                            m->jcc_mode[lo4].Put(&aenc, ctx, 2);
                            for (uint32_t k = 255; k != 0u; --k)
                                recent_jump[k] = recent_jump[k - 1u];
                            recent_jump[0] = target;
                            m->jump_offset.Put(&aenc, lo4 + 1u, (uint32_t)disp);
                        }
                    } else {
                        m->jcc_mode[lo4].Put(&aenc, ctx, 0);
                    }
                }
            }
        }

        // The reference declines when the add-esp area ran into the call-target
        // area (its own writes have already corrupted the targets by then; we
        // just take the decision).
        if (addesp_overflow) return 0;

        aenc.Flush();
        const uint32_t n_addesp = (uint32_t)(ae - addesp.data());
        const uint32_t n_offs = (uint32_t)(of - offs.data());
        const uint32_t body = (uint32_t)(o - out_v->data());

        std::memcpy(out_v->data() + body, addesp.data(), n_addesp);
        std::memcpy(out_v->data() + body + n_addesp, offs.data(), n_offs);
        out_v->resize((size_t)body + n_addesp + n_offs);

        const uint32_t used = (uint32_t)(aenc.cur - side.data());
        side.resize(used);
        PutBackwardsVarint(&side, n_addesp - (n_offs >> 2));
        PutBackwardsVarint(&side, n_offs >> 2);
        // Reaching the descriptor's limit is an "Internal error" abort in the
        // reference (FUN_08048370 right here). Unreachable in practice -- half
        // of 0x108001 bytes of arithmetic stream is far more than a block can
        // produce -- so decline instead of aborting.
        if (side.size() >= (size_t)(kSideCap >> 1)) return 0;
        *side_v = std::move(side);
        return body + n_addesp + n_offs;
    }
};

NzExeFilterEnc::NzExeFilterEnc() : impl_(new EncImpl()) {}
NzExeFilterEnc::~NzExeFilterEnc() = default;
void NzExeFilterEnc::Reset() { impl_->Reset(); }
void NzExeFilterEnc::Advance(std::uint32_t n) { impl_->Advance(n); }
std::uint32_t NzExeFilterEnc::Encode(const std::uint8_t* in, std::uint32_t n,
                                     std::vector<std::uint8_t>* out,
                                     std::vector<std::uint8_t>* side) {
    if (in == nullptr || out == nullptr || side == nullptr) return 0;
    return impl_->Encode(in, n, out, side);
}
