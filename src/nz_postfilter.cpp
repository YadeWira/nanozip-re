// nz_postfilter.cpp — NanoZip CM/BWT post-filters, ported from nzdec_v0 NZ.cpp
// (BwtRleExpander) and nz.h (ArithmeticDecoder). Faithful reimplementation.
#include "nz_env.h"
#include "nz_postfilter.h"
#include <cstring>
#include <vector>
#include <cstdio>
#include <cstdlib>

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

// ---------------------------------------------------------------------------
// The ENCODER side of the u32 RLE, i.e. param2 (FUN_0808ff20 -> FUN_080902e0 ->
// FUN_080901e0), for the -co family's compressor. It is the same shape as the
// byte-wise collapse the BWT bucket coder uses, over 32-bit words and with the
// threshold the decoder's DecodeU32 reads: SIX words equal to the one before
// them open a run, the rest of the run is written as BSR(L) further copies --
// the class DecodeInt's bit tree needs -- and L itself goes into an arithmetic
// side stream of its own. The trailing n & 3 bytes are copied verbatim.
// ---------------------------------------------------------------------------
struct ArithEnc {
    uint32_t lo = 0, hi = 0xffffffffu;
    uint8_t* cur = nullptr;
    uint8_t* end = nullptr;
    bool overflow = false;
    void Put(uint8_t b) { if (cur < end) *cur++ = b; else overflow = true; }
    void Encode(bool bit, uint32_t p12) {
        const uint32_t mid = lo + ((hi - lo) >> 12) * p12;
        if (bit) hi = mid; else lo = mid + 1u;
        while ((hi ^ lo) < 0x1000000u) { Put((uint8_t)(hi >> 24)); hi = (hi << 8) | 0xffu; lo <<= 8; }
    }
    void EncodeModel(bool bit, uint32_t model16) { Encode(bit, model16 >> 4); }
    void EncodeRaw(uint32_t v, uint32_t nbits) { while (nbits--) Encode(((v >> nbits) & 1u) != 0u, 0x800u); }
    void Flush() { Put((uint8_t)(hi >> 24)); }
};

struct BwtRleSideEnc {
    ArithEnc enc;
    uint16_t model_[32];
    BwtRleSideEnc(uint8_t* base, uint8_t* end) {
        enc.cur = base; enc.end = end;
        for (uint32_t i = 0; i < 32u; ++i) model_[i] = 0x8000u;
    }
    // The inverse of BwtRleExpander::DecodeInt: `x` is the class the byte stream
    // carries, L the run length it has to yield back.
    void EncodeInt(uint32_t L, uint32_t x) {
        const uint32_t k = x < 4u ? x : 4u;
        const uint32_t n = 1u << k;
        const uint32_t xx = x + (x == 0u);
        const uint32_t high = (xx > 4u) ? (L >> (xx - 4u)) : L;
        const uint32_t nflags = (x == 0u) ? 1u : k;
        uint32_t i = 1;
        for (uint32_t j = 0; j < nflags; ++j) {
            const bool flag = ((high >> (nflags - 1u - j)) & 1u) != 0u;
            uint16_t* m = &model_[i + n];
            enc.EncodeModel(flag, *m);
            *m = (uint16_t)(*m + ((0x80u - *m + ((uint32_t)flag << 16)) >> 8));
            i = i * 2u + flag;
        }
        if (xx > 4u) enc.EncodeRaw(L & ((1u << (xx - 4u)) - 1u), xx - 4u);
    }
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
        const bool trace = NZ_ENV("NZOPT_TRACE_RLE") != nullptr;
        const uint32_t out_size_orig = *out_size_ptr;
        uint32_t out_size_u32 = *out_size_ptr >> 2;
        uint32_t in_size_u32 = in_size >> 2;
        if (in_size_u32 > out_size_u32) {
            if (trace) fprintf(stderr, "[RLE] fail@entry in_size=%u out_size=%u in_size_u32=%u out_size_u32=%u\n",
                                in_size, out_size_orig, in_size_u32, out_size_u32);
            *out_size_ptr = 0; return false;
        }
        const uint8_t* in32 = in;                       // byte cursors, read as u32 via memcpy
        const uint8_t* in32_end = in + in_size_u32 * 4u;
        uint8_t* out32 = out;
        uint8_t* out32_end = out + out_size_u32 * 4u;
        auto ld = [](const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; };
        auto st = [](uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); };
        uint32_t v = 0;
        int iter = 0;
        for (;;) {
            ++iter;
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
                if (run_len > 30u) {
                    if (trace) {
                        fprintf(stderr, "[RLE] fail@run_len iter=%d run_len=%u in_off=%zu last_v=0x%08x in_size=%u\n",
                                iter, run_len, (size_t)(in32 - in), last_v, in_size);
                        fprintf(stderr, "[RLE] context bytes around start_run (in_off=%zu):", (size_t)(start_run - in));
                        for (std::size_t k = (start_run - in >= 8 ? (size_t)(start_run - in) - 8 : 0);
                             k < (size_t)(start_run - in) + 24 && k < in_size; ++k) {
                            fprintf(stderr, " %02x", in[k]);
                        }
                        fprintf(stderr, "\n");
                    }
                    *out_size_ptr = 0; return false;
                }
                uint32_t new_len = DecodeInt(run_len);
                const uint32_t out_words_left = (uint32_t)((out32_end - out32) / 4);
                const uint32_t in_words_left = (uint32_t)((in32_end - in32) / 4);
                if (out_words_left < in_words_left + new_len) {
                    if (trace) fprintf(stderr, "[RLE] fail@space iter=%d run_len=%u new_len=%u out_words_left=%u in_words_left=%u in_off=%zu out_off=%zu\n",
                                        iter, run_len, new_len, out_words_left, in_words_left,
                                        (size_t)(in32 - in), (size_t)(out32 - out));
                    *out_size_ptr = 0; return false;
                }
                for (uint32_t i = 0; i != new_len; ++i) { st(out32, last_v); out32 += 4; }
            }
            cont:;
        }
        // copy trailing (sub-word) bytes verbatim
        const uint8_t* in_end = in + in_size;
        uint8_t* out_end = out + *out_size_ptr;
        if ((in_end - in32) > (out_end - out32)) {
            if (trace) fprintf(stderr, "[RLE] fail@tail in_left=%zu out_left=%zu\n",
                                (size_t)(in_end - in32), (size_t)(out_end - out32));
            *out_size_ptr = 0; return false;
        }
        while (in32 != in_end) *out32++ = *in32++;
        *out_size_ptr = (uint32_t)(out32 - out);
        if (trace) fprintf(stderr, "[RLE] ok final_size=%u iters=%d\n", *out_size_ptr, iter);
        return true;
    }
};

}  // namespace

// FUN_0808ff20: the whole param2 attempt. Returns the collapsed size (always a
// multiple of 4 plus the n & 3 tail) with the run lengths in `*side`, or 0 when
// the side stream ran out of the room it was given.
uint32_t NzPostfilterParam2Encode(const uint8_t* in, uint32_t in_size,
                                  uint8_t* out, uint32_t out_cap,
                                  std::vector<uint8_t>* side, uint32_t side_cap) {
    if (in_size == 0u || out_cap < in_size || side == nullptr) return 0;
    side->assign(side_cap, 0);
    BwtRleSideEnc sw(side->data(), side->data() + side_cap);
    const uint32_t nwords = in_size >> 2;
    auto ld = [](const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; };
    auto st = [](uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); };

    const uint8_t* p = in;
    const uint8_t* const wend = in + nwords * 4u;
    uint8_t* o = out;
    uint32_t prev = 0;                       // the phantom zero the decoder starts from
    while (p < wend) {
        uint32_t v = ld(p); p += 4; st(o, v); o += 4;
        if (v != prev) { prev = v; continue; }
        // five more equal words (six with the one above) open a run
        uint32_t equal = 1;
        while (equal < 6u && p < wend) {
            v = ld(p); p += 4; st(o, v); o += 4;
            if (v != prev) break;
            ++equal;
        }
        if (equal < 6u) { prev = v; continue; }
        const uint8_t* q = p;
        while (q < wend && ld(q) == prev) q += 4;
        const uint32_t L = (uint32_t)((q - p) / 4);
        p = q;
        uint32_t cls = 0;
        if (L > 1u) { uint32_t t = L >> 1; do { ++cls; st(o, prev); o += 4; t >>= 1; } while (t != 0u); }
        sw.EncodeInt(L, cls);
    }
    sw.enc.Flush();
    if (sw.enc.overflow) { side->clear(); return 0; }
    side->resize((size_t)(sw.enc.cur - side->data()));
    // FUN_080902e0's tail: the bytes below the last whole word are copied as they are
    for (const uint8_t* t = wend; t < in + in_size; ++t) *o++ = *t;
    return (uint32_t)(o - out);
}

bool NzBwtRleDecodeU32(const uint8_t* model_data, uint32_t model_len,
                       const uint8_t* in, uint32_t in_size,
                       uint8_t* out, uint32_t* out_size) {
    BwtRleExpander rle(model_data, model_data + model_len);
    return rle.DecodeU32(in, in_size, out, out_size);
}

// ---------------------------------------------------------------------------
// param1 = AddBytesFilter (NZ.cpp + nz.h BitReader). Faithful port.
// ---------------------------------------------------------------------------
namespace {

static uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

// kBitcountToMask[i] = low-i-bit mask; [0]=0, [32]=0xffffffff.
static uint32_t bitmask(uint32_t nb) { return nb >= 32u ? 0xffffffffu : ((1u << nb) - 1u); }

struct BitReader {
    uint32_t bitcount_, bitbuff_;
    const uint8_t *ptr_, *ptr_end_;
    void Initialize(const uint8_t* data, size_t size) {
        bitcount_ = 0; bitbuff_ = 0;
        ptr_ = data;
        // Reference computes ptr_end_ = data + size EXACTLY (nz.h BitReader),
        // i.e. it does NOT round down to a multiple of 4 -- the "should I fetch
        // another word" test is a raw byte-address comparison, so whenever
        // `size` isn't a multiple of 4 the reference still performs one more
        // (partial) word fetch to reach the final 1-3 trailing bytes, which can
        // carry real bits the decode still needs (a param1 side-stream is only
        // as long as its last meaningful bit, not padded to a u32 boundary).
        // A prior port rounded this down (`size & ~3`), silently dropping the
        // final partial word whenever size % 4 != 0 -- this under-read starved
        // GetY()/GetZ() of real trailing bits, corrupting copy_offset/
        // start_offset/num_delta for the tail of the stream. See
        // NzAddBytesFilter's real-corpus failures (e.g. psionmai.doc, 6-byte
        // param1_data against a 10229-byte block) for the reproduction.
        ptr_end_ = data + size;
    }
    // Fetch the next 32-bit big-endian-ordered word. Unlike the reference's
    // raw `*ptr_++` (which can read up to 3 bytes past `data+size` into
    // whatever memory happens to follow -- harmless there only because a
    // trailing partial word's out-of-range bits are never actually consumed
    // before Process() finishes), this only ever touches bytes inside
    // [data, data+size): any bytes beyond the true end are zero-filled
    // instead of read, which is bit-for-bit equivalent for every position
    // whose value can matter (a real decode always finishes needing bits
    // strictly before it would rely on those unread bytes) while never
    // touching memory outside the caller-owned buffer.
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
            uint32_t new_bitcount = 32u - (nb - bitcount);
            bits = (bitbuff_ >> new_bitcount) | (bits << (nb - bitcount));
            bitcount = new_bitcount;
        } else {
            bitcount -= nb;
            bits >>= bitcount;
        }
        bitcount_ = bitcount;
        return bitmask(nb) & bits;
    }
    uint32_t GetX() {
        uint32_t base = 0, nb = 1;
        if (GetBits(1)) { base = 1; do { base *= 2; } while (GetBits(1) && ++nb != 32u); }
        return base | GetBits(nb);
    }
    uint32_t GetY() { uint32_t nb = GetX(); return nb ? ((1u << nb) | GetBits(nb)) : GetBits(1); }
    uint32_t GetZ(int B) {
        if (B == 0) return GetY();
        uint32_t bits = GetBits((uint32_t)B);
        return bits + (GetY() << B);
    }
};

struct AddBytesFilter {
    BitReader bitreader_;
    uint32_t offset_ = 0;
    void DecodeOne(uint32_t* copy_offset, uint32_t* start_offset, uint32_t* num_delta) {
        *copy_offset = bitreader_.GetY();
        if (*copy_offset) {
            *num_delta = bitreader_.GetZ(8);
            *start_offset = offset_ + bitreader_.GetZ(8);
            offset_ = *num_delta + *start_offset;
        }
    }
    bool Process(const uint8_t* data, uint32_t dlen, const uint8_t* in, uint32_t insize, uint8_t* out) {
        bitreader_.Initialize(data, dlen);
        if (insize <= 263u) return false;
        const uint8_t* in_end = in + insize;
        const uint8_t* in_org = in;
        for (size_t i = 0; i != 255; i++) out[i] = in[i];
        in += 255; out += 255;
        while (in != in_end) {
            uint32_t copy_offset, start_offset = insize, num_delta = 0;
            DecodeOne(&copy_offset, &start_offset, &num_delta);
            if (copy_offset) num_delta += 8u;
            uint32_t ncopy = (uint32_t)(start_offset - (uint32_t)(in - in_org));
            if (ncopy) {
                if (in + ncopy > in_end) return false;
                std::memcpy(out, in, ncopy);
                in += ncopy; out += ncopy;
            }
            const uint8_t* ine = in + num_delta;
            if (ine > in_end) return false;
            intptr_t offs = -(intptr_t)copy_offset;
            while (in != ine) { out[0] = (uint8_t)(out[offs] + in[0]); in++; out++; }
        }
        return true;
    }
};

}  // namespace

bool NzAddBytesFilter(const uint8_t* p1data, uint32_t p1len,
                      const uint8_t* in, uint32_t in_size, uint8_t* out) {
    AddBytesFilter f;
    return f.Process(p1data, p1len, in, in_size, out);
}
