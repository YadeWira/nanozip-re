#include "nz_cm.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>

// ---------------------------------------------------------------------------
// Portability helpers
// ---------------------------------------------------------------------------

static void* nz_aligned_malloc(size_t size, size_t align) {
#if defined(_WIN32)
    // x86-64 malloc is already 16-byte aligned and the CM decoder uses no SIMD,
    // so plain malloc satisfies the alignment the original mirrored. Crucially it
    // stays freeable with plain free() (MSVCRT's _aligned_malloc is not).
    (void)align;
    return malloc(size);
#else
    void* p = nullptr;
    if (posix_memalign(&p, align, size) != 0) return nullptr;
    return p;
#endif
}

#define _rotr(v, n) (((v) >> (n)) | ((v) << (32 - (n))))
#define BSR(x) (31u - static_cast<unsigned>(__builtin_clz(static_cast<unsigned>(x))))

static void memset32(void* dst, uint32_t value, size_t n) {
    uint32_t* p = static_cast<uint32_t*>(dst);
    for (size_t i = 0; i < n; i++)
        p[i] = value;
}

// ---------------------------------------------------------------------------
// ArithmeticDecoder
// ---------------------------------------------------------------------------

struct ArithmeticDecoder {
    uint32_t range_hi_, range_lo_, bitbuff_;
    const uint8_t *data_, *data_end_;

    uint32_t ReadByte() { return (data_ != data_end_ ? *data_++ : 0); }

    void InitializeX(const uint8_t* d, const uint8_t* e) {
        data_ = d; data_end_ = e;
        range_lo_ = 0; range_hi_ = 0xffffffff; bitbuff_ = 0;
    }

    void FillBuffer() {
        for (int i = 0; i != 4; i++)
            bitbuff_ = (bitbuff_ << 8) | ReadByte();
    }

    void Renormalize() {
        while ((range_lo_ ^ range_hi_) < 0x1000000) {
            range_lo_ <<= 8;
            range_hi_ = (range_hi_ << 8) + 0xff;
            bitbuff_ = (bitbuff_ << 8) | ReadByte();
        }
    }

    bool ReadHighPrec(uint32_t model) {
        uint32_t compare = range_lo_ + (uint32_t)(((range_hi_ - range_lo_) * (uint64_t)model) >> 12);
        bool flag = (bitbuff_ <= compare);
        range_hi_ -= flag ? (range_hi_ - compare) : 0;
        range_lo_ -= flag ? 0 : (range_lo_ - (compare + 1));
        Renormalize();
        return flag;
    }
};

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

uint16_t kModelInterpolation[4096];
uint16_t kModelLutLookup[4096];
uint32_t kDivideLookup[256];
uint16_t kLzPredSumLookup[256];
static uint8_t  kCmFlagCrap[256];
static uint32_t kHashHist8Mult[256];
static uint32_t kHashHist4Mult[256];
static uint32_t kHashHist10Mult[256];
static uint32_t kHashHist24Mult[256];
static uint32_t kHashHist6Mult[256];

int16_t kLzModelInterpolation[256];

extern const uint8_t kLzModelLNext[256 * 2] = {
   1,  2,  3,  5,  4,  6,  7, 10,  8, 12,  9, 13, 11, 14, 15, 19,
  16, 23, 17, 24, 18, 25, 20, 27, 21, 28, 22, 29, 26, 30, 31, 33,
  32, 35, 32, 35, 32, 35, 32, 35, 34, 37, 34, 37, 34, 37, 34, 37,
  34, 37, 34, 37, 36, 39, 36, 39, 36, 39, 36, 39, 38, 40, 41, 43,
  42, 45, 42, 45, 44, 47, 44, 47, 46, 49, 46, 49, 48, 51, 48, 51,
  50, 52, 53, 43, 54, 57, 54, 57, 56, 59, 56, 59, 58, 61, 58, 61,
  60, 63, 60, 63, 62, 65, 62, 65, 50, 66, 67, 55, 68, 57, 68, 57,
  70, 73, 70, 73, 72, 75, 72, 75, 74, 77, 74, 77, 76, 79, 76, 79,
  62, 81, 62, 81, 64, 82, 83, 69, 84, 71, 84, 71, 86, 73, 86, 73,
  44, 89, 44, 89, 88, 91, 88, 91, 90, 49, 90, 49, 76, 93, 76, 93,
  78, 95, 78, 95, 80, 96, 97, 69, 98, 87, 98, 87,100, 45,100, 45,
  72, 75, 72, 75, 74, 77, 74, 77, 48,103, 48,103, 92,105, 92,105,
  80,106,107, 69,108, 87,108, 87,110, 57,110, 57, 62,113, 62,113,
  92,115, 92,115, 80,116,117, 85,118, 87,118, 87,120, 57,120, 57,
  62,123, 62,123, 92,125, 92,125, 94,126,127, 85,128,101,128,101,
 130, 57,130, 57, 62,133, 62,133,102,135,102,135, 94,136,137, 85,
 138,101,138,101,140, 57,140, 57, 62,143, 62,143,102,145,102,145,
  94,146,147, 99,148,101,148,101, 68, 57, 68, 57, 62, 81, 62, 81,
 102,149,102,149,104,150,151, 99,152,111,112,153,104,154,155, 99,
 156,111,112,157,104,158,159, 99,160,111,112,161,104,162,163,109,
 164,111,112,165,114,166,167,109,168,121,122,169,114,170,171,109,
 172,121,122,173,114,174,175,109,176,121,122,177,114,178,179,109,
 180,121,122,181,114,182,183,119,184,121,122,185,124,186,187,119,
 188,131,132,189,124,190,191,119,192,131,132,193,124,194,195,119,
 196,131,132,197,124,198,199,119,200,131,132,201,124,202,203,119,
 204,131,132,205,124,206,207,119,208,131,132,209,124,210,211,129,
 212,131,132,213,134,214,215,129,216,141,142,217,134,218,219,129,
 220,141,142,221,134,222,223,129,224,141,142,225,134,226,227,129,
 228,141,142,229,134,230,231,129,232,141,142,233,134,234,235,129,
 236,141,142,237,134,238,239,129,240,141,142,241,134,242,243,129,
 244,141,142,245,134,246,247,139,248,141,142,249,144,250,251,139,
 252, 69, 80,253,144,254,251,139,255, 69, 80,253,144,254,255, 69,
};

// ---------------------------------------------------------------------------
// Build_kModelInterpolation (from NZ.cpp)
// ---------------------------------------------------------------------------

static uint64_t SomeMathCrap(uint64_t v, uint8_t shift) {
    if (v <= 1)
        return 0;
    uint32_t bits = BSR((uint32_t)v);
    uint64_t result = ((uint64_t)bits << shift);
    uint32_t q = 1u << shift;
    uint64_t m = v << shift >> bits;
    while (q >>= 1) {
        m = (m * m) >> shift;
        if (m >= ((uint64_t)2 << shift)) {
            result += q;
            m >>= 1;
        }
    }
    return result;
}

static void Build_kModelInterpolation() {
    uint16_t* dst = kModelInterpolation;
    dst[0] = 0;
    dst[1] = 0x40;
    for (uint32_t i = 2; i < 2048; i++) {
        uint64_t v = SomeMathCrap((i << 12) / (4096 - i), 31);
        dst[i] = (uint16_t)((v * 170 + 0x43C000000ULL) >> 31);
    }
    for (size_t i = 0; i < 2048; i++)
        dst[2048 + i] = (uint16_t)(4096 - 1 - dst[2048 - i - 1]);

    dst = kModelLutLookup;
    uint32_t i = 0;
    for (uint32_t j = 0; j < 2048; j++) {
        uint32_t x = kModelInterpolation[j];
        for (uint32_t n = (x - i) >> 1; n; n--)
            dst[i++] = (uint16_t)(j - 1);
        while (i < x)
            dst[i++] = (uint16_t)j;
    }
    for (uint32_t n = (2048 - i) >> 1; n; n--)
        dst[i++] = 2048 - 2;
    while (i < 2048)
        dst[i++] = 2048 - 1;
    for (size_t ii = 0; ii < 2048; ii++)
        dst[2048 + ii] = (uint16_t)(4096 - 1 - dst[2048 - ii - 1]);
}

// ---------------------------------------------------------------------------
// LzCreateTables (from NZ_LZ.cpp)
// ---------------------------------------------------------------------------

static void LzCreateTables() {
    int16_t* dst = kLzModelInterpolation;
    dst[0] = -2048;
    dst[1] = -1792;
    dst[2] = -1536;
    for (size_t i = 3; i != 253; i++)
        dst[i] = (int16_t)(kModelInterpolation[16 * i + 8] - 2048);
    dst[253] = (int16_t)(~dst[2]);
    dst[254] = (int16_t)(~dst[1]);
    dst[255] = (int16_t)(~dst[0]);

    kDivideLookup[0] = 255;
    for (int i = 1; i < 255; i++)
        kDivideLookup[i] = 1024 / (uint32_t)(3 + i * 2);
    kDivideLookup[255] = 1;

    for (int i = 0; i != 256; i++)
        kLzPredSumLookup[i] = kModelLutLookup[i * 16 + 8];
    kLzPredSumLookup[0] = 0;
    kLzPredSumLookup[255] = 4095;
}

// ---------------------------------------------------------------------------
// CM_InitTables (from NZ_CM.cpp)
// ---------------------------------------------------------------------------

static void CM_InitTables() {
    for (uint32_t i = 0; i != 256; i++) {
        kHashHist24Mult[i] = i * 0xd1a55a41u;
        kHashHist10Mult[i] = i * 0xb5199319u;
        kHashHist6Mult[i]  = i * 0x699c6d11u;
        kHashHist4Mult[i]  = i * 0x502c3f11u;
        kHashHist8Mult[i]  = i * 0x5d615f21u;
    }

    for (uint32_t i = 0; i != 256; i++) {
        uint32_t a = 8 * (i >> 4);
        uint32_t b = 8 * (i & 0xF);
        kCmFlagCrap[i] = (uint8_t)(
            2u  * (uint32_t)((a > 0x32 && b > 0x50) || a > 0x46) |
            32u * (uint32_t)(a <= 0x37 || b <= 0x2F) |
            16u * (uint32_t)(a <= 0x3F || b <= 0x37) |
            ((uint32_t)(a <= 0x17 && b <= 0xD) << 7) |
            ((uint32_t)(a <= 0x1F && b <= 0x11) << 6) |
            8u  * (uint32_t)(a > 0x64 || b > 0x5A) |
            4u  * (uint32_t)(a <= 0x59 || b <= 0x4F));
    }
}

// ---------------------------------------------------------------------------
// CM structs
// ---------------------------------------------------------------------------

struct CM_T {
    uint32_t aa[0x2000];
    uint32_t cc[0x40000];
    // bb[] is a flexible array accessed via pointer arithmetic; declared with size 1
    // to satisfy strict ISO C++ while preserving the original layout intent.
    uint32_t bb[1];
};

struct CM_B {
    uint32_t  cmt_mask;
    uint32_t  mask;
    uint32_t  inverse_mask;
    CM_T*     cmt;
    uint32_t* histhash8_ptr;
    uint32_t* histhash4_ptr;
    uint32_t* histhash2_ptr;
    uint8_t*  window;
    uint32_t  window_size;
    uint32_t  write_pos;
    uint32_t  hash2pos;
    uint32_t  delta1pos;
    uint32_t  delta2pos;
    uint32_t  hash4pos;
    uint32_t  hash8pos;
    int16_t   hash2attr;
    int16_t   hash4attr;
    uint16_t  hash8attr;
    uint16_t  last_bytes;
    uint16_t  deltaattr;
    uint8_t   hash4len;
    uint8_t   hash8len;
    uint8_t   bestlen;
    uint8_t   hash4byte;
    uint8_t   hash8byte;
    uint8_t   hash2byte;
    uint8_t   delta1byte;
    uint8_t   delta2byte;
    uint8_t   byte4E;
    uint32_t  histhash4;
    uint32_t  histbyte4;
    uint8_t   byte58;
    uint32_t  histhash8;
    uint8_t   histbyte8[8];
    uint8_t   histpos8;
    uint32_t* modelx;
    uint32_t* modelx_ptr;
    uint32_t  modelx_cur;
    uint32_t  modelx_size;
    uint32_t* modely;
    uint32_t* modely_ptr;
    uint32_t  modely_cur;
    uint32_t  modely_size;
    uint16_t* modelz;
    uint16_t* modelz_ptr;
    uint32_t  modelz_size;
    uint8_t*  modelq;
    uint8_t*  modelq_ptr;
    uint8_t   modelq_cur;
    uint32_t  modelq_size;
    uint16_t* delta_score;
    uint8_t*  delta_hist;
    uint16_t  delta_hist_index;
    uint8_t   best_delta;
    uint16_t  last_pos_for_byte[256];

    void Allocate(uint32_t size);
};

struct CM_C {
    uint32_t v0, v1;
};

struct CM_ModelE {
    uint32_t* model;
    uint32_t* ptr;
    uint32_t  cur;
    uint32_t  size;

    CM_ModelE() : model(nullptr) {}
};

struct CM_ModelG {
    uint32_t* base_ptr;
    uint32_t* cur_ptr;
    uint32_t  cur;
    uint32_t  size;
};

struct CM {
    uint8_t*  some_ptr;
    uint32_t  some_mask;
    uint8_t*  ptrs8[8];
    uint32_t  hashes_arr28[8];
    uint32_t  upper_3bits_history;
    uint32_t  bit_history2;
    uint32_t  out_byte;
    uint32_t  next_probability;
    uint16_t  out_byte_wip;
    int8_t    factors7_div16;
    uint8_t   bit_index_in_byte;
    uint8_t   cmb_result;
    uint8_t   errorhist;
    uint8_t   ascii_counter;
    uint8_t   flags;
    uint8_t   errorsum;
    uint8_t   factors7_err_flt;
    uint8_t   factors0_err_flt;
    uint8_t   errorsum_flt1;
    uint8_t   errorsum_flt2;
    uint8_t   factors0_err;
    uint8_t   factors7_err;
    uint8_t   ptrs8_cur[8];
    uint32_t  histhash24;
    uint8_t   histbyte24[24];
    uint8_t   histpos24;
    uint32_t  histhash10;
    uint8_t   histbyte10[10];
    uint8_t   histpos10;
    uint32_t  histhash6;
    uint8_t   histbyte6[6];
    uint8_t   histpos6;
    uint8_t*  modeld;
    uint8_t*  modeld_ptr;
    uint8_t   modeld_cur;
    uint32_t  modeld_size;
    uint32_t  modela[256];
    uint32_t* modela_ptr;
    uint32_t  modela_cur;
    uint8_t*  modelb;
    uint8_t*  modelb_ptr;
    uint8_t   modelb_cur;
    uint32_t  modelb_size;
    uint32_t  modelc[256];
    uint32_t* modelc_ptr;
    uint32_t  modelc_cur;
    uint8_t*  modelf;
    uint8_t*  modelf_ptr;
    uint8_t   modelf_cur;
    uint32_t  modelf_size;
    CM_ModelE modele[8];
    int16_t   factors[12];
    int16_t   modelh[84][12];
    int16_t*  modelh_ptr;
    CM_B      cmb;
    CM_C*     cmc;
    CM_C*     cmc_cur;
    uint32_t  cmc_v0_mult;
    uint32_t  cmc_v1_mult;
    uint32_t  next_prob_last;
    uint32_t  cmc_size;
    CM_ModelG modelg;
    uint8_t*  modelv;
    uint8_t*  modelw;
    uint8_t*  modelu;

    CM(int a_bits, int b_bits);
};

// NzCmDecoder is forward-declared as struct NzCmDecoder in nz_cm.h.
// CM is the actual implementation type. The public API casts between them.

// ---------------------------------------------------------------------------
// CM_B::Allocate
// ---------------------------------------------------------------------------

void CM_B::Allocate(uint32_t size) {
    cmt_mask = size - 1;

    this->modelx      = nullptr;
    this->modely      = nullptr;
    this->modelz      = nullptr;
    this->modelz_size = 0;
    this->modelq      = nullptr;
    this->modelq_size = 0;
    this->delta_score = (uint16_t*)nz_aligned_malloc(510, 16);
    this->delta_hist  = (uint8_t*)nz_aligned_malloc(512, 16);
    this->cmt         = (CM_T*)nz_aligned_malloc(4 * this->cmt_mask + 4 + sizeof(CM_T), 16);

    this->modelq_size = 0x2000;
    this->modelq      = (uint8_t*)nz_aligned_malloc(this->modelq_size + 3, 16);

    this->modelz_size = 8194;
    this->modelz_ptr  = this->modelz = (uint16_t*)nz_aligned_malloc(2 * 8194, 16);

    this->modelx_size = 1024;
    this->modelx      = (uint32_t*)nz_aligned_malloc(4096, 16);
    this->modely_size = 1024;
    this->modely      = (uint32_t*)nz_aligned_malloc(4096, 16);
}

// ---------------------------------------------------------------------------
// CM constructor
// ---------------------------------------------------------------------------

CM::CM(int a_bits, int b_bits) {
    some_mask   = (1u << a_bits) - 1;
    some_ptr    = (uint8_t*)nz_aligned_malloc(some_mask + 16450, 64);
    modeld_size = 0;
    modelb_size = 0;
    modelf      = nullptr;
    modelf_size = 0;

    cmb.Allocate(1u << b_bits);

    cmc             = nullptr;
    modelg.size     = 53248;
    modelg.base_ptr = (uint32_t*)nz_aligned_malloc(modelg.size * sizeof(uint32_t), 16);

    modeld_size = 0x10000;
    modeld_ptr = modeld = (uint8_t*)nz_aligned_malloc(0x10000, 16);

    modelb_size = 0x20000;
    modelb_ptr = modelb = (uint8_t*)nz_aligned_malloc(0x20000, 16);

    cmc_size = 0x2000;
    cmc = new CM_C[0x2000];

    modelf_size = 0x20000;
    modelf = (uint8_t*)nz_aligned_malloc(modelf_size + 3, 16);
    modelu = (uint8_t*)nz_aligned_malloc(0x4CA70C, 16);
    modelv = (uint8_t*)nz_aligned_malloc(0x10000, 16);
    modelw = (uint8_t*)nz_aligned_malloc(0x1000000, 16);

    for (size_t kk = 0; kk != 8; kk++) {
        modele[kk].size  = 256;
        modele[kk].model = (uint32_t*)nz_aligned_malloc(256 * sizeof(uint32_t), 16);
    }
}

// ---------------------------------------------------------------------------
// CM_B helper functions
// ---------------------------------------------------------------------------

static void CM_B_NewByte(CM_B* t) {
    uint8_t last_byte = (uint8_t)t->last_bytes;

    uint32_t last_delta = (uint16_t)t->write_pos - 2 - t->last_pos_for_byte[last_byte];
    t->last_pos_for_byte[(uint8_t)t->last_bytes] = (uint16_t)t->write_pos;

    if (last_delta <= 252) {
        uint16_t* dp = &t->delta_score[t->delta_hist[t->delta_hist_index]];
        (*dp)--;
        t->delta_hist[t->delta_hist_index] = (uint8_t)last_delta;

        dp = &t->delta_score[last_delta];
        if (*dp >= t->delta_score[t->best_delta])
            t->best_delta = (uint8_t)last_delta;
        (*dp)++;
        t->delta_hist_index = (uint16_t)((t->delta_hist_index + 1) & 0x1FF);
        if (last_delta <= 127 && last_byte == 32) {
            t->byte4E = (uint8_t)((31 * t->byte4E + 2 * last_delta + 16) >> 5);
        }
    }
    uint32_t histhash2_cur = *t->histhash2_ptr;
    uint32_t histhash4_cur = *t->histhash4_ptr;
    uint32_t histhash8_cur = *t->histhash8_ptr;

    t->hash2attr += (int16_t)((t->hash2attr & 7u) < 7);
    t->hash4attr += (int16_t)((t->hash4attr & 7u) < 7);
    t->hash8attr += (uint16_t)((t->hash8attr & 7u) < 7);

    t->hash4pos  = t->hash4pos  + 1 < t->window_size ? t->hash4pos  + 1 : 0;
    t->hash8pos  = t->hash8pos  + 1 < t->window_size ? t->hash8pos  + 1 : 0;
    t->hash2pos  = t->hash2pos  + 1 < t->window_size ? t->hash2pos  + 1 : 0;
    t->delta1pos = t->delta1pos + 1 < t->window_size ? t->delta1pos + 1 : 0;
    t->delta2pos = t->delta2pos + 1 < t->window_size ? t->delta2pos + 1 : 0;

    *t->histhash8_ptr = t->write_pos | (t->histhash8 & t->inverse_mask);
    *t->histhash4_ptr = t->write_pos | (t->histhash4 & t->inverse_mask);
    *t->histhash2_ptr = t->write_pos | ((t->last_bytes << 16) & t->inverse_mask);

    if (t->hash2attr < 0) {
        uint32_t pos = histhash2_cur & t->mask;
        if (!((t->write_pos - 2 - pos > 0xFF) ||
              ((histhash2_cur ^ (t->last_bytes << 16)) & t->inverse_mask) ||
              (t->last_bytes >> 8 == (uint8_t)t->last_bytes))) {
            if (*(uint16_t*)&t->window[pos - (size_t)2] == *(uint16_t*)&t->window[t->write_pos - (size_t)2]) {
                t->hash2pos  = pos;
                t->hash2attr = (int16_t)(((t->write_pos - pos <= 0x5F) + (t->write_pos - pos <= 0xF)) << 10);
            }
        }
    }
    uint16_t new_deltaattr = (uint16_t)(t->deltaattr + (t->deltaattr < 0x1C00u ? 0x400 : 0));
    if (t->delta1byte != last_byte) {
        t->delta1pos = t->write_pos - (t->best_delta + 2) < t->window_size ? t->write_pos - (t->best_delta + 2) : 0;
        t->delta2pos = t->write_pos - 2 * (t->best_delta + 2) < t->window_size ? t->write_pos - 2 * (t->best_delta + 2) : 0;
        new_deltaattr = 0;
    } else {
        new_deltaattr = new_deltaattr & 0xFFFFFE7Fu;
    }
    if (!(t->best_delta & 1))
        new_deltaattr |= (uint16_t)((t->write_pos & 3) << 7);
    t->deltaattr = new_deltaattr;

    if (t->hash8len) {
        t->hash8len += (t->hash8len < 0x3F);
        t->hash8attr = (uint16_t)((t->hash8attr & ~(15u << 5)) | (32u * std::min<uint32_t>(t->hash8len - 8, 14)));
    } else {
        if (!((t->histhash8 ^ histhash8_cur) & t->inverse_mask)) {
            uint32_t pos = (histhash8_cur & t->mask);
            if (*(uint64_t*)&t->window[pos - (size_t)8] == *(uint64_t*)&t->window[t->write_pos - (size_t)8]) {
                if (t->hash4pos == pos) {
                    t->hash4len  = 0;
                    t->hash4attr = -1;
                }
                t->hash8len  = 8;
                t->hash8pos  = pos;
                t->hash8attr = (uint16_t)(((t->write_pos - pos) < 0x1000u) << 9);
            }
        }
    }

    if (t->hash4len) {
        t->hash4len += (t->hash4len < 0x3F);
        t->hash4attr = (int16_t)((t->hash4attr & ~(15 << 5)) | (int16_t)(32 * std::min<uint32_t>(t->hash4len - 4, 14)));
    } else {
        if (!((t->histhash4 ^ histhash4_cur) & t->inverse_mask) &&
            (*(uint32_t*)&t->window[(histhash4_cur & t->mask) - (size_t)4] == *(uint32_t*)&t->window[t->write_pos - (size_t)4])) {
            t->hash4len  = 4;
            t->hash4pos  = (histhash4_cur & t->mask);
            t->hash4attr = (int16_t)(((t->write_pos - (histhash4_cur & t->mask)) < 0x1000u) << 9);
        }
    }
    t->bestlen    = std::max<uint8_t>(t->hash4len, t->hash8len);
    t->hash2byte  = t->window[t->hash2pos];
    t->delta1byte = t->window[t->delta1pos];
    t->delta2byte = (uint8_t)(2 * t->window[t->delta1pos] - t->window[t->delta2pos]);
    t->hash4byte  = t->window[t->hash4pos];
    t->hash8byte  = t->window[t->hash8pos];
}

static int CM_B_Proc2(CM_B* t, int bit_history, int bit, int bitindex, int16_t* factors) {
    int bitindex_minus1 = bitindex - 1;

    factors[0] = 0;
    if (t->hash4attr >= 0) {
        uint32_t hash4byte = (uint32_t)t->hash4byte + 256, v8;
        if (!t->hash4len || (hash4byte >> bitindex != (uint32_t)bit_history)) {
            if (t->hash4len) {
                t->hash4attr = (int16_t)((t->hash4attr & 0xFFFFFE00) | 1);
                t->hash4len  = 0;
                t->bestlen   = t->hash8len;
            }
            if ((t->hash4attr & 0xF) == 1 || (hash4byte >> bitindex == (uint32_t)bit_history)) {
                v8 = (uint32_t)(t->hash4attr & 0x7FE0) + 2u * (uint32_t)(t->hash4attr & 0xF) + ((hash4byte >> (bitindex - 1)) & 1u);
            } else {
                v8 = 480u + ((hash4byte >> (bitindex - 1)) & 1u) + 2u * (uint32_t)bitindex;
                t->hash4attr |= 8;
            }
        } else {
            v8 = (uint32_t)(t->hash4attr & 0x7FE0) + ((hash4byte >> (bitindex - 1)) & 1u);
        }
        uint32_t* modelx_ptr_new = &t->modelx[v8];
        *t->modelx_ptr = (((uint32_t)(bit << 23) - (t->modelx_cur >> 9)) * kDivideLookup[(uint8_t)t->modelx_cur] & 0xFFFFFF00u) + t->modelx_cur + ((uint8_t)t->modelx_cur <= 0x27u);
        t->modelx_ptr = modelx_ptr_new;
        t->modelx_cur = *modelx_ptr_new;
        factors[0] = (int16_t)(kModelInterpolation[t->modelx_cur >> 20] - 2048);
    }

    uint32_t hash8byte = (uint32_t)t->hash8byte + 256, v13;
    if (!t->hash8len) {
        if ((t->hash8attr & 0xF) == 1 || (hash8byte >> bitindex == (uint32_t)bit_history)) {
            v13 = (uint32_t)(t->hash8attr & 0x7FE0) + 2u * (uint32_t)(t->hash8attr & 0xF) + ((hash8byte >> bitindex_minus1) & 1u);
        } else {
            v13 = 480u + 2u * (uint32_t)bitindex + ((hash8byte >> bitindex_minus1) & 1u);
            t->hash8attr |= 8;
        }
    } else {
        if (hash8byte >> bitindex != (uint32_t)bit_history) {
            t->hash8attr = (uint16_t)((t->hash8attr & 0xFE00u) | 1u);
            t->hash8len  = 0;
            t->bestlen   = t->hash4len;
            if ((t->hash8attr & 0xF) == 1) {
                v13 = (uint32_t)(t->hash8attr & 0x7FE0) + 2u * (uint32_t)(t->hash8attr & 0xF) + ((hash8byte >> bitindex_minus1) & 1u);
            } else {
                v13 = 480u + 2u * (uint32_t)bitindex + ((hash8byte >> bitindex_minus1) & 1u);
                t->hash8attr |= 8;
            }
        } else {
            v13 = (uint32_t)(t->hash8attr & 0x7FE0) + ((hash8byte >> bitindex_minus1) & 1u);
        }
    }
    uint32_t* modely_ptr_new = &t->modely[v13];
    *t->modely_ptr = (((uint32_t)(bit << 23) - (t->modely_cur >> 9)) * kDivideLookup[(uint8_t)t->modely_cur] & 0xFFFFFF00u) + t->modely_cur + ((uint8_t)t->modely_cur <= 39u);
    t->modely_ptr = modely_ptr_new;
    t->modely_cur = *modely_ptr_new;
    factors[1] = (int16_t)(kModelInterpolation[t->modely_cur >> 20] - 2048);

    uint32_t v17 = (uint32_t)t->hash2byte + 256;
    *t->modelz_ptr += (uint16_t)(((uint32_t)(bit << 16) + 8u - *t->modelz_ptr) >> 4);

    if (t->hash2attr < 0)
        goto LABEL_34;
    if (v17 >> bitindex == (uint32_t)bit_history) {
        t->modelz_ptr = &t->modelz[((t->hash2attr & 7) << 7) + (t->hash2attr & 0x7F80) + ((v17 >> bitindex_minus1) & 1u) + (bitindex_minus1 & 0xFFFFFFFE)];
        factors[2] = (int16_t)(kModelInterpolation[(uint32_t)*t->modelz_ptr >> 4] - 2048);
    } else {
        t->hash2attr = (int16_t)((t->hash2attr & 0xFFF0) | (std::min(t->hash2attr & 7, 3) << 7) | (bit << 9) | 0x8001);
        t->bestlen = std::max<uint8_t>(t->hash4len, t->hash8len);
    LABEL_34:
        if ((t->hash2attr & 0xF) == 1 || (v17 >> bitindex == (uint32_t)bit_history)) {
            t->modelz_ptr = &t->modelz[8 * (t->hash2attr & 0xF) + (t->hash2attr & 0x7F80) + ((v17 >> bitindex_minus1) & 1u) + (bitindex_minus1 & 0xFFFFFFFE)];
            factors[2] = (int16_t)(kModelInterpolation[(uint32_t)*t->modelz_ptr >> 4] - 2048);
        } else {
            t->modelz_ptr = t->modelz + 0x2000;
            factors[2] = 0;
            t->hash2attr |= 8;
        }
    }

    uint32_t v23 = ((uint32_t)t->delta1byte + 256u) >> bitindex_minus1;
    uint32_t v24 = ((uint32_t)t->delta2byte + 256u) >> bitindex_minus1;
    uint32_t modelq_new = (uint32_t)(4 * bitindex_minus1) + 2u * (v23 & 1u) + t->deltaattr + (v24 & 1u) + (v24 >> 1 == (uint32_t)bit_history) * 32u + (v23 >> 1 == (uint32_t)bit_history) * 64u;

    *t->modelq_ptr = (uint8_t)(t->modelq_cur + (((uint32_t)(bit << 8) + 4u - t->modelq_cur) >> 3));
    t->modelq_ptr = &t->modelq[modelq_new];
    t->modelq_cur = *t->modelq_ptr;
    factors[3] = (int16_t)(kModelInterpolation[16 * t->modelq_cur] - 2048);
    return t->bestlen;
}

static void CM_B_Finished(CM_B* t, uint32_t out_byte) {
    t->window[t->write_pos] = (uint8_t)out_byte;
    t->write_pos = (t->write_pos + 1) < t->window_size ? t->write_pos + 1 : 0;

    t->last_bytes = (uint16_t)((t->last_bytes << 8) + out_byte);
    t->histhash2_ptr = &t->cmt->aa[(t->last_bytes ^ (t->last_bytes >> 5)) & 0x1FFF];

    t->histhash8 += out_byte;
    t->histhash8 = 0x1000193u * (t->histhash8 - kHashHist8Mult[t->histbyte8[t->histpos8]]);
    t->histbyte8[t->histpos8] = (uint8_t)out_byte;
    t->histpos8 = t->histpos8 < 7 ? t->histpos8 + 1 : 0;

    t->histhash8_ptr = &t->cmt->bb[t->histhash8 & t->cmt_mask];

    t->histhash4 += out_byte;
    t->histhash4 = 0x1000193u * (t->histhash4 - kHashHist4Mult[t->histbyte4 >> 24]);
    t->histbyte4 = (t->histbyte4 << 8) | out_byte;
    t->histhash4_ptr = &t->cmt->cc[t->histhash4 & 0x3FFFFu];
}

static inline int32_t Clamp16(int32_t v) {
    return ((int16_t)v != v) ? (v >> 31) ^ 0x7fff : v;
}

static void ZeroRp(uint8_t* rp) {
    rp[4]  = 0; rp[8]  = 0; rp[12] = 0; rp[16] = 0;
    rp[20] = 0; rp[24] = 0; rp[28] = 0; rp[32] = 0;
    rp[36] = 0; rp[40] = 0; rp[44] = 0; rp[48] = 0;
    rp[52] = 0; rp[56] = 0; rp[60] = 0;
}

static uint8_t* CM_PtrGetX(uint8_t* p, uint8_t b) {
    uint8_t* rp = (uint8_t*)((uintptr_t)&p[64 * (b | 1)] & ~(uintptr_t)63);
    if (rp[0] == b) return rp + 4;
    if (rp[1] == b) return rp + 5;
    if (rp[2] == b) return rp + 6;
    if (rp[3] == b) return rp + 7;
    uint8_t v4 = (uint8_t)(rp[5] < rp[4]);
    uint8_t v5 = (uint8_t)(-(int8_t)(rp[6] >= rp[v4 + 4]));
    uint8_t v6 = (uint8_t)((v5 & v4) + (~v5 & 2));
    uint8_t v7 = (uint8_t)(-(int8_t)(rp[7] >= rp[v6 + 4]));
    rp += (v7 & v6) + (~v7 & 3);
    *rp = b;
    ZeroRp(rp);
    return rp + 4;
}

static uint8_t* CM_GetHashSlot(CM* t, uint32_t hash) {
    uint8_t  b  = (uint8_t)(hash >> 24);
    uint8_t* rp = &t->some_ptr[(hash << 6) & t->some_mask];
    if (*rp   == b) return rp;
    if (rp[1] == b) return rp + 1;
    if (rp[2] == b) return rp + 2;
    if (rp[3] == b) return rp + 3;
    uint8_t v4 = (uint8_t)(rp[5] < rp[4]);
    uint8_t v5 = (uint8_t)(-(int8_t)(rp[6] >= rp[v4 + 4]));
    uint8_t v6 = (uint8_t)((v5 & v4) + (~v5 & 2));
    uint8_t v7 = (uint8_t)(-(int8_t)(rp[7] >= rp[v6 + 4]));
    rp += (v7 & v6) + (~v7 & 3);
    *rp = b;
    ZeroRp(rp);
    return rp;
}

static void CM_Input_Bit(CM* t, uint32_t bit) {
    int32_t error = (int32_t)(4095 * bit - t->next_probability);
    for (int fi = 0; fi != 12; fi++)
        t->modelh_ptr[fi] = (int16_t)Clamp16(t->modelh_ptr[fi] + ((((error * 16 * t->factors[fi]) >> 16) + 1) >> 1));

    uint32_t error_abs = (uint32_t)std::abs(error);
    t->errorhist = (uint8_t)(t->errorhist * 2 + (error_abs > 1280));
    t->errorsum  = (uint8_t)(t->errorsum + (error_abs >> 7));
    t->bit_history2 = (bit + 2 * t->bit_history2) & 0x1FFFFu;

    uint32_t tt;

    tt = t->modele[0].cur;
    *t->modele[0].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt <= 127u);

    tt = t->modele[1].cur;
    *t->modele[1].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt <= 253u);

    tt = t->modele[2].cur;
    *t->modele[2].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt <= 253u);

    *t->ptrs8[0] = kLzModelLNext[t->ptrs8_cur[0] * 2 + bit];
    *t->ptrs8[1] = kLzModelLNext[t->ptrs8_cur[1] * 2 + bit];
    *t->ptrs8[2] = kLzModelLNext[t->ptrs8_cur[2] * 2 + bit];

    if (t->flags & 0x10) {
        tt = t->modele[3].cur;
        *t->modele[3].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);
        *t->ptrs8[3] = kLzModelLNext[t->ptrs8_cur[3] * 2 + bit];

        if (t->flags & 0x20) {
            tt = t->modele[4].cur;
            *t->modele[4].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);
            *t->ptrs8[4] = kLzModelLNext[t->ptrs8_cur[4] * 2 + bit];
        }
    }

    if (t->flags & 4) {
        tt = t->modele[7].cur;
        *t->modele[7].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);
        *t->ptrs8[7] = kLzModelLNext[t->ptrs8_cur[7] * 2 + bit];
    }

    if (t->flags & 0x40) {
        tt = t->modele[5].cur;
        *t->modele[5].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);
        *t->ptrs8[5] = kLzModelLNext[t->ptrs8_cur[5] * 2 + bit];
        if (t->flags & 0x80) {
            tt = t->modele[6].cur;
            *t->modele[6].ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);
            *t->ptrs8[6] = kLzModelLNext[t->ptrs8_cur[6] * 2 + bit];
        }
    } else {
        // NB: reference uses (factors[0] >> 4) — arithmetic shift (floor), NOT
        // truncating division by 16. They differ for negative factors[0] and the
        // 1-LSB drift perturbs factors0_err -> factors0_err_flt -> the factor[7]
        // zeroing condition, causing the documented CM divergence from byte 26.
        t->factors0_err = (uint8_t)(t->factors0_err + (uint8_t)(std::abs((int32_t)((int32_t)(bit << 8) - 128 - ((int32_t)t->factors[0] >> 4))) >> 3));
        t->factors7_err = (uint8_t)(t->factors7_err + (uint8_t)(std::abs((int32_t)((int32_t)(bit << 8) - 128 - (int32_t)t->factors7_div16)) >> 3));

        *t->modeld_ptr = kLzModelLNext[t->modeld_cur * 2 + bit];

        tt = t->modela_cur;
        *t->modela_ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);

        *t->modelb_ptr = kLzModelLNext[t->modelb_cur * 2 + bit];

        tt = t->modelc_cur;
        *t->modelc_ptr = ((kDivideLookup[(uint8_t)tt] * ((uint32_t)(bit << 23) - (tt >> 9))) & ~0xFFu) + tt + ((uint8_t)tt != 255u);

        if (t->flags & 2)
            *t->modelf_ptr = (uint8_t)(t->modelf_cur + ((16 - t->modelf_cur + (bit << 8)) >> 5));
    }

    t->out_byte_wip = (uint16_t)(t->out_byte_wip * 2 + bit);

    if (t->out_byte_wip <= 0xFF) {
        t->bit_index_in_byte = (uint8_t)(t->bit_index_in_byte + 1);
        if (t->bit_index_in_byte == 4) {
            t->ptrs8[0] = &t->modelv[15 * (t->out_byte_wip - 15) + ((uint8_t)t->out_byte << 8)];
            t->ptrs8[1] = &t->modelw[15 * (t->out_byte_wip - 15) + t->hashes_arr28[1]];
            t->ptrs8[2] = CM_PtrGetX(t->ptrs8[2], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[2]));
            if (t->flags & 0x10) {
                t->ptrs8[3] = CM_PtrGetX(t->ptrs8[3], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[3]));
                if (t->flags & 0x20) {
                    t->ptrs8[4] = CM_PtrGetX(t->ptrs8[4], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[4]));
                }
            }
            if (t->flags & 4) {
                if (t->hashes_arr28[7] >= 27u * 27u * 27u) {
                    t->ptrs8[7] = CM_PtrGetX(t->ptrs8[7], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[7]));
                } else {
                    uint32_t tmp = 17u * t->hashes_arr28[7] + 1u + (t->out_byte_wip & 0xFu);
                    t->ptrs8[7] = &t->modelu[60 * (tmp >> 2) + (tmp & 3u)];
                }
            }
            if (t->flags & 0x40) {
                t->ptrs8[5] = CM_PtrGetX(t->ptrs8[5], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[5]));
                if (t->flags & 0x80)
                    t->ptrs8[6] = CM_PtrGetX(t->ptrs8[6], (uint8_t)(t->out_byte_wip ^ t->hashes_arr28[6]));
            } else {
                t->modeld_ptr = &t->modeld[15 * (t->out_byte_wip - 15) + (t->out_byte & 0xFF00u)];
            }
        } else {
            uint32_t incr = (bit + 1u) << ((t->bit_index_in_byte & 3) - 1);
            t->modeld_ptr += incr;
            t->ptrs8[0]   += incr;
            t->ptrs8[1]   += incr;
            incr *= 4;
            t->ptrs8[2] += incr;
            t->ptrs8[3] += incr;
            t->ptrs8[4] += incr;
            t->ptrs8[5] += incr;
            t->ptrs8[6] += incr;
            t->ptrs8[7] += incr;
        }
    } else {
        t->out_byte_wip = (uint16_t)(t->out_byte_wip - 256);

        CM_B_Finished(&t->cmb, (uint8_t)t->out_byte_wip);

        t->hashes_arr28[0] = 32u * t->out_byte_wip;
        t->ptrs8[0] = &t->modelv[256 * t->out_byte_wip];
        t->out_byte = (t->out_byte << 8) + t->out_byte_wip;

        t->hashes_arr28[1] = (uint16_t)t->out_byte << 8;
        t->ptrs8[1] = &t->modelw[t->hashes_arr28[1]];

        t->hashes_arr28[2] = (t->out_byte << 8) ^ t->out_byte_wip ^ 0xFFFFFF00u;
        uint32_t hash2 = 33595399u * t->hashes_arr28[2] ^ (t->hashes_arr28[2] >> 11);
        t->hashes_arr28[3] = t->out_byte;

        t->histhash6 += t->out_byte_wip;
        t->histhash6 = 0x2f208239u * (t->histhash6 - kHashHist6Mult[t->histbyte6[t->histpos6]]);
        t->histbyte6[t->histpos6] = (uint8_t)t->out_byte_wip;
        t->histpos6 = t->histpos6 < 5 ? (t->histpos6 + 1) : 0;
        t->hashes_arr28[4] = t->histhash6;

        if (t->cmb_result <= 31) {
            t->errorsum = std::min<uint8_t>(t->errorsum, 127);
            t->errorsum_flt1 = (uint8_t)((3 * t->errorsum_flt1 + t->errorsum) >> 2);
            t->errorsum_flt2 = (uint8_t)((3 * t->errorsum_flt2 + 2 + t->errorsum_flt1) >> 2);
            t->flags = kCmFlagCrap[16 * (t->errorsum_flt1 >> 3) + (t->errorsum_flt2 >> 3)];
        }
        t->errorsum = 0;

        uint32_t hash3 = 0, hash4 = 0;
        if (t->flags & 0x10) {
            hash3 = 33595399u * t->hashes_arr28[3] ^ (t->hashes_arr28[3] >> 11);
            if (t->flags & 0x20)
                hash4 = t->hashes_arr28[4] ^ _rotr(t->hashes_arr28[4], 11);
        }

        t->histhash10 += t->out_byte_wip;
        t->histhash10 = 0xAE8E8215u * (t->histhash10 - kHashHist10Mult[t->histbyte10[t->histpos10]]);
        t->histbyte10[t->histpos10] = (uint8_t)t->out_byte_wip;
        t->histpos10 = t->histpos10 < 9 ? t->histpos10 + 1 : 0;

        t->histhash24 += t->out_byte_wip;
        t->histhash24 = 0x99ABC1C7u * (t->histhash24 - kHashHist24Mult[t->histbyte24[t->histpos24]]);
        t->histbyte24[t->histpos24] = (uint8_t)t->out_byte_wip;
        t->histpos24 = t->histpos24 < 23 ? t->histpos24 + 1 : 0;

        uint32_t hash5 = 0, hash6 = 0;

        if (t->flags & 0x40) {
            t->hashes_arr28[5] = t->histhash10;
            hash5 = t->histhash10 ^ _rotr(t->histhash10, 11);
            if (t->flags & 0x80) {
                t->hashes_arr28[6] = t->histhash24;
                hash6 = t->histhash24 ^ _rotr(t->histhash24, 11);
            }
        }
        uint32_t hash7;

        bool is_ascii = false;
        uint8_t ascii_lower = 0;

        if (t->flags & 4) {
            ascii_lower = (uint8_t)(t->out_byte_wip ^ ((uint32_t)(t->out_byte_wip - 'A') < 26u ? 0x20u : 0u));
            if ((uint32_t)(ascii_lower - 'a') > 25u) {
                is_ascii = (ascii_lower > 0x7F && t->cmb.byte4E <= 19);
            } else {
                is_ascii = ((ascii_lower -= 96) && (ascii_lower <= 0x7F || t->cmb.byte4E <= 19));
            }
        }
        if (is_ascii) {
            uint32_t ascii_hash = ascii_lower + 27u * t->hashes_arr28[7];
            t->hashes_arr28[7] = ascii_hash;

            t->ascii_counter = (uint8_t)((t->ascii_counter | ((ascii_lower >> 7) & (t->ascii_counter == 0))) + 2);
            if (t->ascii_counter & 0x80)
                t->flags &= ~4;

            if (ascii_hash < 27u * 27u * 27u) {
                t->ptrs8[7] = &t->modelu[60 * (17u * ascii_hash >> 2) + (17u * ascii_hash & 3u)];
                hash7 = 0;
            } else {
                hash7 = 33595399u * ascii_hash ^ (ascii_hash >> 11);
            }
        } else {
            t->ascii_counter   = 0;
            t->hashes_arr28[7] = 0;
            t->ptrs8[7] = t->modelu;
            hash7 = 0;
        }

        t->upper_3bits_history = (t->out_byte_wip & 0xE0u) + (8u * t->upper_3bits_history & 0x1FFFFu);

        if (!(t->flags & 0x40)) {
            t->modeld_ptr = &t->modeld[t->out_byte & 0xFF00u];
            t->factors0_err_flt = (uint8_t)((t->factors0_err + 15u * t->factors0_err_flt + 8u) >> 4);
            t->factors7_err_flt = (uint8_t)((t->factors7_err + 15u * t->factors7_err_flt + 8u) >> 4);
            t->factors0_err = 0;
            t->factors7_err = 0;
        }

        CM_B_NewByte(&t->cmb);

        t->out_byte_wip      = 1;
        t->bit_index_in_byte = 0;

        t->ptrs8[2] = CM_GetHashSlot(t, hash2) + 4;
        if (t->flags & 0x10) {
            t->ptrs8[3] = CM_GetHashSlot(t, hash3) + 4;
            if (t->flags & 0x20)
                t->ptrs8[4] = CM_GetHashSlot(t, hash4) + 4;
        }
        t->ptrs8[5] = t->modelv;
        t->ptrs8[6] = t->modelv;

        if ((t->flags & 4) && t->hashes_arr28[7] >= 27u * 27u * 27u)
            t->ptrs8[7] = CM_GetHashSlot(t, hash7) + 4;

        if (t->flags & 0x40) {
            t->ptrs8[5] = CM_GetHashSlot(t, hash5) + 4;
            if (t->flags & 0x80)
                t->ptrs8[6] = CM_GetHashSlot(t, hash6) + 4;
        }
    }
    uint8_t cmb_result = (uint8_t)CM_B_Proc2(&t->cmb, (int)t->out_byte_wip, (int)bit, 8 - t->bit_index_in_byte, &t->factors[8]);
    t->ptrs8_cur[0] = *t->ptrs8[0];
    t->modele[0].ptr = &t->modele[0].model[t->ptrs8_cur[0]];
    t->modele[0].cur = *t->modele[0].ptr;
    t->factors[0] = (int16_t)(kModelInterpolation[t->modele[0].cur >> 20] - 2048);

    t->ptrs8_cur[1] = *t->ptrs8[1];
    t->modele[1].ptr = &t->modele[1].model[t->ptrs8_cur[1]];
    t->modele[1].cur = *t->modele[1].ptr;
    t->factors[1] = (int16_t)(kModelInterpolation[t->modele[1].cur >> 20] - 2048);

    uint8_t hist_and = (uint8_t)(t->ptrs8_cur[1] != 0);
    uint8_t hist_sum = hist_and;

    t->ptrs8_cur[2] = *t->ptrs8[2];
    t->modele[2].ptr = &t->modele[2].model[t->ptrs8_cur[2]];
    t->modele[2].cur = *t->modele[2].ptr;
    t->factors[2] = (int16_t)(kModelInterpolation[t->modele[2].cur >> 20] - 2048);

    hist_and = (uint8_t)(hist_and & (t->ptrs8_cur[2] != 0));
    hist_sum = (uint8_t)(hist_sum + hist_and);

    t->factors[3] = 0;
    t->factors[4] = 0;
    t->factors[5] = 0;
    t->factors[6] = 0;

    if (t->flags & 0x10) {
        t->ptrs8_cur[3] = *t->ptrs8[3];
        t->modele[3].ptr = &t->modele[3].model[t->ptrs8_cur[3]];
        t->modele[3].cur = *t->modele[3].ptr;
        t->factors[3] = (int16_t)(kModelInterpolation[t->modele[3].cur >> 20] - 2048);
        hist_and = (uint8_t)(hist_and & (t->ptrs8_cur[3] != 0));
        hist_sum = (uint8_t)(hist_sum + hist_and);
        if (t->flags & 0x20) {
            t->ptrs8_cur[4] = *t->ptrs8[4];
            t->modele[4].ptr = &t->modele[4].model[t->ptrs8_cur[4]];
            t->modele[4].cur = *t->modele[4].ptr;
            t->factors[4] = (int16_t)(kModelInterpolation[t->modele[4].cur >> 20] - 2048);
            hist_and = (uint8_t)(hist_and & (t->ptrs8_cur[4] != 0));
            hist_sum = (uint8_t)(hist_sum + hist_and);
        }
    }
    t->ptrs8_cur[5] = 0;
    t->ptrs8_cur[7] = 0;
    if (t->flags & 4) {
        t->ptrs8_cur[7] = *t->ptrs8[7];
        t->modele[7].ptr = &t->modele[7].model[t->ptrs8_cur[7]];
        t->modele[7].cur = *t->modele[7].ptr;
        t->factors[5] = (int16_t)(kModelInterpolation[t->modele[7].cur >> 20] - 2048);
    }
    if (t->flags & 0x40) {
        t->ptrs8_cur[5] = *t->ptrs8[5];
        t->modele[5].ptr = &t->modele[5].model[t->ptrs8_cur[5]];
        t->modele[5].cur = *t->modele[5].ptr;
        t->factors[7] = (int16_t)(kModelInterpolation[t->modele[5].cur >> 20] - 2048);
        hist_and = (uint8_t)(hist_and & (t->ptrs8_cur[5] != 0));
        hist_sum = (uint8_t)(hist_sum + hist_and);
        if (t->flags & 0x80) {
            t->ptrs8_cur[6] = *t->ptrs8[6];
            t->modele[6].ptr = &t->modele[6].model[t->ptrs8_cur[6]];
            t->modele[6].cur = *t->modele[6].ptr;
            t->factors[6] = (int16_t)(kModelInterpolation[t->modele[6].cur >> 20] - 2048);
            hist_and = (uint8_t)(hist_and & (t->ptrs8_cur[6] != 0));
            hist_sum = (uint8_t)(hist_sum + hist_and);
        }
    }

    if (!(t->flags & 0x40)) {
        if (t->flags & 2) {
            t->modelf_ptr = &t->modelf[t->bit_history2];
            t->modelf_cur = *t->modelf_ptr;
            t->factors[4] = (int16_t)(16 * t->modelf_cur - 2048);
        }
        t->modeld_cur = *t->modeld_ptr;

        t->modela_ptr = &t->modela[t->modeld_cur];
        t->modela_cur = *t->modela_ptr;

        t->factors[7]     = (int16_t)((t->modela_cur >> 20) - 2048);
        t->factors7_div16 = (int8_t)(t->factors[7] >> 4);
        if (hist_sum > 2 || cmb_result > 4 || (t->factors0_err_flt <= t->factors7_err_flt) || t->factors7_err_flt > 0x6Eu)
            t->factors[7] = 0;

        if (t->bit_index_in_byte > 4u || hist_sum > 3 || (t->flags & 1)) {
            t->modelb_ptr = &t->modelb[123];
            t->modelb_cur = *t->modelb_ptr;
            t->modelc_ptr = &t->modelc[t->modelb_cur];
            t->modelc_cur = *t->modelc_ptr;
        } else {
            t->modelb_ptr = &t->modelb[t->upper_3bits_history ^ t->out_byte_wip];
            t->modelb_cur = *t->modelb_ptr;
            t->modelc_ptr = &t->modelc[t->modelb_cur];
            t->modelc_cur = *t->modelc_ptr;
            t->factors[6] = (int16_t)(kModelInterpolation[t->modelc_cur >> 20] - 2048);
        }
    }

    uint32_t modelg_index = ((t->errorhist & 7u) << 8) + t->out_byte_wip + 2048u * (hist_sum > 3);

    t->cmb_result = cmb_result;

    uint8_t cm_bc = (t->ptrs8_cur[7] && !(t->ascii_counter & 1))
        ? (uint8_t)((t->ascii_counter > 3) + (t->ascii_counter > 9) + 1)
        : 0;
    t->modelh_ptr = t->modelh[cm_bc + 4 * ((cmb_result > 4) + (cmb_result > 9) + 3 * hist_sum)];

    int32_t fsum = 0;
    for (uint32_t ii = 0; ii != 12; ii++)
        fsum += (int32_t)t->factors[ii] * (int32_t)t->modelh_ptr[ii];
    t->next_probability = (uint32_t)std::min(std::max((fsum >> 16) + 2048, 0), 4095);

    uint32_t modelg_value = kLzPredSumLookup[t->next_probability >> 4];
    uint32_t hv = 12u * t->next_probability;

    uint32_t gmax = std::min<uint32_t>(1u << (hist_sum + (t->flags & 8) + 5), 255u) - (hist_sum == 4);

    uint32_t adjust = (uint8_t)t->modelg.cur > gmax ? gmax - (uint8_t)t->modelg.cur : 0u;

    uint32_t new_val = adjust + ((uint8_t)t->modelg.cur < gmax) + t->modelg.cur
        + ((kDivideLookup[(uint8_t)t->modelg.cur] * ((uint32_t)(bit << 23) - (t->modelg.cur >> 9))) & ~0xFFu);
    *t->modelg.cur_ptr = new_val;

    t->modelg.cur_ptr = &t->modelg.base_ptr[(hv >> 12) + modelg_index * 13];
    t->next_probability = (modelg_value
        + 3u * (((hv & 0xFFFu) * (t->modelg.cur_ptr[1] >> 12)
                + (4096u - (hv & 0xFFFu)) * (t->modelg.cur_ptr[0] >> 12)) >> 20)
        + 2u) >> 2;
    t->modelg.cur_ptr += (hv & 0xFFFu) >> 11;
    t->modelg.cur = *t->modelg.cur_ptr;

    uint32_t cmc_index = t->hashes_arr28[0] + bit + 2u * ((t->errorhist & 1u) + 2u * t->bit_index_in_byte);
    uint32_t cmcmult   = 2u * kModelInterpolation[t->next_probability] - 4096u;
    int32_t  errx      = (int32_t)(bit * 4096u) - (int32_t)t->next_prob_last;
    t->cmc_cur->v0 += t->cmc_v0_mult * (uint32_t)(errx >> 4);
    t->cmc_cur->v1 += t->cmc_v1_mult * (uint32_t)(errx >> 4);
    t->cmc_cur      = &t->cmc[cmc_index];
    t->cmc_v0_mult  = 512;
    t->cmc_v1_mult  = cmcmult;
    int32_t v168 = (int32_t)(
        ((int32_t)(t->cmc_cur->v0) >> 16) * 512
        + ((int32_t)(t->cmc_cur->v1) >> 16) * (int32_t)cmcmult
        + 128) >> 8;
    t->next_prob_last = kModelLutLookup[(uint32_t)std::min(std::max(v168 + 2048, 0), 4095)];

    t->next_probability = (t->next_probability + 3u * t->next_prob_last + 2u) >> 2;
    t->next_probability += (t->next_probability < 0x800u);
}

// ---------------------------------------------------------------------------
// CM_Decode
// ---------------------------------------------------------------------------

static void CM_Decode(CM* cm, const uint8_t* in, uint32_t in_size, uint8_t* out, uint32_t out_size) {
    ArithmeticDecoder adec;
    adec.InitializeX(in, in + in_size);
    adec.FillBuffer();

    if (!out_size)
        return;
    for (;;) {
        bool flag = adec.ReadHighPrec(cm->next_probability);
        CM_Input_Bit(cm, (uint32_t)flag);
        if (!cm->bit_index_in_byte) {
            *out++ = (uint8_t)cm->out_byte;
            if (!--out_size)
                break;
        }
    }
}

// ---------------------------------------------------------------------------
// CM_ModelG_Reset
// ---------------------------------------------------------------------------

static void CM_ModelG_Reset(CM_ModelG* mg) {
    for (uint32_t i = 0; i != 13; i++)
        mg->base_ptr[i] = ((uint32_t)kModelLutLookup[i * 4096 / 13 + 157] << 20) + 8;
    for (size_t i = 13; i != 53248; i++)
        mg->base_ptr[i] = mg->base_ptr[i - 13];
    mg->cur_ptr = mg->base_ptr;
    mg->cur     = *mg->cur_ptr;
}

// ---------------------------------------------------------------------------
// CM_Reset
// ---------------------------------------------------------------------------

static void CM_Reset(CM* cm) {
    CM_ModelG_Reset(&cm->modelg);
    cm->next_prob_last = 0;
    cm->cmc_v1_mult    = 0;
    cm->cmc_v0_mult    = 0;
    cm->cmc_cur        = cm->cmc;
    for (uint32_t i = 0; i < cm->cmc_size; i++) {
        cm->cmc[i].v0 = 0;
        cm->cmc[i].v1 = 0x800000;
    }
}

// ---------------------------------------------------------------------------
// CM_B_Init
// ---------------------------------------------------------------------------

static void CM_B_Init(CM_B* cmb) {
    memset(cmb->last_pos_for_byte, 0, sizeof(cmb->last_pos_for_byte));
    cmb->best_delta       = 0;
    cmb->delta_hist_index = 0;
    memset(cmb->delta_hist,  0, 0x200u);
    memset(cmb->delta_score, 0, 0x1FEu);
    *cmb->delta_score = 512;
    cmb->last_bytes  = 0;
    cmb->hash2pos    = 0;
    cmb->delta2pos   = 0;
    cmb->hash2attr   = 0;
    cmb->delta1pos   = 0;
    cmb->hash8len    = 0;
    cmb->hash4len    = 0;
    cmb->hash8pos    = 0;
    cmb->hash4pos    = 0;
    cmb->hash8attr   = 0;
    cmb->hash4attr   = 0;
    cmb->deltaattr   = 0;
    cmb->hash4byte   = 0;
    cmb->hash8byte   = 0;
    cmb->hash2byte   = 0;
    cmb->delta1byte  = 0;
    cmb->delta2byte  = 0;
    cmb->bestlen     = 0;
    cmb->byte4E      = 0;

    memset32(cmb->modelx, 0x80000000u, cmb->modelx_size);
    cmb->modelx_ptr = cmb->modelx;
    cmb->modelx_cur = *cmb->modelx;

    memset32(cmb->modely, 0x80000000u, cmb->modely_size);
    cmb->modely_ptr = cmb->modely;
    cmb->modely_cur = *cmb->modely;

    cmb->modelz_ptr = cmb->modelz;
    memset32(cmb->modelz, 0x80008000u, cmb->modelz_size >> 1);

    memset(cmb->modelq, 0x80u, 4u * ((cmb->modelq_size + 3) >> 2));
    cmb->modelq_ptr = cmb->modelq;
    cmb->modelq_cur = *cmb->modelq;

    cmb->histhash4  = 0;
    cmb->byte58     = 0;
    cmb->histbyte4  = 0;
    cmb->histhash8  = 0;
    cmb->histpos8   = 0;
    memset(cmb->histbyte8, 0, sizeof(cmb->histbyte8));
    memset(cmb->cmt, 0, 4u * (cmb->cmt_mask + 270337u));
}

// ---------------------------------------------------------------------------
// CM_Init
// ---------------------------------------------------------------------------

static void CM_Init(CM* cm) {
    cm->ptrs8[0] = cm->modelv;
    cm->ptrs8[1] = cm->modelw;
    uint8_t* vv  = CM_GetHashSlot(cm, 0);
    cm->ptrs8[2] = vv;
    cm->ptrs8[3] = vv;
    cm->ptrs8[4] = vv;
    cm->ptrs8[5] = vv;
    cm->ptrs8[6] = vv;
    cm->ptrs8[7] = vv;
    for (uint32_t i = 0; i != 8; i++) {
        memset32(cm->modele[i].model, 0x80000000u, cm->modele[i].size);
        cm->modele[i].ptr = cm->modele[i].model;
        cm->modele[i].cur = *cm->modele[i].ptr;
    }
    memset(cm->modeld, 0, 4u * ((cm->modeld_size + 3) >> 2));
    cm->modeld_ptr = cm->modeld;
    cm->modeld_cur = *cm->modeld_ptr;

    memset32(cm->modela, 0x80000000u, 0x100u);
    cm->modela_ptr = cm->modela;
    cm->modela_cur = cm->modela[0];

    memset(cm->modelb, 0, 4u * ((cm->modelb_size + 3) >> 2));
    cm->modelb_ptr = cm->modelb;
    cm->modelb_cur = *cm->modelb;

    memset32(cm->modelc, 0x80000000u, 0x100u);
    cm->modelc_ptr = cm->modelc;
    cm->modelc_cur = cm->modelc[0];

    memset(cm->modelf, 0x80u, 4u * ((cm->modelf_size + 3) >> 2));
    cm->modelf_ptr = cm->modelf;
    cm->modelf_cur = *cm->modelf;

    CM_ModelG_Reset(&cm->modelg);
    cm->next_prob_last = 0;
    cm->cmc_v1_mult    = 0;
    cm->cmc_v0_mult    = 0;
    cm->cmc_cur        = cm->cmc;
    for (uint32_t i = 0; i < cm->cmc_size; i++) {
        cm->cmc[i].v0 = 0;
        cm->cmc[i].v1 = 0x800000;
    }
    cm->errorsum_flt1 = 127;
    cm->errorsum_flt2 = 127;
    cm->histhash24    = 0;
    cm->histpos24     = 0;
    memset(cm->histbyte24, 0, sizeof(cm->histbyte24));
    cm->histhash10    = 0;
    cm->histpos10     = 0;
    memset(cm->histbyte10, 0, sizeof(cm->histbyte10));
    cm->histhash6     = 0;
    cm->histpos6      = 0;
    memset(cm->histbyte6, 0, sizeof(cm->histbyte6));
    CM_B_Init(&cm->cmb);
    memset(cm->ptrs8_cur, 0, sizeof(cm->ptrs8_cur));
    memset(cm->modelv, 0, 0x10000);
    memset(cm->modelw, 0, 0x1000000);
    memset(cm->modelu, 0, 0x4CA70C);
    memset(cm->hashes_arr28, 0, sizeof(cm->hashes_arr28));
    cm->next_probability    = 2048;
    cm->out_byte_wip        = 1;
    cm->out_byte            = 0;
    cm->bit_index_in_byte   = 0;
    cm->errorsum            = 0;
    cm->factors7_err_flt    = 0;
    cm->factors0_err_flt    = 0;
    cm->factors7_div16      = 0;
    cm->upper_3bits_history = 0;
    cm->cmb_result          = 0;
    cm->errorhist           = 0;
    cm->flags               = 0;
    cm->bit_history2        = 0;
    cm->ascii_counter       = 0;
    cm->factors7_err        = 0;
    cm->factors0_err        = 0;
    memset(cm->factors, 0, sizeof(cm->factors));
    memset(cm->modelh,  0, sizeof(cm->modelh));
    cm->modelh_ptr = (int16_t*)cm->modelh;
    memset(cm->some_ptr, 0, cm->some_mask + 16449);
}

// ---------------------------------------------------------------------------
// CM_Allocate
// ---------------------------------------------------------------------------

static CM* CM_Allocate(int a_bits, int b_bits, uint32_t window_size) {
    CM* cm = new CM(a_bits, b_bits);

    cm->cmb.window_size  = window_size;
    cm->cmb.window       = (new uint8_t[window_size + 64]) + 64;
    memset(cm->cmb.window - 64, 0, cm->cmb.window_size + 64);
    cm->cmb.write_pos    = 1;
    cm->cmb.mask         = (1u << (BSR(window_size - 1) + 1)) - 1;
    cm->cmb.inverse_mask = ~cm->cmb.mask;

    CM_Init(cm);

    return cm;
}

// ---------------------------------------------------------------------------
// CM_Free
// ---------------------------------------------------------------------------

static void CM_Free(CM* cm) {
    free(cm->some_ptr);
    free(cm->cmb.delta_score);
    free(cm->cmb.delta_hist);
    free(cm->cmb.cmt);
    free(cm->cmb.modelq);
    free(cm->cmb.modelz);
    free(cm->cmb.modelx);
    free(cm->cmb.modely);
    free(cm->modelg.base_ptr);
    free(cm->modeld);
    free(cm->modelb);
    delete[] cm->cmc;
    free(cm->modelf);
    free(cm->modelu);
    free(cm->modelv);
    free(cm->modelw);
    for (size_t i = 0; i < 8; i++)
        free(cm->modele[i].model);
    delete[] (cm->cmb.window - 64);
    delete cm;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void NzCmInitAll() {
    Build_kModelInterpolation();
    LzCreateTables();
    CM_InitTables();
}

NzCmDecoder* NzCmCreate(int a_bits, int b_bits, uint32_t window_size) {
    return reinterpret_cast<NzCmDecoder*>(CM_Allocate(a_bits, b_bits, window_size));
}

void NzCmDestroy(NzCmDecoder* cm) {
    CM_Free(reinterpret_cast<CM*>(cm));
}

void NzCmReset(NzCmDecoder* cm) {
    CM_Reset(reinterpret_cast<CM*>(cm));
}

void NzCmDecode(NzCmDecoder* cm, const uint8_t* in, uint32_t in_size,
                uint8_t* out, uint32_t out_size) {
    CM_Decode(reinterpret_cast<CM*>(cm), in, in_size, out, out_size);
}
