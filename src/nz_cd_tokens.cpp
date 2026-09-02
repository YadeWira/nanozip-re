// Native linux32 `-cd` token pipeline. See nz_cd_tokens.h for the contract and
// the reverse-engineering provenance (FUN_08099050 / FUN_080aa070).
#include <cstdio>
#include <cstdlib>
#include "nz_cd_tokens.h"
#include "nz_text_transform.h"
#include "lzpf_arith.h"   // lzpf BitReader (FUN_080b1fb0) for the RLE length coder
#include "nz_cd_texttransform_dict.h"   // &8 bit 0x8 word-dictionary transform
#include "nz_lzhds.h"     // -cD (nz_lzhds) literal model

#include <cstring>
#include <vector>

namespace nzr {
namespace cd {
// NZOPT_TRACE_CD-gated diagnostics, following this project's existing
// NZOPT_TRACE_* convention (zero cost when unset). This file had NO
// instrumentation at all, which made every -cd/-cD decline indistinguishable
// from every other -- the reason -cD sat at 34/60 on the real corpus without
// anyone being able to say why.
static bool CdTrace() {
    static const bool on = (std::getenv("NZOPT_TRACE_CD") != nullptr);
    return on;
}
#define CD_FAIL(...) do { if (CdTrace()) std::fprintf(stderr, "[CD] " __VA_ARGS__); } while (0)


std::uint32_t NzCdReconstruct(const std::uint32_t* tokens, std::uint32_t num_tokens,
                              const std::uint8_t* literals,
                              std::uint8_t* out, std::uint32_t out_size) {
    std::uint32_t rep[4] = {1, 1, 1, 1};
    std::uint32_t pos = 0;
    const std::uint8_t* lp = literals;
    for (std::uint32_t t = 0; t < num_tokens && pos < out_size; ++t) {
        std::uint32_t lit_run = tokens[t * 3 + 0];
        std::uint32_t sel     = tokens[t * 3 + 1];
        std::uint32_t raw_len = tokens[t * 3 + 2];
        std::uint32_t old_rm0 = rep[0];
        std::uint32_t offset, mlen;
        if (sel >= 4) {                       // new match
            offset = sel - 3;
            rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = old_rm0; rep[0] = offset;
            mlen = raw_len + 4 + (offset > 0x63ffu) + (offset > 0x4ffu);
        } else {                              // repeat-match (MTF over rep[])
            offset = rep[sel];
            mlen = raw_len + 2;
            if (sel == 1)      { rep[1] = rep[0]; }
            else if (sel == 2) { rep[2] = rep[1]; rep[1] = rep[0]; }
            else if (sel == 3) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
            rep[0] = offset;
        }
        if (lit_run) {
            if (pos + lit_run > out_size) lit_run = out_size - pos;
            std::memcpy(out + pos, lp, lit_run);
            lp += tokens[t * 3 + 0];  // advance by the full (unclamped) run
            pos += lit_run;
            if (pos >= out_size) break;
        }
        // Sanity: a match can only reference bytes already produced in `out`
        // (offset in [1, pos]). Garbage/mismatched bytecode can decode an
        // out-of-range offset; unchecked, `out + pos - offset` would point
        // before the buffer and read/write out of bounds. Refuse (0 sentinel,
        // safe: normal completion always returns out_size > 0 below) instead.
        if (offset == 0 || offset > pos) return 0;
        std::uint8_t* dst = out + pos;
        const std::uint8_t* src = out + pos - offset;
        if (pos + mlen > out_size) mlen = out_size - pos;
        for (std::uint32_t i = 0; i < mlen; ++i) dst[i] = src[i];  // overlap-safe
        pos += mlen;
    }
    // Trailing literal flush: the legacy recon loops until out_size bytes are
    // produced (FUN_08099050: `while (local_58 != 0)`). When the token stream does
    // not exactly fill the chunk, the remaining bytes are copied straight from the
    // literal stream. `literals` must hold these extra bytes (see total-literal
    // count in DecodeChunk: out_size - sum(match lengths)).
    if (pos < out_size) {
        std::memcpy(out + pos, lp, out_size - pos);
        pos = out_size;
    }
    return pos;
}

namespace {
// MSB-first bit reader over byte-swapped (big-endian) 32-bit words. A word is
// read while the cursor is before the logical end, even if it overruns by up to
// 3 bytes (the buffer carries trailing slack).
struct BitReader {
    const std::uint8_t* base;
    std::size_t orig_bytes;
    std::size_t widx;
    std::uint32_t val;
    std::uint32_t bits;

    BitReader(const std::uint8_t* b, std::size_t orig)
        : base(b), orig_bytes(orig), widx(0), val(0), bits(0) {}

    std::uint32_t word(std::size_t i) const {
        std::uint32_t w;
        std::memcpy(&w, base + i * 4, 4);
        return ((w & 0xff000000u) >> 24) | ((w & 0x00ff0000u) >> 8) |
               ((w & 0x0000ff00u) << 8)  | ((w & 0x000000ffu) << 24);
    }
    std::uint32_t read(std::uint32_t n) {  // n >= 1
        std::uint32_t res;
        if (bits < n) {
            std::uint32_t hi = val << (n - bits);
            std::uint32_t nb = 32 - (n - bits);
            std::uint32_t w = (widx * 4 < orig_bytes) ? word(widx) : nb;
            ++widx;
            val = w;
            res = hi | (val >> nb);
            bits = nb;
        } else {
            bits -= n;
            res = val >> bits;
        }
        return res;
    }
};

inline std::uint32_t DecodeField(std::uint8_t b, const NzCdField& f, BitReader& br) {
    if (b < f.threshold) return b;
    std::uint32_t idx = b - f.threshold;
    std::uint32_t slot = f.slot_tbl[idx];
    std::uint32_t nbits = f.model[slot + 1];
    if (nbits == 0) return b;  // == threshold + idx
    std::uint32_t baseoff = f.model[slot];
    std::uint32_t k = slot >> 1;
    std::uint32_t base = (k == 0) ? 0u : (1u << k);
    std::uint32_t extra = br.read(nbits) & ((1u << nbits) - 1u);
    return (extra | (((idx - baseoff) << nbits) + base)) + f.threshold;
}
}  // namespace

void NzCdTokenAssemble(std::uint32_t num_tokens,
                       const std::uint8_t* col_lit,
                       const std::uint8_t* col_off,
                       const std::uint8_t* col_len,
                       const std::uint8_t* bitstream, std::size_t bitstream_len,
                       const NzCdField& field_lit,
                       const NzCdField& field_off,
                       const NzCdField& field_len,
                       std::uint32_t* out_tokens) {
    BitReader br(bitstream, bitstream_len);
    for (std::uint32_t i = 0; i < num_tokens; ++i) {
        out_tokens[i * 3 + 0] = DecodeField(col_lit[i], field_lit, br);  // lit_run
        out_tokens[i * 3 + 1] = DecodeField(col_off[i], field_off, br);  // sel/offset
        out_tokens[i * 3 + 2] = DecodeField(col_len[i], field_len, br);  // raw_len
    }
}

// ---------------------------------------------------------------------------
// param14 (FUN_080a0ff0): char-class space-insertion text transform.
namespace {
// Character-class table — the deterministic output of FUN_080b7600.
// Class flags tested by the transform: &1, &2, &4, &8.
static const unsigned char kClassTable[256] = {
    6,6,6,6,6,6,6,6,6,2,3,6,6,6,6,6,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    2,7,3,2,6,6,2,3,2,7,2,2,7,3,5,3,
    8,8,8,8,8,8,8,8,8,8,3,3,3,2,3,7,
    6,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    4,4,4,4,4,4,4,4,4,4,4,2,2,3,6,2,
    6,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,12,12,12,8,12,2,3,3,6,6,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
}  // namespace

std::uint32_t NzCdParam14(const std::uint8_t* src, std::uint32_t src_len,
                          std::uint8_t* dst, std::uint32_t dst_cap) {
    const unsigned char* CLS = kClassTable;
    if (src_len == 0) return 0;
    const std::uint8_t* pbVar1 = dst + dst_cap + 1;
    std::uint32_t uVar4 = src[0];
    std::uint8_t* pbVar2 = dst;
    const std::uint8_t* param_1 = src;
    int param_2 = static_cast<int>(src_len);
    std::uint8_t *pbVar5 = nullptr, *pbVar6 = nullptr;
    const std::uint8_t* pbVar8 = nullptr;
    std::uint32_t uVar3 = 0;
    int iVar7 = 0;
LOOP:
    while (true) {
        if (pbVar1 <= pbVar2) return 0;
        *pbVar2 = static_cast<std::uint8_t>(uVar4);
        pbVar5 = pbVar2 + 1;
        iVar7 = param_2 - 1;
        pbVar6 = pbVar5;
        if (iVar7 == 0) goto L_115a;
        pbVar8 = param_1 + 1;
        uVar3 = *pbVar8;
        if (uVar3 > 0x7f && uVar4 > 0x7f) {
            *pbVar5 = static_cast<std::uint8_t>(uVar3);
            pbVar2[2] = 0x20;
            pbVar6 = pbVar2 + 3;
            iVar7 = param_2 - 2;
            if (iVar7 == 0) goto L_115a;
            pbVar8 = param_1 + 2;
            uVar4 = *pbVar8;
            if (uVar4 == 0x20) {
            L_10d0:
                pbVar6 = pbVar6 - 1;
                iVar7 = iVar7 - 1;
                if (iVar7 == 0) goto L_115a;
                pbVar8 = pbVar8 + 1;
            L_10df:
                uVar4 = *pbVar8;
                pbVar2 = pbVar6;
                param_2 = iVar7;
                param_1 = pbVar8;
            } else {
                pbVar2 = pbVar2 + (((CLS[uVar4] & 1) == 0) ? 1 : 0) + 2;
                param_2 = iVar7;
                param_1 = pbVar8;
            }
            goto LOOP;
        L_10d0_entry: goto L_10d0;
        L_10df_entry: goto L_10df;
        }
        param_2 = iVar7;
        if (((CLS[uVar4] & 4) != 0) ||
            ((uVar3 < 0x80 && uVar4 > 0x7f) &&
             (uVar3 != 0x20 || (static_cast<std::int8_t>(param_1[2]) >= 0)) && (iVar7 != 1))) {
            *pbVar5 = 0x20;
            pbVar6 = pbVar2 + 2;
            if (uVar3 == 0x20) goto L_10d0_entry;
            if ((CLS[uVar3] & 1) == 0) goto L_10df_entry;
            uVar4 = *pbVar8;
            pbVar2 = pbVar2 + 1;
            param_1 = pbVar8;
        } else {
            uVar4 = uVar3;
            pbVar2 = pbVar5;
            param_1 = pbVar8;
            if ((CLS[uVar3] & 8) != 0) {
                while (true) {
                    param_2 = iVar7 - 1;
                    *pbVar5 = static_cast<std::uint8_t>(uVar3);
                    pbVar6 = pbVar5 + 1;
                    if (param_2 == 0) goto L_115a;
                    param_1 = pbVar8 + 1;
                    if (pbVar1 <= pbVar6) { uVar4 = *param_1; pbVar2 = pbVar6; goto LOOP; }
                    if ((CLS[uVar3] & 2) != 0) break;
                    uVar3 = *param_1;
                    pbVar5 = pbVar6;
                    iVar7 = param_2;
                    pbVar8 = param_1;
                }
                uVar4 = *pbVar8;
                pbVar2 = pbVar5;
                param_2 = iVar7;
                param_1 = pbVar8;
            }
        }
    }
L_115a:
    return (pbVar6 < pbVar1) ? static_cast<std::uint32_t>(pbVar6 - dst) : 0u;
}

// ---------------------------------------------------------------------------
// param14 ends above.  Per-column RLE run-expander (FUN_080acb90).
std::uint32_t NzCdRleExpand(const std::uint8_t* src, std::uint32_t count,
                            std::uint8_t* dst, std::uint32_t dst_cap, std::uint32_t thr,
                            const std::uint8_t* rle_bits, std::size_t rle_bits_len) {
    if (count == 0) return 0;
    nzr::lzpf::BitReader br{};
    nzr::lzpf::Init(br, rle_bits, rle_bits_len);
    // FUN_08090070: run length = (1<<k) | ReadBits(k), or ReadBits(1) when k==0.
    auto coder = [&](std::uint32_t k) -> std::uint32_t {
        return k ? (nzr::lzpf::ReadBits(br, k) | (1u << k)) : nzr::lzpf::ReadBits(br, 1);
    };
    long cap = static_cast<long>(dst_cap);
    if (cap < static_cast<long>(count)) return 0;
    const std::uint8_t* p1 = src;
    long p2 = static_cast<long>(count) + 1;
    std::uint8_t* p8 = dst;
    std::uint8_t* local_28 = dst;
    std::uint32_t win = 0;          // rolling 4-byte window (CONCAT31)
    std::uint32_t w5 = 0;
    long pcVar9 = 0;
    while (true) {
        p2 -= 1;
        pcVar9 = 0;
        w5 = win;
        if (p2 != 0) {
            std::uint8_t cur = *p1; w5 = (win << 8) | cur; p1++;
            *p8 = cur; p8++;
            std::uint8_t prev = static_cast<std::uint8_t>(win);
            int thr_cd = static_cast<int>(thr);
            win = w5;
            if (cur != prev) continue;               // no run
            bool ended = false;
            while (true) {
                pcVar9 = p2 - 1;
                if (pcVar9 == 0) break;
                cur = *p1; win = (w5 & 0xffffff00u) | cur; p1++;
                *p8 = cur; p8++;
                p2 = pcVar9;
                if (cur != static_cast<std::uint8_t>(w5 >> 8)) { ended = true; break; }
                bool cont = (0 < thr_cd); thr_cd -= 1; w5 = win;
                if (!cont) break;
            }
            if (ended) continue;
        }
        win = w5 & 0xff;
        if (pcVar9 == 0) break;                       // done
        p1 -= 1;
        long pcVar3 = pcVar9;
        while (true) { p1++; pcVar3--; if (pcVar3 == 0) break; if (static_cast<std::uint8_t>(w5) != *p1) break; }
        pcVar3 = pcVar9 + (-1 - pcVar3);
        if (pcVar3 > 0x1e) break;                     // overlong run -> stop
        cap = (local_28 - dst) + (cap - (p8 - dst));
        std::uint32_t len = coder(static_cast<std::uint32_t>(pcVar3));
        p2 = pcVar9 - pcVar3;
        if (cap < p2 + static_cast<long>(len) - 1) break;
        local_28 = p8;
        for (std::uint32_t i = 0; i < len; ++i) p8[i] = static_cast<std::uint8_t>(w5);
        p8 += len;
    }
    return static_cast<std::uint32_t>(p8 - dst);
}


// ---------------------------------------------------------------------------
// Integrated single-chunk -cd LZ decoder (header parse + cols + tokens + recon).
namespace {
static const unsigned char g_kCdSlotLit[256] = {
    0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,
    32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char g_kCdModelLit[64] = {
    0,1,1,1,2,2,3,3,4,4,5,5,6,6,7,7,
    8,8,9,9,10,10,11,11,12,12,13,13,14,14,15,15,
    16,16,17,17,18,18,19,19,20,20,21,21,22,22,23,23,
    24,24,25,25,26,26,27,27,28,28,29,29,30,30,31,31,
};
static const unsigned char g_kCdSlotOff[256] = {
    0,0,2,2,4,4,4,4,6,6,6,6,8,8,8,8,
    10,10,10,10,12,12,12,12,14,14,14,14,16,16,16,16,
    18,18,18,18,20,20,20,20,22,22,22,22,24,24,24,24,
    26,26,26,26,28,28,28,28,30,30,30,30,32,32,32,32,
    34,34,34,34,36,36,36,36,38,38,38,38,40,40,40,40,
    42,44,46,48,50,52,54,56,58,60,62,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char g_kCdModelOff[64] = {
    0,0,2,0,4,0,8,1,12,2,16,3,20,4,24,5,
    28,6,32,7,36,8,40,9,44,10,48,11,52,12,56,13,
    60,14,64,15,68,16,72,17,76,19,80,21,81,22,82,23,
    83,24,84,25,85,26,86,27,87,28,88,29,89,30,90,31,
};
static const unsigned char g_kCdSlotLen[256] = {
    0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,
    32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char g_kCdModelLen[64] = {
    0,1,1,1,2,2,3,3,4,4,5,5,6,6,7,7,
    8,8,9,9,10,10,11,11,12,12,13,13,14,14,15,15,
    16,16,17,17,18,18,19,19,20,20,21,21,22,22,23,23,
    24,24,25,25,26,26,27,27,28,28,29,29,30,30,31,31,
};
// FUN_080b1dc0: bounded LEB-ish varint over a byte cursor (limit bounds byte count).
struct CdRd { const std::uint8_t* cur; const std::uint8_t* end; };
// Bytes still readable. NEVER compute this as `(std::size_t)(r.end - r.cur)`:
// several advances below are driven by a length read out of the stream, and once
// cur passes end that subtraction underflows to ~2^64, after which the next
// DecodeArithBuffer call is handed a "size" of two exabytes and reads whatever
// follows the buffer in memory. A -cdP archive reached exactly that (a 105-byte
// stream whose chunk consumed 907), so it is not hypothetical.
static std::size_t CdAvail(const CdRd& r) {
    return (r.cur < r.end) ? static_cast<std::size_t>(r.end - r.cur) : 0u;
}
// Skip n bytes; false (and cur parked at end) when the stream is too short.
static bool CdSkip(CdRd& r, std::uint32_t n) {
    if (static_cast<std::size_t>(n) > CdAvail(r)) { r.cur = r.end; return false; }
    r.cur += n;
    return true;
}
static std::uint32_t CdReadVar(CdRd& r, std::uint32_t limit) {
    std::uint8_t b = (r.cur < r.end) ? *r.cur++ : 0;
    if (limit < 0x101u) return b;
    std::uint32_t acc = 0, sh = 0;
    while (true) {
        if (!(b & 0x80u)) return (static_cast<std::uint32_t>(b & 0x7fu) << sh) | acc;
        acc |= static_cast<std::uint32_t>(b & 0x7fu) << sh; sh += 7;
        limit = ((limit & 0x7fu) ? 1u : 0u) + (limit >> 7);
        b = (r.cur < r.end) ? *r.cur++ : 0;
        if (limit < 0x101u) return (static_cast<std::uint32_t>(b) << sh) | acc;
    }
}
// Exe filter (chunk flag &4, FUN_080c0540): a BCJ-style x86 E8/E9 call/jmp address
// un-transform. Scans for E8/E9 opcodes; when the 4-byte little-endian address that
// follows has a high byte of 0x00 or 0xFF (a near address), it converts the stored
// value back to absolute by subtracting the current position (& 0xffffff) and
// sign-extends bit 24 into the high byte. After every E8/E9 the 4 address bytes are
// skipped (even when not transformed). `pos_base` = 4 + the chunk's output offset
// (the dispatcher's running *param_1, seeded at 4). Operates in place on `buf`.
}  // namespace
void NzCdExeUnfilter(std::uint8_t* buf, std::uint32_t size, std::uint32_t pos_base) {
    if (size <= 9) return;
    long end = static_cast<long>(size) - 6;
    long i = 0;
    while (i < end) {
        if (buf[i] != 0xE8u && buf[i] != 0xE9u) { ++i; continue; }
        long ap = i + 1;                              // address bytes at ap..ap+3
        std::uint8_t hi = buf[ap + 3];
        if (hi == 0x00u || hi == 0xFFu) {
            std::uint32_t addr = static_cast<std::uint32_t>(buf[ap]) |
                                 (static_cast<std::uint32_t>(buf[ap + 1]) << 8) |
                                 (static_cast<std::uint32_t>(buf[ap + 2]) << 16) |
                                 (static_cast<std::uint32_t>(buf[ap + 3]) << 24);
            std::uint32_t p = (static_cast<std::uint32_t>(ap) + pos_base) & 0xffffffu;
            addr -= p;
            buf[ap]     = addr & 0xffu;
            buf[ap + 1] = (addr >> 8) & 0xffu;
            buf[ap + 2] = (addr >> 16) & 0xffu;
            buf[ap + 3] = (addr & 0x01000000u) ? 0xffu : 0x00u;
        }
        i = ap + 4;
    }
}

namespace {
// FUN_080a2f20 — line-level RLE / back-reference text expander (the bit-5 stage of
// the &8 text pipeline). The first input byte is the line terminator ("match" byte,
// usually '\n'); literal bytes are copied until that terminator, after which the next
// byte selects: <0xE0 = start of a new line (set the back-ref base to here); ==0xE0 =
// skip marker; >0xE0 = copy (byte-0xE0) bytes from the back-ref base (repeat the prior
// line content). Byte-exact vs the binary. `prev` is a pointer into the OUTPUT.
std::uint32_t NzCdLineRle(const std::uint8_t* src0, std::uint32_t size,
                          std::uint8_t* dst, std::uint32_t cap) {
    if (size <= 1) return 0;
    std::uint8_t* dst_end = dst + cap;
    const std::uint8_t* src = src0;
    std::uint8_t match = *src++;
    long counter = static_cast<long>(size) - 1;
    std::uint8_t* out = dst;
    std::uint8_t* prev = dst;
    while (true) {
        long remaining = static_cast<long>(dst_end - out);
        long n = (counter < remaining) ? counter : remaining;
        const std::uint8_t* s = src;
        long c = n;
        std::uint8_t dl = 0;
        while (true) {
            dl = *s++; *out++ = dl; c--;
            if (c == 0) break;
            if (dl != match) continue;
            break;
        }
        counter -= (n - c);
        src = s;
        if (counter == 0) break;
        if (c == 0) return 0;
        std::uint8_t nb = *src;
        if (nb > 0xe0u) {
            std::uint32_t cnt = static_cast<std::uint32_t>(nb) - 0xe0u;
            std::uint8_t* nout = out + cnt;
            if (dst_end < nout) return 0;
            for (std::uint32_t i = 0; i < cnt; ++i) out[i] = prev[i];
            counter -= 1;
            if (counter == 0) { out = nout; break; }
            src += 1; prev = out; out = nout;
        } else if (nb == 0xe0u) {
            counter -= 1;
            if (counter == 0) break;
            src += 1; prev = out;
        } else {
            prev = out;
        }
    }
    return static_cast<std::uint32_t>(out - dst);
}

// FUN_080a19b0 — EOL normalizer (the bit-0 stage): a small state machine that copies
// text and rewrites line endings to CRLF (\r, \n, \r\n -> \r\n), with one-byte
// lookahead. Byte-exact vs the binary.
std::uint32_t NzCdCrlf(const std::uint8_t* src, std::uint32_t insz,
                       std::uint8_t* dst, std::uint32_t cap) {
    if (cap == 0 || insz == 0) return 0;
    const std::uint8_t* ebp = src;
    std::uint8_t* ecx = dst;            // committed out
    std::uint8_t* eax = dst;            // working out
    long s14 = static_cast<long>(cap) + 1;
    std::uint8_t s13 = 0, sb = 0;
    long s1c = 0, s0 = insz;
    const std::uint8_t* s4 = nullptr;
    while (true) {
        long esi = (s0 < s14) ? s0 : s14;
        eax = ecx;
        long edi = esi;
        std::uint8_t cl = sb, bl = 0;
        while (true) {
            bl = cl; cl = *ebp++; *eax++ = cl; edi--;
            if (edi == 0) break;
            if (cl > 0x0d) continue;
            if (cl != 0x0d && cl != 0x0a) continue;
            break;
        }
        esi -= edi;
        s14 -= esi;
        sb = cl; ecx = eax; s4 = ebp; s13 = bl;
        if (s14 == 0) return 0;
        s0 -= esi;
        if (s0 == 0) return static_cast<std::uint32_t>(eax - dst);
        if (s1c == 1) {
            if (sb == 0x0a) {
                eax[-1] = 0x0d; eax[0] = 0x0a; s14 -= 1;
                if (s14 == 0) return 0;
                ecx += 1; sb = 0; continue;
            } else {
                eax[-1] = *s4; s0 -= 1;
                if (s0 == 0) return static_cast<std::uint32_t>(eax - dst);
                ebp += 1; sb = 0; s1c = 0; continue;
            }
        } else if (s1c == 2) {
            if (sb == 0x0a) { eax[-1] = 0x0d; sb = 0; continue; }
            eax[-1] = 0x0a; sb = 0; s1c = 0; continue;
        } else if (sb == 0x0a) {
            if (s13 != 0x0d) continue;
            s1c = 1; continue;
        } else if (sb == 0x0d) {
            if (*s4 <= 0x0d) continue;
            s1c = 2; continue;
        } else continue;
    }
}
}  // namespace

// &8 text pipeline (FUN_080a3c90): a param bitmask selects an ordered sequence of text
// transforms applied with double-buffering. Supported bits: 0x80 param14, 0x8 word
// dictionary (NzCdDict; reorder_ascii=true for -cd, type!=7), 0x20 line-RLE
// (FUN_080a2f20), 0x1 CRLF EOL (FUN_080a19b0), applied in that dispatch order (the
// reference order is 0x80,0x10,0x8,0x4,0x2,0x20,0x40,0x1). Any other bit set means a
// transform not yet ported (0x10 tt16-num, 0x4 html, 0x2 insert-LF) -> return 0 so the
// caller bridges. Every text stage EXPANDS, so each intermediate <= the final output.
std::uint32_t NzCdTextPipeline(const std::uint8_t* src, std::uint32_t size,
                               std::uint8_t* out, std::uint32_t out_cap, std::uint32_t param) {
    const std::uint32_t kSupported = 0x80u | 0x8u | 0x20u | 0x40u | 0x1u;
    if (param & ~kSupported) do { CD_FAIL("text pipeline: unsupported bits 0x%x (param=0x%x)\n", param & ~kSupported, param); return 0; } while (0);
    std::vector<std::uint8_t> sa(out_cap + 64, 0), sb(out_cap + 64, 0);
    std::uint8_t* bufs[2] = {sa.data(), sb.data()};
    const std::uint8_t* cur = src;
    std::uint32_t n = size; int bi = 0;
    if (param & 0x80u) { std::uint32_t m = NzCdParam14(cur, n, bufs[bi], out_cap); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (param & 0x08u) { std::uint32_t m = NzCdDict(cur, n, bufs[bi], out_cap, false); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (param & 0x20u) { std::uint32_t m = NzCdLineRle(cur, n, bufs[bi], out_cap); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    // 0x40 sits between 0x20 and 0x01 in the reference's dispatch order. Same
    // codec-agnostic function the -cc/-co chains use (see nz_text_transform.h).
    if (param & 0x40u) { std::uint32_t m = ::NzTextTransform6(cur, n, bufs[bi], out_cap); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (param & 0x01u) { std::uint32_t m = NzCdCrlf(cur, n, bufs[bi], out_cap);    if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (n > out_cap) n = out_cap;
    std::memcpy(out, cur, n);
    return n;
}

namespace {
// --- cross-chunk LZ ring window (FUN_08099050, obj+0x978) --------------------
// The LZ window is a ring whose size is PER-ARCHIVE: ring_size = (method_p1+1)*0x10000
// (64 KB, 128 KB, 192 KB, ...; the same dictionary-size rule as lzpf, sfx_archive.cpp
// uses for -cf). It is a multiple of 0x10000 but NOT necessarily a power of two
// (192 KB = 3*64 KB), so indices wrap by MODULAR add/subtract, not a bitmask.
// Each chunk's COMPACT recon is written at the chunk base; the base advances by the
// COMPACT out_size and resets to 0 when a chunk would not fit before the ring end
// (GDB-verified vs the binary across f18/text50/elf/map/source: ringsz 65536 -> f18
// chunk2 resets; ringsz 196608 -> sfx chunks advance 0,32768,...,163840 then chunk6
// resets). Matches read ring[(base+pos-offset) mod ring_size].
inline std::uint32_t RingReduce(std::uint32_t idx, std::uint32_t ring_size) {
    return idx >= ring_size ? idx - ring_size : idx;   // idx < 2*ring_size by construction
}
inline void RingWrite(std::uint8_t* ring, std::uint32_t ring_size, std::uint32_t base,
                      const std::uint8_t* src, std::uint32_t n) {
    for (std::uint32_t i = 0; i < n; ++i) ring[RingReduce(base + i, ring_size)] = src[i];
}
inline void RingRead(const std::uint8_t* ring, std::uint32_t ring_size, std::uint32_t base,
                     std::uint8_t* dst, std::uint32_t n) {
    for (std::uint32_t i = 0; i < n; ++i) dst[i] = ring[RingReduce(base + i, ring_size)];
}

// Ring-aware variant of NzCdReconstruct: identical token semantics, but reads and
// writes the ring (size ring_size) at `base` (modular wrap) so matches resolve into
// prior chunks' compact recon. Writes the chunk's out_size compact bytes into the ring.
std::uint32_t ReconstructRing(std::uint8_t* ring, std::uint32_t ring_size, std::uint32_t base,
                              const std::uint32_t* tokens, std::uint32_t num_tokens,
                              const std::uint8_t* literals, std::uint32_t out_size) {
    std::uint32_t rep[4] = {1, 1, 1, 1};
    std::uint32_t pos = 0;
    const std::uint8_t* lp = literals;
    for (std::uint32_t t = 0; t < num_tokens && pos < out_size; ++t) {
        std::uint32_t lit_run = tokens[t * 3 + 0];
        std::uint32_t sel     = tokens[t * 3 + 1];
        std::uint32_t raw_len = tokens[t * 3 + 2];
        std::uint32_t old_rm0 = rep[0];
        std::uint32_t offset, mlen;
        if (sel >= 4) {
            offset = sel - 3;
            rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = old_rm0; rep[0] = offset;
            mlen = raw_len + 4 + (offset > 0x63ffu) + (offset > 0x4ffu);
        } else {
            offset = rep[sel];
            mlen = raw_len + 2;
            if (sel == 1)      { rep[1] = rep[0]; }
            else if (sel == 2) { rep[2] = rep[1]; rep[1] = rep[0]; }
            else if (sel == 3) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
            rep[0] = offset;
        }
        // Sanity: a match offset must reference already-written ring history
        // (at most one full ring back). Garbage or format-mismatched bytecode
        // (e.g. nz_lzhds fed through this nz_lzhd token decoder) can produce
        // an offset far beyond the ring; left unchecked, the wrap arithmetic
        // below (`wi + ring_size - offset`) underflows to a huge uint32 and
        // indexes `ring[]` far out of bounds -> crash. Refuse rather than
        // crash or corrupt: signal failure to the caller via a 0 return (safe
        // sentinel — normal completion always returns out_size > 0, enforced
        // below by the trailing literal flush).
        if (offset == 0 || offset > ring_size) return 0;
        if (lit_run) {
            std::uint32_t run = lit_run;
            if (pos + run > out_size) run = out_size - pos;
            for (std::uint32_t i = 0; i < run; ++i) ring[RingReduce(base + pos + i, ring_size)] = lp[i];
            lp += tokens[t * 3 + 0];            // advance by the full (unclamped) run
            pos += run;
            if (pos >= out_size) break;
        }
        if (pos + mlen > out_size) mlen = out_size - pos;
        // Source resolved ONCE at the match start (wrapped by the capacity only
        // when pos - offset is negative), then copied LINEARLY -- FUN_08099050's
        // `src = base + ((pos-off) >> 31 & cap) + (pos-off)` followed by word/
        // byte copies, the same shape as the -cD reconstruct. A match that
        // starts just before the ring end and runs past it therefore reads the
        // slack past `base + cap`, which the first wrap zeroed
        // (FUN_080bd380: memset(base+pos, 0, cap-pos+0x100)), NOT the bytes
        // just written at the ring start. The previous per-byte modular copy
        // read those instead; it never showed here only because no -cd sample
        // happened to place such a match, while -cD had two real files fail on
        // exactly this (see nz_lzhds.cpp).
        {
            const std::uint32_t wstart = RingReduce(base + pos, ring_size);
            std::uint32_t si = (offset <= wstart) ? (wstart - offset) : (wstart + ring_size - offset);
            for (std::uint32_t i = 0; i < mlen; ++i, ++si) {
                const std::uint32_t wi = RingReduce(base + pos + i, ring_size);
                ring[wi] = (si < ring_size) ? ring[si] : 0u;
            }
        }
        pos += mlen;
    }
    if (pos < out_size) {                       // trailing literal flush
        for (std::uint32_t i = 0, e = out_size - pos; i < e; ++i)
            ring[RingReduce(base + pos + i, ring_size)] = lp[i];
        pos = out_size;
    }
    return pos;
}

// Decode one chunk. The LZ output is reconstructed into the 64 KB ring at
// `ring_pos` (wrapping) so its matches can reference the recon output of PRIOR
// chunks: the sliding window spans chunk boundaries in the recon (pre-post-filter)
// domain (verified byte-exact). The chunk's compact recon slice is extracted from
// the ring and then post-filtered into `out` (block-RLE &2 re-expand, text &8
// pipeline, exe &4 un-transform, or a straight copy). `*recon_advance` receives the
// amount to advance the ring base by: the chunk OUTPUT size for &8, else compact.
std::uint32_t DecodeChunk(const std::uint8_t* block, std::size_t block_len, std::size_t* block_pos,
                          std::uint8_t* ring, std::uint32_t ring_pos, std::uint32_t ring_size,
                          std::uint8_t* out, std::uint32_t out_cap, std::uint32_t out_pos,
                          std::uint32_t* recon_advance,
                          bool is_lzhds, std::uint8_t* lzhds_ctx_table, std::uint32_t* lzhds_ctx_index,
                          nzr::lzpf::PrefilterContext* pf_ctx,
                          nzr::lzpf::LmsObject* pf_lms1, nzr::lzpf::LmsObject* pf_lms2,
                          nzr::audio::NzImageModel* img) {
    *recon_advance = 0;
    CdRd r{block + *block_pos, block + block_len};
    std::uint32_t chunk = CdReadVar(r, 0x80010u);
    std::uint32_t flags = chunk & 0xfu;         // &1=LZ, &2=block-RLE, &4=exe, &8=param14
    // out_size: size_field==0 is a full 32768 chunk encoded WITHOUT a v2 delta
    // (generator FUN_08098cf0 @0x8098d33: `test edx,edx; je` -> `[..+0x2c]=0x8000`).
    // Otherwise out_size = (size_field-1) + v2, v2 a bounded varint (limit 0x8001-base).
    // A chunk is "pure-literal" (no LZ tokens — the whole window is one literal
    // stream) iff size_field==0 (full 32768) or v2==0. Generator FUN_08098cf0 decides
    // at 0x8098f6b (`cmp out_size,(size_field-1); jbe` -> literal) and the size_field==0
    // branch at 0x8098d8b. Otherwise it is the token-LZ form (cols + tokens + recon).
    std::uint32_t size = chunk >> 4;
    std::uint32_t out_size;
    bool pure_literal;
    // The low nibble is a DISPATCH VALUE, not a bit mask (FUN_080994b0):
    //   0xf              -> CM sub-chunk (FUN_080a9ca0 = NzCmDecode)
    //   (nibble & 0xc)==0xc -> prefilter sub-chunk (FUN_080a5bb0)
    //   otherwise        -> the LZ token path, where the bits DO mean
    //                       &1 = LZ, &2 = block-RLE, &4 = exe, &8 = param14
    const bool is_pf_chunk = (flags != 0xfu) && ((flags & 0xcu) == 0xcu);
    const bool is_cm_chunk = (flags == 0xfu);   // image model (FUN_080a9ca0), same framing
    bool full_literal_chunk = false;   // the size_field==0 flavour of pure-literal
    if (size == 0) {
        out_size = 0x8000u; pure_literal = true; full_literal_chunk = true;
    } else if (is_pf_chunk || is_cm_chunk) {
        // The generator FUN_08098cf0 RETURNS EARLY for a 0xc-class chunk, before
        // it would emit the second varint (asm 0x08098d7f and 0x08098f30), and
        // FUN_080994b0 takes the output size from gen+0x2c rather than gen+0x30.
        // So there is no second varint in the stream and out_size is just
        // size_field - 1. Reading a varint here would eat the first payload byte.
        out_size = size - 1u; pure_literal = true;
    } else {
        size -= 1;
        std::uint32_t v2 = CdReadVar(r, 0x8001u - size);
        out_size = v2 + size; pure_literal = (v2 == 0u);
    }
    if (CdTrace()) {
        std::fprintf(stderr, "[CD] hdr: chunk=0x%x flags=0x%x out_size=%u pure_lit=%d is_lzhds=%d\n",
                     chunk, flags, out_size, (int)pure_literal, (int)is_lzhds);
    }
    if (out_size == 0) return 0;     // out_size <= 0x8001 always fits the 64 KB ring
    // The ring write base RESETS to 0 when this chunk would not fit before the ring
    // end (verified vs the binary's obj+0x980: f18 chunk2 53707+26661 > 65536 -> base
    // 0; all chunks that fit keep advancing). Cross-chunk matches still wrap (& mask).
    std::uint32_t base = (ring_pos + out_size > ring_size) ? 0u : ring_pos;
    if (is_cm_chunk) {
        // The 0xf sub-chunk: FUN_080994b0 hands it to FUN_080a9ca0 on the codec's
        // image object (param_1 + 0xe1f0) -- the decr_param-3 image model, NOT the
        // -cc CM. Same framing as the prefilter sub-chunk (no second varint) and
        // the output feeds the LZ ring the same way.
        if (img == nullptr) return 0;
        std::vector<std::uint8_t> im_out(out_size);
        const std::size_t used = img->Decode(r.cur, CdAvail(r), im_out.data(), out_size);
        if (CdTrace()) {
            std::fprintf(stderr, "[CD] image chunk: out_size=%u used=%zu avail=%ld\n",
                         out_size, used, (long)(r.end - r.cur));
        }
        if (used == 0) return 0;
        RingWrite(ring, ring_size, base, im_out.data(), out_size);
        const std::uint32_t n = (out_size <= out_cap) ? out_size : out_cap;
        std::memcpy(out, im_out.data(), n);
        *block_pos = static_cast<std::size_t>((r.cur - block) + used);
        *recon_advance = base + out_size;
        return n;
    }
    if (is_pf_chunk) {
        // Prefilter sub-chunk: the SAME core -cf/-cF use (FUN_080a5bb0), driven by
        // this codec's own state object -- -cd/-cD configure nstages = 3 (and -cD
        // order01 = 32) where lzpf uses nstages = 1. No post-filters apply on this
        // path (&8/&2/&4 are absent, and the generator emitted no mode byte or RLE
        // count because it returned early), and the output still feeds the LZ ring.
        //
        // `flags & 2` additionally means "reset the state object first"
        // (FUN_080b1950 at asm 0x0809980b). Only 0xc has been observed in a
        // 71-file real corpus plus a 90-file sweep; 0xd/0xe are reachable but
        // unobserved, so that reset is wired but untested.
        if (pf_ctx == nullptr) return 0;
        if (flags & 2u) { pf_ctx->ResetAll(); if (pf_lms1) pf_lms1->Init(); if (pf_lms2) pf_lms2->Init(); }
        std::vector<std::uint8_t> pf_out(out_size);
        const std::size_t used = nzr::lzpf::DecodePrefilterStream(
            r.cur, CdAvail(r),
            pf_out.data(), static_cast<std::size_t>(out_size),
            /*is_stereo_variant=*/true, pf_ctx, pf_lms1, pf_lms2);
        if (CdTrace()) {
            std::fprintf(stderr, "[CD] pf chunk: out_size=%u used=%zu avail=%ld\n",
                         out_size, used, (long)(r.end - r.cur));
        }
        if (used == 0) return 0;
        RingWrite(ring, ring_size, base, pf_out.data(), out_size);
        const std::uint32_t n = (out_size <= out_cap) ? out_size : out_cap;
        std::memcpy(out, pf_out.data(), n);
        *block_pos = static_cast<std::size_t>((r.cur - block) + used);
        // `*recon_advance` is the NEW ABSOLUTE ring position, not a delta (see the
        // token path's `base + out_size` below). Returning the bare out_size here
        // left the ring cursor wherever the PREVIOUS chunk had put it, so the next
        // LZ chunk got a stale write base: it overwrote this sub-chunk's own output
        // and resolved every match offset from the wrong origin.
        *recon_advance = base + out_size;
        return n;
    }
    // Every LZ chunk unconditionally resets the prefilter state object
    // (FUN_080994b0 calls FUN_080b1950(obj+0x40) on the LZ path). Measured: the
    // rule is load-bearing -- adjacent 0xc chunks must KEEP state, and 0xc chunks
    // separated by LZ chunks must each start fresh.
    //
    // It has to sit HERE, before the pure-literal / token split. It used to live
    // inside the token branch, so a pure-literal LZ chunk between two prefilter
    // runs never reset anything and the second run resumed with the first run's
    // warm predictor. GDB on the original: the state object at the resumed
    // run's entry is byte-identical to the cold state, the residuals decode
    // identically, and only the LPC cascade differs -- a warm 8-tap predictor
    // handed a cold stream's residuals rings like an unstable filter, which is
    // why the wrong output looked like a large smooth oscillation rather than
    // noise. Seven real audio/geometry files failed this way, always at the
    // first prefilter chunk after such a gap and never in the first run.
    if (pf_ctx != nullptr) {
        pf_ctx->ResetAll();
        if (pf_lms1) pf_lms1->Init();
        if (pf_lms2) pf_lms2->Init();
    }

    std::vector<std::uint8_t> slice(out_size + 64, 0);  // chunk compact recon, linearised

    // Helper: decode `n` bytes of literal stream (arith for flag &1, else raw) into dst.
    // Returns false when the sub-stream ran out: DecodeArithBuffer reports how
    // many bytes it LOGICALLY consumed, which can exceed the buffer it was
    // handed (it reads zeros past the end), and advancing the cursor by that
    // count puts it past r.end -- from there every later length check is
    // computed against an underflowed size. Treat it as a malformed chunk.
    bool ran_out = false;
    auto decode_literals = [&](std::uint8_t* dst, std::uint32_t n) -> bool {
        if (flags & 1u) {
            const std::size_t avail = CdAvail(r);
            std::size_t lc = nzr::lzpf::DecodeArithBuffer(r.cur, avail, dst, n, 12u);
            if (lc > avail) {
                CD_FAIL("lit arith overshoot: lc=%zu avail=%zu n=%u\n", lc, avail, n);
                ran_out = true; r.cur = r.end; return false;
            }
            r.cur += lc;
        } else {
            std::uint32_t take = (CdAvail(r) >= n)
                                 ? n : static_cast<std::uint32_t>(r.end - r.cur);
            std::memcpy(dst, r.cur, take); r.cur += take;
            if (take < n) { ran_out = true; return false; }
        }
        return true;
    };

    const std::uint8_t* brle_bits = nullptr;   // block-RLE (&2) run-length bit-stream
    std::uint32_t brle_len = 0;
    std::uint32_t text_param = 0;              // text-pipeline (&8) transform bitmask

    if (pure_literal) {
        // The window IS the literal stream (out_size bytes); no cols/tokens/recon.
        if (!decode_literals(slice.data(), out_size)) {
            CD_FAIL("pure-literal chunk ran past the stream (out_size=%u)\n", out_size);
            return 0;
        }
        if (flags & 2u) {
            brle_len = CdReadVar(r, 0x1001u);
            brle_bits = r.cur;
            if (!CdSkip(r, brle_len)) return 0;
        }
        if (flags & 8u) {
        const std::uint8_t* tp_at = r.cur;
        text_param = (r.cur < r.end) ? *r.cur++ : 0;
        if (CdTrace()) {
            std::fprintf(stderr, "[CD] text_param=0x%x at blockoff=%ld (is_lzhds=%d flags=0x%x out_size=%u) ctx=",
                         text_param, (long)(tp_at - (block + 0)), (int)is_lzhds, flags, out_size);
            for (int k = -8; k <= 8; ++k) {
                const std::uint8_t* q = tp_at + k;
                if (q >= block && q < block + block_len)
                    std::fprintf(stderr, "%s%02x", k == 0 ? "[" : " ", *q);
                if (k == 0) std::fprintf(stderr, "]");
            }
            std::fprintf(stderr, "\n");
        }
    }
        RingWrite(ring, ring_size, base, slice.data(), out_size);  // window keeps the compact recon
        // `-cD` (nz_lzhds) ONLY: a pure-literal chunk RE-INITIALISES the literal
        // model's persistent per-context MTF state, and resets its order-1 context
        // index to 0. Measured, not inferred: at the first literal of the chunk
        // following a pure-literal one the real decoder resolves every rank code the
        // way a freshly initialised table does (rank code r < 0x20 yields symbol r,
        // r >= 0x20 inserts as new), while our carried-over table resolved the same
        // codes to different symbols -- e.g. `ctx=3a rank=1d` gave 0x3a here where
        // the binary produced 0x1d.
        // The scope of the rule is load-bearing in BOTH directions:
        //   - resetting on EVERY chunk destroys adjacent token chunks (the state
        //     genuinely persists across those -- everything breaks from chunk 1 on),
        //   - resetting on a PREFILTER sub-chunk too breaks Moly, which is byte-exact
        //     when only pure-literal chunks reset,
        //   - and only the size_field==0 flavour (a FULL 0x8000-byte literal window)
        //     resets: the `v2 == 0` flavour, whose window is the shorter compact
        //     recon, does not (tombofchrist10.adf carries two 17-byte ones and needs
        //     the state kept across them).
        if (is_lzhds && full_literal_chunk &&
            lzhds_ctx_table != nullptr && lzhds_ctx_index != nullptr) {
            NzLzhdsInitCtxTable(lzhds_ctx_table);
            *lzhds_ctx_index = 0u;
        }
    } else {

    std::uint32_t N = CdReadVar(r, out_size - 1);
    (void)CdReadVar(r, out_size);               // v6 (unused)

    // thr = the RLE run threshold passed by the assembler per column ROLE. The
    // binary hardcodes thr=1 for the LEN column and thr=0 for LIT/OFF
    // (FUN_080aa070 sets the descriptor field; see 0x80aa167 `mov [..+0x20],1`).
    bool overran = false;
    auto decode_col = [&](std::uint32_t out_n, std::uint32_t thr) -> std::vector<std::uint8_t> {
        std::uint8_t b0 = (r.cur < r.end) ? *r.cur++ : 0;
        // b0 splits into two INDEPENDENT fields, and both matter:
        //   bit 0    codec: 1 = arith-coded (the normal case), 0 = raw-store
        //            (FUN_080b1c30, taken at 0x80a9e18 when `[esp+0x40]&1`==0)
        //            for a column the encoder could not compress.
        //   bits 1+  size-field: when non-zero, that many bytes of per-column
        //            RLE run bits follow, then a varint symbol count, and the
        //            column is RLE-expanded up to out_n afterwards.
        // These were treated as mutually exclusive -- the raw branch returned
        // out_n verbatim bytes and ignored the size-field entirely. A raw column
        // WITH RLE (b0 == 0x02) then consumed the wrong number of bytes and the
        // rest of the chunk was parsed from the wrong offset: the token bitstream
        // size read as 0, every extra bit came out zero, the match lengths were
        // wrong, and the literal stream was sought past the end of the stream.
        // `-cd` never emits that combination (its columns are all b0 == 0x00),
        // which is why only `-cdP`/`-cDP` hit it.
        const bool arith = (b0 & 1u) != 0u;
        const std::uint32_t sf = b0 >> 1;
        const std::uint8_t* rle = nullptr;
        std::uint32_t rlen = 0, acount;
        if (sf) {
            rle = r.cur; rlen = sf;
            if (!CdSkip(r, sf)) { overran = true; return std::vector<std::uint8_t>(); }
            acount = CdReadVar(r, out_size);
        } else {
            acount = out_n;
        }
        std::vector<std::uint8_t> ar(acount + 64, 0);
        if (arith) {
            const std::size_t col_avail = CdAvail(r);
            const std::size_t c = nzr::lzpf::DecodeArithBuffer(r.cur, col_avail,
                                                               ar.data(), acount, 12u);
            if (c > col_avail) { overran = true; r.cur = r.end; return std::vector<std::uint8_t>(); }
            r.cur += c;
        } else {
            const std::size_t avail = CdAvail(r);
            const std::uint32_t take = (avail >= acount) ? acount
                                                         : static_cast<std::uint32_t>(avail);
            std::memcpy(ar.data(), r.cur, take);
            r.cur += take;
            if (take < acount) { overran = true; return std::vector<std::uint8_t>(); }
        }
        if (sf) {
            std::vector<std::uint8_t> o(out_n + 256, 0);
            const std::uint32_t m =
                NzCdRleExpand(ar.data(), acount, o.data(), out_n + 256, thr, rle, rlen);
            o.resize(m); return o;
        }
        ar.resize(acount); return ar;
    };
    // Per-column trace: role, requested length, the codec/RLE selector byte, the
    // arith symbol count, and the cursor -- enough to see which column's length
    // field is being misread when a chunk walks off the end of its stream.
    auto trace_col = [&](const char* role, std::uint32_t out_n) {
        if (CdTrace())
            std::fprintf(stderr, "[CD]   col %s: out_n=%u b0=0x%02x cur=%ld avail=%zu\n",
                         role, out_n, (r.cur < r.end) ? *r.cur : 0,
                         (long)(r.cur - block), CdAvail(r));
    };
    trace_col("lit", N + 1);
    std::vector<std::uint8_t> lit = decode_col(N + 1, 0u); (void)CdReadVar(r, out_size);
    trace_col("len", N);
    std::vector<std::uint8_t> len = decode_col(N, 1u);     (void)CdReadVar(r, out_size);
    trace_col("off", N);
    std::vector<std::uint8_t> off = decode_col(N, 0u);
    if (CdTrace())
        std::fprintf(stderr, "[CD]   cols done: cur=%ld avail=%zu lit=%zu len=%zu off=%zu\n",
                     (long)(r.cur - block), CdAvail(r), lit.size(), len.size(), off.size());
    if (overran) {
        CD_FAIL("column overran the stream (N=%u out_size=%u)\n", N, out_size);
        return 0;
    }
    std::uint32_t bs_size = CdReadVar(r, out_size * 4u);
    const std::uint8_t* bs = r.cur;
    if (CdTrace())
        std::fprintf(stderr, "[CD]   bs_size=%u at cur=%ld avail=%zu\n",
                     bs_size, (long)(r.cur - block), CdAvail(r));
    if (!CdSkip(r, bs_size)) return 0;

    // `-cD` (nz_lzhds) ONLY: a brand-new, length-prefixed control field
    // ("ratebits" -- the Exp-Golomb run-length/order stream NzLzhdsReconstruct's
    // literal model reads) sits immediately after `bs` and immediately before
    // `literals`: one raw, unconditional length byte `L` (NOT a CdReadVar
    // varint), followed by exactly `L` raw bytes. GDB-verified byte-for-byte
    // against the binary (research session; FUN_080bf5a0/FUN_080b1c30).
    const std::uint8_t* ratebits = nullptr;
    std::uint32_t ratebits_len = 0;
    if (is_lzhds) {
        ratebits_len = (r.cur < r.end) ? *r.cur++ : 0u;
        ratebits = r.cur;
        if (!CdSkip(r, ratebits_len)) return 0;
    }

    NzCdField fl{g_kCdSlotLit, g_kCdModelLit, 8u};
    NzCdField fo{g_kCdSlotOff, g_kCdModelOff, 4u};
    NzCdField fn{g_kCdSlotLen, g_kCdModelLen, 14u};
    std::vector<std::uint32_t> toks(static_cast<std::size_t>(N) * 3);
    NzCdTokenAssemble(N, lit.data(), off.data(), len.data(), bs, bs_size, fl, fo, fn, toks.data());
    if (std::getenv("NZOPT_TRACE_CD_TOKENS")) {
        std::fprintf(stderr, "[CD] tokens dump: N=%u base=%u ring_size=%u out_size=%u\n", N, base, ring_size, out_size);
        for (std::uint32_t i = 0; i < N && i < 64u; ++i)
            std::fprintf(stderr, "[CD]   tok[%u] lit_run=%u sel=%u raw=%u\n", i, toks[i*3], toks[i*3+1], toks[i*3+2]);
    }

    // Total literals consumed by recon = out_size - (sum of match lengths): per-token
    // lit_run plus the trailing flush. (Match length doesn't depend on the rep[] MTF,
    // only on sel/raw, so it can be summed here without replaying offsets.) `-cD`
    // uses DIFFERENT match-length-class thresholds than `-cd` (FUN_080982e0:
    // `uVar10=sel-3; mlen=raw+4+(uVar10>0x3ff)+(uVar10>0x3fff)+(uVar10>0x7fffff)`,
    // three classes, vs `-cd`'s two at 0x4ff/0x63ff).
    std::uint32_t litsum = 0, summlen = 0;
    for (std::uint32_t i = 0; i < N; ++i) {
        litsum += toks[i * 3];
        std::uint32_t sel = toks[i * 3 + 1], raw = toks[i * 3 + 2];
        if (sel >= 4u) {
            std::uint32_t off = sel - 3u;
            summlen += is_lzhds
                ? raw + 4u + (off > 0x3ffu) + (off > 0x3fffu) + (off > 0x7fffffu)
                : raw + 4u + (off > 0x63ffu) + (off > 0x4ffu);
        }
        else summlen += raw + 2u;
    }
    std::uint32_t total_lit = litsum;
    if (out_size > summlen && out_size - summlen > litsum) total_lit = out_size - summlen;
    if (CdTrace())
        std::fprintf(stderr, "[CD]   tokens: N=%u litsum=%u summlen=%u total_lit=%u cur=%ld avail=%zu\n",
                     N, litsum, summlen, total_lit, (long)(r.cur - block), CdAvail(r));
    std::vector<std::uint8_t> literals(total_lit + 64, 0);
    if (!decode_literals(literals.data(), total_lit)) {
        CD_FAIL("literal stream ran past the chunk (total_lit=%u)\n", total_lit);
        return 0;
    }

    // Block-RLE (&2) run bits then text (&8) param trail the literals (same order
    // the dispatcher consumes them); both must be read so the next chunk parses.
    if (flags & 2u) {
        brle_len = CdReadVar(r, 0x1001u);
        brle_bits = r.cur;
        if (!CdSkip(r, brle_len)) return 0;
    }
    if (flags & 8u) {
        const std::uint8_t* tp_at = r.cur;
        text_param = (r.cur < r.end) ? *r.cur++ : 0;
        if (CdTrace()) {
            std::fprintf(stderr, "[CD] text_param=0x%x at blockoff=%ld (is_lzhds=%d flags=0x%x out_size=%u) ctx=",
                         text_param, (long)(tp_at - (block + 0)), (int)is_lzhds, flags, out_size);
            for (int k = -8; k <= 8; ++k) {
                const std::uint8_t* q = tp_at + k;
                if (q >= block && q < block + block_len)
                    std::fprintf(stderr, "%s%02x", k == 0 ? "[" : " ", *q);
                if (k == 0) std::fprintf(stderr, "]");
            }
            std::fprintf(stderr, "\n");
        }
    }

    // Reconstruct into the 64 KB ring at this chunk's base (matches reach prior
    // chunks via the wrap), then linearise the chunk's compact recon into `slice`.
    // A 0 return means the reconstruction hit an out-of-range match offset
    // (garbage or format-mismatched bytecode) and refused rather than risk an
    // OOB ring access; propagate that failure so the caller rejects the chunk
    // instead of reading an incomplete/undefined ring back out.
    if (is_lzhds) {
        if (NzLzhdsReconstruct(toks.data(), N, literals.data(), literals.size(),
                               ratebits, ratebits_len,
                               ring, ring_size, base, out_size,
                               lzhds_ctx_table, lzhds_ctx_index) == 0)
            return 0;
    } else {
        if (ReconstructRing(ring, ring_size, base, toks.data(), N, literals.data(), out_size) == 0)
            return 0;
    }
    RingRead(ring, ring_size, base, slice.data(), out_size);
    }

    *block_pos = static_cast<std::size_t>(r.cur - block);

    // Post-filter the compact recon slice into `out`. The ring base advances by the
    // COMPACT recon size (out_size) for EVERY chunk type — text/&2/exe expand only the
    // file OUTPUT, not the LZ window (verified vs the binary's obj+0x980: f18 chunk1
    // &8 advances 20939=recon, not 32768=output). `*recon_advance` is the NEW absolute
    // ring position (base + out_size, where base may have reset to 0 above).
    *recon_advance = base + out_size;
    if (flags & 8u) {   // text pipeline: param14 / line-RLE / CRLF / word-dict
        std::uint32_t n = NzCdTextPipeline(slice.data(), out_size, out, out_cap, text_param);
        return n;
    }
    if (flags & 2u)     // block-RLE: re-expand collapsed zero-runs
        return NzCdRleExpand(slice.data(), out_size, out, out_cap, 1u, brle_bits, brle_len);
    std::uint32_t n = (out_size <= out_cap) ? out_size : out_cap;
    std::memcpy(out, slice.data(), n);
    if (flags & 4u)     // exe: x86 E8/E9 address un-transform (in place on the output)
        NzCdExeUnfilter(out, n, out_pos + 4u);
    return n;
}
}  // namespace

// The cross-chunk LZ window is a ring whose size is PER-ARCHIVE (FUN_08099050,
// obj+0x978): ring_size = (method_p1+1) * 0x10000 — 64 KB when p1=0, 128 KB when
// p1=1, 192 KB when p1=2, ... (same rule as the lzpf dict size). 192 KB = 0x30000
// is not a power of two, so the ring uses modular (not bitmask) wrap.
static const std::uint32_t kCdRingSizeDefault = 0x10000u;

std::uint32_t NzCdDecodeLzChunk(const std::uint8_t* block, std::size_t block_len,
                                std::size_t* block_pos,
                                std::uint8_t* out, std::uint32_t out_cap,
                                std::uint32_t ring_size) {
    // Standalone single chunk: empty window (ring zero-filled, base 0).
    if (ring_size == 0) ring_size = kCdRingSizeDefault;
    std::vector<std::uint8_t> ring(ring_size, 0);
    std::uint32_t adv = 0;
    nzr::lzpf::PrefilterContext local_pf; local_pf.Configure(8u, 3u);
    nzr::lzpf::LmsObject l1{}, l2{}; l1.Init(); l2.Init();
    return DecodeChunk(block, block_len, block_pos,
                       ring.data(), 0u, ring_size,
                       out, out_cap, 0u, &adv,
                       false, nullptr, nullptr, &local_pf, &l1, &l2, nullptr);
}

std::uint32_t NzCdDecodeStream(const std::uint8_t* block, std::size_t block_len,
                               std::uint8_t* out, std::uint32_t out_cap,
                               std::uint8_t* ring, std::uint32_t ring_size,
                               std::uint32_t* ring_pos, std::uint32_t out_pos_base,
                               bool is_lzhds,
                               std::uint8_t* lzhds_ctx_table, std::uint32_t* lzhds_ctx_index,
                               nzr::lzpf::PrefilterContext* pf_ctx,
                               nzr::lzpf::LmsObject* pf_lms1, nzr::lzpf::LmsObject* pf_lms2,
                               nzr::audio::NzImageModel* img) {  // NOLINT
    // Decode one -cd/-cD stream into `out` using a CALLER-OWNED ring that PERSISTS across
    // streams (the binary keeps ONE window object for the whole archive; large files
    // split output into 1 MB streams that match into each other through this ring).
    // Each chunk writes its compact recon at the current ring base (wrapping) and
    // matches reach prior chunks/streams through the wrap; the base advances by the
    // COMPACT recon size and resets to 0 when a chunk would not fit before the ring
    // end. `*ring_pos` is the absolute ring position (in/out). `out_pos_base` is this
    // stream's file-absolute output offset (the &4 exe filter needs the file offset).
    if (ring == nullptr || ring_size == 0 || ring_pos == nullptr) return 0;
    if (is_lzhds && (lzhds_ctx_table == nullptr || lzhds_ctx_index == nullptr)) return 0;
    std::size_t pos = 0;
    std::uint32_t written = 0;
    while (pos < block_len && written < out_cap) {
        std::size_t prev = pos;
        std::uint32_t adv = 0;
        std::uint32_t n = DecodeChunk(block, block_len, &pos,
                                      ring, *ring_pos, ring_size,
                                      out + written, out_cap - written,
                                      out_pos_base + written, &adv,
                                      is_lzhds, lzhds_ctx_table, lzhds_ctx_index,
                                      pf_ctx, pf_lms1, pf_lms2, img);
        if (CdTrace()) {
            std::fprintf(stderr, "[CD] chunk: inpos %zu->%zu (of %zu) produced=%u written=%u/%u adv=%u\n",
                         prev, pos, block_len, n, written + n, out_cap, adv);
        }
        if (n == 0 || pos <= prev) {
            CD_FAIL("stream stop: n=%u pos=%zu prev=%zu block_len=%zu written=%u/%u\n",
                    n, pos, prev, block_len, written, out_cap);
            break;   // malformed / no progress
        }
        written += n;
        *ring_pos = adv;                    // adv is the new absolute ring position
    }
    return written;
}

std::uint32_t NzCdDecodeBlock(const std::uint8_t* block, std::size_t block_len,
                              std::uint8_t* out, std::uint32_t out_cap,
                              std::uint32_t ring_size, bool is_lzhds) {
    // Single-stream convenience (tests / standalone): a fresh ring, base 0, file
    // offset 0. The dispatcher uses NzCdDecodeStream directly to persist the ring.
    if (ring_size == 0) ring_size = kCdRingSizeDefault;
    std::vector<std::uint8_t> ring(ring_size, 0);
    std::uint32_t ring_pos = 0;
    std::vector<std::uint8_t> lzhds_ctx;
    std::uint32_t lzhds_ctx_index = 0;
    std::uint8_t* ctx_ptr = nullptr;
    if (is_lzhds) {
        lzhds_ctx.assign(kLzhdsCtxTableSize, 0u);
        NzLzhdsInitCtxTable(lzhds_ctx.data());
        ctx_ptr = lzhds_ctx.data();
    }
    nzr::lzpf::PrefilterContext pf_ctx;
    pf_ctx.Configure(is_lzhds ? 32u : 8u, 3u);
    nzr::lzpf::LmsObject pf_l1{}, pf_l2{}; pf_l1.Init(); pf_l2.Init();
    nzr::audio::NzImageModel img;
    img.Configure(0x02u, 16u, 16u, true);
    return NzCdDecodeStream(block, block_len, out, out_cap,
                            ring.data(), ring_size, &ring_pos, 0u,
                            is_lzhds, ctx_ptr, &lzhds_ctx_index,
                            &pf_ctx, &pf_l1, &pf_l2, &img);
}

}  // namespace cd
}  // namespace nzr
