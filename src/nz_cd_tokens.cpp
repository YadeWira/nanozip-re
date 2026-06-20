// Native linux32 `-cd` token pipeline. See nz_cd_tokens.h for the contract and
// the reverse-engineering provenance (FUN_08099050 / FUN_080aa070).
#include "nz_cd_tokens.h"
#include "lzpf_arith.h"   // lzpf BitReader (FUN_080b1fb0) for the RLE length coder

#include <cstring>
#include <vector>

namespace nzr {
namespace cd {

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
// transforms applied with double-buffering. Supported bits: 0x80 param14, 0x20 line-RLE
// (FUN_080a2f20), 0x1 CRLF EOL (FUN_080a19b0), applied in that dispatch order. Any other
// bit set means a transform not yet ported -> return 0 so the caller bridges.
std::uint32_t NzCdTextPipeline(const std::uint8_t* src, std::uint32_t size,
                               std::uint8_t* out, std::uint32_t out_cap, std::uint32_t param) {
    const std::uint32_t kSupported = 0x80u | 0x20u | 0x1u;
    if (param & ~kSupported) return 0;
    std::vector<std::uint8_t> sa(out_cap + 64, 0), sb(out_cap + 64, 0);
    std::uint8_t* bufs[2] = {sa.data(), sb.data()};
    const std::uint8_t* cur = src;
    std::uint32_t n = size; int bi = 0;
    if (param & 0x80u) { std::uint32_t m = NzCdParam14(cur, n, bufs[bi], out_cap); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (param & 0x20u) { std::uint32_t m = NzCdLineRle(cur, n, bufs[bi], out_cap); if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (param & 0x01u) { std::uint32_t m = NzCdCrlf(cur, n, bufs[bi], out_cap);    if (!m) return 0; cur = bufs[bi]; n = m; bi ^= 1; }
    if (n > out_cap) n = out_cap;
    std::memcpy(out, cur, n);
    return n;
}

namespace {
// --- 64 KB cross-chunk ring window (FUN_08099050, obj+0x978) -----------------
// The decoder keeps the LZ window in a fixed 64 KB ring (size 0x10000, mask
// 0xffff), NOT a contiguous buffer. Each chunk's COMPACT recon is written at the
// chunk's ring base (`base`) wrapping mod 65536; matches read the ring with the
// same wrap (the unsigned `base+pos-offset` underflow & 0xffff gives the index —
// e.g. base=0,pos=2,offset=15480 -> 50058, verified byte-exact vs the binary).
// The chunk base advances by the chunk's OUTPUT size for text (&8) chunks and by
// the COMPACT recon size otherwise (block-RLE &2 advances by compact: elf ring
// progression 0,21597,30634; text &8 advances by output: atoll 0,32768,0).
inline void RingWrite(std::uint8_t* ring, std::uint32_t mask, std::uint32_t base,
                      const std::uint8_t* src, std::uint32_t n) {
    for (std::uint32_t i = 0; i < n; ++i) ring[(base + i) & mask] = src[i];
}
inline void RingRead(const std::uint8_t* ring, std::uint32_t mask, std::uint32_t base,
                     std::uint8_t* dst, std::uint32_t n) {
    for (std::uint32_t i = 0; i < n; ++i) dst[i] = ring[(base + i) & mask];
}

// Ring-aware variant of NzCdReconstruct: identical token semantics, but reads and
// writes the 64 KB ring at `base` (wrapping) so matches resolve into prior chunks'
// compact recon. Writes the chunk's out_size compact bytes into the ring.
std::uint32_t ReconstructRing(std::uint8_t* ring, std::uint32_t mask, std::uint32_t base,
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
        if (lit_run) {
            std::uint32_t run = lit_run;
            if (pos + run > out_size) run = out_size - pos;
            for (std::uint32_t i = 0; i < run; ++i) ring[(base + pos + i) & mask] = lp[i];
            lp += tokens[t * 3 + 0];            // advance by the full (unclamped) run
            pos += run;
            if (pos >= out_size) break;
        }
        if (pos + mlen > out_size) mlen = out_size - pos;
        for (std::uint32_t i = 0; i < mlen; ++i)   // overlap-safe, ring-wrapped
            ring[(base + pos + i) & mask] = ring[(base + pos + i - offset) & mask];
        pos += mlen;
    }
    if (pos < out_size) {                       // trailing literal flush
        for (std::uint32_t i = 0, e = out_size - pos; i < e; ++i)
            ring[(base + pos + i) & mask] = lp[i];
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
                          std::uint8_t* ring, std::uint32_t ring_pos, std::uint32_t ring_mask,
                          std::uint8_t* out, std::uint32_t out_cap, std::uint32_t out_pos,
                          std::uint32_t* recon_advance) {
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
    if (size == 0) {
        out_size = 0x8000u; pure_literal = true;
    } else {
        size -= 1;
        std::uint32_t v2 = CdReadVar(r, 0x8001u - size);
        out_size = v2 + size; pure_literal = (v2 == 0u);
    }
    if (out_size == 0) return 0;     // out_size <= 0x8001 always fits the 64 KB ring
    std::uint32_t base = ring_pos & ring_mask;       // this chunk's ring write/match base
    std::vector<std::uint8_t> slice(out_size + 64, 0);  // chunk compact recon, linearised

    // Helper: decode `n` bytes of literal stream (arith for flag &1, else raw) into dst.
    auto decode_literals = [&](std::uint8_t* dst, std::uint32_t n) {
        if (flags & 1u) {
            std::size_t lc = nzr::lzpf::DecodeArithBuffer(r.cur, static_cast<std::size_t>(r.end - r.cur),
                                                          dst, n, 12u);
            r.cur += lc;
        } else {
            std::uint32_t take = (static_cast<std::size_t>(r.end - r.cur) >= n)
                                 ? n : static_cast<std::uint32_t>(r.end - r.cur);
            std::memcpy(dst, r.cur, take); r.cur += take;
        }
    };

    const std::uint8_t* brle_bits = nullptr;   // block-RLE (&2) run-length bit-stream
    std::uint32_t brle_len = 0;
    std::uint32_t text_param = 0;              // text-pipeline (&8) transform bitmask

    if (pure_literal) {
        // The window IS the literal stream (out_size bytes); no cols/tokens/recon.
        decode_literals(slice.data(), out_size);
        if (flags & 2u) { brle_len = CdReadVar(r, 0x1001u); brle_bits = r.cur; r.cur += brle_len; }
        if (flags & 8u) text_param = (r.cur < r.end) ? *r.cur++ : 0;
        RingWrite(ring, ring_mask, base, slice.data(), out_size);  // window keeps the compact recon
    } else {

    std::uint32_t N = CdReadVar(r, out_size - 1);
    (void)CdReadVar(r, out_size);               // v6 (unused)

    // thr = the RLE run threshold passed by the assembler per column ROLE. The
    // binary hardcodes thr=1 for the LEN column and thr=0 for LIT/OFF
    // (FUN_080aa070 sets the descriptor field; see 0x80aa167 `mov [..+0x20],1`).
    auto decode_col = [&](std::uint32_t out_n, std::uint32_t thr) -> std::vector<std::uint8_t> {
        std::uint8_t b0 = (r.cur < r.end) ? *r.cur++ : 0;
        // b0 bit0 selects the column codec: 1 = arith-coded (the normal case; an
        // arith column with no RLE has b0==1), 0 = raw-store (FUN_080b1c30 path,
        // taken at 0x80a9e18 when `[esp+0x40]&1`==0) — used for incompressible
        // columns. Raw = out_n verbatim bytes.
        if ((b0 & 1u) == 0u) {
            std::vector<std::uint8_t> raw(out_n + 64, 0);
            std::uint32_t take = (static_cast<std::size_t>(r.end - r.cur) >= out_n)
                                 ? out_n : static_cast<std::uint32_t>(r.end - r.cur);
            std::memcpy(raw.data(), r.cur, take); r.cur += take;
            raw.resize(out_n); return raw;
        }
        std::uint32_t sf = b0 >> 1;             // size-field (RLE bits length)
        const std::uint8_t* rle = nullptr; std::uint32_t rlen = 0, acount;
        if (sf) { rle = r.cur; rlen = sf; r.cur += sf; acount = CdReadVar(r, out_size); }
        else acount = out_n;
        std::vector<std::uint8_t> ar(acount + 64, 0);
        std::size_t c = nzr::lzpf::DecodeArithBuffer(r.cur, static_cast<std::size_t>(r.end - r.cur),
                                                     ar.data(), acount, 12u);
        r.cur += c;
        if (sf) {
            std::vector<std::uint8_t> o(out_n + 256, 0);
            std::uint32_t m = NzCdRleExpand(ar.data(), acount, o.data(), out_n + 256, thr, rle, rlen);
            o.resize(m); return o;
        }
        ar.resize(acount); return ar;
    };
    std::vector<std::uint8_t> lit = decode_col(N + 1, 0u); (void)CdReadVar(r, out_size);
    std::vector<std::uint8_t> len = decode_col(N, 1u);     (void)CdReadVar(r, out_size);
    std::vector<std::uint8_t> off = decode_col(N, 0u);
    std::uint32_t bs_size = CdReadVar(r, out_size * 4u);
    const std::uint8_t* bs = r.cur; r.cur += bs_size;

    NzCdField fl{g_kCdSlotLit, g_kCdModelLit, 8u};
    NzCdField fo{g_kCdSlotOff, g_kCdModelOff, 4u};
    NzCdField fn{g_kCdSlotLen, g_kCdModelLen, 14u};
    std::vector<std::uint32_t> toks(static_cast<std::size_t>(N) * 3);
    NzCdTokenAssemble(N, lit.data(), off.data(), len.data(), bs, bs_size, fl, fo, fn, toks.data());

    // Total literals consumed by recon = out_size - (sum of match lengths): per-token
    // lit_run plus the trailing flush. (Match length doesn't depend on the rep[] MTF,
    // only on sel/raw, so it can be summed here without replaying offsets.)
    std::uint32_t litsum = 0, summlen = 0;
    for (std::uint32_t i = 0; i < N; ++i) {
        litsum += toks[i * 3];
        std::uint32_t sel = toks[i * 3 + 1], raw = toks[i * 3 + 2];
        if (sel >= 4u) { std::uint32_t off = sel - 3u; summlen += raw + 4u + (off > 0x63ffu) + (off > 0x4ffu); }
        else summlen += raw + 2u;
    }
    std::uint32_t total_lit = litsum;
    if (out_size > summlen && out_size - summlen > litsum) total_lit = out_size - summlen;
    std::vector<std::uint8_t> literals(total_lit + 64, 0);
    decode_literals(literals.data(), total_lit);

    // Block-RLE (&2) run bits then text (&8) param trail the literals (same order
    // the dispatcher consumes them); both must be read so the next chunk parses.
    if (flags & 2u) { brle_len = CdReadVar(r, 0x1001u); brle_bits = r.cur; r.cur += brle_len; }
    if (flags & 8u) text_param = (r.cur < r.end) ? *r.cur++ : 0;

    // Reconstruct into the 64 KB ring at this chunk's base (matches reach prior
    // chunks via the wrap), then linearise the chunk's compact recon into `slice`.
    ReconstructRing(ring, ring_mask, base, toks.data(), N, literals.data(), out_size);
    RingRead(ring, ring_mask, base, slice.data(), out_size);
    }

    *block_pos = static_cast<std::size_t>(r.cur - block);

    // Post-filter the compact recon slice into `out`, and advance the ring base: by
    // the chunk OUTPUT size for text (&8), else by the compact recon size. Per-flag
    // advance verified vs the binary (elf &2: 0,21597,30634 compact; atoll &8:
    // 0,32768,0 output). The window holds COMPACT recon for every chunk type.
    if (flags & 8u) {   // text pipeline: param14 / line-RLE / CRLF (NzCdTextPipeline)
        std::uint32_t n = NzCdTextPipeline(slice.data(), out_size, out, out_cap, text_param);
        *recon_advance = n;
        return n;
    }
    *recon_advance = out_size;
    if (flags & 2u)     // block-RLE: re-expand collapsed zero-runs
        return NzCdRleExpand(slice.data(), out_size, out, out_cap, 1u, brle_bits, brle_len);
    std::uint32_t n = (out_size <= out_cap) ? out_size : out_cap;
    std::memcpy(out, slice.data(), n);
    if (flags & 4u)     // exe: x86 E8/E9 address un-transform (in place on the output)
        NzCdExeUnfilter(out, n, out_pos + 4u);
    return n;
}
}  // namespace

// The cross-chunk LZ window is a fixed 64 KB ring (FUN_08099050, obj+0x978).
static const std::uint32_t kCdRingSize = 0x10000u;
static const std::uint32_t kCdRingMask = 0xffffu;

std::uint32_t NzCdDecodeLzChunk(const std::uint8_t* block, std::size_t block_len,
                                std::size_t* block_pos,
                                std::uint8_t* out, std::uint32_t out_cap) {
    // Standalone single chunk: empty window (ring zero-filled, base 0).
    std::vector<std::uint8_t> ring(kCdRingSize, 0);
    std::uint32_t adv = 0;
    return DecodeChunk(block, block_len, block_pos,
                       ring.data(), 0u, kCdRingMask,
                       out, out_cap, 0u, &adv);
}

std::uint32_t NzCdDecodeBlock(const std::uint8_t* block, std::size_t block_len,
                              std::uint8_t* out, std::uint32_t out_cap) {
    // 64 KB ring window shared across chunks: each chunk writes its compact recon at
    // the current ring base (wrapping) and matches reach prior chunks through the
    // wrap. The base advances per chunk by `adv` (OUTPUT size for text &8 chunks,
    // compact recon size otherwise) — see DecodeChunk. `out` is the linear output.
    std::vector<std::uint8_t> ring(kCdRingSize, 0);
    std::size_t pos = 0;
    std::uint32_t written = 0, ring_pos = 0;
    while (pos < block_len && written < out_cap) {
        std::size_t prev = pos;
        std::uint32_t adv = 0;
        std::uint32_t n = DecodeChunk(block, block_len, &pos,
                                      ring.data(), ring_pos, kCdRingMask,
                                      out + written, out_cap - written, written, &adv);
        if (n == 0 || pos <= prev) break;   // malformed / no progress
        written += n;
        ring_pos = (ring_pos + adv) & kCdRingMask;
    }
    return written;
}

}  // namespace cd
}  // namespace nzr
