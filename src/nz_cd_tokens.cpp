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
}  // namespace

namespace {
// Decode one chunk. The LZ output is reconstructed into `recon + recon_off` so its
// matches can reference the recon output of PRIOR chunks: the sliding window spans
// chunk boundaries in the recon (pre-block-RLE) domain (verified byte-exact). For a
// block-RLE chunk (flag &2) the chunk's recon slice is then re-expanded into `out`;
// otherwise the recon slice IS the output and is copied through. `*recon_advance`
// receives the recon (collapsed) size so the caller can advance `recon_off`.
std::uint32_t DecodeChunk(const std::uint8_t* block, std::size_t block_len, std::size_t* block_pos,
                          std::uint8_t* recon, std::uint32_t recon_off, std::uint32_t recon_cap,
                          std::uint8_t* out, std::uint32_t out_cap,
                          std::uint32_t* recon_advance) {
    *recon_advance = 0;
    CdRd r{block + *block_pos, block + block_len};
    std::uint32_t chunk = CdReadVar(r, 0x80010u);
    std::uint32_t flags = chunk & 0xfu;         // &1=LZ, &2=block-RLE, &4=exe, &8=param14
    std::uint32_t size = chunk >> 4;
    if (size) size -= 1; else size = 0x8000u;
    std::uint32_t v2 = CdReadVar(r, 0x8001u - size);
    std::uint32_t out_size = v2 + size;
    if (out_size == 0 || recon_off + out_size > recon_cap) return 0;
    std::uint32_t N = CdReadVar(r, out_size - 1);
    (void)CdReadVar(r, out_size);               // v6 (unused)

    // thr = the RLE run threshold passed by the assembler per column ROLE. The
    // binary hardcodes thr=1 for the LEN column and thr=0 for LIT/OFF
    // (FUN_080aa070 sets the descriptor field; see 0x80aa167 `mov [..+0x20],1`).
    auto decode_col = [&](std::uint32_t out_n, std::uint32_t thr) -> std::vector<std::uint8_t> {
        std::uint8_t b0 = (r.cur < r.end) ? *r.cur++ : 0;
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
    std::size_t lc = nzr::lzpf::DecodeArithBuffer(r.cur, static_cast<std::size_t>(r.end - r.cur),
                                                  literals.data(), total_lit, 12u);
    r.cur += lc;  // advance past the literal arith stream

    // Block-RLE post-filter (chunk flag &2): after the literal stream comes a
    // bounded-varint length (limit 0x1001) + that many bytes of run-length bits.
    // The recon window's collapsed zero-runs are re-expanded by NzCdRleExpand with
    // thr=1 (dispatcher LAB_08099a90: FUN_080c10a0(...,1) then FUN_080ac9e0).
    const std::uint8_t* brle_bits = nullptr; std::uint32_t brle_len = 0;
    if (flags & 2u) {
        brle_len = CdReadVar(r, 0x1001u);
        brle_bits = r.cur; r.cur += brle_len;
    }

    // Reconstruct into the contiguous recon buffer (window spans prior chunks).
    NzCdReconstruct(toks.data(), N, literals.data(), recon + recon_off, out_size);
    *recon_advance = out_size;
    *block_pos = static_cast<std::size_t>(r.cur - block);

    if (flags & 2u)
        return NzCdRleExpand(recon + recon_off, out_size, out, out_cap, 1u, brle_bits, brle_len);
    std::uint32_t n = (out_size <= out_cap) ? out_size : out_cap;
    std::memcpy(out, recon + recon_off, n);
    return n;
}
}  // namespace

std::uint32_t NzCdDecodeLzChunk(const std::uint8_t* block, std::size_t block_len,
                                std::size_t* block_pos,
                                std::uint8_t* out, std::uint32_t out_cap) {
    // Standalone single chunk: no preceding window context (recon_off = 0).
    std::vector<std::uint8_t> recon(out_cap + 64, 0);
    std::uint32_t adv = 0;
    return DecodeChunk(block, block_len, block_pos,
                       recon.data(), 0u, static_cast<std::uint32_t>(recon.size()),
                       out, out_cap, &adv);
}

std::uint32_t NzCdDecodeBlock(const std::uint8_t* block, std::size_t block_len,
                              std::uint8_t* out, std::uint32_t out_cap) {
    // One contiguous recon buffer for the whole block so the LZ window spans chunks.
    std::vector<std::uint8_t> recon(out_cap + 64, 0);
    std::size_t pos = 0;
    std::uint32_t written = 0, recon_off = 0;
    while (pos < block_len && written < out_cap) {
        std::size_t prev = pos;
        std::uint32_t adv = 0;
        std::uint32_t n = DecodeChunk(block, block_len, &pos,
                                      recon.data(), recon_off, static_cast<std::uint32_t>(recon.size()),
                                      out + written, out_cap - written, &adv);
        if (n == 0 || pos <= prev) break;   // malformed / no progress
        written += n;
        recon_off += adv;
    }
    return written;
}

}  // namespace cd
}  // namespace nzr
