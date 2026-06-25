#include "lzpf_arith.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace nzr::lzpf {

namespace {

constexpr auto MakeMaskTable() {
    std::array<std::uint32_t, 33> m{};
    for (unsigned i = 0; i < 32; ++i) {
        m[i] = (i == 0) ? 0u : ((1u << i) - 1u);
    }
    m[32] = 0xffffffffu;
    return m;
}

constexpr auto kMaskTable = MakeMaskTable();

inline std::uint32_t LoadBigEndianU32(const std::uint8_t* p) {
    std::uint32_t le;
    std::memcpy(&le, p, 4);
    return (le >> 24) | ((le & 0x00ff0000u) >> 8) |
           ((le & 0x0000ff00u) << 8) | (le << 24);
}

// Read n_bits from a SideBitState using the same MSB-first big-endian logic
// as DecodeResidualsMono's inline bit reader (mirrors FUN_080b1fb0 applied to
// the local_4c array in FUN_080a5330).
inline std::uint32_t ReadSideBits(SideBitState* br, std::uint32_t n_bits) {
    std::uint32_t old_cache = br->cache;
    std::uint32_t bits;
    if (br->n_valid < n_bits) {
        std::uint32_t need       = n_bits - br->n_valid;
        std::uint32_t new_nvalid = 32u - need;
        std::uint32_t word       = new_nvalid;
        if (br->cur < br->end) {
            std::uint32_t raw;
            __builtin_memcpy(&raw, br->cur, 4);
            word = ((raw >> 24u) & 0xffu) | ((raw >> 8u) & 0xff00u) |
                   ((raw & 0xff00u) << 8u) | ((raw & 0xffu) << 24u);
        }
        br->cur += 4;
        old_cache     = word;
        bits          = (br->cache << (need & 0x1fu)) | (old_cache >> (new_nvalid & 0x1fu));
        br->n_valid   = new_nvalid;
    } else {
        br->n_valid -= n_bits;
        bits         = br->cache >> (br->n_valid & 0x1fu);
    }
    br->cache = old_cache;
    return bits & Mask(n_bits);
}

}  // namespace

std::uint32_t Mask(unsigned n) {
    return kMaskTable[n & 0x3fu];
}

void Init(BitReader& r, const std::uint8_t* data, std::size_t size) {
    r.start = data;
    r.end = data + size;
    r.cur = data;
    r.cache = 0;
    r.n_valid = 0;
}

std::uint32_t ReadBits(BitReader& r, std::uint32_t req) {
    std::uint32_t result;
    if (r.n_valid < req) {
        const std::uint32_t deficit = req - r.n_valid;
        const std::uint32_t new_n = 32u - deficit;
        const std::uint32_t shifted_cache = r.cache << deficit;
        std::uint32_t fresh = new_n;  // legacy: junk-default if past end
        if (r.cur < r.end) {
            fresh = LoadBigEndianU32(r.cur);
        }
        r.cur += 4;
        result = shifted_cache | (fresh >> new_n);
        r.cache = fresh;
        r.n_valid = new_n;
    } else {
        r.n_valid -= req;
        result = r.cache >> r.n_valid;
    }
    return result & kMaskTable[req];
}

void CounterInit(RangeCounter& c, std::uint32_t total) {
    c.total = total;
    c.remaining = total;
    if (total == 0) {
        c.leading_bits = 1;
        return;
    }
    unsigned msb = 31u;
    while ((total >> msb) == 0u) {
        --msb;
    }
    c.leading_bits = msb + 1u;
}

void RangeCoderPrime(std::uint32_t& code_register, BitReader& r) {
    code_register = ReadBits(r, 31);
}

void RangeCoderFinalize(BitReader& r) {
    // Faithful port of FUN_0809cdc0 — including the trailing tail-call to
    // ReadBits(remaining_bits) that the decompiler initially obscured.
    //
    // The legacy does:
    //   bits = (cur - start) * 8 - 31 - n_valid
    //   new_cur = start + (bits >> 3)        ← rewind to byte boundary
    //   remaining = bits & 7                 ← bits "lost" at the partial byte
    //   cache = 0; n_valid = 0
    //   ReadBits(remaining)                  ← advance past those leftover bits
    //
    // The trailing ReadBits is critical: it re-fills the cache from the new
    // cur position so the next decoder (e.g., outer Huffman after meta) sees
    // a properly-aligned bit stream. Without it the outer Huffman starts
    // reading garbage from offset N+4 instead of N+0.
    const std::int32_t cur_off = static_cast<std::int32_t>(r.cur - r.start);
    const std::int32_t bits = cur_off * 8 - 31 - static_cast<std::int32_t>(r.n_valid);
    const std::int32_t bytes = bits >> 3;
    const std::int32_t remaining = bits & 7;
    r.cur = r.start + bytes;
    r.cache = 0;
    r.n_valid = 0;
    // The legacy unconditionally calls ReadBits(remaining). For remaining==0
    // the call reads 0 bits and returns 0 — but it still triggers a refill
    // since n_valid (0) < req (0)? Actually no: 0 < 0 is false, so no refill.
    // Just call it; the cache stays zero for that case.
    if (remaining > 0) {
        (void)ReadBits(r, static_cast<std::uint32_t>(remaining));
    }
}

void BuildHuffman(HuffmanContext& ctx, const std::uint8_t* code_lengths,
                  std::size_t n_symbols) {
    std::memset(&ctx, 0, sizeof(ctx));

    // Mirror the descending-symbol scan from FUN_0809cbe0: copy symbol indices
    // with non-zero code length into `symbols[]` in reverse order. The legacy
    // code's nested while-loops have weird control flow but the net effect is
    // simply "skip zero-length symbols, write surviving indices high-to-low".
    std::size_t n_active = 0;
    for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(n_symbols) - 1; i >= 0; --i) {
        if (code_lengths[i] != 0) {
            ctx.symbols[n_active++] = static_cast<std::uint8_t>(i);
        }
    }

    // Sort active symbols by descending code length, ties broken by descending
    // symbol index. Mirrors FUN_080bd170 (radix-sort by `(length << 8) | sym`
    // ascending, then read out in reverse).
    std::stable_sort(
        ctx.symbols, ctx.symbols + n_active,
        [code_lengths](std::uint8_t a, std::uint8_t b) {
            const unsigned la = code_lengths[a];
            const unsigned lb = code_lengths[b];
            if (la != lb) return la > lb;
            return a > b;
        });

    if (n_active == 0) {
        return;
    }

    // Walk lengths from longest down to 1, emitting first_code[len] and
    // base_index[len]. The legacy code starts at `length + 0x1ff` which is the
    // entry first_code[length+1-1] = first_code[length]. We mirror that with
    // explicit pointer math so it's clear.
    unsigned length = code_lengths[ctx.symbols[0]] + 1u;
    if (length > 31u) length = 32u;
    std::size_t cursor = 0;        // walks ctx.symbols[]
    unsigned base = 0;             // running symbol-array offset (`iVar8`)
    unsigned first_code_acc = 0;   // current canonical first-code (`uVar1`)

    while (true) {
        --length;
        unsigned per_length = 0;
        if (cursor < n_active && code_lengths[ctx.symbols[cursor]] == length) {
            while (cursor < n_active &&
                   code_lengths[ctx.symbols[cursor]] == length) {
                ++cursor;
                ++per_length;
            }
        }
        ctx.first_code[length] = static_cast<std::uint8_t>(first_code_acc);
        ctx.base_index[length] = static_cast<std::uint8_t>(base);

        if (length == 0) break;

        base += per_length;
        first_code_acc = (per_length + first_code_acc) >> 1;
    }

    // Build the 256-entry length-lookup table. Faithful port of the second
    // nested loop in FUN_0809cbe0: walk keys descendingly (256 down to 1),
    // tracking the running length. As soon as the running length exceeds 8,
    // write that one entry then BREAK and fill all remaining lower keys with
    // the escape value 9 (which triggers DecodeHuffmanBytes' canonical
    // extension path). Variable names below mirror the legacy.
    {
        std::uint32_t uVar1 = 1;
        std::uint32_t bVar6 = ctx.first_code[1];
        std::uint32_t uVar3 = 0x100;
        std::uint32_t uVar2 = 0;
        bool early_break = false;
        while (true) {
            uVar2 = uVar3 - 1;
            std::int32_t iVar8 = 8 - static_cast<std::int32_t>(uVar1);
            std::uint32_t uVar5 = uVar1;
            // Walk-up loop: while top-iVar8-bit prefix < first_code[length]:
            //   increment length, decrement shift, refresh first.
            // If length exceeds 8, write the entry and break out of the outer
            // descent.
            auto top_bits = [&]() -> std::uint32_t {
                if (iVar8 < 0) return 0u;
                return uVar2 >> static_cast<std::uint32_t>(iVar8);
            };
            if (top_bits() < bVar6) {
                while (true) {
                    uVar1 = uVar5 + 1;
                    iVar8 -= 1;
                    if (uVar1 > 8u) {
                        ctx.length_table[uVar3 - 1] = static_cast<std::uint8_t>(uVar1);
                        early_break = true;
                        goto joined;
                    }
                    bVar6 = ctx.first_code[uVar5 + 1];
                    uVar5 = uVar1;
                    if (top_bits() >= bVar6) break;
                }
            }
            ctx.length_table[uVar3 - 1] = static_cast<std::uint8_t>(uVar1);
joined:
            if (uVar2 == 0) return;
            if (uVar1 >= 9u || early_break) break;
            uVar3 = uVar2;
        }
        // Fill remaining lower keys (uVar2-1 down to 0) with the escape 9.
        if (uVar2 != 0) {
            std::uint32_t k = uVar2;
            do {
                std::uint32_t next = k - 1;
                ctx.length_table[k - 1] = 9;
                k = next;
            } while (k != 0);
        }
    }
}

namespace {

// Helper: recompute the Kraft-residual table after `cc[]` has changed.
// Mirrors the inline block at lines 97-105 of FUN_080a41d0:
//   local_14c[1] = 2 - local_cc[1];
//   for (L = 2..max_len) ...
// `kraft[L]` ends up = 2^L - sum_{k=1..L} 2^(L-k+1) * cc[k]  (the Kraft
// residual scaled by 2^L).
void RecomputeKraft(std::uint32_t* cc, std::uint32_t* kraft, std::uint32_t max_len) {
    if (max_len < 1) return;
    kraft[1] = 2u - cc[1];
    std::int32_t shifted = 4;
    std::int32_t prev_acc = static_cast<std::int32_t>(cc[1]);
    for (std::uint32_t L = 2; L <= max_len; ++L) {
        const std::int32_t neg2 = prev_acc * -2;
        prev_acc = prev_acc * 2 + static_cast<std::int32_t>(cc[L]);
        kraft[L] = static_cast<std::uint32_t>((shifted - static_cast<std::int32_t>(cc[L])) + neg2);
        shifted *= 2;
    }
}

// Helper: descending "trim" pass that subtracts the codes reserved by longer
// lengths. Mirrors lines 107-114 (and duplicates) of FUN_080a41d0.
//   for (L = last_len-1 down to 1):
//     halved = (cc[L+1_of_first_iter ... varies] + 1) >> 1
//     kraft[L] -= halved
//     carry = halved + cc[L]   (this becomes input to next halved)
void TrimKraftDescending(std::uint32_t* cc, std::uint32_t* kraft,
                          std::uint32_t last_len) {
    if (last_len < 2) return;
    std::int32_t carry = static_cast<std::int32_t>(cc[last_len]);
    for (std::int32_t L = static_cast<std::int32_t>(last_len) - 1; L >= 1; --L) {
        const std::uint32_t halved = static_cast<std::uint32_t>((carry + 1) >> 1);
        kraft[static_cast<std::uint32_t>(L)] -= halved;
        carry = static_cast<std::int32_t>(halved) + static_cast<std::int32_t>(cc[L]);
    }
}

// Helper: find the smallest L in [1, max_search) such that kraft[L] != 0.
// Used to update `local_44` after a Kraft trim. Returns 1 if no non-zero
// found (legacy code starts the loop at 1 unconditionally).
std::uint32_t FirstAvailableLength(const std::uint32_t* kraft,
                                    std::uint32_t max_search) {
    std::uint32_t L = 0;
    do {
        ++L;
    } while (L < max_search && kraft[L] == 0);
    return L;
}

// Helper: compute max(a, b) but expressed the way the legacy code does it
// (uVar7 + (~-(a < b) & (a - b)) — saturating subtract trick).
inline std::uint32_t MaxLen(std::uint32_t a, std::uint32_t b) {
    return a < b ? b : a;
}

}  // namespace

std::uint32_t ReadRangeBisect(BitReader& br, std::uint32_t hi) {
    // Faithful port of FUN_080c06f0. The structure mirrors the legacy
    // outer/inner-loop pair: the inner loop only advances when bit==1 (hi := mid);
    // bit==0 jumps back to the outer loop which recomputes mid with the new lo.
    std::uint32_t lo = 0;
    while (true) {
        std::uint32_t mid = (lo + hi) >> 1;
        if (lo >= mid) return mid;
        bool exited_inner_via_bit0 = false;
        for (;;) {
            const std::uint32_t bit = ReadBits(br, 1);
            if (bit == 0) {
                lo = mid;
                exited_inner_via_bit0 = true;
                break;
            }
            hi = mid;
            mid = (lo + hi) >> 1;
            if (lo >= mid) return mid;
        }
        if (!exited_inner_via_bit0) return mid;  // unreachable: defensive
    }
}

void DecodeHuffmanBytes(HuffmanContext& ctx, BitReader& br,
                        std::uint8_t* dst, std::size_t count) {
    if (count == 0) return;

    std::uint32_t code = ctx.code_register;
    for (std::size_t i = 0; i < count; ++i) {
        unsigned length = ctx.length_table[code >> 23];
        unsigned val = code >> (31u - length);
        unsigned sym_offset;
        if (length < 9u) {
            sym_offset = val - ctx.first_code[length];
        } else {
            unsigned first = ctx.first_code[length];
            if (val < first) {
                int shift = static_cast<int>(31u - length) - 1;
                while (val < first) {
                    ++length;
                    first = ctx.first_code[length];
                    val = code >> static_cast<unsigned>(shift & 31);
                    --shift;
                }
            }
            sym_offset = val - first;
        }
        dst[i] = ctx.symbols[sym_offset + ctx.base_index[length]];

        // Inline-refill the code register: shift out `length` bits, pull in
        // `length` fresh bits. Equivalent to the tail of the slow-path loop in
        // FUN_0809cf40 — implemented through ReadBits to centralise the
        // big-endian/refill semantics.
        const std::uint32_t fresh = ReadBits(br, length);
        code = ((code << length) & 0x7fffffffu) | (fresh & Mask(length));
    }
    ctx.code_register = code;
}

// Faithful port of FUN_080a41d0 — pass 1 only (meta-Huffman code lengths).
//
// Vector validation against legacy gdb traces (see work/reports/trace_080a41d0.gdb):
//   - repeats_256.txt.cf.nz: input `2f 29 fa 9f fb 47 fe f7 76 90` (10 bytes),
//     max_len=12 → meta_lengths = [1, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//   - text_8k.txt.cf.nz:     input starts `6b 00 80 96 ...`, max_len=12 →
//     meta_lengths = [1, 3, 6, 6, 5, 6, 6, 4, 5, 4, 3, 0, 0]
std::uint32_t ReadCodeLengthsPass1(BitReader& br, std::uint8_t* meta_lengths_out,
                                    std::uint32_t max_len) {
    // Hoisted locals mirror the legacy stack frame; names track the decompile.
    std::uint32_t cc[33] = {0};                       // local_cc[32]
    std::uint32_t kraft[33] = {0};                    // local_14c[32]
    kraft[0] = 0xffffffffu;                           // sentinel
    kraft[1] = 2; kraft[2] = 4; kraft[3] = 8;
    kraft[4] = 16; kraft[5] = 32; kraft[6] = 64;
    const std::uint32_t kraft_max = 6u;               // local_40 — meta-cap
    std::uint32_t local_4c = 0;                       // total non-zero symbols
    std::uint32_t local_48 = 0;                       // max length seen so far
    std::uint32_t local_44 = 1;                       // current length cursor
    std::uint32_t uVar7 = 1;                          // local_44's mirror
    std::uint32_t uVar17 = max_len + 1u;              // remaining symbols

    // Pre-clear the output array (legacy zeroes via rep stosb).
    for (std::uint32_t i = 0; i < max_len + 1u; ++i) meta_lengths_out[i] = 0;

    const std::uint32_t mode = ReadBits(br, 2);

    while (true) {
        // ---- Inner loop ("while (uVar7 == 1)" pattern). ----
        bool exit_pass1 = false;
        bool break_to_outer = false;
        std::uint32_t uVar6 = local_48;  // tracks "current effective last length" across inner/outer

        while (true) {
            uVar17 -= 1;
            local_44 = uVar7;
            if (uVar17 == 0) {
                if (local_4c == 1) {
                    meta_lengths_out[max_len] =
                        static_cast<std::uint8_t>(ReadBits(br, 1));
                } else {
                    meta_lengths_out[max_len] = static_cast<std::uint8_t>(uVar7);
                }
                exit_pass1 = true;
                break;
            }
            if (uVar7 != 1) { break_to_outer = true; break; }

            // ---- uVar7 == 1 special path: read length 0..7 with bisect. ----
            uVar7 = ReadRangeBisect(br, 7);
            meta_lengths_out[max_len - uVar17] = static_cast<std::uint8_t>(uVar7);
            uVar6 = local_48;
            if (uVar7 != 0) {
                cc[uVar7] += 1;
                uVar6 = MaxLen(local_48, uVar7);
                local_48 = uVar6;
                local_4c += 1;
                RecomputeKraft(cc, kraft, kraft_max);
                if (uVar6 > 1) {
                    TrimKraftDescending(cc, kraft, uVar6);
                    local_44 = FirstAvailableLength(kraft, uVar6);
                }
            }
            // LAB_080a46bc: load uVar7 from local_44, check exit condition.
            uVar7 = local_44;
            if (kraft[uVar6] == 0) { exit_pass1 = true; break; }
            // Continue inner while loop.
        }

        if (exit_pass1) break;
        if (!break_to_outer) continue;

        // ---- Outer body (uVar7 != 1): read length via bisect[0, 8 - uVar7]. ----
        const std::int32_t bisect = static_cast<std::int32_t>(
            ReadRangeBisect(br, 8u - uVar7));
        uVar6 = local_48;
        if (bisect == 0) {
            meta_lengths_out[max_len - uVar17] = 0;
            // Fall to LAB_080a46bc: uVar7 = local_44, check exit.
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        uVar7 = static_cast<std::uint32_t>(bisect) + uVar7 - 1u;
        meta_lengths_out[max_len - uVar17] = static_cast<std::uint8_t>(uVar7);
        if (uVar7 == 0) {
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        cc[uVar7] += 1;
        uVar6 = MaxLen(local_48, uVar7);
        local_48 = uVar6;
        local_4c += 1;
        RecomputeKraft(cc, kraft, kraft_max);
        if (uVar6 < 2) {
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        TrimKraftDescending(cc, kraft, uVar6);
        local_44 = FirstAvailableLength(kraft, uVar6);
        // The legacy do-while: `while (local_14c[uVar6] != 0)`. If kraft
        // exhausted, exit; else continue outer (which re-enters inner with
        // uVar7 = local_44).
        uVar7 = local_44;
        if (kraft[uVar6] == 0) break;
        // continue outer
    }

    return mode;
}

namespace {

// `DAT_081b4380[L]` (recovered via gdb): u32 array, value 0 at index 0 and
// `1 << L` for L in [1..]. Used as the per-bit-count run-length offset in
// FUN_080a41d0's RLE branch and in the LZ77 bytecode dispatcher (FUN_0809baa0).
inline std::uint32_t RunLengthOffset(std::uint32_t L) {
    return (L == 0) ? 0u : (1u << L);
}

// Inline meta-Huffman decode (canonical, mirrors the pattern in FUN_0809cf40
// and inlined into FUN_080a41d0). Returns the decoded symbol; caller updates
// `code_register` afterwards by `((code_register << len) & 0x7fffffff) | (fresh & Mask(len))`.
inline std::uint8_t MetaDecode(const HuffmanContext& ctx, std::uint32_t code,
                                std::uint32_t* out_len) {
    std::uint32_t len = ctx.length_table[code >> 23];
    std::uint32_t val = code >> (31u - len);
    std::uint32_t first = ctx.first_code[len];
    if (len >= 9u && val < first) {
        int shift = static_cast<int>(31u - len) - 1;
        while (val < first) {
            ++len;
            first = ctx.first_code[len];
            val = code >> static_cast<unsigned>(shift & 31);
            --shift;
        }
    }
    *out_len = len;
    return ctx.symbols[(val - first) + ctx.base_index[len]];
}

}  // namespace

bool ReadCodeLengthsHuffman(BitReader& br, std::uint8_t* dst,
                            std::size_t n_symbols, std::uint32_t max_len) {
    if (n_symbols == 0 || max_len == 0) return false;

    // ---- Pass 1: read meta-Huffman code lengths and discover mode. ----
    std::uint8_t meta_lengths[33] = {0};
    if (max_len + 1u > sizeof(meta_lengths)) return false;
    const std::uint32_t mode = ReadCodeLengthsPass1(br, meta_lengths, max_len);

    // ---- Reset Kraft state for pass 2. ----
    std::uint32_t cc[33] = {0};                     // local_cc[]
    std::uint32_t kraft[33] = {0};                  // local_14c[]
    kraft[0] = 0xffffffffu;
    for (std::uint32_t L = 1; L <= max_len; ++L) {
        kraft[L] = 1u << L;
    }
    const std::uint32_t kraft_max = max_len;        // local_40 ← uVar11
    const std::uint32_t modulus = max_len + 1u;     // uVar1 (mode-3 wraparound)

    // Build the meta-Huffman context and prime the bit stream.
    HuffmanContext meta_ctx{};
    BuildHuffman(meta_ctx, meta_lengths, max_len + 1u);
    RangeCoderPrime(meta_ctx.code_register, br);

    // ---- Pass 2 state. ----
    std::uint8_t* puVar15 = dst;                    // write cursor
    std::uint8_t* const out_end = dst + n_symbols;
    std::uint32_t param_4 = static_cast<std::uint32_t>(n_symbols);  // remaining
    std::uint32_t local_3cc = 0;                    // RLE consecutive-equal counter
    std::uint32_t local_3c8 = 0;                    // last decoded value
    std::uint32_t local_3e0 = 0xffffffffu;          // RLE-lookahead carry
    std::uint8_t local_3c4 = 0;                     // last emitted byte

    while (param_4 != 0 && puVar15 < out_end) {
        const std::uint32_t prev = local_3c8;       // uVar7 in legacy

        // Determine `emitted` and whether to update Kraft + check RLE.
        std::uint32_t emitted;
        bool from_lookahead = (local_3e0 != 0xffffffffu);

        if (from_lookahead) {
            // Lookahead from a previous RLE termination: just commit it.
            emitted = local_3e0;
            local_3e0 = 0xffffffffu;
        } else {
            // Decode one symbol from the meta-Huffman.
            std::uint32_t len;
            std::uint32_t decoded = MetaDecode(meta_ctx, meta_ctx.code_register, &len);
            const std::uint32_t fresh = ReadBits(br, len);
            meta_ctx.code_register =
                ((meta_ctx.code_register << len) & 0x7fffffffu) | (fresh & Mask(len));
            if (decoded > max_len) decoded = max_len;
            local_3c8 = decoded;

            // Apply mode (delta / literal / modular). The mode-1 and mode-3
            // formulas are direct ports of the legacy bit-twiddling.
            if (mode == 1) {
                emitted = (decoded == 0) ? prev
                          : ((prev < decoded) ? decoded : (decoded - 1u));
            } else if (mode == 2) {
                if (decoded == 0) {
                    emitted = prev;  // = uVar7 (LAB_080a4849 with uVar6 = uVar7)
                } else if (prev != decoded) {
                    emitted = decoded;
                } else {
                    emitted = 0;  // anti-repeat: collapse to 0
                }
            } else {
                emitted = decoded;
                if (mode == 3) {
                    const std::uint32_t sum = decoded + prev;
                    emitted = (sum >= modulus) ? (sum - modulus) : sum;
                }
            }
        }

        // Write the emitted byte.
        local_3c4 = static_cast<std::uint8_t>(emitted);
        *puVar15++ = local_3c4;
        local_3c8 = emitted;

        // Update Kraft if emitted != 0 (zero entries don't consume capacity).
        if (emitted != 0) {
            cc[emitted] += 1;
            local_3c8 = emitted;
            RecomputeKraft(cc, kraft, kraft_max);
        }

        // Determine the running last-length (highest L with cc[L] > 0). The
        // legacy tracks this in `local_48`; we re-derive each time for
        // simplicity — fine perf-wise since max_len is tiny.
        std::uint32_t local_48_running = 0;
        for (std::uint32_t L = max_len; L >= 1; --L) {
            if (cc[L] != 0) { local_48_running = L; break; }
        }
        if (kraft[local_48_running] == 0) break;

        // RLE check applies regardless of zero/non-zero emitted.
        if (prev != emitted) {
            local_3cc = 0;
            param_4 -= 1;
            continue;
        }
        local_3cc += 1;
        if (local_3cc != 3u) {
            param_4 -= 1;
            continue;
        }

        // ---- RLE TRIGGERED: 3 consecutive equal values. ----
        if (local_48_running > 1) {
            TrimKraftDescending(cc, kraft, local_48_running);
        }
        param_4 -= 1;  // legacy: param_4 = uVar11 - 1

        std::uint32_t rl_max = kraft[local_3c8];
        if (param_4 < rl_max) rl_max = param_4;
        local_3e0 = 0xffffffffu;

        if (rl_max == 0) continue;

        std::int32_t local_3bc = 0;
        if (rl_max >= 2) {
            std::uint32_t local_3f4 = meta_ctx.code_register;
            while (true) {
                std::uint32_t L2;
                std::uint8_t d2 = MetaDecode(meta_ctx, local_3f4, &L2);
                const std::uint32_t f2 = ReadBits(br, L2);
                meta_ctx.code_register =
                    ((local_3f4 << L2) & 0x7fffffffu) | (f2 & Mask(L2));
                std::uint32_t cap_d2 = (d2 > max_len) ? max_len : d2;

                bool terminate = false;
                std::uint32_t lookahead_value = cap_d2;
                if (mode == 1) {
                    if (cap_d2 != 0) {
                        lookahead_value =
                            (prev < cap_d2) ? cap_d2 : (cap_d2 - 1u);
                        if (lookahead_value != local_3c8) terminate = true;
                    }
                    // else: silently extend the run (no terminate, no value)
                } else if (mode == 2) {
                    if (cap_d2 != 0) {
                        lookahead_value =
                            (local_3c8 == cap_d2) ? 0u : cap_d2;
                        terminate = true;
                    }
                } else {
                    if (mode == 3) {
                        std::uint32_t sum = cap_d2 + local_3c8;
                        lookahead_value = (sum >= modulus) ? (sum - modulus) : sum;
                    }
                    if (lookahead_value != local_3c8) terminate = true;
                }

                if (terminate) {
                    local_3e0 = lookahead_value;
                    break;
                }
                local_3bc += 1;
                local_3f4 = meta_ctx.code_register;
                if (static_cast<std::uint32_t>(2 << local_3bc) > rl_max) {
                    local_3e0 = 0xffffffffu;
                    break;
                }
            }
        }

        // Read run-length suffix (`bits_to_read` = max(local_3bc, 1) bits).
        const std::int32_t bits_to_read = (local_3bc == 0) ? 1 : local_3bc;
        const std::uint32_t hi_bits = meta_ctx.code_register >>
            (31u - static_cast<std::uint32_t>(bits_to_read));
        const std::uint32_t shifted =
            (meta_ctx.code_register << bits_to_read) & 0x7fffffffu;
        const std::uint32_t lo_bits = ReadBits(br,
            static_cast<std::uint32_t>(bits_to_read));
        meta_ctx.code_register = shifted | lo_bits;

        std::uint32_t run = hi_bits +
            RunLengthOffset(static_cast<std::uint32_t>(local_3bc));
        if (run > param_4) run = param_4;

        if (local_3c8 != 0) {
            cc[local_3c8] += run;
            RecomputeKraft(cc, kraft, kraft_max);
            for (std::uint32_t L = max_len; L >= 1; --L) {
                if (cc[L] != 0) { local_48_running = L; break; }
            }
        }

        for (std::uint32_t i = 0; i < run; ++i) {
            if (puVar15 >= out_end) break;
            *puVar15++ = local_3c4;
        }

        if (kraft[local_48_running] == 0) break;
        local_3cc = 0;
        param_4 -= run;
    }

    // Pad rest of output with zeros.
    while (puVar15 < out_end) *puVar15++ = 0;
    RangeCoderFinalize(br);
    return true;
}

bool DecodeLz77VariantA(const std::uint8_t* bytecode, std::size_t bytecode_size,
                        std::uint8_t* dict, std::size_t dict_capacity,
                        std::size_t* dict_cursor, std::size_t output_size,
                        std::int32_t* hash_table,
                        std::int32_t* last_lz_dest,
                        std::size_t* bytecode_consumed) {
    if (bytecode_consumed) *bytecode_consumed = 0;
    if (output_size == 0) return true;
    if (*dict_cursor + output_size > dict_capacity) return false;

    const std::uint8_t* bp = bytecode;          // puVar13/puVar12 in legacy
    const std::uint8_t* const bend = bytecode + bytecode_size;
    std::uint8_t* const dict_base = dict;       // uVar18 in legacy
    std::uint8_t* out = dict + *dict_cursor;    // pbVar7 in legacy
    std::uint8_t* const out_end = out + output_size;  // pbVar16

    // Helper: read 4 bytes at out_ptr - 2 as little-endian u32 (matches
    // the legacy `*(uint *)(pbVar7 + -2)`). May read into the dict's
    // "left-padding" zone for the very first call — caller is responsible
    // for ensuring `dict[-2..-1]` is allocated and zero-initialised.
    auto hash_at_minus2 = [](const std::uint8_t* p) -> std::uint32_t {
        std::uint32_t v;
        std::memcpy(&v, p - 2, 4);
        return v;
    };

    std::int32_t local_50 = *last_lz_dest;

    while (out < out_end) {
        // Outer-loop entry: refresh hash key from output bytes [-2..+1].
        std::uint32_t hash_key = hash_at_minus2(out);
        std::uint8_t* const hash_anchor_out = out;
        const std::uint8_t* const hash_anchor_in = bp;

        // Inner literal loop.
        bool break_to_outer = false;
        while (true) {
            if (bp >= bend) goto done;       // input exhausted
            const std::uint8_t opcode = *bp;
            const std::uint32_t hash13 = hash_key & 0x1fffu;
            const std::uint8_t* next_bp = bp + 1;
            const std::int32_t cur_off = static_cast<std::int32_t>(out - dict_base);
            if (opcode > 0xf5u) {
                bp = next_bp;  // legacy advances opcode-pos but keeps puVar13 at opcode for f7/f8 sub-reads
                // (For f7/f8/medium, we re-derive offsets from `bp` (now past opcode)
                //  and possibly bp+1, bp+2, etc.)
                break_to_outer = true;
                // Restore puVar13 = opcode position, puVar12 = next_bp.
                // We track them via `bp_opcode = bp - 1` below.
                break;
            }
            // Literal branch.
            hash_table[hash13] = cur_off;
            *out = opcode;
            ++out;
            // Legacy `uVar14 = *(uint *)(pbVar6 + -1)` BEFORE pbVar6 is
            // updated. Equivalently after ++out: read at out-2.
            hash_key = hash_at_minus2(out);
            bp = next_bp;
            if (out >= out_end) goto done;
        }
        (void)hash_anchor_out;
        (void)hash_anchor_in;
        if (!break_to_outer) continue;

        // Non-literal opcode handling. `bp` points just PAST the opcode.
        const std::uint8_t* bp_opcode = bp - 1;
        const std::uint8_t opcode = *bp_opcode;
        const std::uint32_t hash13 = hash_key & 0x1fffu;
        const std::int32_t cur_off = static_cast<std::int32_t>(out - dict_base);

        if (opcode == 0xf6u) {
            // 1-byte repeat from local_50 (previous LZ destination).
            hash_table[hash13] = cur_off;
            *out = out[local_50];
            ++out;
            // bp already at next opcode.
        } else if (opcode == 0xf7u) {
            // Long match: peek at next byte.
            if (bp >= bend) return false;
            const std::uint8_t b1 = *bp;
            if (b1 < 0xf5u) {
                // Long match: 6 more bytes total (b1 + len_lo + 4-byte src offset).
                // length = b1 + 8 + (b2 << 8)... actually let me re-derive.
                // Legacy: iVar8 = (byte)puVar13[1] + 8 + (uint)bVar2 * 0x100;
                // puVar13 was the OPCODE position. puVar13[1] = ushort* index 1
                // = the 2 bytes at opcode+2..+3. (byte)puVar13[1] = byte at opcode+2.
                // bVar2 = byte at opcode+1 = b1 (the byte we just read).
                // So length = byte_at(opcode+2) + 8 + b1 * 256.
                if (bp + 6 > bend) return false;
                const std::uint8_t b2 = bp[1];
                const std::uint32_t length = b2 + 8u + (std::uint32_t)b1 * 256u;
                // src offset = *(int *)((int)puVar13 + 3) = 4 LE bytes at opcode+3..+6.
                std::uint32_t src_off;
                std::memcpy(&src_off, bp + 2, 4);
                if (out + length > out_end) return false;
                if (src_off >= dict_capacity) return false;
                // Copy length bytes from dict_base + src_off.
                for (std::uint32_t k = 0; k < length; ++k) {
                    out[k] = dict_base[src_off + k];
                }
                out += length;
                bp += 6;  // consumed b1, b2, src_off (4 bytes)
                // legacy `puVar12 = (ushort *)((int)puVar13 + 7)` → +7 from
                // opcode = +6 from bp_opcode+1 = +6 from current bp before this.
            } else {
                // Escape-literal: write b1 as literal byte and update hash.
                hash_table[hash13] = cur_off;
                *out = b1;
                ++out;
                bp += 1;  // consumed b1
            }
        } else if (opcode == 0xf8u) {
            // Short match (with possible extended length).
            if (bp >= bend) return false;
            std::int32_t* hash_slot = &hash_table[hash13];
            local_50 = *hash_slot;
            *hash_slot = cur_off;
            const std::uint8_t b = *bp;
            std::uint32_t length = static_cast<std::uint32_t>(static_cast<std::uint8_t>(~b));
            std::uint32_t consumed = 1;
            if (length > 0x7fu) {
                // Extended: need to read one more byte (lo). The legacy
                // accesses a ushort (2 bytes) but only consumes the low byte
                // — so we only need bp[1] to be in range.
                if (bp + 2 > bend) return false;
                const std::uint8_t lo = bp[1];
                // legacy: uVar4 = *puVar12 (ushort at opcode+2..+3);
                //  puVar12 was puVar13+1 (= opcode+2 in bytes).
                //  ushort *puVar12 reads bytes [opcode+2..+3] little-endian.
                // So uVar4 = (lo) | (next byte)<<8. But the legacy uses (byte)uVar4 = lo.
                // We then take CONCAT11(~b, ~lo) ^ 0xff00 = ((~b ^ 0xff) << 8) | ~lo
                //   = (b << 8) | ~lo.
                length = (static_cast<std::uint32_t>(b) << 8) |
                         static_cast<std::uint32_t>(static_cast<std::uint8_t>(~lo));
                consumed = 2;
            }
            length += 8;
            if (out + length > out_end) return false;
            const std::int32_t src_abs = local_50;  // window-relative (signed)
            // Per legacy: local_50 = local_50 + uVar18 (absolute pointer).
            // src = dict_base + local_50.
            // Then iVar10 = -length; loop pbVar7[iVar10] = src[length + iVar10].
            // Effectively: out[k] = dict_base[src_abs + k] for k = 0..length-1.
            for (std::uint32_t k = 0; k < length; ++k) {
                out[k] = dict_base[static_cast<std::size_t>(src_abs) + k];
            }
            // Update local_50 = local_50 - (int)pbVar6 (= src_abs - cur_off).
            // But we'll re-read it from hash_table next time. Skip the relative
            // tracking — we just store the absolute current_offset.
            local_50 = src_abs - cur_off;
            out += length;
            bp += consumed;
        } else {
            // Medium match (opcode 0xf9..0xff): length = ~opcode + 1.
            std::int32_t* hash_slot = &hash_table[hash13];
            local_50 = *hash_slot;
            *hash_slot = cur_off;
            const std::uint32_t length =
                static_cast<std::uint32_t>(static_cast<std::uint8_t>(~opcode)) + 1u;
            if (out + length > out_end) return false;
            const std::int32_t src_abs = local_50;
            for (std::uint32_t k = 0; k < length; ++k) {
                out[k] = dict_base[static_cast<std::size_t>(src_abs) + k];
            }
            local_50 = src_abs - cur_off;
            out += length;
        }
    }

done:
    *dict_cursor = static_cast<std::size_t>(out - dict_base);
    *last_lz_dest = local_50;
    if (bytecode_consumed) *bytecode_consumed = static_cast<std::size_t>(bp - bytecode);
    return true;
}

bool DecodeLz77VariantB(const std::uint8_t* bytecode, std::size_t bytecode_size,
                        std::uint8_t* dict, std::size_t dict_capacity,
                        std::size_t* dict_cursor, std::size_t output_size,
                        std::int32_t* hash_table_24bit,
                        std::uint8_t* byte_buffer_8k,
                        std::int32_t* last_lz_dest,
                        std::size_t* bytecode_consumed) {
    if (bytecode_consumed) *bytecode_consumed = 0;
    if (output_size == 0) return true;
    if (*dict_cursor + output_size > dict_capacity) return false;

    const std::uint8_t* bp = bytecode;
    const std::uint8_t* const bend = bytecode + bytecode_size;
    std::uint8_t* const dict_base = dict;
    std::uint8_t* out = dict + *dict_cursor;
    std::uint8_t* const out_end = out + output_size;

    // Variant B reads 4 LE bytes at `out - 3` and masks to 24 bits → uses
    // bytes [out-3..out-1] as the hash key.
    auto hash_key_at_minus3 = [](const std::uint8_t* p) -> std::uint32_t {
        std::uint32_t v;
        std::memcpy(&v, p - 3, 4);
        return v;
    };
    // Secondary 13-bit index reads 2 LE bytes at `out - 2`.
    auto bytebuf_idx_at_minus2 = [](const std::uint8_t* p) -> std::uint32_t {
        std::uint16_t v;
        std::memcpy(&v, p - 2, 2);
        return static_cast<std::uint32_t>(v) & 0x1fffu;
    };

    std::int32_t local_48 = *last_lz_dest;

    while (out < out_end) {
        std::uint32_t hash_key = hash_key_at_minus3(out);

        bool break_to_outer = false;
        while (true) {
            if (bp >= bend) goto done;
            const std::uint8_t opcode = *bp;
            const std::uint32_t hash24 = hash_key & 0xffffffu;
            const std::uint8_t* next_bp = bp + 1;
            const std::int32_t cur_off = static_cast<std::int32_t>(out - dict_base);
            if (opcode > 0xf4u) {
                bp = next_bp;
                break_to_outer = true;
                break;
            }
            // Literal branch.
            hash_table_24bit[hash24] = cur_off;
            byte_buffer_8k[bytebuf_idx_at_minus2(out)] = opcode;
            *out = opcode;
            ++out;
            // Legacy reads `*(uint *)(pbVar6 + -2)` BEFORE pbVar6 advances.
            // Equivalently after ++out: read at out - 3.
            hash_key = hash_key_at_minus3(out);
            bp = next_bp;
            if (out >= out_end) goto done;
        }
        if (!break_to_outer) continue;

        const std::uint8_t* bp_opcode = bp - 1;
        const std::uint8_t opcode = *bp_opcode;
        const std::uint32_t hash24 = hash_key & 0xffffffu;
        const std::int32_t cur_off = static_cast<std::int32_t>(out - dict_base);

        if (opcode == 0xf5u) {
            // Emit byte from secondary buffer keyed by 13-bit hash of out-2.
            hash_table_24bit[hash24] = cur_off;
            *out = byte_buffer_8k[bytebuf_idx_at_minus2(out)];
            ++out;
        } else if (opcode == 0xf6u) {
            // 1-byte repeat from previous LZ destination.
            hash_table_24bit[hash24] = cur_off;
            *out = out[local_48];
            ++out;
        } else if (opcode == 0xf7u) {
            if (bp >= bend) return false;
            const std::uint8_t b1 = *bp;
            if (b1 < 0xf5u) {
                if (bp + 6 > bend) return false;
                const std::uint8_t b2 = bp[1];
                const std::uint32_t length = b2 + 8u + (std::uint32_t)b1 * 256u;
                std::uint32_t src_off;
                std::memcpy(&src_off, bp + 2, 4);
                if (out + length > out_end) return false;
                if (src_off >= dict_capacity) return false;
                for (std::uint32_t k = 0; k < length; ++k) {
                    out[k] = dict_base[src_off + k];
                }
                out += length;
                bp += 6;
            } else {
                // Escape-literal: also writes to secondary byte buffer.
                hash_table_24bit[hash24] = cur_off;
                byte_buffer_8k[bytebuf_idx_at_minus2(out)] = b1;
                *out = b1;
                ++out;
                bp += 1;
            }
        } else if (opcode == 0xf8u) {
            if (bp >= bend) return false;
            std::int32_t* hash_slot = &hash_table_24bit[hash24];
            local_48 = *hash_slot;
            *hash_slot = cur_off;
            const std::uint8_t b = *bp;
            std::uint32_t length = static_cast<std::uint32_t>(static_cast<std::uint8_t>(~b));
            std::uint32_t consumed = 1;
            if (length > 0x7fu) {
                if (bp + 2 > bend) return false;
                const std::uint8_t lo = bp[1];
                length = (static_cast<std::uint32_t>(b) << 8) |
                         static_cast<std::uint32_t>(static_cast<std::uint8_t>(~lo));
                consumed = 2;
            }
            length += 8;
            if (out + length > out_end) return false;
            const std::int32_t src_abs = local_48;
            for (std::uint32_t k = 0; k < length; ++k) {
                out[k] = dict_base[static_cast<std::size_t>(src_abs) + k];
            }
            local_48 = src_abs - cur_off;
            out += length;
            bp += consumed;
        } else {
            // Medium match (opcode 0xf9..0xff): length = ~opcode + 1.
            std::int32_t* hash_slot = &hash_table_24bit[hash24];
            local_48 = *hash_slot;
            *hash_slot = cur_off;
            const std::uint32_t length =
                static_cast<std::uint32_t>(static_cast<std::uint8_t>(~opcode)) + 1u;
            if (out + length > out_end) return false;
            const std::int32_t src_abs = local_48;
            for (std::uint32_t k = 0; k < length; ++k) {
                out[k] = dict_base[static_cast<std::size_t>(src_abs) + k];
            }
            local_48 = src_abs - cur_off;
            out += length;
        }
    }

done:
    *dict_cursor = static_cast<std::size_t>(out - dict_base);
    *last_lz_dest = local_48;
    if (bytecode_consumed) *bytecode_consumed = static_cast<std::size_t>(bp - bytecode);
    return true;
}

std::size_t DecodeArithBuffer(const std::uint8_t* input, std::size_t input_size,
                               std::uint8_t* output, std::size_t output_count,
                               std::uint32_t max_len) {
    if (input_size == 0 || output_count == 0) return 0;

    BitReader br;
    Init(br, input, input_size);

    std::uint8_t code_lengths[256];
    if (!ReadCodeLengthsHuffman(br, code_lengths, 256, max_len)) return 0;

    HuffmanContext outer{};
    BuildHuffman(outer, code_lengths, 256);

    RangeCoderPrime(outer.code_register, br);
    DecodeHuffmanBytes(outer, br, output, output_count);
    RangeCoderFinalize(br);

    // Bytes consumed: legacy `((7 - n_valid) + (cur - start) * 8) >> 3`.
    const std::int64_t bits =
        (7 - static_cast<std::int64_t>(br.n_valid)) +
        static_cast<std::int64_t>(br.cur - br.start) * 8;
    const std::int64_t bytes = bits >> 3;
    if (bytes < 0) return 0;
    return static_cast<std::size_t>(bytes);
}

// ---------------------------------------------------------------------------
// Scratch buffer (legacy notes — kept for reference). Not compiled.
// ---------------------------------------------------------------------------
#if 0
bool ReadCodeLengthsHuffmanScratch(BitReader& br, std::uint8_t* dst,
                            std::size_t n_symbols, std::uint32_t max_len_in) {
    if (n_symbols == 0 || max_len_in == 0) return false;
    const std::uint32_t max_len = max_len_in;       // *param_1 in the legacy
    const std::uint32_t uVar1 = max_len + 1u;       // length-cap for mode 3 modulus
    const std::uint32_t pass1_count = max_len + 1u; // = uVar11 + 1

    // ---- Pass 1: read meta-Huffman code lengths (`local_3c[0..max_len]`).
    std::uint8_t meta_lengths[44] = {0};            // local_3c[44]
    const std::uint32_t mode = ReadBits(br, 2);     // iVar9: 0..3
    std::uint32_t kraft_max = 6u;                   // local_40 — meta-cap
    std::uint32_t kraft[33] = {0};                  // local_14c[32]
    kraft[0] = 0xffffffffu;
    kraft[1] = 2; kraft[2] = 4; kraft[3] = 8;
    kraft[4] = 16; kraft[5] = 32; kraft[6] = 64;
    std::uint32_t cc[33] = {0};                     // local_cc[32]
    std::uint32_t local_4c = 0;
    std::uint32_t local_48 = 0;                     // last assigned length
    std::uint32_t local_44 = 1;                     // current length cursor (uVar7)
    std::uint32_t uVar7 = local_44;
    std::uint32_t uVar17 = pass1_count;             // remaining symbols to read

    while (true) {
        // Inner loop: while uVar7 == 1, do special 1-length read with bisect-7.
        bool exit_pass1 = false;
        while (true) {
            uVar17--;
            local_44 = uVar7;
            if (uVar17 == 0) {
                if (local_4c == 1) {
                    meta_lengths[max_len] = static_cast<std::uint8_t>(ReadBits(br, 1));
                } else {
                    meta_lengths[max_len] = static_cast<std::uint8_t>(uVar7);
                }
                exit_pass1 = true;
                break;
            }
            if (uVar7 != 1) break;
            uVar7 = ReadRangeBisect(br, 7);
            meta_lengths[max_len - uVar17] = static_cast<std::uint8_t>(uVar7);
            std::uint32_t uVar6 = local_48;
            if (uVar7 != 0) {
                cc[uVar7]++;
                uVar6 = MaxLen(local_48, uVar7);
                local_48 = uVar6;
                local_4c++;
                RecomputeKraft(cc, kraft, kraft_max);
                if (uVar6 > 1) {
                    TrimKraftDescending(cc, kraft, uVar6);
                    local_44 = FirstAvailableLength(kraft, uVar6);
                }
            }
            uVar7 = local_44;
            if (kraft[uVar6] == 0) { exit_pass1 = true; break; }
        }
        if (exit_pass1) break;

        // Outer loop body: decode a length using bisect over the remaining
        // length range [uVar7, 8].
        const std::int32_t bisect = static_cast<std::int32_t>(
            ReadRangeBisect(br, 8u - uVar7));
        std::uint32_t uVar6 = local_48;
        if (bisect == 0) {
            meta_lengths[max_len - uVar17] = 0;
            // Fall through to "check if exhausted" check.
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        uVar7 = static_cast<std::uint32_t>(bisect) + uVar7 - 1u;
        meta_lengths[max_len - uVar17] = static_cast<std::uint8_t>(uVar7);
        if (uVar7 == 0) {
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        cc[uVar7]++;
        uVar6 = MaxLen(local_48, uVar7);
        local_48 = uVar6;
        local_4c++;
        RecomputeKraft(cc, kraft, kraft_max);
        if (uVar6 < 2) {
            uVar7 = local_44;
            if (kraft[uVar6] == 0) break;
            continue;
        }
        TrimKraftDescending(cc, kraft, uVar6);
        local_44 = FirstAvailableLength(kraft, uVar6);
        uVar7 = local_44;
        if (kraft[uVar6] == 0) break;
    }

    // ---- Pass 1 done. Reset state for Pass 2.
    kraft[0] = 0xffffffffu;
    kraft_max = max_len;
    if (max_len != 0) {
        for (std::uint32_t L = 1; L <= max_len; ++L) {
            kraft[L] = 1u << L;
        }
    }
    for (std::uint32_t i = 0; i < 33; ++i) cc[i] = 0;
    local_4c = 0;
    local_48 = 0;
    local_44 = 1;

    HuffmanContext meta_ctx{};
    BuildHuffman(meta_ctx, meta_lengths, max_len + 1);
    RangeCoderPrime(meta_ctx.code_register, br);

    // ---- Pass 2: decode `n_symbols` length values into dst[].
    std::uint8_t* puVar15 = dst;
    std::uint8_t* const out_end = dst + n_symbols;
    std::uint32_t param_4_remain = static_cast<std::uint32_t>(n_symbols);
    std::uint32_t local_3cc = 0;       // RLE consecutive-equal counter
    std::uint32_t local_3c8 = 0;       // last decoded value
    std::uint32_t local_3e0 = 0xffffffffu;  // RLE lookahead value
    std::uint8_t local_3c4 = 0;        // current emitted byte

    while (param_4_remain != 0) {
        std::uint32_t prev = local_3c8;     // uVar7 in the legacy
        if (local_3e0 == 0xffffffffu) {
            // Decode one symbol from the meta-Huffman.
            std::uint32_t len = meta_ctx.length_table[meta_ctx.code_register >> 23];
            std::uint32_t val = meta_ctx.code_register >> (31u - len);
            std::uint32_t first = meta_ctx.first_code[len];
            if (len < 9u) {
                // simple lookup
            } else if (val < first) {
                int shift = static_cast<int>(31u - len) - 1;
                while (val < first) {
                    ++len;
                    first = meta_ctx.first_code[len];
                    val = meta_ctx.code_register >> static_cast<unsigned>(shift & 31);
                    --shift;
                }
            }
            const std::uint32_t sym_off = val - first;
            std::uint32_t decoded = meta_ctx.symbols[sym_off + meta_ctx.base_index[len]];
            // Refill the meta-Huffman code register inline (matches the
            // legacy that doesn't go through ReadBits — but ReadBits has
            // identical semantics).
            const std::uint32_t fresh = ReadBits(br, len);
            meta_ctx.code_register =
                ((meta_ctx.code_register << len) & 0x7fffffffu) | (fresh & Mask(len));
            // Cap decoded value at max_len.
            if (decoded > max_len) decoded = max_len;
            local_3c8 = decoded;

            // Apply mode (delta / literal / modular).
            std::uint32_t emitted = decoded;
            bool falls_to_lab_45a8 = false;
            bool falls_to_lab_4849 = false;
            if (mode == 1) {
                if (decoded != 0) {
                    emitted = decoded - (prev < decoded ? 1u : 0u);
                }
                falls_to_lab_4849 = true;  // unconditional in mode 1
            } else if (mode == 2) {
                if (decoded == 0) {
                    falls_to_lab_4849 = true;
                } else if (prev != decoded) {
                    local_3c4 = static_cast<std::uint8_t>(decoded);
                    *puVar15 = local_3c4;
                    falls_to_lab_45a8 = true;
                } else {
                    emitted = 0;
                    *puVar15 = 0;
                    local_3c4 = 0;
                }
            } else {  // mode == 0 or 3
                emitted = decoded;
                if (mode == 3) {
                    emitted = (decoded + prev) -
                              ((decoded + prev >= uVar1) ? uVar1 : 0u);
                }
                falls_to_lab_4849 = true;
            }
            if (falls_to_lab_4849) {
                local_3c4 = static_cast<std::uint8_t>(emitted);
                *puVar15 = local_3c4;
                local_3c8 = emitted;
                if (emitted != 0) {
                    falls_to_lab_45a8 = true;
                }
            }

            std::uint32_t cur_last = local_48;  // uVar17 capture before Kraft updates
            (void)cur_last;
            if (falls_to_lab_45a8) {
                puVar15 = puVar15 + 1;  // legacy: param_3 = puVar15 + 1
                cc[local_3c8]++;
                std::uint32_t new_last = MaxLen(local_48, local_3c8);
                local_48 = new_last;
                local_4c++;
                RecomputeKraft(cc, kraft, kraft_max);
                if (kraft[new_last] == 0) break;
                if (prev == local_3c8) {
                    // RLE: same value as previous → bump counter.
                    puVar15 = puVar15;  // already at the next slot
                    local_3cc++;
                    if (local_3cc == 3) {
                        // Fall into RLE handler below.
                        goto rle_handler;
                    }
                    param_4_remain -= 1;
                    continue;
                }
                local_3cc = 0;
                param_4_remain -= 1;
                continue;
            }

            // emitted == 0: don't update Kraft; advance write cursor.
            puVar15 = puVar15 + 1;
            if (kraft[local_48] == 0) break;
            if (prev == local_3c8) {
                goto rle_handler;
            }
            local_3cc = 0;
            param_4_remain -= 1;
            continue;

        rle_handler: {
                puVar15 = puVar15;
                local_3cc++;
                if (local_3cc != 3) {
                    param_4_remain -= 1;
                    continue;
                }
                // Three in a row: read run length and emit.
                std::uint32_t rl_max = param_4_remain - 1u;  // remaining after this
                std::uint32_t rl_count = 0;
                local_3e0 = 0xffffffffu;
                if (rl_max != 0) {
                    std::int32_t local_3bc = 0;
                    if (rl_max >= 2) {
                        // Read up to log2(rl_max) lookahead codes; each must
                        // either match local_3c8 (extend run) or be a
                        // distinct value (terminate with `local_3e0` set).
                        std::uint32_t local_3f4 = meta_ctx.code_register;
                        std::uint32_t local_3d4 = br.n_valid;
                        bool terminated = false;
                        while (true) {
                            // Inline meta-Huffman decode against local_3f4.
                            std::uint32_t L2 = meta_ctx.length_table[local_3f4 >> 23];
                            std::uint32_t v2 = local_3f4 >> (31u - L2);
                            std::uint32_t f2 = meta_ctx.first_code[L2];
                            if (L2 >= 9 && v2 < f2) {
                                int sh = static_cast<int>(31u - L2) - 1;
                                while (v2 < f2) {
                                    ++L2;
                                    f2 = meta_ctx.first_code[L2];
                                    v2 = local_3f4 >> static_cast<unsigned>(sh & 31);
                                    --sh;
                                }
                            }
                            std::uint32_t d2 = meta_ctx.symbols[(v2 - f2) + meta_ctx.base_index[L2]];

                            const std::uint32_t fresh2 = ReadBits(br, L2);
                            meta_ctx.code_register =
                                ((local_3f4 << L2) & 0x7fffffffu) |
                                (fresh2 & Mask(L2));
                            if (d2 > max_len) d2 = max_len;
                            local_3e0 = d2;

                            // Mode-relative interpretation:
                            std::uint32_t cmp_val = d2;
                            if (mode == 1) {
                                if (d2 != 0) {
                                    cmp_val = (d2 - 1u) + (prev < d2 ? 1u : 0u);
                                    if (cmp_val != local_3c8) { terminated = true; break; }
                                }
                            } else if (mode == 2) {
                                if (d2 != 0) {
                                    cmp_val = (local_3c8 == d2) ? 0u : d2;
                                    terminated = true; break;
                                }
                            } else {
                                if (mode == 3) {
                                    cmp_val = (d2 + local_3c8) -
                                        ((d2 + local_3c8 >= uVar1) ? uVar1 : 0u);
                                }
                                if (cmp_val != local_3c8) { terminated = true; break; }
                            }
                            local_3bc++;
                            local_3f4 = meta_ctx.code_register;
                            if (static_cast<std::uint32_t>(2 << local_3bc) > rl_max) break;
                        }
                        if (!terminated) {
                            local_3e0 = 0xffffffffu;
                        }
                        // Read run-length suffix: log2(rl_max)+ bits.
                        const std::int32_t bits_to_read = (local_3bc == 0) ? 1 : local_3bc;
                        const std::uint32_t hi_bits = meta_ctx.code_register >>
                            (31u - static_cast<std::uint32_t>(bits_to_read));
                        meta_ctx.code_register =
                            (meta_ctx.code_register << bits_to_read) & 0x7fffffffu;
                        const std::uint32_t lo_bits = ReadBits(br,
                            static_cast<std::uint32_t>(bits_to_read));
                        meta_ctx.code_register |= lo_bits;
                        // Run base table: kPrefixOffsets[local_3bc].
                        // Legacy reads from DAT_081b4380 — we approximate with
                        // 2^L - 2 (canonical exponential-Golomb-like prefix).
                        // TODO: confirm this against gdb trace.
                        rl_count = hi_bits + ((1u << bits_to_read) - 2u);
                        if (rl_count > rl_max) rl_count = rl_max;
                    }
                    // Update Kraft for `local_3c8` repeated `rl_count` more times.
                    if (local_3c8 != 0) {
                        cc[local_3c8] += rl_count;
                        local_4c += rl_count;
                        std::uint32_t new_last = MaxLen(local_48, local_3c8);
                        local_48 = new_last;
                        RecomputeKraft(cc, kraft, kraft_max);
                    }
                    // Emit run of `local_3c4` rl_count times.
                    for (std::uint32_t i = 0; i < rl_count; ++i) {
                        if (puVar15 >= out_end) break;
                        *puVar15++ = local_3c4;
                    }
                    if (kraft[local_48] == 0) break;
                    local_3cc = 0;
                    param_4_remain = (param_4_remain - rl_count) - 1u;
                    if (static_cast<std::int32_t>(param_4_remain) <= 0) break;
                    continue;
                }
                // rl_max == 0: nothing more to write.
                local_3e0 = 0xffffffffu;
                param_4_remain -= 1;
                continue;
            }
        } else {
            // Lookahead from previous RLE termination.
            local_3c4 = static_cast<std::uint8_t>(local_3e0);
            *puVar15 = local_3c4;
            puVar15 = puVar15 + 1;
            local_3c8 = local_3e0;
            if (local_3e0 == 0) {
                if (kraft[local_48] == 0) break;
                if (prev == 0) {
                    goto rle_handler;
                }
                local_3e0 = 0xffffffffu;
                local_3cc = 0;
                local_3c8 = 0;
                param_4_remain -= 1;
                continue;
            }
            // Update Kraft.
            cc[local_3c8]++;
            std::uint32_t new_last = MaxLen(local_48, local_3c8);
            local_48 = new_last;
            local_4c++;
            RecomputeKraft(cc, kraft, kraft_max);
            if (kraft[new_last] == 0) break;
            if (prev == local_3c8) {
                goto rle_handler;
            }
            local_3e0 = 0xffffffffu;
            local_3cc = 0;
            param_4_remain -= 1;
            continue;
        }
    }

    // Pad the rest of the output with zeros.
    while (puVar15 < out_end) *puVar15++ = 0;
    RangeCoderFinalize(br);
    return true;
}
#endif
// ---------------------------------------------------------------------------
// Prefilter+arith decoder (task #13)
// ---------------------------------------------------------------------------

// FUN_0809bbf0 — stereo-variant residual decoder.
// Threshold=1: symbol 0 → zero; symbols 1+ → VLC-style magnitude + sign bit.
// Tables extracted from DAT_081b3a00/39c0/39c1/42f0/4380 at runtime via GDB.
void DecodeResidualsStereo(std::int32_t* out, std::size_t count,
                           const std::uint8_t* arith_bytes, SideBitState* br) {
    // bVar1 = kStereoRange[symbol-1]  (group selector, always even, 0..62)
    static constexpr std::uint8_t kStereoRange[256] = {
        0x00,0x00,0x02,0x02,0x04,0x04,0x04,0x04,0x06,0x06,0x06,0x06,0x08,0x08,0x08,0x08,
        0x0a,0x0a,0x0a,0x0a,0x0c,0x0c,0x0c,0x0c,0x0e,0x0e,0x0e,0x0e,0x10,0x10,0x10,0x10,
        0x12,0x12,0x12,0x12,0x14,0x14,0x14,0x14,0x16,0x16,0x16,0x16,0x18,0x1a,0x1c,0x1e,
        0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
        /* 64-255: all 0 (direct magnitude = symbol, no extra bits) */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    };
    // DAT_081b39c0[0..63]: sub-range start offset per bVar1 (even indices used)
    static constexpr std::uint8_t kSubOffset[64] = {
        0x00,0x00,0x02,0x00,0x04,0x00,0x08,0x01,0x0c,0x02,0x10,0x03,0x14,0x04,0x18,0x05,
        0x1c,0x06,0x20,0x07,0x24,0x08,0x28,0x0a,0x2c,0x0c,0x2d,0x0d,0x2e,0x0e,0x2f,0x0f,
        0x30,0x10,0x31,0x11,0x32,0x12,0x33,0x13,0x34,0x14,0x35,0x15,0x36,0x16,0x37,0x17,
        0x38,0x18,0x39,0x19,0x3a,0x1a,0x3b,0x1b,0x3c,0x1c,0x3d,0x1d,0x3e,0x1e,0x3f,0x1f,
    };
    // DAT_081b39c1[0..63]: extra bits count per bVar1 (even indices used)
    static constexpr std::uint8_t kExBits[64] = {
        0x00,0x02,0x00,0x04,0x00,0x08,0x01,0x0c,0x02,0x10,0x03,0x14,0x04,0x18,0x05,0x1c,
        0x06,0x20,0x07,0x24,0x08,0x28,0x0a,0x2c,0x0c,0x2d,0x0d,0x2e,0x0e,0x2f,0x0f,0x30,
        0x10,0x31,0x11,0x32,0x12,0x33,0x13,0x34,0x14,0x35,0x15,0x36,0x16,0x37,0x17,0x38,
        0x18,0x39,0x19,0x3a,0x1a,0x3b,0x1b,0x3c,0x1c,0x3d,0x1d,0x3e,0x1e,0x3f,0x1f,0x00,
    };
    // DAT_081b4380[0..31] as uint32: base magnitude for range bVar1>>1
    static constexpr std::uint32_t kBase[32] = {
        0,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,
        65536,131072,262144,524288,1048576,2097152,4194304,8388608,
        16777216,33554432,67108864,134217728,268435456,536870912,1073741824,2147483648u,
    };

    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t b = arith_bytes[i];
        if (b == 0u) { out[i] = 0; continue; }

        std::uint32_t iVar5 = b - 1u;  // b - threshold
        std::uint32_t bVar1 = kStereoRange[iVar5];
        std::uint32_t bVar2 = kExBits[bVar1];
        std::uint32_t magnitude;

        if (bVar2 == 0u) {
            magnitude = b;  // = iVar5 + 1 (threshold)
        } else {
            std::uint32_t extra   = ReadSideBits(br, bVar2);
            std::uint32_t shifted = ((iVar5 - kSubOffset[bVar1]) << (bVar2 & 0x1fu))
                                    + kBase[bVar1 >> 1u];
            magnitude = (extra | shifted) + 1u;
            if (magnitude == 0u) { out[i] = 0; continue; }
        }

        // Sign bit: 0 → positive, 1 → negative
        std::uint32_t sign = ReadSideBits(br, 1u);
        out[i] = static_cast<std::int32_t>((magnitude ^ (0u - sign)) + sign);
    }
}

// FUN_0809baa0 — mono residual decoder.
// Bytes < 0xe0: direct zigzag. Bytes >= 0xe0: pull extra bits from side stream.
// Zigzag: value = (byte >> 1) ^ -(byte & 1)
void DecodeResidualsMono(std::int32_t* out, std::size_t count,
                         const std::uint8_t* arith_bytes, SideBitState* br) {
    const std::uint8_t* end_ptr = br->end;
    const std::uint8_t* cur     = br->cur;
    std::uint32_t       cache   = br->cache;
    std::uint32_t       n_valid = br->n_valid;

    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t b = arith_bytes[i];
        if (b <= 0xdfu) {
            out[i] = static_cast<std::int32_t>((b >> 1u) ^ (0u - (b & 1u)));
        } else {
            std::uint32_t n_bits  = (b < 0xe1u) ? 1u : (b - 0xe0u);
            std::uint32_t old_cache = cache;
            std::uint32_t bits;
            if (n_valid < n_bits) {
                std::uint32_t need      = n_bits - n_valid;
                std::uint32_t new_nvalid = 32u - need;
                std::uint32_t word = new_nvalid;
                if (cur < end_ptr) {
                    std::uint32_t raw;
                    __builtin_memcpy(&raw, cur, 4);
                    word = ((raw >> 24u) & 0xffu) | ((raw >> 8u) & 0xff00u) |
                           ((raw & 0xff00u) << 8u) | ((raw & 0xffu) << 24u);
                }
                cur += 4;
                old_cache = word;
                bits = (cache << (need & 0x1fu)) | (old_cache >> (new_nvalid & 0x1fu));
                n_valid = new_nvalid;
            } else {
                n_valid -= n_bits;
                bits = cache >> (n_valid & 0x1fu);
            }
            cache = old_cache;
            std::uint32_t base = RunLengthOffset(b - 0xe0u) + 0xe0u;
            std::uint32_t val  = base + (bits & Mask(n_bits));
            out[i] = static_cast<std::int32_t>((val >> 1u) ^ (0u - (val & 1u)));
        }
    }

    br->cur     = cur;
    br->cache   = cache;
    br->n_valid = n_valid;
}

// FUN_080a50c0 — reconstruct sample output from int32 delta residuals.
// Integrates deltas and writes sample_width-byte samples (LE or BE).
void ReconstructOutputSamples(std::uint8_t* out, std::size_t total_bytes,
                               const std::int32_t* residuals,
                               const PrefilterParams* p) {
    const std::uint8_t sw  = p->sample_width;
    const std::uint8_t end = p->endian;
    if (sw == 0 || total_bytes == 0) return;
    std::size_t n_samples = total_bytes / sw;
    if (n_samples == 0) return;

    std::int32_t accum = 0;
    std::uint8_t* dst  = out;
    for (std::size_t i = 0; i < n_samples; ++i) {
        accum += residuals[i];
        std::int32_t v = accum;
        if (sw == 1u) {
            *dst++ = static_cast<std::uint8_t>(v);
        } else if (sw == 2u) {
            if (end == 0u) {
                dst[0] = static_cast<std::uint8_t>((v >> 8u) & 0xffu);
                dst[1] = static_cast<std::uint8_t>(v & 0xffu);
            } else {
                std::uint16_t v16 = static_cast<std::uint16_t>(v);
                __builtin_memcpy(dst, &v16, 2);
            }
            dst += 2;
        } else {
            if (end == 0u) {
                dst[0] = static_cast<std::uint8_t>((v >> 16u) & 0xffu);
                dst[1] = static_cast<std::uint8_t>((v >> 8u)  & 0xffu);
                dst[2] = static_cast<std::uint8_t>(v & 0xffu);
            } else {
                dst[0] = static_cast<std::uint8_t>(v & 0xffu);
                dst[1] = static_cast<std::uint8_t>((v >> 8u)  & 0xffu);
                dst[2] = static_cast<std::uint8_t>((v >> 16u) & 0xffu);
            }
            dst += 3;
        }
    }
}

// FUN_080a50c0 — STEREO branch. ch1/ch2 are PLANAR residual halves (per_chan each);
// each channel is delta-integrated (cumsum) and the pair is reconstructed and
// interleaved. channels==1 = L/R, channels==2 = mid/side; both fast paths require
// flag_a && sample_width==2 && endian (LE int16). Otherwise a generic per-channel
// cumsum + width/endian interleave.
void ReconstructStereoSamples(std::uint8_t* out, const std::int32_t* ch1,
                              const std::int32_t* ch2, std::uint32_t per_chan,
                              const PrefilterParams* p) {
    const bool fast = (p->flag_a && p->sample_width == 2u && p->endian != 0u);
    std::int32_t acc1 = 0, acc2 = 0;
    std::uint8_t* dst = out;
    if (fast && p->channels == 2) {            // mid/side
        for (std::uint32_t k = 0; k < per_chan; ++k) {
            acc1 += ch1[k]; acc2 += ch2[k];    // acc1=mid, acc2=side
            std::int16_t s = static_cast<std::int16_t>(
                static_cast<std::int16_t>(acc2) - static_cast<std::int16_t>(acc1 >> 1));
            std::int16_t l = static_cast<std::int16_t>(s + static_cast<std::int16_t>(acc1));
            std::memcpy(dst, &l, 2); std::memcpy(dst + 2, &s, 2); dst += 4;
        }
        return;
    }
    if (fast && p->channels == 1) {            // L/R
        for (std::uint32_t k = 0; k < per_chan; ++k) {
            acc1 += ch1[k]; acc2 += ch2[k];
            std::int16_t l = static_cast<std::int16_t>(acc1);
            std::int16_t r = static_cast<std::int16_t>(acc2);
            std::memcpy(dst, &l, 2); std::memcpy(dst + 2, &r, 2); dst += 4;
        }
        return;
    }
    // Generic: per-channel cumsum, interleave with sample_width/endian byte order.
    auto put = [&](std::int32_t v) {
        if (p->sample_width == 1u) { *dst++ = static_cast<std::uint8_t>(v); }
        else if (p->sample_width == 2u) {
            if (p->endian == 0u) { dst[0] = static_cast<std::uint8_t>((v >> 8) & 0xff);
                                   dst[1] = static_cast<std::uint8_t>(v & 0xff); }
            else { std::uint16_t v16 = static_cast<std::uint16_t>(v); std::memcpy(dst, &v16, 2); }
            dst += 2;
        } else {
            if (p->endian == 0u) { dst[0] = static_cast<std::uint8_t>((v >> 16) & 0xff);
                                   dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
                                   dst[2] = static_cast<std::uint8_t>(v & 0xff); }
            else { dst[0] = static_cast<std::uint8_t>(v & 0xff);
                   dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
                   dst[2] = static_cast<std::uint8_t>((v >> 16) & 0xff); }
            dst += 3;
        }
    };
    for (std::uint32_t k = 0; k < per_chan; ++k) {
        acc1 += ch1[k]; acc2 += ch2[k];
        put(acc1); put(acc2);
    }
}

// FUN_080a5330 — core prefilter block decoder (internal implementation).
// `pred` carries LPC predictor state across successive blocks.
// `lms_ch1` / `lms_ch2` carry LMS inter-channel state (only used when
// is_stereo_variant && channels != 0 && predictor_bit=1).
static std::size_t DecodePFBlock(const std::uint8_t* input, std::size_t input_size,
                                  std::uint8_t* output, std::size_t output_size,
                                  bool is_stereo_variant, LpcPredictor* pred,
                                  LmsObject* lms_ch1 = nullptr,
                                  LmsObject* lms_ch2 = nullptr,
                                  LpcPredictor* pred2 = nullptr) {
    if (input_size == 0 || output_size == 0) return 0;

    // Header byte → packed format params (FUN_080a5330 lines 44-101).
    std::uint8_t hdr = input[0];
    PrefilterParams p{};
    p.flag_a  = hdr & 1u;
    std::uint32_t bVar7 = hdr >> 1u;
    std::uint32_t cVar1 = bVar7 / 3u;
    p.channels = static_cast<std::int8_t>(bVar7 - cVar1 * 3u);
    std::uint32_t w     = cVar1 / 5u;
    std::uint32_t bVar7b = cVar1 - w * 5u;
    if (bVar7b != 0u) {
        p.endian       = static_cast<std::uint8_t>((bVar7b - 1u) & 1u);
        std::uint8_t cVar12 = static_cast<std::uint8_t>(((bVar7b - 1u) >> 1u) + 1u);
        p.sample_width = cVar12 + 1u;
    } else {
        p.endian       = 0u;
        p.sample_width = 1u;
    }
    p.prefix_count = static_cast<std::int16_t>(w);

    const std::uint8_t* ptr = input + 1;
    std::size_t remaining   = input_size - 1u;

    // Extended prefix_count (local_26 == 6 → read one more byte).
    if (p.prefix_count == 6) {
        if (remaining == 0) return 0;
        p.prefix_count = static_cast<std::int16_t>(static_cast<std::uint32_t>(ptr[0]) + 6u);
        ++ptr; --remaining;
    }

    // Copy literal prefix bytes.
    std::uint32_t prefix = static_cast<std::uint32_t>(p.prefix_count < 0 ? 0 : p.prefix_count);
    if (prefix > remaining || prefix > output_size) return 0;
    if (prefix > 0) { __builtin_memcpy(output, ptr, prefix); ptr += prefix; remaining -= prefix; }

    // Sample counts.
    std::uint32_t sw         = p.sample_width;
    if (sw == 0) return 0;
    std::uint32_t avail      = static_cast<std::uint32_t>(output_size) - prefix;
    std::uint32_t n_per_chan = avail / sw;
    if (p.channels != 0) n_per_chan &= ~1u;
    std::uint32_t remainder  = avail - n_per_chan * sw;
    std::uint32_t aligned_out = avail - remainder;
    std::uint32_t n_elems    = aligned_out / sw; // = uStack_5007c

    // For stereo (channels != 0) everything downstream is PLANAR: ch1 occupies
    // [0, per_chan), ch2 occupies [per_chan, 2*per_chan).
    const bool stereo_split = (is_stereo_variant && p.channels != 0 && n_elems >= 2u);
    const std::uint32_t per_chan = stereo_split ? (n_elems / 2u) : n_elems;

    // Arith-decode residual bytes. FUN_080a5330 decodes stereo as TWO per-channel
    // FUN_080a4ea0 calls (each reads its own Huffman header), writing PLANAR halves;
    // a single n_elems call would read only one header and mis-locate the side stream.
    std::vector<std::uint8_t> arith_buf(n_elems);
    std::size_t consumed_arith = 0;
    if (n_elems > 0) {
        if (!stereo_split) {
            consumed_arith = DecodeArithBuffer(ptr, remaining, arith_buf.data(),
                                               n_elems, 12u);
            if (consumed_arith == 0) return 0;
        } else {
            std::size_t c0 = DecodeArithBuffer(ptr, remaining, arith_buf.data(),
                                               per_chan, 12u);
            if (c0 == 0) return 0;
            std::size_t c1 = DecodeArithBuffer(ptr + c0, remaining - c0,
                                               arith_buf.data() + per_chan, per_chan, 12u);
            if (c1 == 0) return 0;
            consumed_arith = c0 + c1;
        }
        ptr += consumed_arith; remaining -= consumed_arith;
    }

    // Side-bit stream (follows the arith payload).
    SideBitState br{};
    br.ignored = ptr;
    br.end     = ptr + remaining;
    br.cur     = ptr;
    br.cache   = 0u;
    br.n_valid = 0u;

    // Predictor init bit-reads (FUN_080a5330 lines 216-254).
    // predictor_count = param_1[1] = 1 for the lzpf mono path.
    // 1 bit: predictor active flag; if 1, 3 more bits give order_bits such
    // that order = shift = order_bits + 8 (confirmed GDB: byte 0x80 → bit=1,
    // order_bits=0 → order=8, shift=8 for ramp16_cf.nz).
    // For stereo (channels != 0) the residual array is PLANAR: ch1=[0,per_chan),
    // ch2=[per_chan,2*per_chan). The predictor-init bit layout differs by channel
    // count (FUN_080a5330 lines 216-254): mono reads [active(1), order(3 if active)];
    // stereo reads a leading bit G then, per channel, [active(1), order(3 if active)]
    // (order = bits + 8). Verified by GDB: stereo side-bit sequence [1,1,3,1,3] = 9
    // bits, both channels active with order 8 (order_bits 0) for stereo_lms_cf.nz.
    std::uint32_t predictor_bit   = 0u;   // mono predictor-active flag
    std::uint32_t predictor_order = 0u;
    std::uint32_t lms_enable      = 0u;   // stereo leading bit G (gates inter-channel LMS)
    std::uint32_t ch_active[2]    = {0u, 0u};
    std::uint32_t ch_order[2]     = {8u, 8u};
    if (!stereo_split) {
        predictor_bit = ReadSideBits(&br, 1u);
        if (predictor_bit != 0u)
            predictor_order = ReadSideBits(&br, 3u) + 8u;
    } else {
        lms_enable = ReadSideBits(&br, 1u);
        for (int c = 0; c < 2; ++c) {
            ch_active[c] = ReadSideBits(&br, 1u);
            if (ch_active[c] != 0u)
                ch_order[c] = ReadSideBits(&br, 3u) + 8u;
        }
    }
    // Residual decode → int32 array. FUN_0809baa0 is the UNIVERSAL (channel-agnostic)
    // residual decoder used for BOTH mono and stereo: it reads one arith byte per
    // element (escapes ≥0xe0 pull extra bits from the side stream) and the n_elems
    // results are laid out PLANAR for stereo (ch1=[0,per_chan), ch2=[per_chan,2*per_chan)).
    // The old speculative DecodeResidualsStereo (even/odd) was never the real path.
    std::vector<std::int32_t> residuals(n_elems);
    DecodeResidualsMono(residuals.data(), n_elems, arith_buf.data(), &br);
    // Side-stream bytes consumed (FUN_080a5330 line 263).
    // Uses signed arithmetic: (7 - n_valid) can be negative when n_valid > 7.
    std::int32_t side_bits_signed =
        static_cast<std::int32_t>(7) - static_cast<std::int32_t>(br.n_valid)
        + static_cast<std::int32_t>(br.cur - ptr) * 8;
    std::size_t side_consumed = (side_bits_signed > 0)
        ? (static_cast<std::uint32_t>(side_bits_signed) >> 3u)
        : 0u;
    if (side_consumed > remaining) side_consumed = remaining;

    // FUN_080a5330 applies LPC per planar channel (separate predictor state), then the
    // inter-channel LMS, then FUN_080a50c0 (cumsum + L/R | mid/side interleave).
    LpcPredictor local_pred2{};
    LpcPredictor* p2 = (pred2 != nullptr) ? pred2 : &local_pred2;

    // LPC inverse filter (FUN_08095d90, 4-tap path): in-place per planar channel.
    if (pred != nullptr) {
        if (!stereo_split) {
            if (predictor_bit) { pred->shift = predictor_order; pred->Run(residuals.data(), per_chan); }
            else               { pred->ResetState(); }
        } else {
            if (ch_active[0]) { pred->shift = ch_order[0]; pred->Run(residuals.data(), per_chan); }
            else              { pred->ResetState(); }
            if (ch_active[1]) { p2->shift = ch_order[1]; p2->Run(residuals.data() + per_chan, per_chan); }
            else              { p2->ResetState(); }
        }
    }

    // LMS inter-channel predictor (FUN_08096e20) on the PLANAR halves, gated by the
    // stereo leading bit G (lms_enable) AND the lzpf-context stereo flag.
    if (stereo_split && lms_enable != 0u &&
        lms_ch1 != nullptr && lms_ch2 != nullptr && per_chan > 0u) {
        ApplyLmsInterChannel(residuals.data(), residuals.data() + per_chan,
                             per_chan, lms_ch1, lms_ch2);
    }

    // Output reconstruction (FUN_080a50c0).
    if (stereo_split) {
        ReconstructStereoSamples(output + prefix, residuals.data(),
                                 residuals.data() + per_chan, per_chan, &p);
    } else {
        ReconstructOutputSamples(output + prefix, aligned_out, residuals.data(), &p);
    }

    return static_cast<std::size_t>(ptr - input) + side_consumed;
}

// Public single-block wrapper (no persistent LPC state across calls).
std::size_t DecodePrefilterBlock(const std::uint8_t* input, std::size_t input_size,
                                  std::uint8_t* output, std::size_t output_size,
                                  bool is_stereo_variant) {
    LpcPredictor local_pred{};
    return DecodePFBlock(input, input_size, output, output_size,
                         is_stereo_variant, &local_pred);
}

// FUN_080a5bb0 — loop wrapper splitting output into ≤ 65536-byte chunks.
// LPC predictor state persists across blocks (matches nz_context lifetime).
std::size_t DecodePrefilterStream(const std::uint8_t* input, std::size_t input_size,
                                   std::uint8_t* output, std::size_t output_size,
                                   bool is_stereo_variant,
                                   LpcPredictor* persistent_pred) {
    if (output_size == 0) return 0;
    LpcPredictor local_pred{};
    LpcPredictor* pred = persistent_pred ? persistent_pred : &local_pred;
    std::size_t in_off = 0, out_off = 0;
    while (out_off < output_size) {
        std::size_t chunk = std::min<std::size_t>(output_size - out_off, 0x10000u);
        std::size_t used  = DecodePFBlock(
            input + in_off, input_size - in_off,
            output + out_off, chunk, is_stereo_variant, pred);
        if (used == 0) return 0;
        in_off  += used;
        out_off += chunk;
    }
    return in_off;
}

std::size_t DecodePrefilterStream(const std::uint8_t* input, std::size_t input_size,
                                   std::uint8_t* output, std::size_t output_size,
                                   bool is_stereo_variant,
                                   LpcPredictor* persistent_pred,
                                   LmsObject* persistent_lms_ch1,
                                   LmsObject* persistent_lms_ch2,
                                   LpcPredictor* persistent_pred2) {
    if (output_size == 0) return 0;
    LpcPredictor local_pred{}, local_pred2b{};
    LpcPredictor* pred  = persistent_pred  ? persistent_pred  : &local_pred;
    LpcPredictor* pred2 = persistent_pred2 ? persistent_pred2 : &local_pred2b;
    LmsObject local_lms1{}, local_lms2{};
    if (persistent_lms_ch1 == nullptr) { local_lms1.Init(); persistent_lms_ch1 = &local_lms1; }
    if (persistent_lms_ch2 == nullptr) { local_lms2.Init(); persistent_lms_ch2 = &local_lms2; }
    std::size_t in_off = 0, out_off = 0;
    while (out_off < output_size) {
        std::size_t chunk = std::min<std::size_t>(output_size - out_off, 0x10000u);
        std::size_t used  = DecodePFBlock(
            input + in_off, input_size - in_off,
            output + out_off, chunk, is_stereo_variant, pred,
            persistent_lms_ch1, persistent_lms_ch2, pred2);
        if (used == 0) return 0;
        in_off  += used;
        out_off += chunk;
    }
    return in_off;
}

std::size_t DecodePrefilterStream(const std::uint8_t* input, std::size_t input_size,
                                   std::uint8_t* output, std::size_t output_size,
                                   bool is_stereo_variant) {
    return DecodePrefilterStream(input, input_size, output, output_size,
                                 is_stereo_variant, nullptr, nullptr, nullptr);
}

// ---------------------------------------------------------------------------
// End scratch port body.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// LMS inter-channel predictor (FUN_08096e20, MMX path — scalar port).
// ---------------------------------------------------------------------------
// Per the decompile at work/reports/decomp_lzpf/FUN_08096e20_FUN_08096e20.c
// (lines 64-118), the active path on x86 hosts uses MMX primitives
// (pmaddwd, paddsw, psubsw). The scalar port below performs the same
// arithmetic step-by-step on int16 (saturating) and widens for dot products.
// Final result is byte-equivalent to the MMX code for the inputs the
// encoder produces (int16 saturated coeffs + sign + ring).
//
// State per object (0x2070 bytes per HANDOFF §6A):
//   coeffs1[4] @+0x00   (i16, saturated under paddsw / psubsw)
//   sign1[4]   @+0x08   (i16, ±1 or 0)
//   ring1[1024] @+0x10  (i16 sample history; ptr1 indexes modulo 1024)
//   ptr1       @+0x1010 (... actually @+0x1020 per layout; i32)
//   dot1       @+0x1024 (i32 accumulator)
//   coeffs2[4] @+0x1030 sign2[4] @+0x1038 ring2[1024] @+0x1040 ptr2 @+0x2050 dot2 @+0x2054
//   shift      @+0x2060 (u8, init 0xd)
//
// The legacy code uses a 64-byte MMX register window over coeffs+sign+ring
// (16 i16 = 32 bytes per stage, fits in one MMX register). The scalar port
// walks the same data manually.
// --- Faithful scalar port of the legacy LMS helpers ------------------------
// FUN_080be8e0 / FUN_080be820 / FUN_080beaa0 / FUN_080beae0. The legacy MMX
// path (selected when DAT_081835b8 != 0) is numerically identical to this
// scalar fallback (CPU-feature dispatch of the same arithmetic).

static inline std::int16_t LmsSat16(std::int32_t v) {
    if (v > 32767) v = 32767;
    if (v < -32768) v = -32768;
    return static_cast<std::int16_t>(v);
}

// Byte offset -> ring[] index. Ring spans byte [0x10, 0x1020).
static inline std::int16_t& LmsRing(LmsStage& s, int byte_off) {
    return s.ring[(byte_off - 0x10) >> 1];
}

// FUN_080be8e0: push sample x into the stage ring, store its sign 8 bytes
// ahead, then compute the 4-tap dot product into s.dot.
static void LmsRun(LmsStage& s, std::int32_t x) {
    s.ptr -= 2;
    // sign = ((x >> 30) & 2) - 1  ->  +1 if x<0, -1 otherwise.
    std::int16_t sgn = static_cast<std::int16_t>(
        ((static_cast<std::uint32_t>(x >> 30) & 2u)) - 1u);
    if (s.ptr < 0x10) {
        // Ring underflow: reset to the top, carrying the 3 surviving samples
        // and their signs so the sliding window stays continuous.
        s.ptr = 0x1010;
        LmsRing(s, 0x1012) = LmsRing(s, 0x10);
        LmsRing(s, 0x1014) = LmsRing(s, 0x12);
        LmsRing(s, 0x1016) = LmsRing(s, 0x14);
        LmsRing(s, 0x101a) = LmsRing(s, 0x18);
        LmsRing(s, 0x101c) = LmsRing(s, 0x1a);
        LmsRing(s, 0x101e) = LmsRing(s, 0x1c);
        LmsRing(s, 0x1010) = static_cast<std::int16_t>(x);
        LmsRing(s, 0x1018) = sgn;
    } else {
        LmsRing(s, s.ptr)     = static_cast<std::int16_t>(x);
        LmsRing(s, s.ptr + 8) = sgn;
    }
    std::int32_t acc = 0;
    for (int k = 0; k < 4; ++k)
        acc += static_cast<std::int32_t>(s.coeffs[k]) *
               static_cast<std::int32_t>(LmsRing(s, s.ptr + k * 2));
    s.dot = acc;
}

// FUN_080be820: sign-sign coefficient adaptation driven by `driver`'s sign.
static void LmsAdapt(LmsStage& s, std::int32_t driver) {
    if (driver >= 0) {
        if (driver != 0)
            for (int k = 0; k < 4; ++k)
                s.coeffs[k] = LmsSat16(static_cast<std::int32_t>(s.coeffs[k]) -
                                       static_cast<std::int32_t>(LmsRing(s, s.ptr + 8 + k * 2)));
    } else {
        for (int k = 0; k < 4; ++k)
            s.coeffs[k] = LmsSat16(static_cast<std::int32_t>(LmsRing(s, s.ptr + 8 + k * 2)) +
                                   static_cast<std::int32_t>(s.coeffs[k]));
    }
}

// FUN_080beaa0: run stage 2 on x, then predict = (dot2 + dot1) >> shift.
static std::int32_t LmsPredict(LmsObject& o, std::int32_t x) {
    LmsRun(o.st[1], x);
    std::int32_t pr = o.st[1].dot + o.st[0].dot;
    return pr >> (o.shift & 0x1f);
}

// FUN_080beae0: adapt stage1 by residual, run stage1 on the reconstructed
// sample, then adapt stage2 by residual.
static void LmsUpdate(LmsObject& o, std::int32_t sample, std::int32_t residual) {
    LmsAdapt(o.st[0], residual);
    LmsRun(o.st[0], sample);
    LmsAdapt(o.st[1], residual);
}

// FUN_08096e20 (scalar path). Reconstructs interleaved ch1/ch2 samples in
// place. `carry` (legacy iVar5) chains across channels: ch2 predicts from
// ch1's just-reconstructed sample (inter-channel decorrelation), and the
// next ch1 sample predicts from the previous ch2 sample.
void ApplyLmsInterChannel(std::int32_t* ch1_residuals, std::int32_t* ch2_residuals,
                          std::size_t n, LmsObject* obj_ch1, LmsObject* obj_ch2) {
    if (n == 0 || ch1_residuals == nullptr || ch2_residuals == nullptr ||
        obj_ch1 == nullptr || obj_ch2 == nullptr) return;
    std::int32_t carry = 0;  // iVar5
    for (std::size_t i = 0; i < n; ++i) {
        std::int32_t res1 = ch1_residuals[i];
        carry = LmsPredict(*obj_ch1, carry) + res1;
        LmsUpdate(*obj_ch1, carry, res1);
        ch1_residuals[i] = carry;

        std::int32_t res2 = ch2_residuals[i];
        carry = LmsPredict(*obj_ch2, carry) + res2;
        LmsUpdate(*obj_ch2, carry, res2);
        ch2_residuals[i] = carry;
    }
}

}  // namespace nzr::lzpf
