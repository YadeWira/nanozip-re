// Native `-cD` (nz_lzhds) literal model. See nz_lzhds.h for the contract and
// provenance. Ported mechanically (goto-preserving where the control flow is
// intricate) from the Ghidra decompile of FUN_080982e0 + supporting functions
// -- deliberately NOT "cleaned up", per the odd-looking-but-load-bearing detail
// warning in work/reports/decomp_lzhd/decomp_cD_nz_lzhds.txt (e.g. the
// `u - (u+3>>2)` MTF swap index, the `+0x200 >> 10` predictor rounding, the
// `local_58 < 5` re-zero condition, the two-level Elias-delta-style run-length
// code). Validated byte-exact against 3 real GDB-captured chunks (see the
// session's research artifacts) before this C++ transcription.
#include "nz_lzhds.h"
#include <cstdio>
#include <cstdlib>

#include <cstring>
#include <vector>

namespace nzr {
namespace cd {

namespace {

// ---------------------------------------------------------------------------
// Cross-chunk ring helpers (duplicated from nz_cd_tokens.cpp's anonymous-
// namespace RingReduce -- kept local here since that one isn't exported, and
// this file must not depend on nz_cd_tokens.cpp's internals).
inline std::uint32_t LzhdsRingReduce(std::uint32_t idx, std::uint32_t ring_size) {
    return idx >= ring_size ? idx - ring_size : idx;  // idx < 2*ring_size by construction
}

// ---------------------------------------------------------------------------
// Bit reader (FUN_080b1fb0): read `n` (1..32) bits MSB-first from a byte-
// swapped 32-bit-word stream. Refills a fresh byteswapped word from `cur` when
// the accumulator runs low; past the logical end (`cur >= end`) the refill uses
// a harmless filler word (`nb`, the same convention nz_cd_tokens.cpp's token
// BitReader uses) -- for well-formed streams the decode never actually needs
// bits past the true logical end, so the filler's value is never observed.
struct LzhdsBitReader {
    const std::uint8_t* cur;
    const std::uint8_t* end;
    std::uint32_t word = 0;
    std::uint32_t bits = 0;
};

inline std::uint32_t LzhdsBSwap32(std::uint32_t w) {
    return (w >> 24) | ((w & 0x00ff0000u) >> 8) | ((w & 0x0000ff00u) << 8) | (w << 24);
}

std::uint32_t LzhdsReadBits(LzhdsBitReader& r, std::uint32_t n) {
    // A corrupt Exp-Golomb prefix can ask for more than 32 bits; clamp so the
    // shifts stay defined (the decode is garbage either way and the entry
    // checksum rejects it). 64-bit intermediates keep a 32-bit shift legal.
    if (n > 32u) n = 32u;
    std::uint32_t bits = r.bits, word = r.word, res;
    if (bits < n) {
        std::uint32_t hi = static_cast<std::uint32_t>(static_cast<std::uint64_t>(word) << (n - bits));
        std::uint32_t nb = 32u - (n - bits);
        std::uint32_t neww;
        if (r.cur < r.end) {
            std::uint32_t raw;
            std::memcpy(&raw, r.cur, 4);  // may read up to 3 bytes past the logical end
            neww = LzhdsBSwap32(raw);
        } else {
            neww = nb;
        }
        r.cur += 4;
        res = hi | static_cast<std::uint32_t>(static_cast<std::uint64_t>(neww) >> nb);
        bits = nb;
        word = neww;
    } else {
        bits -= n;
        res = word >> bits;
    }
    r.bits = bits;
    r.word = word;
    std::uint32_t mask = (n >= 32u) ? 0xffffffffu : ((1u << n) - 1u);
    return res & mask;
}

// FUN_080c07d0: Elias-delta-style "prefix" decode -- count consecutive 1-bits
// (each doubling `local_20`, i.e. a unary/Elias-gamma-style prefix), then read
// that many more bits as the mantissa; returns `mantissa | local_20`. Note the
// RESULT of this function is itself treated as an EXPONENT by the caller
// (FUN_080c0a20) -- this is a genuine two-level (Elias-delta-like) code, not a
// simplification artifact.
std::uint32_t LzhdsPrefix(LzhdsBitReader& r) {
    std::uint32_t local_20 = 1;
    int iVar5 = 1;
    bool overflow = false;
    for (;;) {
        std::uint32_t bit = LzhdsReadBits(r, 1);
        if ((bit & 1u) == 0u) break;
        iVar5 += 1;
        if (iVar5 == 0x21) { iVar5 = 0x20; overflow = true; break; }
        local_20 <<= 1;
    }
    if (!overflow) {
        iVar5 -= 1;
        if (iVar5 == 0) { iVar5 = 1; local_20 = 0; }
    }
    std::uint32_t val = LzhdsReadBits(r, static_cast<std::uint32_t>(iVar5));
    return val | local_20;
}

// FUN_080c0a20: the run-length/order integer decoder used throughout the
// literal model.
std::uint32_t LzhdsExpGolomb(LzhdsBitReader& r) {
    std::uint32_t k = LzhdsPrefix(r);
    if (k == 0) return LzhdsReadBits(r, 1);
    return LzhdsReadBits(r, k) | (1u << (k & 0x1fu));
}

// ---------------------------------------------------------------------------
// DAT_081b3f20 (FUN_080bf140): signed "half" table -- half_signed(u) = u>>1 for
// even u, else -1-(u>>1). Built once (deterministic, no runtime dependency).
struct LzhdsHalfTable {
    std::int8_t v[256];
    LzhdsHalfTable() {
        for (int u = 0; u < 256; ++u) {
            if ((u & 1) == 0) {
                v[u] = static_cast<std::int8_t>(u >> 1);
            } else {
                v[u] = static_cast<std::int8_t>(-1 - static_cast<std::int8_t>(u >> 1));
            }
        }
    }
};
const LzhdsHalfTable& HalfTable() {
    static const LzhdsHalfTable t;
    return t;
}

inline std::int8_t S8(int x) { return static_cast<std::int8_t>(static_cast<std::uint8_t>(x)); }

// ---------------------------------------------------------------------------
// Per-context record accessors (0x40 bytes: rank[0..0x1f], bitmap[0x20..0x3f]).
inline std::uint8_t* CtxRank(std::uint8_t* ctx_table, std::uint32_t ctx) {
    return ctx_table + static_cast<std::size_t>(ctx) * kLzhdsCtxRecordSize;
}
inline std::uint8_t* CtxBitmap(std::uint8_t* ctx_table, std::uint32_t ctx) {
    return ctx_table + static_cast<std::size_t>(ctx) * kLzhdsCtxRecordSize + 0x20u;
}
inline bool BitmapTest(const std::uint8_t* bitmap, std::uint32_t sym) {
    return ((bitmap[sym >> 3] >> (sym & 7u)) & 1u) != 0u;
}
inline void BitmapClear(std::uint8_t* bitmap, std::uint32_t sym) {
    bitmap[sym >> 3] = static_cast<std::uint8_t>(bitmap[sym >> 3] & ~(1u << (sym & 7u)));
}
inline void BitmapSet(std::uint8_t* bitmap, std::uint32_t sym) {
    bitmap[sym >> 3] = static_cast<std::uint8_t>(bitmap[sym >> 3] | (1u << (sym & 7u)));
}

// Shared "insert as new" tail (LAB_08098b9d + the evict/shift-insert code):
// used when a symbol (raw explicit byte, or a predicted byte not currently
// tracked) isn't present in the context's 32-slot MTF window. Evicts rank
// 0x1f, shifts ranks 0x10..0x1e up to 0x11..0x1f, inserts `sym` at rank 0x10.
// (Scalar path only -- DAT_081835b8's SIMD recent-symbol-window path is an
// equivalent fast path per the architecture doc; not ported.)
std::uint32_t InsertNew(std::uint8_t* ctx_table, std::uint32_t ctx, std::uint32_t sym) {
    std::uint8_t* rank = CtxRank(ctx_table, ctx);
    std::uint8_t* bitmap = CtxBitmap(ctx_table, ctx);
    std::uint32_t evict = rank[0x1f];
    BitmapClear(bitmap, evict);
    BitmapSet(bitmap, sym);
    for (int i = 0x1f; i != 0x10; --i) rank[i] = rank[i - 1];
    rank[0x10] = static_cast<std::uint8_t>(sym);
    return sym;
}

// Raw-mode literal decode (uVar15==0 dispatch): reads one byte `b` from the
// litstream. b<0x20 => direct MTF rank-code (symbol = rank[b], then partial
// MTF swap toward the front using the `b - ((b+3)>>2)` swap index -- ported
// exactly, do not "simplify" to a full move-to-front). b>=0x20 => `b` IS the
// explicit symbol value; GDB-verified this can still require the full
// presence-bitmap-guided rank search (odd but load-bearing: for `-cD`-encoded
// data, a symbol byte >=0x20 already tracked by the context's MTF window
// resolves through the SAME search loop as the predictor path, and the search
// loop's outer re-check quirk -- re-testing the FOUND RANK INDEX itself against
// the presence bitmap -- is preserved verbatim) before falling into the shared
// insert-as-new tail. Returns the emitted symbol; `next_ctx` == the emitted
// symbol (order-1 context keyed by the last emitted byte).
std::uint32_t RawDecodeAndUpdate(std::uint8_t* ctx_table, std::uint32_t ctx, std::uint32_t b) {
    std::uint8_t* rank = CtxRank(ctx_table, ctx);
    std::uint8_t* bitmap = CtxBitmap(ctx_table, ctx);
    if (b < 0x20u) {
        std::uint32_t sym = rank[b];
        if (b == 0u) return sym;  // already at front, no swap needed
        std::uint32_t swapidx = b - ((b + 3u) >> 2);
        rank[b] = rank[swapidx];
        rank[swapidx] = static_cast<std::uint8_t>(sym);
        return sym;
    }
    // b >= 0x20: presence-bitmap-guided search (mechanical port of the
    // decompile's nested while/do-while, including its outer re-check).
    std::uint32_t search = b;
    std::uint32_t cand = search;
    for (;;) {
        cand = search;
        if (!BitmapTest(bitmap, cand)) break;
        search = 0;
        if (cand == rank[0]) {
            search = 0;
        } else {
            std::uint32_t s2 = 0;
            bool exhausted = false;
            do {
                s2 += 1;
                if (s2 == 0x20u) { exhausted = true; break; }
            } while (cand != rank[s2]);
            search = s2;
            if (exhausted) break;
        }
    }
    // b > 0x1f always takes the insert-as-new path (mirrors the decompile's
    // unconditional `if (0x1f < uVar8) goto LAB_08098b9d`).
    return InsertNew(ctx_table, ctx, cand);
}

// Predictor-mode symbol placement (shared LAB_08098888 / LAB_08098b9d tail):
// given the predicted byte `sym`, either move it toward the front (if already
// tracked) or insert it as new.
std::uint32_t EmitPredictorSymbol(std::uint8_t* ctx_table, std::uint32_t ctx, std::uint32_t sym) {
    std::uint8_t* rank = CtxRank(ctx_table, ctx);
    std::uint8_t* bitmap = CtxBitmap(ctx_table, ctx);
    if (BitmapTest(bitmap, sym)) {
        std::uint32_t found_idx = 0;
        bool found = false;
        for (std::uint32_t i = 0; i < 0x20u; ++i) {
            if (rank[i] == sym) { found_idx = i; found = true; break; }
        }
        if (found) {
            if (found_idx == 0) return sym;
            std::uint32_t swapidx = found_idx - ((found_idx + 3u) >> 2);
            rank[found_idx] = rank[swapidx];
            rank[swapidx] = static_cast<std::uint8_t>(sym);
            return sym;
        }
    }
    return InsertNew(ctx_table, ctx, sym);
}

}  // namespace

// Per-byte decode trace, zero cost unless NZOPT_TRACE_LZHDS is set. The value is
// the index of the NzLzhdsReconstruct call to trace (chunks that bypass this model
// -- pure-literal and prefilter sub-chunks -- do not consume an index), or "all".
// This path shipped with no instrumentation at all, which is what made its
// cross-chunk state bugs expensive to find.
namespace {
int g_call_index = -1;
long g_trace_want = -2;
bool TraceOn() {
    if (g_trace_want == -2) {
        const char* e = std::getenv("NZOPT_TRACE_LZHDS");
        g_trace_want = (e == nullptr) ? -1 : ((*e == 'a') ? -3 : std::atol(e));
    }
    return g_trace_want == -3 || (g_trace_want >= 0 && g_call_index == (int)g_trace_want);
}
}  // namespace

void NzLzhdsInitCtxTable(std::uint8_t* ctx_table) {
    for (std::uint32_t c = 0; c < kLzhdsCtxCount; ++c) {
        std::uint8_t* rank = CtxRank(ctx_table, c);
        for (std::uint32_t i = 0; i < 0x20u; ++i) rank[i] = static_cast<std::uint8_t>(i);
        std::uint8_t* bitmap = CtxBitmap(ctx_table, c);
        bitmap[0] = bitmap[1] = bitmap[2] = bitmap[3] = 0xffu;  // symbols 0..31 present
        for (std::uint32_t i = 4; i < 0x20u; ++i) bitmap[i] = 0u;
    }
}

std::uint32_t NzLzhdsReconstruct(const std::uint32_t* tokens, std::uint32_t num_tokens,
                                 const std::uint8_t* litstream, std::size_t litstream_len,
                                 const std::uint8_t* ratebits, std::size_t ratebits_len,
                                 std::uint8_t* ring, std::uint32_t ring_size, std::uint32_t base,
                                 std::uint32_t out_size,
                                 std::uint8_t* ctx_table, std::uint32_t* ctx_index) {
    if (ring == nullptr || ctx_table == nullptr || ctx_index == nullptr || ring_size == 0u)
        return 0u;
    (void)litstream_len;

    LzhdsBitReader rb{ratebits, ratebits + ratebits_len, 0, 0};

    // Rep-distance cache: LOCAL to this call, reset every time (matches
    // FUN_080982e0's top-of-function `local_2c[0..3] = 1`).
    std::uint32_t rep[4] = {1, 1, 1, 1};

    // Adaptive predictor state: LOCAL to this call, reset every time (matches
    // FUN_080bf140(local_dc) being called unconditionally at function entry,
    // not just once per archive -- GDB/decompile-confirmed).
    std::int32_t pred[32] = {0};
    std::uint32_t order = 0;
    std::uint32_t stage = 0;
    std::uint32_t mode = 0;  // uVar15: 0 => raw dispatch; nonzero => predictor run, value == order

    std::uint32_t run_ctr = LzhdsExpGolomb(rb) + 1;

    ++g_call_index;
    if (const char* dc = std::getenv("NZ_LH_DUMP_CTX")) {
        // Per call: the 16 KB per-context MTF table + the ctx index, to diff against
        // a GDB dump of the original's object (table at obj+0x20, index at obj+4).
        char nm[512]; std::snprintf(nm, sizeof(nm), "%s.%d", dc, g_call_index);
        if (FILE* f = std::fopen(nm, "wb")) { std::fwrite(ctx_table, 1, kLzhdsCtxTableSize, f); std::fwrite(ctx_index, 4, 1, f); std::fclose(f); }
    }
    if (const char* dc = std::getenv("NZ_LH_DUMP_CTX")) {
        char nm[512]; std::snprintf(nm, sizeof(nm), "%s.tok.%d", dc, g_call_index);
        if (FILE* f = std::fopen(nm, "wb")) { std::fwrite(tokens, 4, static_cast<std::size_t>(num_tokens) * 3, f); std::fclose(f); }
        std::snprintf(nm, sizeof(nm), "%s.lit.%d", dc, g_call_index);
        if (FILE* f = std::fopen(nm, "wb")) { std::fwrite(litstream, 1, litstream_len, f); std::fclose(f); }
        std::snprintf(nm, sizeof(nm), "%s.rate.%d", dc, g_call_index);
        if (FILE* f = std::fopen(nm, "wb")) { std::fwrite(ratebits, 1, ratebits_len, f); std::fclose(f); }
    }
    if (TraceOn())
        std::fprintf(stderr, "[LH] call=%d enter: out_size=%u ntok=%u base=%u ring_size=%u ctx=%u litlen=%zu ratebits=%zu\n",
                     g_call_index, out_size, num_tokens, base, ring_size, *ctx_index,
                     litstream_len, ratebits_len);
    std::uint32_t ctx = *ctx_index;
    std::size_t lp = 0;
    std::uint32_t pos = 0;
    std::uint32_t ti = 0;
    const LzhdsHalfTable& HALF = HalfTable();

    auto ring_at = [&](std::uint32_t rel) -> std::uint8_t& {
        return ring[LzhdsRingReduce(base + rel, ring_size)];
    };
    // Predictor history `k` bytes back, modulo the ring: after a wrap the
    // original reads `out[pos - k]` below the buffer start, where FUN_080bd380
    // has just copied the ring's last 256 bytes -- i.e. the previous lap's tail.
    // On a true cold start the ring is all zeros, so this equals the old guard.
    auto ring_back = [&](std::uint32_t p, std::uint32_t k) -> std::uint8_t {
        if (k == 0u || k > ring_size) return 0u;
        const std::uint32_t idx = LzhdsRingReduce(base + p, ring_size);
        return ring[(idx >= k) ? (idx - k) : (idx + ring_size - k)];
    };

    while (pos < out_size) {
        std::uint32_t lit_run, sel, raw_len;
        if (ti >= num_tokens) {
            // Trailing literal flush: tokens legitimately run out ~= a few
            // bytes short of out_size for real `-cD` chunks (GDB-verified);
            // finish via literal decode alone, continuing the same model
            // state (no match follows).
            lit_run = out_size - pos;
            sel = 0xffffffffu;  // sentinel: never taken (sel>=4 branch computed but unused, loop breaks first)
            raw_len = 0;
        } else {
            lit_run = tokens[ti * 3 + 0];
            sel     = tokens[ti * 3 + 1];
            raw_len = tokens[ti * 3 + 2];
            ++ti;
        }
        std::uint32_t old_rm0 = rep[0];
        std::uint32_t offset = 0, mlen = 0;
        if (sel >= 4u) {
            offset = sel - 3u;
            rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = old_rm0; rep[0] = offset;
            mlen = raw_len + 4u + (offset > 0x3ffu) + (offset > 0x3fffu) + (offset > 0x7fffffu);
        } else {
            offset = rep[sel];
            mlen = raw_len + 2u;
            if (sel == 1u)      { rep[1] = rep[0]; }
            else if (sel == 2u) { rep[2] = rep[1]; rep[1] = rep[0]; }
            else if (sel == 3u) { rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; }
            rep[0] = offset;
        }

        std::uint32_t run = (lit_run < out_size - pos) ? lit_run : (out_size - pos);
        for (std::uint32_t i = 0; i < run; ++i) {
            std::uint32_t sym;
            bool did_emit = false;
            if (mode == 0u) {
                run_ctr -= 1u;
                if (run_ctr == 0u) {
                    // LAB_08098901: new model run.
                    run_ctr = LzhdsExpGolomb(rb);
                    run_ctr += 200u;
                    std::uint32_t neworder = LzhdsExpGolomb(rb) + 1u;
                    mode = neworder;
                    std::memset(pred, 0, sizeof(pred));
                    order = neworder;
                    std::uint8_t predicted = ring_back(pos, neworder);
                    std::uint32_t residual_byte = (lp < litstream_len) ? litstream[lp] : 0u;
                    std::uint32_t use_stage, next_stage;
                    if (stage < neworder) { use_stage = stage; next_stage = stage + 1u; }
                    else                  { use_stage = 0u;    next_stage = 1u; }
                    std::int32_t resid = HALF.v[residual_byte];
                    if (order < 5u) {
                        std::int32_t* s = pred + use_stage * 8;
                        std::int32_t tap = (s[3] * s[7] + s[2] * s[6] + s[0] * s[4] + 0x200 + s[1] * s[5]) >> 10;
                        std::int32_t corr = S8(S8(tap) + resid);
                        predicted = static_cast<std::uint8_t>(predicted + corr);
                        if (resid != 0) {
                            std::int32_t sgn = (resid < 0) ? -1 : 0;
                            for (int k = 0; k < 4; ++k) s[k] += ((s[4 + k] ^ sgn) - sgn);
                        }
                        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = corr;
                    } else {
                        predicted = static_cast<std::uint8_t>(predicted + resid);
                    }
                    stage = next_stage;
                    sym = EmitPredictorSymbol(ctx_table, ctx, predicted);
                    did_emit = true;
                    ctx = sym;
                    ++pos; ++lp;
                } else {
                    // fallthrough to raw fetch below (mode stays 0)
                }
            } else {
                run_ctr -= 1u;
                if (run_ctr == 0u) {
                    run_ctr = LzhdsExpGolomb(rb);
                    if (run_ctr != 0u) {
                        mode = 0u;
                        std::uint32_t b = (lp < litstream_len) ? litstream[lp] : 0u;
                        sym = RawDecodeAndUpdate(ctx_table, ctx, b);
                        did_emit = true;
                        ctx = sym;
                        ++pos; ++lp;
                    } else {
                        // LAB_08098901: new model run (reached from mid-stream too).
                        run_ctr = LzhdsExpGolomb(rb);
                        run_ctr += 200u;
                        std::uint32_t neworder = LzhdsExpGolomb(rb) + 1u;
                        mode = neworder;
                        std::memset(pred, 0, sizeof(pred));
                        order = neworder;
                        std::uint8_t predicted = ring_back(pos, neworder);
                        std::uint32_t residual_byte = (lp < litstream_len) ? litstream[lp] : 0u;
                        std::uint32_t use_stage, next_stage;
                        if (stage < neworder) { use_stage = stage; next_stage = stage + 1u; }
                        else                  { use_stage = 0u;    next_stage = 1u; }
                        std::int32_t resid = HALF.v[residual_byte];
                        if (order < 5u) {
                            std::int32_t* s = pred + use_stage * 8;
                            std::int32_t tap = (s[3] * s[7] + s[2] * s[6] + s[0] * s[4] + 0x200 + s[1] * s[5]) >> 10;
                            std::int32_t corr = S8(S8(tap) + resid);
                            predicted = static_cast<std::uint8_t>(predicted + corr);
                            if (resid != 0) {
                                std::int32_t sgn = (resid < 0) ? -1 : 0;
                                for (int k = 0; k < 4; ++k) s[k] += ((s[4 + k] ^ sgn) - sgn);
                            }
                            s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = corr;
                        } else {
                            predicted = static_cast<std::uint8_t>(predicted + resid);
                        }
                        stage = next_stage;
                        sym = EmitPredictorSymbol(ctx_table, ctx, predicted);
                        did_emit = true;
                        ctx = sym;
                        ++pos; ++lp;
                    }
                } else {
                    // Mid-run predictor byte.
                    std::uint8_t predicted = ring_back(pos, mode);
                    std::uint32_t residual_byte = (lp < litstream_len) ? litstream[lp] : 0u;
                    std::uint32_t use_stage, next_stage;
                    if (order <= stage) { use_stage = 0u; next_stage = 1u; }
                    else                { use_stage = stage; next_stage = stage + 1u; }
                    std::int32_t resid = HALF.v[residual_byte];
                    if (order < 5u) {
                        std::int32_t* s = pred + use_stage * 8;
                        std::int32_t tap = (s[3] * s[7] + s[2] * s[6] + s[0] * s[4] + 0x200 + s[1] * s[5]) >> 10;
                        std::int32_t corr = S8(S8(tap) + resid);
                        predicted = static_cast<std::uint8_t>(predicted + corr);
                        if (resid != 0) {
                            std::int32_t sgn = (resid < 0) ? -1 : 0;
                            for (int k = 0; k < 4; ++k) s[k] += ((s[4 + k] ^ sgn) - sgn);
                        }
                        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = corr;
                    } else {
                        predicted = static_cast<std::uint8_t>(predicted + resid);
                    }
                    stage = next_stage;
                    sym = EmitPredictorSymbol(ctx_table, ctx, predicted);
                    did_emit = true;
                    ctx = sym;
                    ++pos; ++lp;
                }
            }
            if (!did_emit) {
                // Raw mode processing (mode==0, run_ctr didn't hit zero this byte).
                std::uint32_t b = (lp < litstream_len) ? litstream[lp] : 0u;
                sym = RawDecodeAndUpdate(ctx_table, ctx, b);
                if (TraceOn())
                    std::fprintf(stderr, "[LH]   raw: ctx=%02x rank=%02x -> sym=%02x\n",
                                 ctx, b, sym);
                ctx = sym;
                mode = 0u;
                ++pos; ++lp;
            }
            if (TraceOn())
                std::fprintf(stderr, "[LH] lit pos=%u sym=%02x mode=%u order=%u stage=%u runctr=%u lp=%zu\n",
                             pos - 1u, sym, mode, order, stage, run_ctr, lp);
            ring_at(pos - 1u) = static_cast<std::uint8_t>(sym);
        }
        if (pos >= out_size) break;

        if (TraceOn()) std::fprintf(stderr, "[LH] match pos=%u off=%u mlen=%u sel=%u\n", pos, offset, mlen, sel);

        // Match copy (identical semantics to nz_cd_tokens.cpp's ReconstructRing;
        // only the match-length class thresholds differ from -cd, per
        // FUN_080982e0's own `uVar10 = uVar8-3; uVar13 = iVar11+4+
        // (0x3fff<uVar10)+(0x3ff<uVar10)+(0x7fffff<uVar10)`).
        if (offset == 0u || offset > ring_size) return 0u;
        std::uint32_t mcopy = (mlen < out_size - pos) ? mlen : (out_size - pos);
        // The source pointer is resolved ONCE, at the match start -- wrapped by
        // the capacity only if pos - offset is negative -- and the copy then
        // runs LINEARLY from there (FUN_080982e0: `src = base + ((pos-off) >>
        // 31 & cap) + (pos-off)`, then `rep movsb` / word copies). When a match
        // starts just before the ring end and extends past it, the original keeps
        // reading past `base + cap` into the slack the first wrap zeroed
        // (FUN_080bd380's memset covers cap - pos + 0x100 bytes; later overshoots
        // into it are undone by the guard word saved at out + size), so those
        // source bytes are ZERO -- not the bytes just written at the ring start,
        // which is what a per-byte modular copy reads. Seen on a 256-byte last
        // chunk that began exactly at a lap boundary: `match pos=1 off=3 len=4`
        // copied ring[65534], ring[65535], then 00 00 where the modular copy
        // produced out[0], out[1]. Byte-exact for the first 65540 bytes and wrong
        // from the fifth of that chunk.
        {
            const std::uint32_t wstart = LzhdsRingReduce(base + pos, ring_size);
            std::uint32_t si = (offset <= wstart) ? (wstart - offset) : (wstart + ring_size - offset);
            for (std::uint32_t k = 0; k < mcopy; ++k, ++si) {
                const std::uint32_t wi = LzhdsRingReduce(base + pos + k, ring_size);
                ring[wi] = (si < ring_size) ? ring[si] : 0u;
            }
        }
        pos += mcopy;

        // Partial predictor-history re-zero (once per TOKEN, not per byte):
        // FUN_080982e0's `if (local_58!=0) { local_5c%=local_58; if (local_58<5)
        // zero h0..h3 of stages 0..local_58-1 }` -- zeroes HISTORY only, not
        // weights.
        if (order != 0u) {
            // The stage index advances by the MATCH LENGTH before the modulo:
            // FUN_080982e0 does `local_5c = uVar13 + local_5c;` (uVar13 == the
            // match length) and only then `local_5c %= local_58`. This port
            // previously did the modulo alone, so every match left the stage
            // index behind by mlen and the error ACCUMULATED across matches --
            // which is why literal-only regions decoded byte-exact while files
            // with matches diverged at a content-dependent offset.
            stage = (stage + mlen) % order;
            if (order < 5u) {
                for (std::uint32_t st = 0; st < order; ++st) {
                    std::int32_t* s = pred + st * 8;
                    s[4] = s[5] = s[6] = s[7] = 0;
                }
            }
        }
        ctx = ring_at(pos - 1u);  // next context = last emitted byte value
    }

    *ctx_index = ctx;
    return pos;
}

}  // namespace cd
}  // namespace nzr
