// tt_flags & 0x40 -- the chess/PGN transform (TransformText_6, FUN_080a3000).
//
// Its own translation unit on purpose: the -cd text pipeline
// (nz_cd_tokens.cpp) needs it too, and nz_text_transform.cpp drags in the
// arithmetic-decoder tables that the -cd unit tests do not link.
//
// Format and provenance: see nz_text_transform.h.
#include "nz_text_transform.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

// ---------------------------------------------------------------------------
// tt_flags & 0x40: the chess/PGN transform (TransformText_6, FUN_080a3000).
// See nz_text_transform.h for the format. Every write is bounded; a would-be
// overrun returns 0 so the caller declines rather than trusting a partial
// buffer.
// ---------------------------------------------------------------------------
uint32_t NzTextTransform6(const uint8_t* in, uint32_t in_size,
                          uint8_t* out, uint32_t allocated) {
    if (in_size == 0u) return 0;

    // 128 slots, all seeded to the output start (the binary fills the whole
    // table with `out` before the loop, so a reference to a slot that was never
    // written copies from the beginning rather than reading uninitialised).
    uint8_t* table[128];
    for (uint32_t k = 0; k < 128u; ++k) table[k] = out;

    const uint8_t* ip = in;
    const uint8_t* const in_end = in + in_size;
    uint8_t* op = out;
    uint8_t* const out_end = out + allocated;
    uint32_t move_no = 1u;

    while (ip != in_end) {
        const uint8_t b = *ip++;

        if (b >= 0xBEu && b <= 0xFDu) {              // board square
            if (out_end - op < 2) return 0;
            const uint32_t i = static_cast<uint32_t>(b) - 0xBEu;
            *op++ = static_cast<uint8_t>(0x61u + (i & 7u));
            *op++ = static_cast<uint8_t>(0x31u + ((i >> 3) & 7u));
            continue;
        }
        if (b == 0xFEu) {                            // move number + '.'
            char digits[12];
            int n = 0;
            uint32_t v = move_no;
            do { digits[n++] = static_cast<char>('0' + (v % 10u)); v /= 10u; } while (v != 0u);
            if (out_end - op < static_cast<std::ptrdiff_t>(n) + 1) return 0;
            while (n-- > 0) *op++ = static_cast<uint8_t>(digits[n]);
            *op++ = 0x2Eu;
            ++move_no;
            continue;
        }
        if (b == 0x5Du) {                            // ']' ends a tag: reset
            if (op == out_end) return 0;
            *op++ = b;
            move_no = 1u;
            continue;
        }
        if (b >= 0x31u && b <= 0x38u) {              // literal number: resync
            // Pure LOOKAHEAD -- the input cursor does not move and the digits
            // are emitted one at a time by this same loop on later iterations.
            uint32_t v = static_cast<uint32_t>(b) - 0x30u;
            uint32_t k = 0;
            uint8_t last = 0;
            while (k < 10u && ip + k != in_end) {
                last = ip[k];
                if (last < 0x30u || last > 0x39u) break;
                v = v * 10u + (static_cast<uint32_t>(last) - 0x30u);
                ++k;
            }
            if (last == 0x2Eu) move_no = v + 1u;
            if (op == out_end) return 0;
            *op++ = b;
            continue;
        }
        if (b == 0xFFu) {                            // back-reference / escape
            if (ip == in_end) return 0;
            const uint8_t arg = *ip++;
            if (arg > 0x7Fu) {                       // escape for a raw byte
                if (op == out_end) return 0;
                *op++ = arg;
                continue;
            }
            if (op == out_end) return 0;
            *op++ = 0x5Bu;                           // '['
            const uint8_t* src = table[arg];
            const uint32_t set = arg & 0xFEu;        // way 0 of this set
            table[set + 1u] = table[set];
            table[set] = op;
            // Copy the cached line up to and including its ']'.
            for (;;) {
                if (src >= op || op == out_end) return 0;
                const uint8_t c = *src++;
                *op++ = c;
                if (c == 0x5Du) break;
            }
            move_no = 1u;
            continue;
        }
        if (b == 0x5Bu) {                            // literal '[': cache it
            if (ip + 1 >= in_end) {                  // needs two lookahead bytes
                if (op == out_end) return 0;
                *op++ = b;
                continue;
            }
            const uint32_t c0 = ip[0];
            const uint32_t c1 = ip[1];
            const uint32_t set = ((((c0 + 15u) & 15u) * 4u) + (c1 & 3u)) * 2u;
            if (out_end - op < 3) return 0;
            *op++ = b;
            table[set + 1u] = table[set];
            table[set] = op;                         // the byte just past '['
            // The two hashed bytes are copied RAW and consumed (FUN_080a3000:
            // `pbVar7[1] = c0; pbVar7[2] = c1; local_238 = pbVar11 + 3`). Feeding
            // them back through the loop looked equivalent on chess text, but on
            // wiki markup ("[[Special:...") the second '[' then caches a second
            // line and every later back-reference in that set resolves to the
            // wrong line (MediaWiki SQL dump under -cd, 2026-09-03 sweep).
            *op++ = static_cast<uint8_t>(c0);
            *op++ = static_cast<uint8_t>(c1);
            ip += 2;
            continue;
        }
        if (op == out_end) return 0;
        *op++ = b;
    }
    return static_cast<uint32_t>(op - out);
}
