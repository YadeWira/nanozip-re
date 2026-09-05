// nz_lzpf_encoder.cpp -- see the header. Function names in comments are the
// original's (linux32/nz); the decompiles live in
// ~/.cache/nzre_tools/encode/decomp/lzpf_encoder_*.c.
#include "nz_lzpf_encoder.h"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace nzr::lzpf_enc {

namespace {

inline std::uint32_t LoadU32(const std::uint8_t* p) {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
inline std::uint16_t LoadU16(const std::uint8_t* p) {
    std::uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}
inline void StoreU32(std::uint8_t* p, std::uint32_t v) { std::memcpy(p, &v, 4); }

}  // namespace

// FUN_080b6a00 / FUN_080b6c60: the window is capacity + 0x9004 bytes (the wrap
// memset reaches 32 KB past the capacity), the cursor STARTS AT 4 with the first
// four bytes zeroed, and every hash entry starts at 3 -- so an unwritten slot
// points at base + 3, a zero byte inside that head padding (the decoder's
// "window_left_pad = 4, initial cursor 4, init value 3" seen from the writer).
void State::Init(bool vb, std::size_t cap) {
    variant_b = vb;
    capacity = cap;
    window_alloc.assign(cap + 0x9004u, 0u);
    window = window_alloc.data();
    cursor = 4;
    dirty = true;
    if (variant_b) {
        hash.assign(std::size_t{0x1000000u}, 3);
        hash_bytes_b.assign(std::size_t{0x8000u}, 0u);
    } else {
        hash.assign(std::size_t{0x2000u} + 0x80000u, 3);
        hash_bytes_b.clear();
    }
    last_long = 0;
    exe_pos = 4;
    literal_bytes = 0;
    audio_pending = 0;
    probe = AudioProbe{};
    audio.Configure(variant_b ? 8u : 4u);
}

void State::Wrap() {
    if (capacity < cursor + 0x8000u) {
        if (dirty) {
            dirty = false;
            std::memset(window + cursor, 0, capacity + 0x8000u - cursor);
        }
        cursor = 0;
    }
}

void State::BackfillDense(std::size_t len) {
    const std::size_t begin = cursor - len, end = cursor;
    if (!variant_b) {
        for (std::size_t p = begin; p < end; ++p) hash[LoadU32(window + p - 2) & 0x1fffu] = static_cast<std::int32_t>(p);
    } else {
        for (std::size_t p = begin; p < end; ++p) hash[LoadU32(window + p - 3) & 0xffffffu] = static_cast<std::int32_t>(p);
        std::fill(hash_bytes_b.begin(), hash_bytes_b.end(), 0u);   // FUN_080b6c20
    }
}

void State::BackfillSparse(std::size_t len) {
    const std::size_t begin = cursor - len;
    const std::size_t stop = begin + len - 100u;   // the original's `uVar4 - 100 + len`, unsigned
    if (!variant_b) {
        for (std::size_t p = begin; p < stop; p += 0x65u) hash[LoadU32(window + p - 2) & 0x1fffu] = static_cast<std::int32_t>(p);
    } else {
        for (std::size_t p = begin; p < stop; p += 0x65u) hash[LoadU32(window + p - 3) & 0xffffffu] = static_cast<std::int32_t>(p);
        std::fill(hash_bytes_b.begin(), hash_bytes_b.end(), 0u);
    }
}

// FUN_0805a190. Pointers mirror the decompile: `block` walks the input inside the
// window, `end` its end, `win_end` the window's end, `out` the bytecode cursor.
std::size_t LzParse(State& st, std::size_t pos, std::size_t len, std::vector<std::uint8_t>& out) {
    const std::size_t start_size = out.size();
    // the bytecode can exceed the block (escapes, long-match records): 9 bytes per input byte is a safe bound
    out.resize(start_size + len * 9u + 16u);
    std::uint8_t* o = out.data() + start_size;
    std::uint8_t* const base = st.window;
    const std::uint8_t* block = base + pos;
    const std::uint8_t* const end = block + len;
    const std::uint8_t* const win_end = base + st.capacity;
    std::int32_t* const hash = st.hash.data();
    std::int32_t last_long = st.last_long;

    // The head of the block may continue the previous block's long match.
    if (last_long != 0) {
        const std::uint8_t* cand = block + last_long;
        if ((end <= cand || cand < block) && cand < win_end && base <= cand && *cand == *block && len != 0) {
            std::size_t n = 0, k = 0;
            do {
                k = n;
                n = k + 1;
                if (len <= n) break;
            } while (cand[n] == block[n]);
            if (n > 7u) {
                const std::uint32_t l = static_cast<std::uint32_t>(k - 7u);
                o[0] = 0xf7u;
                o[1] = static_cast<std::uint8_t>(l >> 8u);
                o[2] = static_cast<std::uint8_t>(l);
                StoreU32(o + 3, static_cast<std::uint32_t>(cand - base));
                o += 7;
                block += n;
            }
        }
    }

    if (!st.variant_b) {
        std::ptrdiff_t prev_dest = -1;                  // pbVar12: source - position of the last match
        std::uint32_t h = LoadU32(block - 2);
        while (block < end) {
            std::int32_t* slot = &hash[h & 0x1fffu];
            const std::uint8_t* cand = base + *slot;
            *slot = static_cast<std::int32_t>(block - base);
            const std::uint8_t c = *block;
            std::uint32_t sym = c;
            std::uint8_t* op = o;
            const std::uint8_t* next;
            if (c == *cand && (end <= cand || cand < block)) {
                prev_dest = cand - block;
                next = block + 1;
                sym = 0xffu;                                // a 1-byte match
                if (block[1] == cand[1]) {
                    const std::uint8_t* p = cand + 2;
                    const std::uint8_t* q = block + 2;
                    const std::uint8_t* w;                   // the word where they differ
                    for (;;) {
                        w = q;
                        if (end <= w) { q = end; goto matched; }
                        const std::uint32_t x = LoadU32(p) ^ LoadU32(w);
                        p += 4;
                        q = w + 4;
                        if (x != 0u) {
                            const bool lo_equal = (x & 0xffffu) == 0u;
                            q = w + ((((x >> (lo_equal ? 16u : 0u)) & 0xffu) == 0u) ? 1u : 0u) + (lo_equal ? 2u : 0u);
                            break;
                        }
                    }
                    if (end < q) q = end;
                matched:
                    const std::size_t mlen = static_cast<std::size_t>(q - block);
                    next = q;
                    if (mlen > 7u) {
                        const std::uint32_t l8 = static_cast<std::uint32_t>(mlen - 8u);
                        o[0] = 0xf8u;
                        sym = static_cast<std::uint8_t>(~l8);
                        op = o + 1;
                        if (l8 > 0x7fu) {
                            o[1] = static_cast<std::uint8_t>(l8 >> 8u);
                            op = o + 2;
                            last_long = static_cast<std::int32_t>(prev_dest);
                        }
                    } else {
                        sym = static_cast<std::uint8_t>(0u - mlen);        // 0xf9..0xfe: ~opcode + 1 = length
                    }
                }
            } else if (block[prev_dest] == c) {
                next = block + 1;
                sym = 0xf6u;
            } else {
                next = block + 1;
                if (c > 0xf5u) {
                    o[0] = 0xf7u;
                    op = o + 1;
                    // Only at a 4-aligned OUTPUT position: try a long match keyed on 16 bytes
                    if ((reinterpret_cast<std::uintptr_t>(op) & 3u) == 0u) {
                        *op = c;
                        const std::uint32_t k16 = ((LoadU32(block + 1) + LoadU32(block + 5)) - LoadU32(block + 9)) ^ LoadU32(block + 13);
                        std::int32_t* slot2 = &hash[((k16 ^ (k16 >> 19u)) & 0x7ffffu) + 0x2000u];
                        const std::uint8_t* cand2 = base + *slot2;
                        *slot2 = static_cast<std::int32_t>(next - base);
                        if ((cand2 < next || end <= cand2) && base <= cand2 && cand2 < win_end) {
                            const std::uint8_t* p = cand2 - 1;
                            const std::uint8_t* b = block;
                            do {
                                ++b;
                                ++p;
                                if (end <= b) break;
                            } while (*p == *b);
                            const std::size_t n = static_cast<std::size_t>(b - next);
                            if (n > 7u) {
                                last_long = static_cast<std::int32_t>(cand2 - next);
                                const std::uint32_t l8 = static_cast<std::uint32_t>(n - 8u);
                                o[2] = 0xf7u;
                                o[3] = static_cast<std::uint8_t>(l8 >> 8u);
                                o[4] = static_cast<std::uint8_t>(l8);
                                StoreU32(o + 5, static_cast<std::uint32_t>(cand2 - base));
                                op = o + 8;
                                next = next + n;
                            }
                        }
                        sym = *op;   // the byte already there (c, or the offset's last byte)
                    }
                }
            }
            h = LoadU32(next - 2);
            *op = static_cast<std::uint8_t>(sym);
            o = op + 1;
            block = next;
        }
    } else {
        std::ptrdiff_t prev_dest = -1;
        std::uint8_t* const bytes_b = st.hash_bytes_b.data();
        std::uint32_t h = LoadU32(block - 3);
        while (block < end) {
            std::int32_t* slot = &hash[h & 0xffffffu];
            const std::uint8_t* cand = base + *slot;
            *slot = static_cast<std::int32_t>(block - base);
            const std::uint8_t c = *block;
            std::uint32_t sym = c;
            std::uint8_t* op = o;
            const std::uint8_t* next;
            if (c == *cand && (end <= cand || cand < block)) {
                prev_dest = cand - block;
                next = block + 1;
                sym = 0xffu;
                if (block[1] == cand[1]) {
                    const std::uint8_t* p = cand + 2;
                    const std::uint8_t* q = block + 2;
                    const std::uint8_t* w;
                    for (;;) {
                        w = q;
                        if (end <= w) { q = end; goto matched_b; }
                        const std::uint32_t x = LoadU32(p) ^ LoadU32(w);
                        p += 4;
                        q = w + 4;
                        if (x != 0u) {
                            const bool lo_equal = (x & 0xffffu) == 0u;
                            q = w + ((((x >> (lo_equal ? 16u : 0u)) & 0xffu) == 0u) ? 1u : 0u) + (lo_equal ? 2u : 0u);
                            break;
                        }
                    }
                    if (end < q) q = end;
                matched_b:
                    const std::size_t mlen = static_cast<std::size_t>(q - block);
                    next = q;
                    if (mlen > 7u) {
                        const std::uint32_t l8 = static_cast<std::uint32_t>(mlen - 8u);
                        o[0] = 0xf8u;
                        sym = static_cast<std::uint8_t>(~l8);
                        op = o + 1;
                        if (l8 > 0x7fu) {
                            o[1] = static_cast<std::uint8_t>(l8 >> 8u);
                            op = o + 2;
                            last_long = static_cast<std::int32_t>(prev_dest);
                        }
                    } else {
                        sym = static_cast<std::uint8_t>(0u - mlen);
                    }
                }
            } else if (block[prev_dest] == c) {
                next = block + 1;
                sym = 0xf6u;
            } else {
                const std::uint32_t idx = LoadU16(block - 2) & 0x1fffu;
                const std::uint8_t predicted = bytes_b[idx];
                bytes_b[idx] = c;
                next = block + 1;
                if (c == predicted) {
                    sym = 0xf5u;
                } else if (c > 0xf4u) {
                    o[0] = 0xf7u;
                    op = o + 1;
                }
            }
            h = LoadU32(next - 3);
            *op = static_cast<std::uint8_t>(sym);
            o = op + 1;
            block = next;
        }
    }
    st.last_long = last_long;
    const std::size_t produced = static_cast<std::size_t>(o - (out.data() + start_size));
    out.resize(start_size + produced);
    return produced;
}

// FUN_08059cb0 (regparm: out, size, flags, image).
void WriteBlockHeader(std::vector<std::uint8_t>& out, std::uint32_t size, std::uint32_t flags, std::uint32_t image) {
    std::uint32_t v;
    if (flags == 4u) {
        v = (size == 0x8000u ? 0u : size) * 16u + 4u + image * 8u;
    } else {
        v = flags + (size == 0x8000u ? 0u : size) * 8u;
    }
    if (v < 0x80u) { out.push_back(static_cast<std::uint8_t>(v)); return; }
    const std::uint32_t u = (v >> 7u) - 1u;
    out.push_back(static_cast<std::uint8_t>(v | 0x80u));
    if (u > 0x7fu) {
        out.push_back(static_cast<std::uint8_t>(u | 0x80u));
        out.push_back(static_cast<std::uint8_t>((u >> 7u) - 1u));
    } else {
        out.push_back(static_cast<std::uint8_t>(u));
    }
}

// FUN_080bd170: the canonical order -- by code length descending, ties by symbol
// descending (a radix sort on (length << 8) | symbol read out backwards).
static void CanonicalOrder(const std::uint8_t* lengths, std::uint8_t* syms, std::size_t n) {
    std::stable_sort(syms, syms + n, [lengths](std::uint8_t a, std::uint8_t b) {
        if (lengths[a] != lengths[b]) return lengths[a] > lengths[b];
        return a > b;
    });
}

// FUN_0805cbe0. `codes[256]` receives the canonical code of every used symbol
// (always below 256: the assignment starts at 0 from the longest length).
std::size_t BuildCodeLengths(const std::uint32_t* hist, std::uint32_t max_len, std::uint8_t* lengths, std::uint8_t* codes) {
    std::uint8_t syms[256 + 12];
    std::size_t n = 0;
    for (std::uint32_t s = 0; s < 256u; ++s) if (hist[s] != 0u) syms[n++] = static_cast<std::uint8_t>(s);
    std::memset(lengths, 0, 256);
    if (n == 0u) return 0u;
    // FUN_0805d080: a stable LSD radix sort on frequency (the low byte of the key
    // is the symbol and stays in ascending order): ascending frequency, ties by
    // ascending symbol.
    std::stable_sort(syms, syms + n, [hist](std::uint8_t a, std::uint8_t b) { return hist[a] < hist[b]; });

    if (n > 2u) {
        // local_920 (a[0..n]) and local_51c (f[0..n-1]) of the decompile, indices kept.
        std::uint32_t a[257 + 8];
        std::uint32_t f[256 + 8];
        for (std::size_t i = 0; i < n; ++i) { a[i + 1] = hist[syms[i]]; f[i] = hist[syms[i]]; }
        a[0] = static_cast<std::uint32_t>(n - 1u);
        for (;;) {
            // LAB_0805cd39: the in-place tree (Moffat/Katajainen), transcribed.
            std::uint32_t r = 1u, s = 2u, t = 0u;
            std::uint32_t w = a[2] + a[1];
            a[1] = w;
            for (;;) {
                std::uint32_t leaf;
                if (s < n && (leaf = a[s + 1]) <= w) {
                    ++s;
                    a[r + 1] = leaf;
                    if (n <= s) {
                        a[r + 1] = leaf + a[t + 1]; a[t + 1] = r; ++t;                   // LAB_0805cd6a
                    } else if (t < r) {                                                    // LAB_0805cd9a
                        if (a[t + 1] < a[s + 1]) { a[r + 1] = leaf + a[t + 1]; a[t + 1] = r; ++t; }
                        else { const std::uint32_t v = a[s + 1]; ++s; a[r + 1] = leaf + v; }
                    } else {
                        const std::uint32_t v = a[s + 1]; ++s; a[r + 1] = leaf + v;
                    }
                } else {
                    a[r + 1] = w; a[t + 1] = r; ++t;
                    leaf = a[r + 1];
                    if (s < n) {                                                            // LAB_0805cd9a
                        if (t < r) {
                            if (a[t + 1] < a[s + 1]) { a[r + 1] = leaf + a[t + 1]; a[t + 1] = r; ++t; }
                            else { const std::uint32_t v = a[s + 1]; ++s; a[r + 1] = leaf + v; }
                        } else {
                            const std::uint32_t v = a[s + 1]; ++s; a[r + 1] = leaf + v;
                        }
                    } else {
                        a[r + 1] = leaf + a[t + 1]; a[t + 1] = r; ++t;                       // LAB_0805cd6a
                    }
                }
                if (r == n - 2u) break;
                w = a[t + 1];
                ++r;
            }
            // LAB_0805cdd0: depths of the internal nodes
            a[n - 1u] = 0u;
            for (std::int32_t i = static_cast<std::int32_t>(n) - 3; i >= 0; --i) a[i + 1] = a[a[i + 1] + 1u] + 1u;
            if (a[1] + 1u <= max_len) break;
            // too deep: scale the frequencies and rebuild (the original's byte shift)
            const std::uint32_t shift = ((a[1] + 1u) - max_len) & 0xffu;
            for (std::size_t i = 0; i < n; ++i) {
                const std::uint32_t v = (f[i] + (1u << (shift & 31u)) - 1u) >> (shift & 31u);
                a[i + 1] = v; f[i] = v;
            }
        }
        // LAB_0805ce77: leaf depths, deepest first, from the node depths
        {
            std::uint32_t depth = 0u, avail = 1u, k = a[0], leaves = static_cast<std::uint32_t>(n);
            for (;;) {
                std::uint32_t internal = 0u, twice = 0u;
                if (k != 0u && a[k] == depth) {
                    const std::uint32_t d = a[k];
                    do { --k; ++internal; if (k == 0u) break; } while (a[k] == d);
                    twice = internal * 2u;
                }
                if (internal < avail) {
                    std::uint32_t idx = leaves, cnt = avail;
                    do { --cnt; a[idx] = depth; --idx; } while (cnt != internal);
                    leaves = (leaves - avail) + cnt;
                }
                if (twice == 0u) break;
                ++depth;
                avail = twice;
            }
        }
        for (std::size_t k = n; k-- > 0;) lengths[syms[k]] = static_cast<std::uint8_t>(a[k + 1]);
    } else if (n == 1u) {
        lengths[syms[0]] = 1u;
    } else {
        lengths[syms[0]] = 1u;
        lengths[syms[1]] = 1u;
    }
    CanonicalOrder(lengths, syms, n);
    // the canonical codes: the first (longest) symbol gets 0, then code = (prev + 1) >> (prev_len - len)
    std::uint32_t next = 0u;
    std::uint32_t prev_len = lengths[syms[0]];
    for (std::size_t k = 0; k < n; ++k) {
        const std::uint32_t l = lengths[syms[k]];
        const std::uint32_t code = next >> ((prev_len - l) & 0x1fu);
        next = code + 1u;
        codes[syms[k]] = static_cast<std::uint8_t>(code);
        prev_len = l;
    }
    return n;
}

// ---------------------------------------------------------------------------
// The Huffman side stream ("arith" in the decoder's vocabulary).
// ---------------------------------------------------------------------------

// DAT_081b42f0: the mask table, [0] = 1 (!), [k] = 2^k - 1 (0x080c034f).
std::uint32_t MaskBits(std::uint32_t k) {
    if (k == 0u) return 1u;
    if (k >= 32u) return 0xffffffffu;
    return (1u << k) - 1u;
}

// FUN_0805c980: the symbols. The original writes whole big-endian words once its
// cursor is 4-byte ALIGNED IN MEMORY and single bytes until then; the bit
// stream is the same either way, only where an overflow is detected differs, so
// `align` (the cursor's address modulo 4 in the original) is kept.
static void WriteSymbols(BitWriter& w, const std::uint8_t* src, std::size_t n, const std::uint8_t* codes, const std::uint8_t* lengths, std::uintptr_t align) {
    const std::uint8_t* const src_end = src + n;
    const auto misaligned = [&]() { return ((static_cast<std::uintptr_t>(w.cur - w.base) + align) & 3u) != 0u; };
    if (n != 0u) {
        while (misaligned()) {
            if (w.nbits > 7u) {
                w.nbits -= 8u;
                if (w.cur < w.end) *w.cur++ = static_cast<std::uint8_t>(w.bitbuf >> (w.nbits & 31u));
            }
            if (!misaligned()) break;
            const std::uint8_t c = *src++;
            w.Put(codes[c], lengths[c]);
            if (src == src_end) break;
        }
    }
    // the word path (the inlined loop of FUN_0805c980)
    while (src != src_end) {
        const std::uint8_t c = *src++;
        const std::uint32_t len = lengths[c], code = codes[c];
        const std::uint32_t total = w.nbits + len;
        if (total < 0x21u) {
            w.bitbuf = (w.bitbuf << (len & 31u)) | code;
            w.nbits = total;
        } else {
            const std::uint32_t room = 32u - w.nbits;
            const std::uint32_t keep = len - room;
            const std::uint32_t word = (w.bitbuf << (room & 31u)) | (code >> (keep & 31u));
            w.nbits = keep;
            if (w.end < w.cur + 4) { w.cur = w.end; w.bitbuf = code; break; }
            w.cur[0] = static_cast<std::uint8_t>(word >> 24u); w.cur[1] = static_cast<std::uint8_t>(word >> 16u);
            w.cur[2] = static_cast<std::uint8_t>(word >> 8u);  w.cur[3] = static_cast<std::uint8_t>(word);
            w.cur += 4;
            w.bitbuf = code;
        }
    }
}

// FUN_08074b10: the code lengths. The four transmission modes are simulated at
// once (a histogram and a score each), the best scoring mode is chosen, the
// meta code built over its symbols, and the recorded command list replayed.
static void WriteCodeLengths(BitWriter& w, const std::uint8_t* lengths, std::uint32_t n, std::uint32_t max_len) {
    std::uint32_t hist[4][256];
    std::memset(hist, 0, sizeof(hist));
    std::uint32_t score[4] = {0, 0, 0, 0};
    std::uint32_t kraft[33]; kraft[0] = 0xffffffffu;
    for (std::uint32_t L = 1; L <= max_len; ++L) kraft[L] = 1u << L;
    std::uint32_t cc[33]; std::memset(cc, 0, sizeof(cc));
    std::uint8_t rec[256 * 4 + 16];          // per emitted symbol: its symbol under each mode
    std::uint8_t cmd[1024 + 16];             // 0 = emit next record; k > 0 = k raw bits, value follows; 0xff = end
    std::size_t nrec = 0, ncmd = 0;
    std::uint32_t total = 0, maxlen = 0, prev = 0, run = 0, pending = 0;
    std::uint32_t remaining = n;
    const std::uint8_t* p = lengths;
    const auto recompute = [&]() {
        kraft[1] = 2u - cc[1];
        std::uint32_t pw = 4u, acc = cc[1];
        for (std::uint32_t L = 2; L <= max_len; ++L) {
            const std::uint32_t neg = 0u - 2u * acc;
            acc = 2u * acc + cc[L];
            kraft[L] = (pw - cc[L]) + neg;
            pw *= 2u;
        }
    };
    const auto trim = [&](std::uint32_t last) {
        std::uint32_t carry = cc[last];
        for (std::uint32_t L = last - 1u; L != 0u; --L) {
            const std::uint32_t half = (carry + 1u) >> 1u;
            kraft[L] -= half;
            carry = half + cc[L];
        }
    };
    const auto bump = [&](std::uint32_t v, std::uint32_t m1, std::uint32_t m2, std::uint32_t m3) {
        score[0] += ++hist[0][v]; score[1] += ++hist[1][m1]; score[2] += ++hist[2][m2]; score[3] += ++hist[3][m3];
        rec[nrec * 4 + 0] = static_cast<std::uint8_t>(v); rec[nrec * 4 + 1] = static_cast<std::uint8_t>(m1);
        rec[nrec * 4 + 2] = static_cast<std::uint8_t>(m2); rec[nrec * 4 + 3] = static_cast<std::uint8_t>(m3);
        ++nrec;
        cmd[ncmd++] = 0u;
        if (pending != 0u) { cmd[ncmd++] = static_cast<std::uint8_t>(pending); cmd[ncmd++] = static_cast<std::uint8_t>(pending >> 8u); pending = 0u; }
    };
    bool exhausted = false;
    while (remaining != 0u) {
        const std::uint32_t v = *p;
        if (v == prev) {
            ++run;
            bump(v, 0u, 0u, 0u);
        } else {
            const std::uint32_t m1 = v + (v <= prev ? 1u : 0u);
            const std::uint32_t m2 = (v == 0u) ? prev : v;
            const std::uint32_t diff = v - prev;
            const std::uint32_t m3 = ((static_cast<std::int32_t>(diff) >> 31) & (max_len + 1u)) + diff;
            run = 0u;
            bump(v, m1, m2, m3);
        }
        if (v != 0u) {
            ++cc[v]; ++total;
            if (v > maxlen) maxlen = v;
            recompute();
        }
        if (kraft[maxlen] == 0u) { exhausted = true; break; }
        prev = v;
        if (run != 3u) { --remaining; ++p; continue; }
        // three repeats in a row: the run-length escape (the decoder's mirror)
        if (maxlen > 1u) trim(maxlen);
        const std::uint32_t rest = remaining - 1u;
        std::uint32_t rl_max = kraft[v];
        if (rest < rl_max) rl_max = rest;
        pending = 0u;
        run = 3u;
        if (rl_max == 0u) { remaining = rest; ++p; continue; }
        // the run that follows
        std::uint32_t r = 0u;
        if (rest != 0u && p[1] == v) {
            r = 0u;
            for (;;) {
                const std::uint32_t nx = r + 1u;
                if (rest <= nx) { r = nx; break; }
                r = nx;
                if (p[nx + 1u] != v) break;
            }
        }
        run = r;
        std::uint32_t doublings = 0u;
        if (rl_max < 2u) {
            cmd[ncmd++] = 1u; cmd[ncmd++] = static_cast<std::uint8_t>(run & MaskBits(0u));
        } else {
            std::uint32_t half = run >> 1u;
            if (half == 0u) {
                pending = 1u;
            } else {
                bool emitted_bits = false;
                do {
                    ++doublings;
                    // an "extend" symbol: the same value again, under every mode the zero symbol
                    score[0] += ++hist[0][v]; score[1] += ++hist[1][0]; score[2] += ++hist[2][0]; score[3] += ++hist[3][0];
                    rec[nrec * 4 + 0] = static_cast<std::uint8_t>(v); rec[nrec * 4 + 1] = 0u; rec[nrec * 4 + 2] = 0u; rec[nrec * 4 + 3] = 0u;
                    ++nrec;
                    cmd[ncmd++] = 0u;
                    if (rl_max < (2u << (doublings & 31u))) {
                        cmd[ncmd++] = static_cast<std::uint8_t>(doublings); cmd[ncmd++] = static_cast<std::uint8_t>(run & MaskBits(doublings));
                        emitted_bits = true;
                        break;
                    }
                    half >>= 1u;
                } while (half != 0u);
                if (!emitted_bits) pending = doublings;
            }
            if (pending != 0u) pending = ((run & MaskBits(doublings)) << 8u) + pending;
        }
        if (v != 0u) {
            cc[v] += run; total += run;
            if (v > maxlen) maxlen = v;
            recompute();
        }
        if (kraft[maxlen] == 0u) { exhausted = true; break; }
        p += run + 1u;
        remaining = rest - run;
        run = 3u;   // stays armed until a different value resets it (the decoder's local_3cc = 0 happens after its run)
        run = 0u;
    }
    (void)exhausted;
    if (pending != 0u) { cmd[ncmd++] = static_cast<std::uint8_t>(pending); cmd[ncmd++] = static_cast<std::uint8_t>(pending >> 8u); pending = 0u; }
    cmd[ncmd++] = 0xffu;

    // the mode: the highest score, ties to the lower mode (0 before 1 only when 0 >= 1)
    std::uint32_t mode = (score[0] < score[1]) ? 1u : 0u;
    std::uint32_t best = score[mode];
    if (best < score[2]) { mode = 2u; best = score[2]; }
    if (best < score[3]) { mode = 3u; }
    std::uint8_t meta_len[256], meta_code[256];
    BuildCodeLengths(hist[mode], 6u, meta_len, meta_code);
    w.Put(mode, 2u);
    // pass 1: the meta lengths with the Kraft-bounded bisect (ReadCodeLengthsPass1 mirrored)
    {
        std::uint32_t k2[33]; k2[0] = 0xffffffffu; k2[1] = 2u; k2[2] = 4u; k2[3] = 8u; k2[4] = 16u; k2[5] = 32u; k2[6] = 64u;
        std::uint32_t c2[33]; std::memset(c2, 0, sizeof(c2));
        std::uint32_t tot2 = 0u, max2 = 0u, first_avail = 1u;
        const std::uint8_t* ml = meta_len;
        bool stopped = false;
        for (std::uint32_t i = 0; i < max_len; ++i, ++ml) {
            const std::uint32_t cur_first = first_avail;
            std::uint32_t v = *ml;
            if (v != 0u) {
                ++c2[v]; ++tot2;
                if (v > max2) max2 = v;
                k2[1] = 2u - c2[1];
                std::uint32_t pw = 4u, acc = c2[1];
                for (std::uint32_t L = 2; L <= 6u; ++L) { const std::uint32_t neg = 0u - 2u * acc; acc = 2u * acc + c2[L]; k2[L] = (pw - c2[L]) + neg; pw *= 2u; }
                if (max2 > 1u) {
                    std::uint32_t carry = c2[max2];
                    for (std::uint32_t L = max2 - 1u; L != 0u; --L) { const std::uint32_t half = (carry + 1u) >> 1u; k2[L] -= half; carry = half + c2[L]; }
                    first_avail = 0u;
                    do { ++first_avail; } while (first_avail < max2 && k2[first_avail] == 0u);
                }
            }
            std::uint32_t hi = 7u;
            if (cur_first != 1u) {
                if (v != 0u) v = (v - cur_first) + 1u;
                hi = 8u - cur_first;
            }
            w.PutBisect(v, hi);
            if (k2[max2] == 0u) { stopped = true; break; }
        }
        if (!stopped && tot2 == 1u) w.Put(meta_len[max_len] != 0u ? 1u : 0u, 1u);
    }
    // replay
    {
        const std::uint8_t* r = rec + mode;
        for (std::size_t i = 0; i < ncmd;) {
            const std::uint8_t c = cmd[i];
            if (c == 0xffu) break;
            if (c == 0u) {
                const std::uint8_t sym = *r;
                r += 4;
                // the inlined word writer of FUN_08074b10 (same stream as Put)
                w.Put(meta_code[sym], meta_len[sym]);
                ++i;
            } else {
                w.Put(cmd[i + 1u], c);
                i += 2;
            }
        }
    }
}

// FUN_080757d0. `align` = the output pointer's address modulo 4 in the original
// (see WriteSymbols); the header and the u16 count precede this stream, so the
// caller passes the alignment of `out`'s first byte.
std::size_t EncodeArithAt(const std::uint8_t* src, std::size_t n, std::uint8_t* out, std::size_t limit, std::uintptr_t align) {
    if (n == 0u) return 0u;
    std::uint32_t hist[256];
    std::memset(hist, 0, sizeof(hist));
    for (std::size_t i = 0; i < n; ++i) ++hist[src[i]];
    std::uint8_t lengths[256], codes[256];
    const std::size_t nsyms = BuildCodeLengths(hist, 12u, lengths, codes);
    std::uint32_t bits = 0;
    for (std::uint32_t s = 0; s < 256u; ++s) bits += static_cast<std::uint32_t>(lengths[s]) * hist[s];
    if ((nsyms >> 1u) + (bits >> 3u) >= limit) return 0u;
    BitWriter w;
    w.base = out; w.end = out + limit; w.cur = out; w.bitbuf = 0; w.nbits = 0;
    WriteCodeLengths(w, lengths, 256u, 12u);
    if (limit <= static_cast<std::size_t>(w.cur - w.base) + ((w.nbits + 7u) >> 3u) + (bits >> 3u)) return 0u;
    WriteSymbols(w, src, n, codes, lengths, align);
    w.Flush();
    if (w.end <= w.cur) return 0u;
    return static_cast<std::size_t>(w.cur - w.base) + ((w.nbits + 7u) >> 3u);
}

std::size_t EncodeArith(const std::uint8_t* src, std::size_t n, std::size_t limit, std::vector<std::uint8_t>& out) {
    const std::size_t start = out.size();
    out.resize(start + limit + 8u);
    const std::size_t got = EncodeArithAt(src, n, out.data() + start, limit, 0u);
    out.resize(start + got);
    return got;
}

// FUN_08059dd0: the "distinct 15-bit pair hashes" score of a block -- 8 windows
// of 512 bytes spread over the block, each new hash counted; (count*256)>>12.
// Blocks under 4096 bytes score 0 (under 8 bytes: their length).
std::uint32_t Score(const std::uint8_t* p, std::uint32_t len) {
    if (len < 8u) return len;
    if (len < 0x1000u) return 0u;
    std::uint8_t seen[4096];
    std::memset(seen, 0, sizeof(seen));
    std::uint32_t h = 0u, count = 0u;
    const std::uint8_t* q = p;
    for (int w = 8; w != 0; --w) {
        for (int i = 0; i < 0x200; ++i) {
            const std::uint8_t c = q[i];
            h = (h << 8u) ^ c;
            const std::uint32_t bit = c & 7u;
            const std::uint32_t idx = (h & 0x7fffu) >> 3u;
            count += ((seen[idx] >> bit) & 1u) ^ 1u;
            seen[idx] |= static_cast<std::uint8_t>(1u << bit);
        }
        q += len >> 3u;
    }
    return (count * 0x100u) >> 12u;
}

// The inline estimate of FUN_0805a790 (variant A) / FUN_08059d20 (variant B): the
// bytecode size the LZ parse would produce for the first `n` bytes, without
// touching the hash table.
static std::uint32_t LzCostEstimate(const State& st, const std::uint8_t* block, std::uint32_t n) {
    const std::uint8_t* const end = block + n;
    const std::uint8_t* p = block;
    std::uint32_t cost = 0;
    while (p < end) {
        const std::uint8_t* cand = st.window + (st.variant_b ? st.hash[LoadU32(p - 3) & 0xffffffu] : st.hash[LoadU32(p - 2) & 0x1fffu]);
        if (*cand == *p && (end <= cand || cand < p)) {
            std::uint32_t k = 0, m = 0;
            do {
                m = k;
                ++p;
                k = m + 1u;
                if (end <= p) break;
            } while (*p == cand[k]);
            cost += 1u;
            if (k > 7u) cost += 2u - ((m - 7u) < 0x80u ? 1u : 0u);
        } else {
            const std::uint8_t c = *p++;
            cost += (c > (st.variant_b ? 0xf6u : 0xf6u)) ? 2u : 1u;
        }
    }
    return cost;
}

// DAT_081b4620: bit 0 = call/jmp opcode (E8, E9), bit 1 = a plausible high
// displacement byte (00, FF); bit 2 marks 0F (unused here).
static inline std::uint8_t ExeClass(std::uint8_t b) {
    if (b == 0xe8u || b == 0xe9u) return 1u;
    if (b == 0x00u || b == 0xffu) return 2u;
    if (b == 0x0fu) return 4u;
    return 0u;
}

// FUN_080c0430: how many E8/E9 displacements (with a 00/FF top byte) point at
// one of the last four targets seen -- repeated call targets mean real code.
std::uint32_t ExeMetric(const std::uint8_t* p, std::uint32_t n) {
    if (n < 10u) return 0u;
    std::uint32_t count = 0;
    // the last four targets: pbVar6, pbVar7, local_18, local_14 of the decompile;
    // after a hit they become (old local_18, old pbVar6, target, old pbVar7)
    std::intptr_t h6 = 0, h7 = 0, h18 = 0, h14 = 0;
    const std::uint8_t* const end = p + (n - 5u);
    const std::uint8_t* q = p;
    do {
        std::uint8_t cls = ExeClass(*q);
        ++q;
        while ((cls & 1u) != 0u) {
            if ((ExeClass(q[3]) & 2u) == 0u) {
                q += 4;
                if (end <= q) return count;
                break;   // back to the outer loop with the byte at q
            }
            const std::intptr_t target = static_cast<std::intptr_t>(q - p) + static_cast<std::intptr_t>(static_cast<std::int32_t>(LoadU32(q)));
            const std::uint8_t* nx = q + 4;
            count += (h6 == target ? 1u : 0u) + (h18 == target ? 1u : 0u) + (h7 == target ? 1u : 0u) + (h14 == target ? 1u : 0u);
            if (end <= nx) return count;
            q += 5;
            cls = ExeClass(*nx);
            const std::intptr_t old18 = h18;
            h14 = h7; h18 = target; h7 = h6; h6 = old18;
        }
    } while (q < end);
    return count;
}

// FUN_080c0540 with param_5 = 0: the forward filter, in place. `pos` is the
// running position counter (State::exe_pos) of the block's first byte.
void ExeFilterForward(std::uint8_t* p, std::uint32_t n, std::uint64_t pos) {
    if (n < 10u) return;
    const std::uint8_t* const end = p + (n - 6u);
    std::uint8_t* q = p;
    for (; q < end; q += 4) {
        std::uint8_t cls = ExeClass(*q);
        for (;;) {
            ++q;
            if ((cls & 1u) != 0u) break;
            if (end <= q) return;
            cls = ExeClass(*q);
        }
        if ((ExeClass(q[3]) & 2u) != 0u) {
            const std::uint32_t rel = static_cast<std::uint32_t>(pos + static_cast<std::uint64_t>(q - p)) & 0xffffffu;
            const std::uint32_t v = rel + LoadU32(q);
            q[0] = static_cast<std::uint8_t>(v); q[1] = static_cast<std::uint8_t>(v >> 8u); q[2] = static_cast<std::uint8_t>(v >> 16u);
            q[3] = static_cast<std::uint8_t>(static_cast<std::int32_t>(v << 7u) >> 31);
        }
    }
}

// FUN_0805a790 without the audio and image paths (those need their own models);
// `align` is the address modulo 4 of the first byte this block writes in the
// original's output buffer (see WriteSymbols).
void EncodeBlock(State& st, const std::uint8_t* src, std::size_t len, std::size_t remaining, std::vector<std::uint8_t>& out, std::uintptr_t align, bool first_in_chunk) {
    (void)remaining;
    if (len == 0u) return;
    st.Wrap();
    std::uint8_t* const block = st.window + st.cursor;
    std::memcpy(block, src, len);
    st.cursor += len;
    // The analysis job (FUN_0805b2b0), run for this block: outside a header's
    // audio span it re-runs the format probe (which rewrites the probe struct),
    // then, if the probe is confident and the block noisy enough, asks the
    // prefilter decision; the exe metric comes last. Inside the span nothing runs.
    // Two copies of the probe (FUN_0805a790): the job's, which the analysis
    // rewrites and whose bytes_done the driver advances, and the codec's, which
    // the prefilter encoder edits (its alignment carry). The codec's copy is
    // REPLACED by the job's before every block, so those edits only survive into
    // the first block of a chunk (where the job's copy is refreshed from it): a
    // WAV's 44 header bytes come back as the "prefix" of every later block.
    if (first_in_chunk) st.probe = st.probe_ctx;
    std::uint32_t score = 0;
    bool audio_decision = false;
    std::uint32_t exe_metric = 0;
    if (st.probe.audio_end <= st.probe.bytes_done) {
        score = Score(src, static_cast<std::uint32_t>(len));
        AudioProbeBlock(st.probe, src, static_cast<std::uint32_t>(len));
        if (st.probe.audio_end <= st.probe.bytes_done) {
            bool skip_exe = false;
            if (st.probe.conf != 0u && 0x32u < score && st.probe.conf < score && 0x800u < len) {
                audio_decision = AudioDecide(st.probe, src, 0x400u, static_cast<std::uint32_t>(len));
                if (st.probe.bytes_done < st.probe.audio_end) skip_exe = true;
            }
            if (!skip_exe) {
                const std::uint32_t m = static_cast<std::uint32_t>(len < 0x2000u ? len : 0x2000u);
                exe_metric = ExeMetric(src, m) / ((m >> 12u) + 1u);
            }
        }
    }
    st.probe_ctx = st.probe;
    st.probe.bytes_done += static_cast<std::uint32_t>(len);
    const std::size_t out_start = out.size();
    const auto literal = [&](std::uint32_t flags) {
        WriteBlockHeader(out, static_cast<std::uint32_t>(len), flags, 0u);
        out.insert(out.end(), block, block + len);
    };
    // the prefilter block (FUN_0805a790's LAB_0805a97b, audio flavour): a literal
    // with flags 0 when the encoder declines; sparse backfill either way, and the
    // models are NOT reset after a prefilter block
    const auto audio_block = [&]() {
        std::vector<std::uint8_t> hdr;
        WriteBlockHeader(hdr, static_cast<std::uint32_t>(len), 4u, 0u);
        std::vector<std::uint8_t> payload;
        const std::size_t got = AudioEncodeBlock(st.audio, block, static_cast<std::uint32_t>(len), st.probe_ctx, payload, (align + hdr.size()) & 3u);
        if (got == 0u) {
            literal(0u);
            st.BackfillSparse(len);
            st.audio.ResetAll(); st.image.Reset();
        } else {
            out.insert(out.end(), hdr.begin(), hdr.end());
            out.insert(out.end(), payload.begin(), payload.end());
            st.BackfillSparse(len);
        }
        st.literal_bytes += len;
        st.exe_pos += len;
        st.probe_ctx.bytes_done += static_cast<std::uint32_t>(len);
    };
    if (std::getenv("NZ_TRACE_LZPFENC")) {
        const AudioProbe& q = st.probe;
        std::fprintf(stderr, "[lzpfenc] len=%zu score=%u probe{s=%u le=%u w=%u ch=%u pfx=%u hdr=%u code=%x conf=%u lz=%u pf=%u done=%u end=%u} dec=%d exe=%u\n",
                     len, score, q.signed_, q.le, q.width, q.chans, q.prefix, q.hdr, q.code, q.conf, q.lz_cost, q.pf_cost, q.bytes_done, q.audio_end, (int)audio_decision, exe_metric);
    }
    // the image flavour (FUN_0805a790: `rows_done < height || (0x32 < score && detect)`),
    // checked BEFORE the audio span; a declined block is a literal with flags 0
    // and resets both models (the driver's LAB_0805ab47 for every non-prefilter block)
    ImageProbe img;
    ImageDetect(img, src, static_cast<std::uint32_t>(len));
    if (st.image.rows_done < st.image.height || (0x32u < score && img.width != 0u)) {
        std::vector<std::uint8_t> hdr;
        WriteBlockHeader(hdr, static_cast<std::uint32_t>(len), 4u, 1u);
        std::vector<std::uint8_t> payload;
        const std::size_t got = ImageEncodeBlock(st.image, img, block, static_cast<std::uint32_t>(len), payload, (align + hdr.size()) & 3u);
        if (got == 0u) {
            literal(0u);
            st.BackfillSparse(len);
            st.audio.ResetAll();
            st.image.Reset();
        } else {
            out.insert(out.end(), hdr.begin(), hdr.end());
            out.insert(out.end(), payload.begin(), payload.end());
            st.BackfillSparse(len);
        }
        st.literal_bytes += len;
        st.exe_pos += len;
        st.probe_ctx.bytes_done += static_cast<std::uint32_t>(len);
        return;
    }
    if (st.probe_ctx.bytes_done < st.probe_ctx.audio_end) { audio_block(); return; }
    std::uint32_t flags58 = 0u;
    if (st.probe_ctx.conf != 0u) {
        if (score < 0x33u || score <= st.probe_ctx.conf) flags58 = 0u;
        else if (0x800u < len && (!st.variant_b || LzCostEstimate(st, block, 0x400u) * 4u > 0xc00u)) flags58 = audio_decision ? 4u : 0u;
    }
    // random data: no parse at all when the first 256 bytes would not shrink
    if (score > 0xe8u) {
        const std::uint32_t n = static_cast<std::uint32_t>(len < 0x100u ? len : 0x100u);
        const std::uint32_t cost = LzCostEstimate(st, block, n);
        if (n - (n >> 7u) <= cost && (len < 0x401u || Score(block + len / 2u, static_cast<std::uint32_t>(len / 2u)) > 0xe8u)) {
            literal(0u);
            st.BackfillSparse(len);
            st.literal_bytes += len;
            st.exe_pos += len;
            st.probe_ctx.bytes_done += static_cast<std::uint32_t>(len);
            st.audio.ResetAll(); st.image.Reset();
            return;
        }
    }
    if (flags58 == 4u) { audio_block(); return; }
    // the exe metric: repeated call targets in the first 8 KB
    if (exe_metric != 0u) {
        flags58 = 4u;
        ExeFilterForward(block, static_cast<std::uint32_t>(len), st.exe_pos);
    }
    std::vector<std::uint8_t> bc;
    LzParse(st, static_cast<std::size_t>(block - st.window), len, bc);
    const std::uint32_t flags = flags58 | 3u;
    const std::size_t limit = len - (len < 2u ? len : 2u);
    std::vector<std::uint8_t> ar;
    // the header comes first; its length decides the alignment of what follows
    std::vector<std::uint8_t> hdr;
    WriteBlockHeader(hdr, static_cast<std::uint32_t>(len), flags, 0u);
    ar.resize(limit + 8u);
    const std::size_t got = EncodeArithAt(bc.data(), bc.size(), ar.data(), limit, (align + hdr.size() + 2u) & 3u);
    if (bc.size() < len) {
        // the queued job (FUN_08059f10): raw bytecode when the side stream does not pay
        if (got == 0u || len <= got + 2u) {
            WriteBlockHeader(out, static_cast<std::uint32_t>(len), (flags & ~3u) | 2u, 0u);
            out.insert(out.end(), bc.begin(), bc.end());
        } else {
            out.insert(out.end(), hdr.begin(), hdr.end());
            out.push_back(static_cast<std::uint8_t>(bc.size()));
            out.push_back(static_cast<std::uint8_t>(bc.size() >> 8u));
            out.insert(out.end(), ar.begin(), ar.begin() + static_cast<std::ptrdiff_t>(got));
        }
    } else {
        // parsed in place: a literal block when the side stream does not pay
        if (got == 0u || len <= got + 2u) {
            literal(flags58 | 1u);
            st.BackfillDense(len);
        } else {
            out.insert(out.end(), hdr.begin(), hdr.end());
            out.push_back(static_cast<std::uint8_t>(bc.size()));
            out.push_back(static_cast<std::uint8_t>(bc.size() >> 8u));
            out.insert(out.end(), ar.begin(), ar.begin() + static_cast<std::ptrdiff_t>(got));
        }
    }
    (void)out_start;
    st.literal_bytes += len;
    st.exe_pos += len;
    st.probe_ctx.bytes_done += static_cast<std::uint32_t>(len);
    st.audio.ResetAll(); st.image.Reset();   // FUN_080b6b60 after every non-prefilter block
}

}  // namespace nzr::lzpf_enc
