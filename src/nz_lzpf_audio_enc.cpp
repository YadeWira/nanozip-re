// nz_lzpf_audio_enc.cpp -- the audio side of the original's lzpf compressor:
// the format probe (FUN_08080ef0 with the RIFF/AIFF parser FUN_08080a60 and the
// sanity check FUN_080809b0), the prefilter-vs-LZ decision (FUN_08081760), and
// the prefilter block encoder (FUN_08082d00 -> FUN_08081c40: sample unpack
// FUN_080806c0, the forward LPC FUN_08053220, the residual coder FUN_0806b400,
// the side-bit stream, the Huffman side streams). Decompiles in
// ~/.cache/nzre_tools/encode/decomp/lzpf_{analysis,media_encoders,audio_*}.c.
#include "nz_lzpf_encoder.h"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace nzr::lzpf_enc {

namespace {

inline std::uint32_t LoadU32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }
inline std::uint16_t LoadU16(const std::uint8_t* p) { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
inline std::uint32_t LoadBE32(const std::uint8_t* p) { return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3]; }
inline std::uint16_t LoadBE16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }

// floor(log2(x)) for x >= 1; the original's `for (; x >> i == 0; --i)` from 31
// (and 31 when x == 0, which its callers never pass).
inline std::uint32_t BitLen(std::uint32_t x) {
    std::uint32_t i = 31u;
    if (x != 0u) while ((x >> i) == 0u) --i;
    return i;
}
inline std::uint32_t AbsPlus1(std::int32_t v) { const std::uint32_t s = static_cast<std::uint32_t>(v >> 31); return ((static_cast<std::uint32_t>(v) ^ s) - s) + 1u; }
// DAT_081b4410[b] = floor(log2 b) (0 for 0): the cost of coding a bit count
inline std::uint32_t CostTable(std::uint32_t b) { return b == 0u ? 0u : BitLen(b); }

}  // namespace

// ---------------------------------------------------------------------------
// FUN_08080690: sum of bit lengths of |v|+1
std::uint32_t AudioCost(const std::int32_t* v, std::uint32_t n) {
    std::uint32_t c = 0;
    for (std::uint32_t i = 0; i < n; ++i) c += BitLen(AbsPlus1(v[i]));
    return c;
}

// FUN_080806c0: `nbytes` of samples -> first differences, planar for stereo
// (ch 1 = L/R, ch 2 = side/mid). Each call starts its integration at 0.
void AudioUnpack(const std::uint8_t* src, std::uint32_t nbytes, std::int32_t* out, const AudioProbe& pr) {
    const std::uint32_t width = pr.width;
    const std::uint32_t n = (nbytes / width) >> (pr.chans != 0u ? 1u : 0u);
    const std::uint32_t nv = pr.chans != 0u ? 2u : 1u;
    if (n == 0u) return;
    std::int32_t* out2 = out + n;
    std::int32_t prev0 = 0, prev1 = 0;
    const std::uint8_t* p = src;
    for (std::uint32_t i = 0; i < n; ++i) {
        std::int32_t v[2];
        for (std::uint32_t k = 0; k < nv; ++k) {
            std::uint32_t u;
            if (width == 1u) { u = *p++; if (pr.signed_) u = static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(u))); }
            else if (width == 2u) { u = pr.le ? LoadU16(p) : LoadBE16(p); p += 2; if (pr.signed_) u = static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int16_t>(u))); }
            else { u = pr.le ? (std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16)) : ((std::uint32_t(p[0]) << 16) | (std::uint32_t(p[1]) << 8) | p[2]); p += 3; if (pr.signed_) u = static_cast<std::uint32_t>(static_cast<std::int32_t>(u << 8) >> 8); }
            v[k] = static_cast<std::int32_t>(u);
        }
        if (nv == 2u) {
            if (pr.chans == 2u) { v[0] = v[0] - v[1]; v[1] = (v[0] >> 1) + v[1]; }
            *out2++ = v[1] - prev1;
            prev1 = v[1];
        }
        *out++ = v[0] - prev0;
        prev0 = v[0];
    }
}

// FUN_080809b0: true = REJECT (the mean |delta| of up to 1024 samples after the
// header is above a quarter of the sample range).
static bool AudioSanityReject(const std::uint8_t* block, std::uint32_t len, const AudioProbe& pr) {
    const std::int32_t rest = static_cast<std::int32_t>(len) - pr.prefix;
    if (rest < 0x400) return false;
    std::uint32_t n = static_cast<std::uint32_t>(rest) / pr.width;
    if (n > 0x400u) n = 0x400u;
    std::int32_t buf[0x400 + 8];
    AudioUnpack(block + pr.prefix, n * pr.width, buf, pr);
    std::uint32_t sum = 0;
    for (std::uint32_t i = 0; i < n; ++i) { const std::int32_t v = buf[i]; const std::uint32_t s = static_cast<std::uint32_t>(v >> 31); sum += (static_cast<std::uint32_t>(v) ^ s) - s; }
    return ((1u << ((pr.width & 3u) << 3u)) >> 2u) < (sum >> 10u);
}

// FUN_08080a60: AIFF/AIFC ("FORM" ... "COMM"/"SSND") and RIFF WAVE headers.
// Fills signed/le/width/chans/prefix and the data end (relative to the block).
static bool AudioHeaderProbe(const std::uint8_t* block, std::uint32_t len, AudioProbe& pr, std::uint32_t& audio_end) {
    const std::uint8_t* const lim = block + (len < 0x4000u ? len : 0x4000u);
    if (block + 12 < lim && LoadU32(block) == 0x4d524f46u && (LoadU32(block + 8) == 0x43464941u || LoadU32(block + 8) == 0x46464941u)) {
        // AIFF: big-endian chunk sizes; a "sowt" compression in COMM means little-endian
        const std::uint8_t* chunk = block + 12;
        if (chunk + 16 < lim && LoadBE32(chunk + 4) != 0 && (chunk[4] & 0x80u) == 0u) {
            std::uint8_t le = 0;
            const std::uint8_t* comm = nullptr;
            const std::uint8_t* data = chunk + 8;
            const std::uint8_t* cur = chunk;
            bool ok = true;
            while (LoadU32(cur) != 0x444e5353u) {   // "SSND"
                const std::uint32_t size = LoadBE32(cur + 4);
                if (LoadU32(cur) == 0x4d4d4f43u) {   // "COMM"
                    if (size == 0x12u) comm = cur + 8;
                    else if (size > 0x12u && LoadU32(cur + 8 + 0x12) == 0x74776f73u) { le = 1u; comm = cur + 8; }
                }
                const std::uint8_t* next = cur + 8 + size;
                data = next + 8;
                cur = next;
                if (lim <= next + 16 || next + 8 <= block || LoadBE32(next + 4) == 0u || (next[4] & 0x80u) != 0u) { ok = false; break; }
            }
            if (ok && comm != nullptr) {
                const std::int16_t ch = static_cast<std::int16_t>(LoadBE16(comm));
                const std::int16_t bits = static_cast<std::int16_t>(LoadBE16(comm + 6));
                if ((ch == 1 || ch == 2) && (bits == 8 || bits == 16 || bits == 24)) {
                    pr.le = le;
                    pr.signed_ = bits != 8 ? 1u : 0u;
                    pr.prefix = static_cast<std::uint16_t>((data + 8) - block);   // FUN_08080a60: local_28 = the SSND chunk's payload
                    pr.width = static_cast<std::uint8_t>(bits >> 3);
                    pr.chans = static_cast<std::uint8_t>(ch - 1);
                    audio_end = LoadBE32(block + 4);
                    if (!AudioSanityReject(block, len, pr)) return true;
                }
            }
        }
    }
    if (block + 12 < lim && LoadU32(block) == 0x46464952u && LoadU32(block + 8) == 0x45564157u) {   // "RIFF" "WAVE"
        const std::uint8_t* cur = block + 20;          // first chunk's payload
        std::uint32_t size = LoadU32(block + 16);
        std::uint32_t id = LoadU32(block + 12);
        if (block + 28 < lim && size != 0u && id != 0x61746164u) {
            const std::uint8_t* fmt = nullptr;
            bool ok = true;
            for (;;) {
                if (id == 0x20746d66u && size > 0xfu && size < 0x51u) fmt = cur;
                const std::uint8_t* next = cur + size;
                cur = next + 8;
                if (lim <= next + 16 || cur <= block) { ok = false; break; }
                size = LoadU32(next + 4);
                if (size == 0u) { ok = false; break; }
                id = LoadU32(next);
                if (id == 0x61746164u) break;   // "data": cur = its payload
            }
            if (ok && fmt != nullptr) {
                const std::int16_t tag = static_cast<std::int16_t>(LoadU16(fmt));
                const std::uint16_t chm1 = static_cast<std::uint16_t>(LoadU16(fmt + 2) - 1u);
                const std::int16_t bits = static_cast<std::int16_t>(LoadU16(fmt + 0xe));
                if ((tag == -2 || tag == 1) && chm1 < 2u && (bits == 16 || bits == 8 || bits == 24)) {
                    pr.le = bits != 8 ? 1u : 0u;
                    pr.signed_ = bits != 8 ? 1u : 0u;
                    pr.prefix = static_cast<std::uint16_t>(cur - block);
                    pr.width = static_cast<std::uint8_t>(LoadU16(fmt + 0xe) >> 3);
                    pr.chans = static_cast<std::uint8_t>(chm1);
                    audio_end = LoadU32(block + 4) + 8u;
                    return !AudioSanityReject(block, len, pr);
                }
            }
        }
    }
    return false;
}

// FUN_08080ef0: rewrites the whole probe. A header wins; otherwise sixteen
// interpretations of the bytes (8/16-bit, mono/stereo, signed/unsigned, two
// alignments) are costed on sampled windows and the cheapest one is kept.
void AudioProbeBlock(AudioProbe& pr, const std::uint8_t* block, std::uint32_t len) {
    pr = AudioProbe{};
    std::uint32_t audio_end = 0;
    if (AudioHeaderProbe(block, len, pr, audio_end)) {
        pr.audio_end = audio_end;
        pr.b18 = 1u;
        pr.hdr = 1u;
        if (pr.chans == 1u && pr.b24 == 0u) {
            // L/R or side/mid: whichever costs less over the first 8 KB
            AudioProbe t = pr;
            std::uint32_t nbytes = len - pr.prefix;
            if (nbytes > 0x2000u) nbytes = 0x2000u;
            std::vector<std::int32_t> buf(nbytes / pr.width + 8u);
            t.chans = 1u; AudioUnpack(block + pr.prefix, nbytes, buf.data(), t);
            const std::uint32_t c1 = AudioCost(buf.data(), nbytes / pr.width);
            t.chans = 2u; AudioUnpack(block + pr.prefix, nbytes, buf.data(), t);
            const std::uint32_t c2 = AudioCost(buf.data(), nbytes / pr.width);
            if (c2 * 0x21u < c1 << 5u) pr.chans = 2u;
        }
        return;
    }
    pr.hdr = 0u;
    pr.audio_end = 0u;
    std::uint32_t code, conf, prefix_bits;
    std::uint8_t width, chans, sgn, le;
    if (len < 0x80u) {
        code = 0u; conf = 0u; prefix_bits = 0u; width = 1u; chans = 0u; sgn = 0u; le = 1u;
    } else {
        // phase 1: eight 16-bit little-endian interpretations over eight 36-byte
        // windows -- indices: 0 mono even unsigned, 1 mono even signed, 2 stereo
        // even u, 3 stereo even s, 4 stereo odd u, 5 stereo odd s, 6 mono odd u,
        // 7 mono odd s ("odd" = the 16-bit words start one byte in).
        std::uint32_t acc[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const std::uint8_t* win = block + 0x40;
        const std::uint32_t step = ((len - 0x40u) >> 3u) & ~3u;
        for (int w = 0; w < 8; ++w) {
            std::uint8_t b[36]; std::memcpy(b, win, 36); win += step;
            std::uint32_t a0 = acc[0], a1 = acc[1], a2 = acc[2], a3 = acc[3], a4 = acc[4], a5 = acc[5], a6 = acc[6], a7 = acc[7];
            std::uint32_t cur_even = LoadU16(b), prev_even2 = 0, prev_odd_u = 0;
            std::int32_t prev_even_s = 0, prev_odd_s = 0;
            const std::uint8_t* p = b;
            while (p != b + 32) {
                // (&local_70)[k]: 0/1 = 16-bit words two bytes apart (mono, even
                // alignment, unsigned/signed), 2/3 = the same one byte in, 4/5 = words
                // four apart (stereo, even), 6/7 = stereo one byte in
                const std::uint32_t nxt = LoadU16(p + 2);
                a4 += BitLen(AbsPlus1(static_cast<std::int32_t>(nxt - prev_even2)));
                a5 += BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(nxt)) - prev_even_s));
                const std::uint32_t odd3 = LoadU16(p + 3);
                a6 += BitLen(AbsPlus1(static_cast<std::int32_t>(odd3 - prev_odd_u)));
                a7 += BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(odd3)) - prev_odd_s));
                const std::uint32_t saved = cur_even;
                a0 += BitLen(AbsPlus1(static_cast<std::int32_t>(cur_even - prev_even2)));
                const std::int32_t cur_s = static_cast<std::int16_t>(cur_even);
                a1 += BitLen(AbsPlus1(cur_s - prev_even_s));
                const std::uint32_t odd1 = LoadU16(p + 1);
                a2 += BitLen(AbsPlus1(static_cast<std::int32_t>(odd1 - prev_odd_u)));
                p += 2;
                a3 += BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(odd1)) - prev_odd_s));
                cur_even = nxt; prev_even_s = cur_s; prev_odd_u = odd1; prev_odd_s = static_cast<std::int16_t>(odd1); prev_even2 = saved;
            }
            acc[0] = a0; acc[1] = a1; acc[2] = a2; acc[3] = a3; acc[4] = a4; acc[5] = a5; acc[6] = a6; acc[7] = a7;
        }
        std::uint32_t best = 0;
        for (std::uint32_t k = 1; k < 8u; ++k) if (acc[k] < acc[best]) best = k;
        const std::uint32_t c_alt = acc[2u + (best & ~3u)];          // local_68[best & ~3]
        const std::uint32_t c_ref = acc[best & ~3u];                 // (&local_70)[best & ~3]
        const std::uint32_t start = (c_alt < c_ref ? 1u : 0u) + 0x40u;
        // phase 2: sixteen candidates over three 84-byte windows starting at `start`
        std::uint32_t cand[16];
        for (std::uint32_t k = 0; k < 16u; ++k) cand[k] = ((k & 3u) < 2u) ? 0u : 0xffffffffu;
        const std::uint8_t* w2 = block + start;
        const std::uint32_t step2 = ((len - start) / 3u) & ~3u;
        for (int w = 0; w < 3; ++w) {
            std::uint8_t b[0x54]; std::memcpy(b, w2, 0x54); w2 += step2;
            // 8-bit mono, unsigned (0) and signed (8): 80 samples
            { std::uint32_t pu = 0; std::int32_t ps = 0;
              for (int i = 0; i < 0x50; ++i) { const std::uint8_t c = b[i];
                  const std::uint32_t bu = BitLen(AbsPlus1(static_cast<std::int32_t>(c - pu))); cand[0] += CostTable(bu) + bu;
                  const std::uint32_t bs = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int8_t>(c)) - ps)); cand[8] += CostTable(bs) + bs;
                  pu = c; ps = static_cast<std::int8_t>(c); } }
            // 8-bit stereo, unsigned (4) and signed (12): 40 pairs
            { std::uint32_t pu0 = 0, pu1 = 0; std::int32_t ps0 = 0, ps1 = 0; std::uint32_t c4 = cand[4], c12 = cand[12];
              for (int i = 0; i < 0x50; i += 2) { const std::uint8_t c0 = b[i], c1 = b[i + 1];
                  const std::uint32_t bu0 = BitLen(AbsPlus1(static_cast<std::int32_t>(c0 - pu0))), bs0 = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int8_t>(c0)) - ps0));
                  const std::uint32_t bu1 = BitLen(AbsPlus1(static_cast<std::int32_t>(c1 - pu1)));
                  c4 = bu0 + 2u + bu1 + c4 + CostTable(bu0) + CostTable(bu1);
                  const std::uint32_t bs1 = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int8_t>(c1)) - ps1));
                  c12 = bs0 + 2u + bs1 + c12 + CostTable(bs0) + CostTable(bs1);
                  ps0 = static_cast<std::int8_t>(c0); pu1 = c1; pu0 = c0; ps1 = static_cast<std::int8_t>(c1); }
              cand[4] = c4; cand[12] = c12; }
            // 16-bit LE mono, unsigned (1) and signed (9): 40 samples
            { std::uint32_t pu = 0; std::int32_t ps = 0;
              for (int i = 0; i < 0x50; i += 2) { const std::uint32_t c = LoadU16(b + i);
                  const std::uint32_t bu = BitLen(AbsPlus1(static_cast<std::int32_t>(c - pu))); cand[1] += CostTable(bu) + bu;
                  const std::uint32_t bs = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(c)) - ps)); cand[9] += CostTable(bs) + bs;
                  pu = c; ps = static_cast<std::int16_t>(c); } }
            // 16-bit LE stereo, unsigned (5) and signed (13): 20 pairs
            { std::uint32_t pu0 = 0, pu1 = 0; std::int32_t ps0 = 0, ps1 = 0; std::uint32_t c5 = cand[5], c13 = cand[13];
              for (int i = 0; i < 0x50; i += 4) { const std::uint32_t c0 = LoadU16(b + i), c1 = LoadU16(b + i + 2);
                  const std::uint32_t bu0 = BitLen(AbsPlus1(static_cast<std::int32_t>(c0 - pu0))), bs0 = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(c0)) - ps0));
                  const std::uint32_t bu1 = BitLen(AbsPlus1(static_cast<std::int32_t>(c1 - pu1)));
                  c5 = bu1 + bu0 + c5 + CostTable(bu0) + CostTable(bu1);
                  const std::uint32_t bs1 = BitLen(AbsPlus1(static_cast<std::int32_t>(static_cast<std::int16_t>(c1)) - ps1));
                  c13 = bs1 + bs0 + c13 + CostTable(bs0) + CostTable(bs1);
                  pu1 = c1; ps0 = static_cast<std::int16_t>(c0); pu0 = c0; ps1 = static_cast<std::int16_t>(c1); }
              cand[5] = c5; cand[13] = c13; }
        }
        std::uint32_t best2 = 0, total = cand[0];
        for (std::uint32_t k = 1; k < 16u; ++k) { total += cand[k]; if (cand[k] < cand[best2]) best2 = k; }
        code = (total / 0xf0u) * 0x100u + best2;
        if ((code & 3u) != 0u) code = (c_alt < c_ref ? 0x20u : 0u) + (code & 0xffu) + (code & 0xffffff00u);
        le = ((code & 0x10u) == 0u) ? 1u : 0u;
        width = static_cast<std::uint8_t>((code & 3u) + 1u);
        prefix_bits = (code >> 5u) & 7u;
        sgn = static_cast<std::uint8_t>((code >> 3u) & 1u);
        conf = code >> 8u;
        chans = static_cast<std::uint8_t>((code >> 2u) & 1u);
    }
    pr.code = code;
    pr.le = le;
    pr.signed_ = sgn;
    pr.prefix = static_cast<std::uint16_t>(prefix_bits);
    pr.conf = conf;
    pr.chans = chans;
    pr.width = width;
}

// FUN_08081760: is the prefilter worth it? An LZ estimate (a 12-bit-hash parse
// of the raw bytes, Huffman-costed) against the order-8 predictor's residual
// cost; both are kept in the probe.
bool AudioDecide(AudioProbe& pr, const std::uint8_t* block, std::uint32_t len, std::uint32_t avail) {
    if (len < 0x10u) return false;
    if (AudioSanityReject(block, len, pr) && AudioSanityReject(block + (((len >> 1u) + 3u) & ~3u), len >> 1u, pr)) return false;
    std::uint32_t hist[256]; std::memset(hist, 0, sizeof(hist));
    std::uint32_t table[4096]; std::memset(table, 0, sizeof(table));
    {
        // a 12-bit hash of the two previous bytes; a mismatch costs symbol 255 plus
        // the byte, a 1-byte match symbol 0, a longer one its length-1
        std::uint32_t prev = 1u;
        while (prev + 1u < len) {
            std::uint32_t pos = prev + 1u;
            bool handled = false;
            for (;;) {
                const std::uint32_t h = LoadU16(block + pos - 2u) & 0xfffu;
                const std::uint32_t cand = table[h];
                table[h] = pos;
                const std::uint8_t c = block[pos];
                prev = pos;
                if (block[cand] != c) break;
                // the original reads block[pos + 1] / block[i + 1] without a bound: the
                // window sits inside the 32 KB block, so those bytes exist (`avail`)
                if ((pos + 1u < avail ? block[pos + 1u] : 0u) == block[cand + 1u]) {
                    std::uint32_t i = pos + 1u;
                    const std::uint8_t* q = block + cand + 1u;
                    while (i < len) {
                        ++q;
                        if ((i + 1u < avail ? block[i + 1u] : 0u) != *q) break;
                        ++i;
                    }
                    ++hist[(i - pos) & 0xffu];
                    prev = i;
                    handled = true;
                    break;
                }
                ++hist[0];
                pos += 1u;
                if (len <= pos) { handled = true; prev = len; break; }
            }
            if (!handled) { ++hist[255]; ++hist[block[prev]]; }
        }
    }
    std::uint8_t lens[256], codes[256];
    const std::uint32_t nsyms = static_cast<std::uint32_t>(BuildCodeLengths(hist, 0x1fu, lens, codes));
    std::uint32_t lz_bits = 0; for (int s = 0; s < 256; ++s) lz_bits += static_cast<std::uint32_t>(lens[s]) * hist[s];
    if (len <= pr.prefix) return false;
    std::uint32_t nb = (len - pr.prefix) / pr.width;
    if (pr.chans != 0u) nb &= ~1u;
    nb *= pr.width;
    // an order-8 predictor of its own (shift 8), starting clean
    // FUN_080bda10(8), shift byte := 8, then FUN_080bdac0 -- whose reset puts the shift back to 13
    LpcPlane pred; pred.Configure(8u); pred.Reset();
    std::uint32_t hist2[256]; std::memset(hist2, 0, sizeof(hist2));
    std::uint32_t side_bytes = pr.prefix;
    std::vector<std::int32_t> buf(0x1000 + 8);
    std::vector<std::uint8_t> bytes(0x1000 + 8);
    const std::uint8_t* src = block + pr.prefix;
    std::uint32_t chunk = nb < 0x1000u ? nb : 0x1000u;
    while (chunk != 0u) {
        AudioUnpack(src, chunk, buf.data(), pr);
        src += chunk;   // FUN_080806c0 advances its source (regparm eax), see the decision's disassembly
        nb -= chunk;
        const std::uint32_t k = chunk / pr.width;
        pred.Forward(buf.data(), k);
        const std::uint32_t extra = ResidualCostBits(buf.data(), k, bytes.data());
        side_bytes += extra >> 3u;
        for (std::uint32_t q = 0; q < k; ++q) ++hist2[bytes[q]];
        chunk = nb < 0x1000u ? nb : 0x1000u;
    }
    const std::uint32_t nsyms2 = static_cast<std::uint32_t>(BuildCodeLengths(hist2, 0x1fu, lens, codes));
    const std::uint32_t lz_est = (lz_bits >> 3u) + (nsyms >> 1u);
    std::uint32_t pf_bits = 0; for (int s = 0; s < 256; ++s) pf_bits += static_cast<std::uint32_t>(lens[s]) * hist2[s];
    pr.lz_cost = lz_est;
    const std::uint32_t pf_est = (nsyms2 >> 1u) + (pf_bits >> 3u) + side_bytes;
    pr.pf_cost = pf_est;
    if (lz_est <= pf_est) return false;
    if (len * 3u <= pf_est * 4u) return false;
    return len * 7u < lz_est * 8u;
}

// ---------------------------------------------------------------------------
// FUN_08053220, order < 9: residual = sample - prediction, then the same
// sign-sign adaptation the decoder runs (LpcPredictor::step) on the sample.
void LpcPlane::Forward(std::int32_t* v, std::uint32_t n) {
    if (order >= 9u) { big.shift = shift; big.Forward(v, n); pred = big.pred; return; }   // FUN_08053220's order >= 9 branch
    const std::uint32_t t = taps;
    if (t >= 8u) {
        for (std::uint32_t i = 0; i < n; ++i) StepForward(v[i], true);
    } else {
        for (std::uint32_t i = 0; i < n;) {
            StepForward(v[i++], true);
            if (i < n) StepForward(v[i++], false);
        }
    }
}

void LpcPlane::StepForward(std::int32_t& v, bool adapt) {
    if (order >= 9u) { big.shift = shift; big.Forward(&v, 1u); pred = big.pred; (void)adapt; return; }
    const std::uint32_t t = taps;
    const std::int32_t x = v;
    v = x - pred;
    if (adapt) {
        if (pred < x) { for (std::uint32_t k = 0; k < t; ++k) factors[k] = static_cast<std::int16_t>(factors[k] - sign_hist[k]); }
        else { for (std::uint32_t k = 0; k < t; ++k) factors[k] = static_cast<std::int16_t>(factors[k] + sign_hist[k]); }
    }
    const std::int16_t h16 = static_cast<std::int16_t>(x);
    for (std::uint32_t k = t - 1u; k > 0u; --k) hist[k] = hist[k - 1u];
    hist[0] = h16;
    const std::int16_t s16 = h16 > 0 ? static_cast<std::int16_t>(-1) : (h16 < 0 ? static_cast<std::int16_t>(1) : 0);
    for (std::uint32_t k = t - 1u; k > 0u; --k) sign_hist[k] = sign_hist[k - 1u];
    sign_hist[0] = s16;
    std::int32_t sum = 0;
    for (std::uint32_t k = 0; k < t; ++k) sum += static_cast<std::int32_t>(hist[k]) * static_cast<std::int32_t>(factors[k]);
    pred = sum >> (shift & 0x1fu);
}

// FUN_0806b390: the residual bytes and the side bits they will need (cost only).
std::uint32_t ResidualCostBits(const std::int32_t* v, std::uint32_t n, std::uint8_t* bytes) {
    std::uint32_t bits = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t s = static_cast<std::uint32_t>(v[i] >> 31);
        std::uint32_t zz = (static_cast<std::uint32_t>(v[i]) ^ s) * 2u - s;
        bytes[i] = static_cast<std::uint8_t>(zz);
        if (zz >= 0xe0u) {
            zz -= 0xe0u;
            const std::uint32_t nb = zz == 0u ? 0u : BitLen(zz);
            bytes[i] = static_cast<std::uint8_t>(nb + 0xe0u);
            bits += nb + (nb == 0u ? 1u : 0u);
        }
    }
    return bits;
}

// FUN_0806b400: the residual bytes, escapes' extra bits into the side writer.
void ResidualEncode(const std::int32_t* v, std::uint32_t n, std::uint8_t* bytes, BitWriter& w) {
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t s = static_cast<std::uint32_t>(v[i] >> 31);
        std::uint32_t zz = (static_cast<std::uint32_t>(v[i]) ^ s) * 2u - s;
        bytes[i] = static_cast<std::uint8_t>(zz);
        if (zz >= 0xe0u) {
            zz -= 0xe0u;
            const std::uint32_t nb = zz == 0u ? 0u : BitLen(zz);
            bytes[i] = static_cast<std::uint8_t>(nb + 0xe0u);
            const std::uint32_t nbits = nb + (nb == 0u ? 1u : 0u);
            w.Put(zz & MaskBits(nb), nbits);
        }
    }
}

// FUN_08081c40 for the lzpf configuration (flags 0: no LMS, one stage). Appends
// the block's bytes to `out` and returns their count, 0 when the prefilter does
// not pay (the caller then stores the block as a literal).
std::size_t AudioEncodeBlock(AudioModel& m, const std::uint8_t* src0, std::uint32_t len, AudioProbe& pr, std::vector<std::uint8_t>& out, std::uintptr_t align) {
    if (len < 8u) return 0u;
    std::uint32_t width = pr.width;
    if (width == 1u && pr.le != 0u) pr.le = 0u;
    std::uint32_t prefix;
    std::vector<std::int32_t> buf(0x10000 / 1 + 16);
    if (pr.hdr == 0u) {
        if (len < 0x401u || width < 2u) {
            prefix = pr.prefix;
        } else {
            // the byte alignment: unpack 256 bytes from each of `width` offsets past the prefix
            std::uint32_t cost[8] = {0, 0, 0, 0, 0, 0, 0, 0}, best = 0;
            for (std::uint32_t k = 0; k < width; ++k) {
                AudioUnpack(src0 + pr.prefix + k, 0x100u, buf.data(), pr);
                cost[k] = AudioCost(buf.data(), 0x100u / width);
                if (cost[k] < cost[best]) best = k;
            }
            if (cost[best] * 0x21u < (cost[0] << 5u)) pr.prefix = static_cast<std::uint16_t>(pr.prefix + best);
            prefix = pr.prefix;
        }
        if (pr.chans != 0u && width * 0x1001u <= len) {
            // the channel phase: does shifting by one sample predict better?
            std::uint32_t cost[2] = {0, 0};
            const std::uint32_t per = (0x1000u / width) >> 1u;
            for (std::uint32_t c = 0; c < 2u; ++c) {
                AudioUnpack(src0 + prefix + c * width, 0x1000u, buf.data(), pr);
                LpcPlane t0 = m.plane[0], t1 = m.plane[1];
                t0.Forward(buf.data(), per);
                t1.Forward(buf.data() + per, per);
                std::uint32_t s = 0;
                for (std::uint32_t i = 0; i < per; ++i) s += BitLen(AbsPlus1(buf[i])) + BitLen(AbsPlus1(buf[per + i]));
                cost[c] = s;
            }
            if (std::getenv("NZ_TRACE_LZPFENC")) std::fprintf(stderr, "[audioblk] phase cost0=%u cost1=%u prefix=%u\n", cost[0], cost[1], prefix);
            if (cost[1] * 0x21u < (cost[0] << 5u)) {
                if (pr.prefix < width) pr.prefix = static_cast<std::uint16_t>(pr.prefix + width);
                else pr.prefix = static_cast<std::uint16_t>(pr.prefix - width);
            }
            prefix = pr.prefix;
        }
    } else {
        prefix = pr.prefix;
    }
    if (prefix > 0x105u) {
        prefix = (prefix & 0xffffu) % ((pr.chans == 0u ? 1u : 2u) * width);
        pr.prefix = static_cast<std::uint16_t>(prefix);
    }
    const std::size_t start = out.size();
    // the header byte
    const std::int32_t cv = width > 1u ? static_cast<std::int32_t>(pr.le) - 3 + static_cast<std::int32_t>(width) * 2 : 0;
    const std::uint32_t pfx6 = prefix < 6u ? prefix : 6u;
    out.push_back(static_cast<std::uint8_t>(pr.signed_ + ((cv + static_cast<std::int32_t>(pfx6) * 5) * 3 + pr.chans) * 2));
    if (prefix > 5u) out.push_back(static_cast<std::uint8_t>(prefix - 6u));
    const std::uint8_t* src = src0;
    out.insert(out.end(), src, src + prefix);
    src += prefix;
    std::uint32_t rest = len - prefix;
    std::uint32_t nsmp = rest / width;
    if (pr.chans != 0u) nsmp &= ~1u;
    const std::uint32_t rem = rest - nsmp * width;
    const std::uint32_t aligned = rest - rem;
    if (rem != 0u) {
        out.insert(out.end(), src + aligned, src + aligned + rem);
        pr.prefix = static_cast<std::uint16_t>((pr.chans == 0u ? 1u : 2u) * width - rem);
    } else {
        pr.prefix = 0u;
    }
    const std::uint32_t per = pr.chans != 0u ? nsmp >> 1u : nsmp;
    AudioUnpack(src, aligned, buf.data(), pr);
    // the side bits
    std::vector<std::uint8_t> side(0x10000 + 16);
    BitWriter w; w.base = side.data(); w.end = side.data() + 0x10000; w.cur = side.data(); w.bitbuf = 0; w.nbits = 0;
    const std::uint32_t nch = pr.chans != 0u ? 2u : 1u;
    if (pr.chans != 0u) {
        if (m.flags & 0x10u) {
            // FUN_08081af0: channels of comparable cost get the inter-channel LMS (G = 1)
            std::uint32_t c1 = 100, c2 = 100;
            for (std::uint32_t i = 0; i < per; ++i) { c1 += BitLen(AbsPlus1(buf[i])); c2 += BitLen(AbsPlus1(buf[per + i])); }
            const std::uint32_t lo = std::min(c1, c2), hi = std::max(c1, c2);
            if (!(lo * 7u < hi * 3u)) {
                w.Put(1u, 1u);
                m.lms[0].shift = 0x0cu; m.lms[1].shift = (pr.chans == 2u) ? 0x0bu : 0x0cu;   // FUN_080beb90
                w.Put(m.lms[0].shift - 7u, 3u); w.Put(m.lms[1].shift - 7u, 3u);
                // FUN_08054670: ch1 predicted from the previous ch2 sample, ch2 from the current ch1
                std::int32_t prev2 = 0;
                for (std::uint32_t i = 0; i < per; ++i) {
                    const std::int32_t x1 = buf[i];
                    const std::int32_t p1 = nzr::lzpf::LmsPredictSample(m.lms[0], prev2);
                    buf[i] = x1 - p1; nzr::lzpf::LmsUpdateSample(m.lms[0], x1, x1 - p1);
                    const std::int32_t x2 = buf[per + i];
                    const std::int32_t p2 = nzr::lzpf::LmsPredictSample(m.lms[1], x1);
                    buf[per + i] = x2 - p2; nzr::lzpf::LmsUpdateSample(m.lms[1], x2, x2 - p2);
                    prev2 = x2;
                }
            } else { w.Put(0u, 1u); m.lms[0].Init(); m.lms[1].Init(); }   // FUN_080beb60
        } else {
            w.Put(0u, 1u);   // flags & 2 never set here: FUN_080be670 resets the other LMS flavour
        }
    }
    // the LPC stages: stage 0 always applies; later stages only when a trial on the
    // first samples pays (FUN_08081b70: stage 1 within 64/65, stage 2 strictly)
    for (std::uint32_t st = 0; st < m.nstages; ++st) {
        for (std::uint32_t j = 0; j < nch; ++j) {
            LpcPlane& pl = m.plane[2u * st + j];
            pl.shift = (pl.order > 8u) ? std::min<std::uint32_t>(pl.order / 20u + 12u, 15u) : 8u;   // (flags & 1) == 0
        }
        for (std::uint32_t j = 0; j < nch; ++j) {
            LpcPlane& pl = m.plane[2u * st + j];
            std::int32_t* data = buf.data() + j * per;
            if (st == 0u) { w.Put(1u, 1u); w.Put(pl.shift - 8u, 3u); pl.Forward(data, per); continue; }
            const std::uint32_t n2 = std::min<std::uint32_t>(per, 0x1000u);
            const std::uint32_t p4 = (st == 1u) ? 0x40u : 1u, p5 = (st == 1u) ? 0x41u : 1u;
            std::vector<std::int32_t> copy(data, data + n2);
            LpcPlane trial = pl;
            trial.Forward(copy.data(), n2);
            std::uint32_t cf = 0, co = 0;
            for (std::uint32_t i = 0; i < n2; ++i) { cf += BitLen(AbsPlus1(copy[i])); co += BitLen(AbsPlus1(data[i])); }
            const bool act = cf * p4 < co * p5;
            w.Put(act ? 1u : 0u, 1u);
            if (act) { w.Put(pl.shift - 8u, 3u); pl.Forward(data, per); }
            else pl.Reset();   // FUN_080bdac0
        }
    }
    std::vector<std::uint8_t> bytes(nsmp + 16);
    ResidualEncode(buf.data(), nsmp, bytes.data(), w);
    w.Flush();
    const std::size_t side_bytes = static_cast<std::size_t>(w.cur - w.base) + ((w.nbits + 7u) >> 3u);
    const bool side_overflow = w.end <= w.cur;
    // the Huffman side stream(s), limit = the sample count
    std::vector<std::uint8_t> ar(static_cast<std::size_t>(nsmp) + 32u);
    std::size_t a_total;
    const std::uintptr_t al = (align + (out.size() - start)) & 3u;
    if (pr.chans == 0u) {
        a_total = EncodeArithAt(bytes.data(), nsmp, ar.data(), nsmp, al);
        if (a_total == 0u) { out.resize(start); return 0u; }
    } else {
        const std::size_t a1 = EncodeArithAt(bytes.data(), per, ar.data(), per, al);
        const std::size_t a2 = a1 ? EncodeArithAt(bytes.data() + per, per, ar.data() + a1, per, (al + a1) & 3u) : 0u;
        if (std::getenv("NZ_TRACE_LZPFENC")) std::fprintf(stderr, "[audioblk] stereo arith a1=%zu a2=%zu per=%u prefix=%u\n", a1, a2, per, prefix);
        if (a1 == 0u || a2 == 0u) { out.resize(start); return 0u; }
        a_total = a1 + a2;
    }
    const std::size_t produced = (out.size() - start) + a_total + side_bytes;
    if (std::getenv("NZ_TRACE_LZPFENC"))
        std::fprintf(stderr, "[audioblk] len=%u prefix=%u carry=%u nsmp=%u per=%u hdr=%02x arith=%zu side=%zu produced=%zu aligned=%u ovf=%d\n",
                     len, prefix, pr.prefix, nsmp, per, out[start], a_total, side_bytes, produced, aligned, (int)side_overflow);
    if (aligned <= produced || side_overflow) { out.resize(start); return 0u; }
    out.insert(out.end(), ar.begin(), ar.begin() + static_cast<std::ptrdiff_t>(a_total));
    out.insert(out.end(), side.begin(), side.begin() + static_cast<std::ptrdiff_t>(side_bytes));
    return produced;
}

}  // namespace nzr::lzpf_enc
