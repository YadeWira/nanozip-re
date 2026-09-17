#pragma once
#include <cstdint>
#include <vector>
#include <memory>

// NanoZip decr_param == 2 ("audio") block decoding, ported from the community
// reference decoder (nzdec_v0 NZ_Audio.cpp / NZ_Audio.h).
//
// A block whose header carries decr_param == 2 is an audio block. Its header
// layout differs from every other block: it reads a mode2_type byte, forces
// param6 to 1, reads size18, and then STOPS -- there is no staged-checksum
// count and none of the param2/param1/param16/text-transform/dece fields that
// follow an ordinary block. Its payload is decoded by this predictor rather
// than by the archive's LZ/CM/BWT engine, so every codec that can emit one
// (-cd, -cD, -cc, -co, -cO) needs it.
//
// The predictor is stateful across blocks. The reference keeps exactly one
// instance for the whole decode and resets it:
//   * before every NON-audio block, and
//   * on an audio block only when that block's mode2_type is non-zero.
// Callers must reproduce that rule or the model drifts out of sync.
//
// Requires NzCmInitAll() to have run: the bit-count model is seeded from the
// shared kModelLutLookup table that nz_cm.cpp builds.

namespace nzr {
namespace audio {

class NzAudioPred {
 public:
    NzAudioPred();
    ~NzAudioPred();

    NzAudioPred(const NzAudioPred&) = delete;
    NzAudioPred& operator=(const NzAudioPred&) = delete;

    // Selects the inter-channel stage, from the decoder object's flag byte in
    // the real binary (`*param_1` in FUN_080a5330). GDB-read per codec:
    // -cO 0x03, -cc 0x0f, -co 0x13. Only bit 4 matters here: clear selects
    // FUN_08096160 (two 4-bit shifts biased +0x10, the AudioStereoDecoder this
    // file has always implemented), set selects FUN_08096e20 (two 3-bit shifts
    // biased +7, i.e. the LMS already ported as nzr::lzpf::LmsObject).
    // Reading the wrong one costs two bits of side-channel and desynchronises
    // everything after it, which is exactly how -co used to fail.
    void SetContextFlags(std::uint8_t flags);

    // The six linear predictors' orders, one per PAIR (planes 0/1, 2/3, 4/5).
    // A per-CODEC constant, GDB-read from the real decoder's plane objects:
    //     -co :  64, 8,  8       -cO :  96, 8,  8       -cc : 384, 16, 8
    // Not fixed, and not read from the stream. Getting it wrong can put a plane
    // on the wrong code path entirely (order > 8 uses a different filter).
    void SetPlaneOrders(std::uint32_t pair0, std::uint32_t pair1, std::uint32_t pair2);

    // The inter-channel decoder's order parameter, also a per-CODEC constant
    // (GDB-read): -co 4, -cO 8, -cc 16. The old hardcoded 8 was -cO's.
    void SetStereoParam(std::uint32_t param);

    // Selects the second bit-count decoder CLASS (vtable 0x0813c860, FUN_0809bdc0),
    // which only -co uses. -cO and -cc use the default (vtable 0x0813c848,
    // FUN_0809c070).
    void SetBitcountVariantB(bool b);

    // Clears the bit-count models, the stereo decoder and all six linear
    // predictors, exactly as the reference AudioPred::Reset does.
    void Reset();

    // Decodes one audio block: `in_size` payload bytes producing exactly
    // `out_size` bytes into `out`. Returns false on any malformed or
    // inconsistent input, in which case `out` must be treated as garbage and
    // the caller should decline rather than emit it.
    bool Decode(const std::uint8_t* in, std::uint32_t in_size,
                std::uint8_t* out, std::uint32_t out_size);

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Encoder side, test hook: writes the bit-count array of ONE channel exactly as
// a decr_param==2 payload carries it (variant A: the -cO/-cc coder), u16 length
// prefix included. Appends to `out` and returns true on success.
// One decr_param==2 chunk, in the writing direction. The decisions still come
// from the caller; choosing them the way the reference does is the next piece.
struct NzAudioChunkParams {
    bool stereo_filter = false;
    std::uint8_t channels = 0;       // 0 mono, 1 or 2 two-channel (2 = mid/side)
    std::uint8_t sample_size = 2;
    bool little_endian = true;
    std::uint32_t header_bytes = 0;  // leading bytes copied verbatim
    bool gate = false;               // the inter-channel stage
    std::uint32_t gate_a = 0, gate_b = 0;
    std::uint8_t lp_flag[3][2] = {{0, 0}, {0, 0}, {0, 0}};
    std::uint8_t lp_bits[3][2] = {{0, 0}, {0, 0}, {0, 0}};
    std::uint32_t span_len = 0;      // where a recognised audio span ends, 0 = none
};

class NzAudioEncoder {
 public:
    NzAudioEncoder();
    ~NzAudioEncoder();
    NzAudioEncoder(const NzAudioEncoder&) = delete;
    NzAudioEncoder& operator=(const NzAudioEncoder&) = delete;

    void SetContextFlags(std::uint8_t flags);
    void SetPlaneOrders(std::uint32_t pair0, std::uint32_t pair1, std::uint32_t pair2);
    void SetStereoParam(std::uint32_t param);
    void SetBitcountVariantB(bool b);
    void Reset();

    // `in`/`outsize` are the bytes the decoder would produce for this chunk.
    bool EncodeChunk(const std::uint8_t* in, std::uint32_t outsize,
                     const NzAudioChunkParams& params, std::vector<std::uint8_t>* out);

    // A whole decr_param==2 payload: chunks of 0x10000 output bytes with the
    // models carried across them. `params` carries the format (from ChooseFormat);
    // everything else is decided per chunk.
    bool Encode(const std::uint8_t* in, std::uint32_t size,
                const NzAudioChunkParams& params, std::vector<std::uint8_t>* out);

    // Fills the format fields from the shared audio detector.
    void ChooseFormat(const std::uint8_t* in, std::uint32_t size, NzAudioChunkParams* params);

    // The same detector, asked only where a recognised span ends (0 = none). The
    // block driver needs this before any encoder object exists.
    static void SpanOf(const std::uint8_t* in, std::uint32_t size, NzAudioChunkParams* params);

    // Picks the per-plane flags and shifts by a greedy search (metric 0 = sum of
    // |residual|, 1 = sum of class indices). Experimental: which search the
    // reference runs is still being measured.
    void ChoosePlanes(const std::uint8_t* in, std::uint32_t outsize,
                      NzAudioChunkParams* params, int metric);

    // Debug: the per-channel arrays as they reach the plane decisions.
    void PreparedPlanes(const std::uint8_t* in, std::uint32_t outsize,
                        const NzAudioChunkParams& params, std::vector<std::int32_t>* out);

    // Cost proxies of the last chunk, for the decision search.
    std::uint64_t LastClassSum() const;
    std::uint64_t LastAbsSum() const;

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Test hooks for the residual stage: `NzAudioEncodeResiduals` fills `counts`
// (one class per sample) and appends the magnitude/sign bit stream to `bits`;
// `NzAudioDecodeResiduals` reads them back.
bool NzAudioEncodeResiduals(const std::int32_t* samples, std::uint32_t n,
                            std::uint8_t* counts, std::vector<std::uint8_t>* bits,
                            const std::uint32_t* prefix = nullptr,
                            std::uint32_t prefix_n = 0);
bool NzAudioDecodeResiduals(const std::uint8_t* bits, std::size_t bits_size,
                            const std::uint8_t* counts, std::uint32_t n,
                            std::int32_t* samples);

// Test hook, decoder half: reads one variant-A bit-count block (u16 length
// prefix included) and returns the bytes consumed, 0 on failure.
std::uint32_t NzAudioDecodeBitcounts(const std::uint8_t* in, std::size_t in_size,
                                     std::uint8_t* out, std::uint32_t n,
                                     bool variant_b = false);

bool NzAudioEncodeBitcounts(const std::uint8_t* counts, std::uint32_t n,
                            std::vector<std::uint8_t>* out, bool variant_b = false);

// NanoZip decr_param == 3 ("image") block decoding, ported from the binary
// (FUN_080a9ca0 = 64 KB-chunk wrapper, FUN_080a90c0 = per-chunk decoder).
//
// The encoder puts a block on decr_param 3 when its detector chain recognises
// an image (BMP so far). The block's payload is a sequence of chunks of up to
// 65536 output bytes, each headed by one byte:
//     bit 0     width comes from the object (1) or from a u16 in the stream (0)
//     bit 1     16-bit sample byte order (0 = big-endian, 1 = little-endian)
//     bit 2     bytes per sample - 1
//     bits 3-4  channels - 1 (1..4; a 24-bit BMP is 3)
//     bits 5-7  raw prefix length (6 = next byte + 6, 7 = next u16 + 0xfa)
// followed by the raw prefix, the misaligned tail bytes (raw, stored at the
// END of the chunk), per-channel bit-count streams, a side-bit header (3-bit
// prediction mode, optional per-plane shifts, optional cascade shifts) and the
// residual stream. Each pixel is rebuilt as
//     out = Predict2D(left, above, above-left, above-right; mode) + residual
// where, depending on the codec's flag byte, the residual first goes through
// a per-channel LMS (planes 0..3 and a shared plane 4) and a 4-stage 4-tap
// sign-sign cascade fed by the four neighbouring rows' intermediate values.
// The same core serves every codec: -cc/-co/-cO via the CM dispatcher's
// mode 3, -cd/-cD as the 0xf sub-chunk, -cf/-cF as the (uVar9&7)==4 variant
// with bit 3 set. Only the flag byte and the plane orders differ per codec.
//
// The state (history rings, LMS planes, cascade coefficients, row/column
// counters) persists across chunks and across blocks of one stream; nothing
// in the decoder ever resets it (row starts clear only the LMS windows when
// flag bit 1 is set).
class NzImageModel {
 public:
    NzImageModel();
    ~NzImageModel();
    NzImageModel(const NzImageModel&) = delete;
    NzImageModel& operator=(const NzImageModel&) = delete;

    // Per-codec profile, GDB-read at FUN_080a90c0's entry (obj+0x52940, the
    // planes' +0x1c08 order fields, and the bit-count objects' vtables):
    //     codec  flags  planes0-3  plane4  bitcount class
    //     -cc    0x0f      32        48    A (0x0813c848)
    //     -cO    0x0f      32        48    A
    //     -co    0x07      32        48    B (0x0813c860)
    //     -cd    0x02      16        16    (unused: flag bit 0 clear)
    //     -cf    0x00      16        16    (unused)
    // flag bit 0 = per-channel bit-count objects + FUN_0809bbf0 residuals (else
    // FUN_080a4ea0 + FUN_0809baa0); bit 1 = LMS planes; bit 2 = 4-stage cascade.
    void Configure(std::uint8_t flags, std::uint32_t order_planes0_3,
                   std::uint32_t order_plane4, bool bitcount_variant_b);

    // FUN_080b6170: the dispatcher's reset after every non-prefilter block (an
    // LZ or literal block; audio and image blocks leave it alone). The format
    // goes back to 1 x 1 x 1 and, if a chunk was committed since the last
    // reset, the rings, their indices and the shift tables are cleared too. The
    // object is NOT reset between chunks: an image's first block predicts from
    // whatever the previous image left in the rings.
    void Reset();

    // Decodes one block of `out_size` bytes (FUN_080a9ca0). Returns the number
    // of input bytes consumed, or 0 on malformed input (output is garbage then).
    std::size_t Decode(const std::uint8_t* in, std::size_t in_size,
                       std::uint8_t* out, std::size_t out_size);

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace audio
}  // namespace nzr
