#pragma once
#include <cstdint>
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

}  // namespace audio
}  // namespace nzr
