#pragma once
#include <cstdint>

// Apply the NanoZip word-dictionary inverse transform (tt_flags & 0x08).
// in:         CM-decoded bytes (compressed dict stream, must end with 0x20)
// in_size:    size of CM-decoded data
// out:        output buffer (pre-allocated to allocated bytes)
// allocated:  capacity of out buffer
// Returns decoded size on success, 0 on error.
uint32_t NzTextTransformDict(const uint8_t* in, uint32_t in_size,
                             uint8_t* out, uint32_t allocated);

// Apply the NanoZip "escape + run-length repeat" inverse transform
// (tt_flags & 0x20). Ported from TransformText_4 in the community reference
// decoder (encode_su/nzdec_v0/src/NZ_TextTransforms.cpp) -- a pure byte
// post-filter with no side-channel data and no dependency on the entropy
// coder, so the reference source is directly usable here (same technique
// already used successfully for NzTextTransformDict/NzTextTransformNumber).
//
// Format: in[0] is the "escape" byte value. Bytes are copied verbatim until
// an occurrence of the escape byte is copied to `out`; the byte immediately
// following that occurrence in `in` (not yet consumed) is then a control
// byte: <=224 (except exactly 224) means "this escape occurrence was a
// literal byte" and just re-anchors the back-reference point at the current
// output position (the control byte itself is left unconsumed and copied
// normally on the next iteration); ==224 consumes the control byte and
// changes nothing else; >224 consumes it as a run-length command (value-224
// bytes, 1..31) that copies that many bytes forward from the last anchor.
// in:        CM-decoded bytes (escape+RLE stream)
// in_size:   size of CM-decoded data
// out:       output buffer (pre-allocated to allocated bytes)
// allocated: capacity of out buffer
// Returns decoded size on success, 0 on error (including any bounds
// violation -- callers must treat 0 as "decline", never trust a partial
// write).
uint32_t NzTextTransformRle(const uint8_t* in, uint32_t in_size,
                            uint8_t* out, uint32_t allocated);

// Apply the NanoZip "insert linefeed" inverse transform (tt_flags & 0x02).
// Ported from TransformText_3_InsertLF in the community reference decoder
// (encode_su/nzdec_v0/src/NZ_TextTransforms.cpp) -- an adaptive-model pure
// byte post-filter driven by its own dedicated side-channel (`tt2_data`,
// already parsed but previously discarded by the -cc/-co callers in
// sfx_archive.cpp). It runs its own embedded arithmetic decoder over `side`
// (the same ArithDec/InterpolateLut/CreateModelLut idiom already ported for
// tt16 in nz_texttransform_num.cpp, transcribed here rather than shared
// across translation units) to decide, position by position, whether a
// space/LF byte already copied through verbatim from `in` should instead be
// written as an inserted line-feed (10).
//
// This transform is byte-count-preserving: it only ever rewrites a byte
// already copied, never adds or removes one, so the output is always
// exactly in_size bytes. `allocated` must therefore be >= in_size or the
// call declines immediately.
//
// side/side_len : the tt2_data side stream (arith input).
// in/in_size    : the transform input (previous-stage output).
// out/allocated : output buffer + capacity.
// Returns in_size on success, 0 on error (including any bounds violation --
// callers must treat 0 as "decline", never trust a partial write).
// Requires NzCmInitAll() to have run (uses kModelInterpolation/kModelLutLookup).
uint32_t NzTextTransformInsertLf(const uint8_t* side, uint32_t side_len,
                                 const uint8_t* in, uint32_t in_size,
                                 uint8_t* out, uint32_t allocated);
