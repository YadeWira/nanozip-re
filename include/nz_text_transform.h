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

// tt_flags & 0x40: the chess/PGN transform (TransformText_6, FUN_080a3000).
//
// NOT in the community reference -- its body there is `assert(0); return 0;` --
// so this was decoded from (input, output) pairs plus the binary, and validated
// byte-exact on a 108 KB PGN file. Three token classes:
//
//   0xBE..0xFD  a board square -> two ASCII bytes:
//               i = b - 0xBE, file = 'a' + (i & 7), rank = '1' + ((i >> 3) & 7)
//   0xFE        the move number: the counter in decimal, then '.', counter++
//   0xFF <arg>  arg > 0x7f: emit `arg` verbatim -- the escape for a byte that
//               would otherwise read as a square or a token;
//               otherwise: emit '[' then copy a cached line up to and
//               including its ']'.
//
// The cache is 128 pointers, 2-way set-associative, all initialised to `out`.
// A literal '[' hashes the two bytes that follow it:
//     set = (((c0 + 15) & 15) * 4) + (c1 & 3)          (0..63)
// and stores the position just past the '[' in way 0, shifting way 0 into
// way 1. A back-reference reads slot `arg` directly, then updates the SET
// (arg & 0xfe) the same way -- so referencing way 1 does not preserve it.
// `]` and a back-reference both reset the move counter to 1; a literal number
// followed by '.' resyncs it to value + 1 by LOOKAHEAD (the digits themselves
// are emitted by the normal path).
uint32_t NzTextTransform6(const uint8_t* in, uint32_t in_size,
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

// tt bit 0x01: CR/CRLF line-ending restoration (reference
// TransformText_CR_to_CRLF, NZ_TextTransforms.cpp:402). Applied LAST in the
// text-transform chain, after 0x20 and 0x40.
//
// IMPORTANT: `out` must have room for out_cap + 1 bytes. The reference starts
// its output budget at out_cap + 1 and only notices the overrun after writing
// that extra byte, so a faithful port needs one byte of caller slack. The
// returned size never exceeds out_cap; a stream that would need more makes the
// function return 0 (decline), exactly as the reference does.
uint32_t NzTextTransformCrToCrLf(const uint8_t* in, uint32_t in_size,
                                 uint8_t* out, uint32_t out_cap);

// tt bit 0x04: HTML closing-tag restoration (reference HtmlTransformer,
// NZ_TextTransforms.cpp:781). The encoder shortens "</div>" to "</" and the
// decoder rebuilds the name from a stack of opened tags; a literal "</" in the
// source is escaped as "<//". Returns 0 on any inconsistency.
uint32_t NzTextTransformHtml(const uint8_t* in, uint32_t in_size,
                             uint8_t* out, uint32_t out_cap);
