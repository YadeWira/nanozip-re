#pragma once
#include <cstdint>

void NzCmInitAll();

struct NzCmDecoder;

NzCmDecoder* NzCmCreate(int a_bits, int b_bits, uint32_t window_size);
void NzCmDestroy(NzCmDecoder* cm);

void NzCmReset(NzCmDecoder* cm);

void NzCmDecode(NzCmDecoder* cm, const uint8_t* in, uint32_t in_size,
                uint8_t* out, uint32_t out_size);

// Feeds a single already-known byte through the CM context/prediction model
// (the same per-bit update path CM_Decode uses) WITHOUT consuming any
// arithmetic-coded input. This is needed to keep the model's rolling byte
// window/hash context in sync with the true decompressed-output position
// when a chunk in between two CM-coded blocks was emitted "stored" (raw,
// param6==0, e.g. incompressible data) rather than CM-arithmetic-coded: the
// original encoder's CM model observes every byte of the output stream in
// order, even ones it chose not to entropy-code. See TryDecodeLegacyCm in
// sfx_archive.cpp for the call site and the empirical differential trace
// that found this (integrty.doc real-file corpus regression).
void NzCmFeedByte(NzCmDecoder* cm, uint8_t byte);
