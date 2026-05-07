#pragma once
#include <cstdint>

void NzCmInitAll();

struct NzCmDecoder;

NzCmDecoder* NzCmCreate(int a_bits, int b_bits, uint32_t window_size);
void NzCmDestroy(NzCmDecoder* cm);

void NzCmReset(NzCmDecoder* cm);

void NzCmDecode(NzCmDecoder* cm, const uint8_t* in, uint32_t in_size,
                uint8_t* out, uint32_t out_size);
