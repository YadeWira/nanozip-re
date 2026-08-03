// nz_bwt.cpp — NanoZip decr_param == 0 ("BWT") block decoding, ported from the
// community reference decoder (nzdec_v0 NZ.cpp). Faithful reimplementation.
#include "nz_bwt.h"

#include <cstring>
#include <vector>

// BwtUntransform (reference NZ.cpp:645). The reference has two code paths --
// one for data_size >= 0x1000000 that keeps a separate copy of the input and a
// table of plain indices, one below that which packs the byte and the index
// into a single u32 (byte | index << 8). They compute the same permutation;
// the packed form is only an allocation optimisation, and it silently caps the
// addressable index at 2^24. This port always uses the general form.
//
// The reference also aliases its index table onto the bytes just past `data`
// (`(uint32*)((data + data_size + 3) & ~3)`), which requires every caller to
// have over-allocated by 4*data_size + 3. That coupling is not worth
// replicating: this port owns its scratch buffers, so a caller only has to
// provide the block's own bytes.
bool NzBwtUntransform(uint8_t* data, uint32_t data_size, uint32_t bwt_pos) {
    if (data_size == 0u) return true;
    // The reference reads table[bwt_pos] unchecked on the first iteration; a
    // corrupt or misparsed header would walk off the table. Decline instead.
    if (bwt_pos >= data_size) return false;

    uint32_t byte_count[256];
    std::memset(byte_count, 0, sizeof(byte_count));
    for (uint32_t i = 0; i != data_size; ++i) byte_count[data[i]]++;
    uint32_t sum = 0;
    for (uint32_t i = 0; i != 256u; ++i) {
        const uint32_t t = byte_count[i];
        byte_count[i] = sum;
        sum += t;
    }

    std::vector<uint8_t> source(data, data + data_size);
    std::vector<uint32_t> table(data_size);
    for (uint32_t i = 0; i != data_size; ++i) table[byte_count[source[i]]++] = i;

    for (uint32_t i = 0; i != data_size; ++i) {
        const uint32_t v = table[bwt_pos];
        data[i] = source[v];
        bwt_pos = v;
    }
    return true;
}
