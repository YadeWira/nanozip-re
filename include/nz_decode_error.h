// The original's decode error channel, reproduced.
//
// Every codec object of the original returns a small STATUS from its stream
// step (vtable +0x14); the extraction driver prints it as
//   "Archive corrupted. Error decoding (code N)"
// either plain (a later record made the driver notice it) or as N<<8 | slot
// (the failing record was the last one, or the input ended). Assertions inside
// the engines call a fatal handler that prints "Internal error: <id>!" and
// exits with -1. See ~/.cache/nzre_tools/cli_parity/ERROR_CODES.md for the
// per-codec tables (GDB + Ghidra, 2026-09-04).
//
// The decoders record the status here, per thread, at the point of failure;
// the layer that adopts the failure copies it into the context.
#ifndef NZ_DECODE_ERROR_H
#define NZ_DECODE_ERROR_H
#include <cstddef>
#include <cstdint>
namespace nzr {
namespace derr {
struct State {
    std::uint32_t code = 0;       // the original's status (0 = none recorded)
    std::uint32_t fatal_id = 0;   // "Internal error: <id>!" assertion id (0 = none)
    std::size_t input_pos = 0;    // input offset of the failing block, when known
    bool has_pos = false;
    bool parallel = false;        // failure of one worker stream of a parallel container
    std::size_t slot = 0;         // that stream's slot (the original's low report byte)
};
inline thread_local State t_state;
inline void Clear() { t_state = State{}; }
inline void Set(std::uint32_t code) {
    if (t_state.code == 0u && t_state.fatal_id == 0u) t_state.code = code;
}
inline void SetAt(std::uint32_t code, std::size_t input_pos) {
    if (t_state.code == 0u && t_state.fatal_id == 0u) { t_state.code = code; t_state.input_pos = input_pos; t_state.has_pos = true; }
}
inline void Fatal(std::uint32_t id) { if (t_state.fatal_id == 0u) t_state.fatal_id = id; }
inline const State& Current() { return t_state; }
// The CM/optimum family's per-stage check bytes: the stage that fails names the code.
inline std::uint32_t StageCode(const char* stage) {
    switch (stage[0]) {
        case 'p':
            if (stage[1] == 'a') return 100u;   // payload
            if (stage[1] == '1' && stage[2] == '4') return 104u;
            if (stage[1] == '1' && stage[2] == '5') return 105u;
            if (stage[1] == '2') return 107u;
            if (stage[1] == '1') return 108u;
            return 100u;
        case 'l': return 101u;                     // lz (raw-flag engine output)
        case 'c': return 101u;                     // cm engine output
        case 'b': return (stage[3] == 'i') ? 102u : 103u;   // bwtin / bwt
        case 't': return 109u;                     // tt
        case 'd': return 111u;                     // dece
        default: return 100u;
    }
}
}  // namespace derr
}  // namespace nzr
#endif
