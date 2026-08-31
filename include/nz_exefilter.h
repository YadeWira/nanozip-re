#pragma once
#include <cstdint>
#include <memory>

// dece post-filter: x86 CALL/JMP address un-relativiser, ported from the
// community reference decoder (nzdec_v0 NZ_x86.cpp, ExeFilter).
//
// It is the LAST step of the post-filter chain (reference DecodeFromStream:
// param2 -> param1 -> text transforms -> dece). The encoder rewrites the
// 32-bit displacement of every CALL (0xe8), JMP (0xe9) and Jcc (0x0f 0x8x)
// into an absolute-ish form that compresses far better, and drops the
// displacement bytes plus an optional "add esp, imm8" tail into side streams;
// this puts them back.
//
// STATE LIFETIME -- the reference gets this wrong. It writes
//     size = ExeFilter().Decode(...)
// i.e. a TEMPORARY, so the recent-target caches reset on every block and its
// exe_base_ is stuck at 0. That is only correct while no two dece blocks are
// adjacent. Measured against real archives, the reference model produces wrong
// bytes on 22 of 88 dece archives; the model that is exact everywhere is:
//
//   * the recent-call/recent-jump caches and the base persist across a RUN of
//     consecutive dece blocks;
//   * the base counts the output bytes produced so far BY THAT RUN;
//   * everything resets as soon as a block without dece intervenes.
//
// The per-block probability models are NOT part of that state: they are locals
// of the reference's Decode and stay fresh on every call in every model.
//
// So the caller keeps one instance per stream, calls Decode() for each dece
// block, and Reset() on any block that has no dece field. Parallel-container
// streams each need their own instance -- the base counts stream-local output,
// not the file-absolute offset. Member/file boundaries inside one stream do
// NOT break a run.
//
// Output GROWS relative to input (each restored displacement adds 4 bytes, and
// an add-esp adds 3 more), so `out_cap` must be the room actually available.
//
// Decode returns false on any malformed or inconsistent input, leaving
// *out_size unset; the caller declines rather than emitting partial output.
// `in` and `out` must not overlap.
class NzExeFilter {
 public:
    NzExeFilter();
    ~NzExeFilter();

    NzExeFilter(const NzExeFilter&) = delete;
    NzExeFilter& operator=(const NzExeFilter&) = delete;

    // Ends the current run: restores the identity recent-target caches and
    // zeroes the base. Call this for every block that carries no dece field.
    void Reset();

    // Decodes one dece block and advances the run's base by the bytes produced.
    bool Decode(const std::uint8_t* side, std::uint32_t side_len,
                const std::uint8_t* in, std::uint32_t in_size,
                std::uint8_t* out, std::uint32_t out_cap, std::uint32_t* out_size);

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
