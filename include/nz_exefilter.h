#pragma once
#include <cstdint>
#include <memory>
#include <vector>

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

    // An upper bound on what Decode will write for this (side, in_size) pair.
    // Decode declines when it runs out of room, but its recent-target caches
    // are already mutated by then, so "try small, retry bigger" would decode
    // from the wrong state -- a caller has to size the output buffer correctly
    // the FIRST time, and this is what lets it size it from the BLOCK rather
    // than from the whole rest of the stream's output.
    static std::uint64_t DecodedSizeBound(const std::uint8_t* side, std::uint32_t side_len,
                                          std::uint32_t in_size);

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// The ENCODER of the same filter: `dece` of the -co family's compressor
// (reference FUN_08090360, called from the block analysis FUN_0808da10 when
// the exe metric fires).
//
// It walks the block and, at every CALL (0xe8), JMP (0xe9) and Jcc
// (0x0f 0x8x) whose 32-bit displacement fits in 25 bits, replaces the
// displacement with an arithmetic-coded decision: the target is either in a
// recent-target cache (a slot index) or new (written raw to a side area). The
// displacement bytes leave the payload, which is why the filtered block is
// SMALLER than the input and the decoder's output grows.
//
// Output layout, exactly what NzExeFilter::Decode expects:
//     [filtered instruction bytes][one add-esp byte per transformed call]
//     [4 big-endian bytes per NEW call target]
// and `side` gets the arithmetic stream followed by two varints (the two
// counts, which the decoder reads backwards off the tail).
//
// STATE LIFETIME: same rule as the decoder. One instance per stream, Encode()
// per block; Advance(n) with the block's UNFILTERED size after a block the
// filter was kept on, Reset() on any block it was not.
class NzExeFilterEnc {
 public:
    NzExeFilterEnc();
    ~NzExeFilterEnc();

    NzExeFilterEnc(const NzExeFilterEnc&) = delete;
    NzExeFilterEnc& operator=(const NzExeFilterEnc&) = delete;

    // The reference's side-stream budget for this filter: a fixed 0x108001
    // bytes of which only the first half may be written (measured at
    // FUN_08090360's descriptor, identical at every -m).
    static const std::uint32_t kSideCap = 0x108001u;

    void Reset();                       // FUN_080b98a0
    void Advance(std::uint32_t n);      // FUN_080b98e0: base = (base + n) & 0x7fffff

    // Returns the filtered length, or 0 when the reference would decline.
    // `out` and `side` are cleared and filled; `in` must not be `out`.
    std::uint32_t Encode(const std::uint8_t* in, std::uint32_t n,
                         std::vector<std::uint8_t>* out,
                         std::vector<std::uint8_t>* side);

 private:
    struct EncImpl;
    std::unique_ptr<EncImpl> impl_;
};
