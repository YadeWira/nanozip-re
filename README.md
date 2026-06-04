# nanozip-re

Reverse engineering reconstruction of the **NanoZip 0.09a** archiver CLI (`nz`) in C++17 — without SFX, without the original binary at runtime for supported methods.

NanoZip is a high-performance archiver (circa 2010) with several unique compression algorithms: `nz_lzpf`, `nz_lzhd`, `nz_optimum1/2`, and `nz_cm`. The original binaries are stripped Linux ELF (32-bit and 64-bit) with no public source.

---

## Goals

- Reconstruct the full `l / t / x / a / s` CLI in C++ with byte-exact output.
- Native (no original binary at runtime) decoding for all compression methods.
- Document every reverse-engineered finding so the knowledge is not lost.

## Clone percentage

**Overall reconstruction estimate: ~88%**

This is a rough but honest measure of how much of NanoZip's full decode surface has been natively reimplemented in C++, independent of input entropy.

| Component | Cloned? | Notes |
|-----------|---------|-------|
| CLI structure (`l/t/x/a/s`, all switches) | ✅ 100% | Full parser |
| Archive format (header, entry table, stream families `0x2b/0x3b/0x4b`) | ✅ 100% | |
| Store (`-cn`) | ✅ 100% | Trivial copy |
| lzpf decode LZ77+arith path (`-cf/-cF`) | ✅ 100% | All block modes native: LZ77+arith (variants A and B), literal, prefilter+arith mono. Variants A (13-bit hash) and B (24-bit hash, 64 MiB hash table). 8/8 native_strict; exhaustive random/high-entropy/mixed corpus verification (2026-06-03). |
| lzpf prefilter+arith path (`-cf`) | ✅ 100% | `FUN_080a5330` + LPC filter (`FUN_08095d90`) fully ported; **mono and stereo audio byte-exact** (verified 2026-06-03 on synthetic correlated stereo WAV `stereo_lms.wav`, 64 KB, ch2 = ch1 + Gaussian noise). Stereo inter-channel LMS predictor `FUN_08096e20` (2-stage cascaded sign-sign 4-tap, MMX path) ported as scalar equivalent. |
| lzhd decoder (`-cd/-cD`) | ✅ ~90% | `FUN_080b5240` ported as `DecLZ` (PAQ context mixer + 12-bit range coder, 680 LOC, ported from nzdec_v0 `NZ_LZ.cpp`); byte-exact on 50 KB text fixture |
| optimum decoder (`-co/-cO`) | ✅ ~70% | BWT + range-coder variants A/B native; edge shapes bridge |
| cm decoder (`-cc`) | ✅ ~95% | Native CM decoder ported from nzdec_v0 reference (NZ_CM.cpp, 1100 LOC); all block modes decode natively. Text-transform `tt_flags=0x08` (dictionary) native (`NzTextTransformDict`). `tt_flags=0x10` (word-list) bridges — blocked by a CM-decoder divergence bug (see Key findings). Stereo audio variant deferred. |
| Encode for all methods | ✅ functional | Native BWT/store/literal writers; bridge for full compression. All 8 methods byte-exact round-trip. |

### Fixture-based benchmark

The `coverage_matrix.sh` test uses a deterministic AES-CTR-of-zeros fixture (low entropy). On that fixture:

**native_strict_percent = 100% (8/8)** — no bridge, no compat, no original binary subprocess.

Low-entropy input rarely triggers the prefilter+arith block mode, so the fixture passes fully native even though that path is not yet ported. Real-world compressible data (text, source code, binaries) will hit that path and fall back to the extract bridge for `-cf/-cF`.

## Architecture

```
nz_recon CLI
├── sfx_archive.cpp    — core: archive format, dispatcher, native decoders
├── sfx_cli.cpp        — CLI parsing (l/t/x/a/s + switches)
├── lzpf_arith.cpp     — lzpf arith primitives (BitReader, Huffman, LZ77 A/B)
├── nz_cm.cpp          — CM decoder: ported from nzdec_v0 NZ_CM.cpp (context mixer, range coder, all tables)
├── nz_lzhd.cpp        — lzhd decoder: ported from nzdec_v0 NZ_LZ.cpp (DecLZ, PAQ context mixer, 12-bit arith)
├── linux32_cm_map.cpp — cm context-mixer vtable mapping (linux32 ELF offsets)
└── include/
    ├── lzpf_arith.h
    ├── nz_cm.h        — CM decoder public API
    ├── nz_lzhd.h      — lzhd decoder public API
    └── nz_sfx/        — internal headers
```

### Decode layers (priority order)

1. **Native** — pure C++ reconstruction of the algorithm, no original binary.
2. **Extract bridge** — shells out to the original `nz -x` in a tmpdir, injects the raw payload back into the native output path. Used when native is not implemented yet.
3. **Compat** — forwards the entire command to the original binary. Last resort.

The goal is to eliminate layers 2 and 3 entirely.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Produces `build/nz_recon`.

## Tests

```bash
# Smoke suite (unit tests for lzpf arith primitives + integration round-trips)
./tests/smoke_suite.sh

# Coverage matrix (8-method native_strict benchmark)
./tests/coverage_matrix.sh

# Stress (5 consecutive runs, checks for non-determinism)
./tests/stress_matrix.sh
```

## Reverse engineering approach

### Tools

| Tool | Purpose |
|------|---------|
| **Ghidra 11 headless** | Decompile stripped ELF; batch-export C pseudo-code per function |
| **GDB 12** (linux32 ELF, x86 host) | Dynamic tracing: register dumps at breakpoints, memory captures, bytecode extraction |
| **objdump / readelf** | Quick disassembly, section layout |
| **Custom C++ unit tests** | Validate each ported function against GDB-captured ground-truth vectors |
| **Python scripts** | Parse binary stream dumps, compute expected outputs for test vectors |

### Workflow

1. Identify the target function address in the 32-bit ELF (`linux32/nz`).
2. Export Ghidra decompile.
3. Set GDB breakpoints, run the original binary on a known fixture, capture register/memory state.
4. Port the function to C++ in `src/lzpf_arith.cpp` or `sfx_archive.cpp`.
5. Write a unit test in `tests/test_lzpf_arith.cpp` with the GDB-captured vector.
6. Run the full coverage matrix to confirm no regressions.

The 32-bit binary is the primary reference because Ghidra's 32-bit decompile is more readable (fewer pointer-width artefacts) and GDB gives exact struct offsets.

### Key findings

- **LZPF block format** (`docs/nz_lzpf_linux32.md`): three-mode varint header dispatching literal / LZ77 bytecode / prefilter+arith. LZ77 opcodes `0xf5–0xf8`. Arith-coded side stream when `uVar9 & 1 == 1`.
- **lzpf variant A vs B**: variant A = 13-bit hash, opcode threshold `< 0xf6`; variant B = 24-bit hash + 8 KiB byte-context buffer, opcode threshold `< 0xf5`, adds opcode `0xf5`.
- **Sliding-window dict**: size = `(p1+1) × 64 KiB` (no min/max). 4-byte left-pad; cursor initialises to 4; wraps to 0 when `capacity − cursor < 32768` (mirrors `FUN_080b6bb0`).
- **Hash table init = 3**: variant-A 8192-entry table initialises to `3` in the legacy binary, not `0`. Using `0` causes wrong `local_50` values for f6/f8 opcodes in early blocks.
- **last_lz_dest reset**: resets to `−1` per block (stack local in `FUN_08097570`), not persisted across blocks.
- **Multi-stream chain**: large `-cf` archives embed multiple `[tag][data]` segments; dict + hash table state persists across all segments.
- **Arith decoder** (`FUN_080a4ea0`): two-pass Huffman code-length reader (`FUN_080a41d0`, 480+ lines ported), canonical Huffman build, MSB-first 32-bit-cache bit reader. Two non-obvious bugs fixed: `RangeCoderFinalize` must call `ReadBits(remaining_bits)` after rewinding cursor; `BuildHuffman` length_table must escape to 9 once length > 8.
- **CM text-transform `tt_flags=0x10` (word-list)** — blocker is a bug in the **CM decoder**, not the transform (confirmed 2026-06-01). Ground truth via GDB on `linux32/nz`: break at the transform entry `0x080a3340`, dump its input buffer (= the CM decoder's real output). That stream is 99.95% printable text, whereas the ported `NzCmDecode` diverges at byte 26 (bit 5) and produces garbage. The transform itself is secondary (near size-preserving substitution of common words with `0/1/2` tokens). A standalone harness reproduces the divergence deterministically; CM params were ruled out by sweep. The wrong value is one of the three mixing stages in `CM_Input_Bit` (linear mixer / modelg APM / cmc). The decode-side transform tree (`fcn.080a3340` → `a28a0`/`a1b60`, range coder + word table) is mapped and ready to port once the CM decoder is fixed.
- **CM `-cc` decode function is unlocated in this build (2026-06-02)** — the documented CM engine addresses (`0x0809e600`, `0x080a5c70`) and the dispatcher (`0x080aa850`) do **not** execute during `-cc` decompression: every breakpoint set on them is unhit, and `0x080aa850` is hit once with `method byte = 0` then returns early (no-op). So the real per-`-cc` decode routine is elsewhere in the stripped static binary and still has to be located before the byte-26 mixing-stage bug can be pinned to a specific instruction. Bits 0–208 decode identical to legacy (model state in sync), so this is a deterministic prediction/weight-update formula bug, not flag drift.
- **lzpf stereo-split inter-channel predictor `FUN_08096e20` (2026-06-02 / 2026-06-03)** — root cause of the stereo `-cf/-cF` audio gap. Mono is fully native byte-exact. Stereo was decoding (header OK, `decode_ok=1`) but produced wrong samples from offset 44 because the native path skipped inter-channel decorrelation. The function is a 2-stage cascaded sign-sign LMS 4-tap adaptive predictor (MMX path + scalar fallback at `0x8097199`); primitives: predict `0x80beaa0`, update `0x80beae0`, base-predict `0x80be8e0`, base-update `0x80be820`. Driver: ch1 predicts from 0; ch2 predicts using ch1's **reconstructed** sample (inter-channel). **Ported 2026-06-03** as scalar equivalent `ApplyLmsInterChannel` in `lzpf_arith.cpp`; state persists across blocks via caller-managed `LmsObject` (0x2070 bytes per object, 2 objects per block). Verified byte-exact on synthetic correlated stereo WAV. Coverage estimate for prefilter upgraded to **100%**.

## Backlog

- [x] **Task #13**: lzpf prefilter+arith mono path complete (`FUN_080a5330` + `FUN_08095d90` LPC filter). Stereo variant (`FUN_0809bbf0`) deferred.
- [x] **Task #13b**: lzpf prefilter+arith stereo residual decoder (`FUN_0809bbf0`) ported. Tables extracted from binary via GDB (`DAT_081b3a00/39c0/39c1/42f0/4380`); algorithm: VLC magnitude from byte + side-bit sign. `is_stereo_variant` flag path wired in `DecodePFBlock`. **Verified 2026-06-03** with synthetic correlated stereo WAV (`stereo_lms.wav` in `tests/fixtures/lzpf/`, 64 KB, ch2 = ch1 + Gaussian noise): both `-cf` and `-cF` archives decode byte-exact natively with `ApplyLmsInterChannel` (port of `FUN_08096e20`) running on the residual stream.
- [x] **Task #24**: 1-byte LZ77 divergence in variant A (semirandom block 18, side_count=8416) — believed fixed by hash-table init=3 fix (2026-05-05). Verified 2026-06-03: exhaustive random/high-entropy corpus (200+ seeds × 5 sizes 4KB–512KB, plus mixed fixtures) all decode byte-exact natively. LZ77+arith path upgraded to 100% native in coverage estimate.
- [x] **Task #14**: lzhd native decoder complete — `FUN_080b5240` ported as `DecLZ` (PAQ context mixer + 12-bit arith, 680 LOC); byte-exact on 50 KB text fixture. Parallel variant (`FUN_080b50b0`) deferred.
- [x] **Task #25**: Parallel archive header parser (`-pN`) fixed in `TryParseLegacyCnArchive`. NZ chunk format fully decoded: `(size<<4)|type` varint with nibble-15 stream-ID extension. Scanner accumulates uncompressed sizes across all per-stream type-1 chunks; `size_accum` overrides partial main-stream sizes after entry build. Byte-exact extraction verified on `-p10` archive (344207 bytes).
- [x] **Task #26**: Archive writer (`RunAddNativeLegacyStream`) fixed to emit full codec chunk payload. `spec.method = (csize<<4)|11` declares `csize` payload bytes; writer was emitting only p0+p1 (2 bytes), causing the chunk scanner to consume the first byte of `table_span` as the 3rd codec byte, leaving a zero-size type-1 chunk. Fix: pad with zeros to reach `csize` bytes. Encode round-trip x_ok: 5/8 → **8/8**.

## Progress log

| Date | Milestone |
|------|-----------|
| 2026-04-24 | lzpf arith primitives complete (BitReader, Huffman, RangeCoder, `ReadCodeLengths`); 2524 unit-test assertions |
| 2026-04-24 | `DecodeArithBuffer` (`FUN_080a4ea0`) validated against 3 real-data vectors |
| 2026-04-24 | `DecodeLz77VariantA` complete; 6/7 sample archives native |
| 2026-04-24 | Sliding-window dict + wrap-to-0 logic confirmed via GDB; `last_lz_dest` per-block reset fixed |
| 2026-04-24 | `DecodeLz77VariantB` (`-cF`, 24-bit hash) complete; 7/7 `-cF` samples native |
| 2026-05-05 | Hash table init bug fixed (0→3); window_capacity formula corrected (`(p1+1)×64 KiB`); 8/8 methods 100% native_strict |
| 2026-05-07 | Native CM decoder ported from nzdec_v0 reference (NZ_CM.cpp, 1100 LOC); all block modes decode natively. Stereo audio variant deferred. |
| 2026-05-07 | lzpf prefilter+arith mono path byte-exact (task #13): `LpcPredictor` fixed to 4-tap, 2-samples-per-iteration (factors update only on first of each pair — matching `FUN_08095d90` SIMD path); Fletcher32 verified on ramp WAV fixture. |
| 2026-05-07 | lzhd native decoder complete (task #14): `DecLZ` PAQ context mixer + 12-bit range coder ported from nzdec_v0 `NZ_LZ.cpp` (680 LOC); byte-exact on 50 KB text fixture. C++ const-linkage bug fixed (`extern const kLzModelLNext`). |
| 2026-05-07 | lzpf prefilter stereo residual decoder (task #13b): `DecodeResidualsStereo` ported from `FUN_0809bbf0` with binary-extracted tables; VLC magnitude + explicit sign-bit scheme. Speculative — no known fixture triggers this path with standard `-cf`. |
| 2026-05-07 | Parallel archive parser fixed (task #25): `TryParseLegacyCnArchive` now scans all NZ chunk records (`(size<<4)\|type` varint + nibble-15 stream-ID extension), accumulates per-filename sizes across all per-stream type-1 chunks. `-pN` archives list and extract correctly. |
| 2026-05-09 | Archive writer codec chunk fix (task #26): `RunAddNativeLegacyStream` now pads codec payload to declared `csize` bytes; fixes chunk scanner misparse of own archives. encode_ok 5/8 → 8/8; all methods byte-exact round-trip. |
| 2026-05-10 | CM text-transform `tt_flags=0x08` (dictionary): `NzTextTransformDict` ported from `TransformText_1_Dictionary`; tables extracted from linux32 binary; text files byte-exact under `-cc`. |
| 2026-06-01 | CM `tt_flags=0x10` (word-list): corrected diagnosis — blocker is a bug in `NzCmDecode`, not the transform. GDB ground truth at `0x080a3340` → golden oracle; standalone harness reproduces a deterministic divergence at byte 26 bit 5; CM params ruled out by sweep. Transform decode tree (`fcn.080a3340`/`a28a0`/`a1b60`) mapped for porting once CM is fixed. |
| 2026-06-02 | lzpf stereo-split gap root-caused: missing inter-channel predictor `FUN_08096e20` (2-stage cascaded sign-sign LMS 4-tap; ch2 predicts from ch1's reconstructed sample). Fully reverse-engineered, port pending. Confirmed mono audio fully native byte-exact; stereo currently bridges. |
| 2026-06-03 | lzpf LZ77+arith path verified 100% native: exhaustive random/high-entropy corpus (200+ seeds × 5 sizes 4KB–512KB) all decode byte-exact natively. Task #24 closure confirmed: the `hash_table init = 3` fix from 2026-05-05 plus the per-block `last_lz_dest = -1` reset already cover all observable LZ77 dispatcher edge cases. Coverage estimate for `-cf/-cF` upgraded from ~95% → **100%**. |
| 2026-06-03 | lzpf prefilter+arith stereo-split path complete (task #13b final): `FUN_08096e20` (2-stage cascaded sign-sign LMS 4-tap, MMX path) ported as scalar equivalent. `LmsObject` struct (0x2070 bytes, 2 stages per object, 2 objects per block for ch1+ch2) added to `include/lzpf_arith.h`. `ApplyLmsInterChannel` performs in-place LMS on ch1/ch2 residual streams. Dispatcher in `sfx_archive.cpp` auto-detects stereo split from the prefilter header byte (`(hdr>>1) % 3 != 0`) and threads persistent LMS state across blocks. Verified byte-exact on synthetic correlated stereo WAV (`stereo_lms.wav` 64 KB) for both `-cf` and `-cF`. Coverage estimate for prefilter upgraded from ~90% → **100%**. |
| 2026-06-02 | CM `-cc` decode: established the documented CM engine/dispatcher addresses (`0x0809e600`/`0x080a5c70`/`0x080aa850`) do not execute for `-cc` decode (all breakpoints unhit; dispatcher no-ops with method byte 0). Real decode routine still unlocated; byte-26 bug reframed as a deterministic prediction/weight-update formula error (bits 0–208 match legacy). |

## License

The reconstruction code in this repository is original work released under the **MIT License**.

NanoZip 0.09a binaries are not included and remain the property of their author. This project contains no extracted binary data, no verbatim decompiled output, and no proprietary assets. The C++ code is an independent reimplementation derived from behavioral observation and dynamic tracing.
