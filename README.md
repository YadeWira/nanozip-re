# nanozip-re

Reverse engineering reconstruction of the **NanoZip 0.09a** archiver CLI (`nz`) in C++17 — without SFX, without the original binary at runtime for supported methods.

NanoZip is a high-performance archiver (circa 2010) with several unique compression algorithms: `nz_lzpf`, `nz_lzhd`, `nz_optimum1/2`, and `nz_cm`. The original binaries are stripped Linux ELF (32-bit and 64-bit) with no public source.

---

## Goals

- Reconstruct the full `l / t / x / a / s` CLI in C++ with byte-exact output.
- Native (no original binary at runtime) decoding for all compression methods.
- Document every reverse-engineered finding so the knowledge is not lost.

## Decode coverage (measured, no bridge)

### Measured native decode (no bridge)

The honest metric is how much decodes **byte-exact with no original binary at runtime**.
`tests/native_only_v2.sh` runs extraction under `NZ_NO_BRIDGE=1` (which disables the
legacy `nz` fallback entirely) and diffs against the legacy oracle. On a mixed
corpus (random, text, source, repeats, zeros, audio; 10 fixtures × 8 methods):

| method | native byte-exact | method | native byte-exact |
|--------|-------------------|--------|-------------------|
| `-cn` (store)      |  9/10 | `-cd` (lzhd)        | 9/10 |
| `-cf` (lzpf A)     | 10/10 | `-cD` (lzhd big)    | 6/10 |
| `-cF` (lzpf B)     |  8/10 | `-co` (optimum1)    | 3/10 |
| `-cc` (cm)         |  9/10 | `-cO` (optimum2)    | 3/10 |

**≈ 57/80 (~71%) byte-exact native, zero bridge.** This synthetic corpus is harsh on
`-cd`/`-cD`: its fixtures include multi-region text and stereo audio. `-cd` is native on a
varied real corpus (10/10 on the elf/map/image/atoll + f-series unit-fixture set) plus
multi-chunk text (text_50k/repeat_100k/CRLF) and large multi-stream files (e.g. a 7-chunk
source file and 2–3.5 MB code/text/base64). The non-native cases fall to the extract
bridge (legacy `nz`) and are the known gaps below. `-cn`/`-cf`/`-cF`/`-cc` are native for
typical real inputs; `-cd`/`-cD` are native for LZ, block-RLE, raw-store, pure-literal, exe,
the text pipeline (param14, line-RLE, CRLF, word-dictionary), multi-chunk text and large
multi-stream files (2–3.5 MB code/text/base64, incl. heavily-repetitive input) — and
bridge only on rare CM/BWT sub-chunks; `-co`/`-cO`
(large) bridge on the virtual-stream LZ framing. Counts vary ±1 because the corpus uses
random fixtures.

> The older `tests/native_only.sh` is a **false positive**: it checks byte-exact
> equality but does NOT verify the bridge was avoided (`FindLegacyBackend` silently
> finds a system `nz` in `$PATH`). Use `native_only_v2.sh` + `NZ_NO_BRIDGE=1` for the
> real figure.

**Known gaps where the bridge is invoked at runtime** (the bridge produces byte-exact output but the C++ does not decode these paths natively):
- `lzpf` **`-cF` (lzpf B) stereo** audio: the `-cf` (lzpf A) stereo prefilter is now native end-to-end (see the component table), but `-cF` uses a different arith decoder (the `*param_1&1` vtable path in `FUN_080a5330`, not `FUN_080a4ea0`) and still bridges for compressed stereo.
- `lzhd` (`-cd/-cD`): the coroutine token-LZ is native incl. multi-chunk text and large multi-stream files (see the component table). The LZ window is a single per-archive ring whose size the encoder sets to `round(total_output / 0x10000) · 0x10000` (min 64 KB; modular helpers so non-power-of-two sizes work) — confirmed by GDB on `FUN_08099050` (obj+0x978): `1/3/19/46 × 64 KB` for text50/source.cpp/big_code/repeat_3M. The ring is sized to hold the whole compact recon, so its cursor advances monotonically and never wraps for real archives; it persists across the archive's 1 MB output streams. The decoder still self-verifies against the stored per-file checksum and bridges on any mismatch (defense in depth). Remaining bridge cases: rare CM/BWT `-cd` sub-chunks.
- large `optimum` (`-co/-cO`): the LZ payload is delivered through a **virtual-stream framing** (not the flat `payload_size` header). The ported `DecLZ` is byte-exact-faithful to the reference, but a flat call on the virtual-stream framing wild-reads (the reference `nzdec_v0` decoder also SIGSEGVs on these), so large blocks bridge until the arith-byte-sequence extraction is reverse-engineered. (Small flat `-co/-cO` blocks decode natively.)
- `cm` stereo audio variant deferred; `param1` (AddBytes) / `dece` (exe-filter) post-filters not yet ported (rare).

**Work to reach 100% native decode** (no runtime bridge):
1. ✅ Done: `NZ_NO_BRIDGE=1` flag — when set, `FindLegacyBackend*` return empty and a missing native path is a hard error (no silent `$PATH`/`/usr/bin/nz` fallback). This is what `native_only_v2.sh` uses to measure honestly.
2. ✅ Done: the `-cd` cross-chunk / cross-stream LZ window. It is a single per-archive ring of size `round(total_output / 0x10000) · 0x10000` (min 64 KB; GDB-confirmed on `FUN_08099050` obj+0x978) that persists across the archive's 1 MB output streams (`NzCdDecodeStream` threads the ring position and the file-absolute output offset). The ring is sized to hold the whole compact recon, so it never wraps for real archives. This made multi-chunk text and large multi-stream files (a 7-chunk source file; 2–3.5 MB code/text/base64 incl. heavily-repetitive input) byte-exact native, with a checksum self-verify → bridge fallback as defense in depth.
3. Reverse-engineer the **virtual-stream LZ framing** (the arith byte sequence the linux32 stream object behind vtable `0x08132d48` delivers) for large `-co`/`-cO`. The `DecLZ` port is already faithful, so this piece unblocks large `optimum`.
4. Port the remaining rare post-filters (`param1` AddBytes, `dece` exe-filter) and the CM stereo-audio variant.

| Component | Cloned? | Notes |
|-----------|---------|-------|
| CLI structure (`l/t/x/a/s`, all switches) | ✅ 100% | Full parser |
| Archive format (header, entry table, stream families `0x2b/0x3b/0x4b`) | ✅ 100% | |
| Store (`-cn`) | ✅ 100% | Trivial copy |
| lzpf decode LZ77+arith path (`-cf/-cF`) | ✅ native (≈9/10, 8/10 measured) | LZ77+arith (variants A 13-bit hash, B 24-bit hash) + literal block modes native. Native byte-exact on most real inputs under `NZ_NO_BRIDGE=1`; a minority bridge (prefilter+arith / multi-stream paths). The "8/8 100%" figure is from the low-entropy `coverage_matrix.sh` fixture only and does NOT reflect real data — see the measured table above. Variant B hash init=3 fix (commit `049d041`) closed the multi-file silent corruption. |
| lzpf prefilter+arith path (`-cf`) | ✅ mono + stereo native | `FUN_080a5330` + LPC filter (`FUN_08095d90`) ported; **mono AND stereo audio byte-exact**. The stereo path was closed end-to-end (`stereo_lms_cf.nz` → `stereo_lms.wav`, both blocks byte-exact, `-cf` `native_only_v2` 9/10→10/10). The full `FUN_080a5330` stereo flow is now reproduced in `DecodePFBlock`: residuals are **PLANAR** (ch1=`[0,per_chan)`, ch2=`[per_chan,2·per_chan)`) decoded by **two per-channel `DecodeArithBuffer` calls** (each reads its own Huffman header — a single `n_elems` call mis-locates the side stream by ~1.4 KB); the predictor-init reads a leading bit G (`iStack_50078`, gates the inter-channel LMS) then per channel `[active(1), order(3 if active)]` (order = bits+8); **per-channel LPC** with two persistent predictor states (`pred`/`pred2`, threaded across blocks); the verified inter-channel LMS `FUN_08096e20` (`ApplyLmsInterChannel`, regression test `TestLmsInterChannel`); and `FUN_080a50c0` reconstruction (`ReconstructStereoSamples`: per-channel delta-integrate + L/R (`channels==1`) or mid/side (`channels==2`) interleave). The `-cF` (lzpf B, `*param_1&1` vtable arith path) stereo variant still bridges. |
| lzhd decoder (`-cd/-cD`) | ✅ LZ + block-RLE + raw-store + pure-literal + exe + text-pipeline (param14/line-RLE/CRLF/word-dict) + multi-chunk text + large multi-stream files native; only rare CM/BWT sub-chunks bridge | The real linux32 `-cd` is a coroutine token-LZ (NOT the reference `DecLZ`). Fully ported in `nz_cd_tokens.{h,cpp}` and **validated byte-exact** against the binary: token assembler (`FUN_080aa070`), reconstruction with trailing-literal flush (`FUN_08099050`), per-column RLE run-expander (`FUN_080acb90`, thr=1 for the LEN column / 0 for LIT·OFF), param14 text transform (`FUN_080a0ff0`), the bounded-varint header (`FUN_080b1dc0`), and the integrated chunk/stream/block decoders (`NzCdDecodeLzChunk`/`NzCdDecodeStream`/`NzCdDecodeBlock`). Columns/literals reuse `DecodeArithBuffer`. The reconstruction runs over a **single per-archive ring** (`FUN_08099050`, obj+0x978) whose size the encoder sets to `round(total_output / 0x10000) · 0x10000` (min 64 KB) — GDB-confirmed across text50/source.cpp/big_code/repeat_3M = `1/3/19/46 × 64 KB`. The size need not be a power of two, so the ring uses **modular** helpers (not a bitmask). The ring is sized to hold the whole compact recon, so its cursor (obj+0x980) advances monotonically and **never wraps for real archives** (the reset/wrap path is a safety fallback). Large files split their output into **1 MB streams**; the ring is allocated once and **persists across streams** (`NzCdDecodeStream` threads `ring_pos` and the file-absolute output offset), so cross-stream matches resolve correctly. **Wired into the extract dispatcher** and BYTE-EXACT end-to-end under `NZ_NO_BRIDGE=1` for: token-LZ (recon == file), **block-RLE** (flag `&2`, post-recon run-length re-expansion of collapsed zero-runs), **raw-store** (per-column `b0&1==0` and flag-`&1`-clear literals = verbatim bytes), **pure-literal** (no LZ tokens — the whole window is one literal stream; generator picks this when `size_field==0` or `v2==0`), **exe** (flag `&4`: a BCJ-style x86 E8/E9 call/jmp address un-transform, `NzCdExeUnfilter`), and the **text pipeline** (flag `&8`, `FUN_080a3c90`): param14 (`NzCdParam14`), line-RLE (`FUN_080a2f20`), CRLF EOL (`FUN_080a19b0`), and the **word-dictionary** transform (`FUN_080a0a00` = the reference `TransformText_1_Dictionary` + dict/char-trait tables, in `nz_cd_texttransform_dict.cpp`). Verified on text (map.txt), binary (image.cat), an ELF (elf.bin, flags=3 block-RLE), an EXE (play.exe, flags=5), atoll (multi-chunk `&8`), word-dictionary text, multi-chunk text (text_50k/repeat_100k/CRLF), a 7-chunk source file (single-stream 192 KB ring), large multi-stream files (2–3.5 MB code/text/base64, incl. heavily-repetitive input), and a varied real corpus spanning images/audio/video/executables. As defense in depth `TryDecodeLegacyLzhd` **self-verifies the decoded output against the archive's stored per-file checksum** and returns false on mismatch, so any unforeseen edge falls through to a byte-exact bridge decode (no silent corruption, and `NZ_NO_BRIDGE` native-only is a provable correctness signal). Remaining bridge cases: rare CM/BWT `-cd` sub-chunks. The old `DecLZ` (`nz_lzhd.cpp`, nzdec_v0) is the wrong format for linux32 `-cd`. |
| optimum decoder (`-co/-cO`) | ⚠️ small native / large bridge | `-co/-cO` use **DecLZ** (not BWT). Small blocks use a flat `payload_size` framing and decode natively (DecLZ + `kReorderAscii` + tt08/tt16); large blocks use the virtual-stream LZ framing (shared `-cd` blocker, see gaps) and bridge. |
| cm decoder (`-cc`) | ✅ native byte-exact | Native CM decoder (NZ_CM.cpp, 1100 LOC). **The documented "byte-26" divergence is FIXED (2026-06-08)**: it was a one-line port error in `CM_Input_Bit` — `factors0_err` used truncating `factors[0] / 16` instead of the reference arithmetic shift `factors[0] >> 4` (differs for negative values, flipping the `factor[7]` zeroing condition). Found by a per-bit `next_probability` diff vs a compiled reference oracle. With the full post-filter pipeline ported — param2 RLE (`NzBwtRleDecodeU32`), param1 AddBytes delta filter (`NzAddBytesFilter`), tt08 dictionary, tt16 number-transform (`NzTextTransformNumber`) — plus **multi-chunk** decoding (CM state persists across consecutive type-0 chunks) and **stored blocks** (`param6==0` = raw payload, for incompressible data), `-cc` decodes byte-exact natively (no bridge) on source, numbers, dates, IPs, prose, markdown, random/large multi-chunk: 13/13 on a comprehensive sweep, 9/10 on `native_only_v2` (the one miss is the deferred stereo audio-CM variant). |
| Encode for all methods | ⚠️ functional | Native BWT/store/literal writers; the legacy compression bridge was disabled in commit `049d041` (`IsInternalLegacyCompressionBridgeCompressor` returns false unconditionally). Codecs the native encoder cannot handle now produce an explicit error. All 8 methods byte-exact round-trip via the native encoder for low-entropy inputs. |

### Fixture-based benchmark

The `coverage_matrix.sh` test uses a deterministic AES-CTR-of-zeros fixture (low entropy). On that fixture:

**native_strict_percent = 100% (8/8)** — no bridge, no compat, no original binary subprocess.

Low-entropy input rarely triggers the prefilter+arith block mode, so the fixture passes fully native even though that path is not yet ported. Real-world compressible data (text, source code, binaries) will hit that path and fall back to the extract bridge for `-cf/-cF`.

**Important caveat**: `native_strict_percent` measures "no [bridge] / [compat] log line in stdout". It does NOT measure "the C++ code path actually ran the native decode vs silently called the legacy binary via `FindLegacyBackend`". A fixture that triggers the prefilter+arith block mode shows the bridge being invoked at runtime but still reports `native_strict_percent=100` because the bridge produces byte-exact output. To verify the code path is truly native, use `tests/native_only.sh` with the planned `NZ_NO_BRIDGE=1` flag.

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

1. **Native** — pure C++ reconstruction of the algorithm, no original binary. **Mostly achieved for decode as of 2026-06-04, but NOT 100%** (see "Known gaps" above; the bridge is still invoked on some archives at runtime even when no `NZ_LEGACY_BACKEND` env var is set, because `FindLegacyBackend` also searches `$PATH` and finds `/usr/bin/nz` if installed system-wide).
2. **Extract bridge** — shells out to the original `nz -x` in a tmpdir. The bridge is currently the FALLBACK path: invoked when the native decode fails validation or returns a size-correct but content-wrong candidate. Not opt-in; runs automatically whenever the system has a `nz` binary reachable.
3. **Compat** — forwards the entire command to the original binary. Used only for CLI-level compatibility (unknown switches, not decode).

The legacy **compression** bridge (`TryRunLegacyCompressionBridge`) is disabled: `IsInternalLegacyCompressionBridgeCompressor` returns false unconditionally (commit `049d041`). Codecs the native encoder cannot handle produce an explicit error rather than silently invoking the original binary. The legacy **extract** bridge is NOT yet disabled (it is the runtime fallback described in "Known gaps" above). `NZ_NO_BRIDGE=1` flag is planned (Phase 8.1) to make the bridge opt-out and force hard errors when the C++ code cannot decode natively.

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

# Native-only validation: extract 16 fixtures x 8 codecs with NO legacy
# binary at runtime. Unsets NZ_LEGACY_BACKEND and NZ_LEGACY_BRIDGE_BACKEND
# so the native code path is the only one that can run. 128/128 byte-exact.
./tests/native_only.sh
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
| 2026-06-03 | lzpf `-cf/-cF` multi-file content corruption bug found and fixed via defensive cross-check. Root cause: the native LZ77+arith path silently produced size-correct but content-wrong output for `-cF` multi-file archives with mixed random+repeat+zero files (no per-entry checksums to catch it). Reproducer: 3 random files (1KB/2KB/3KB) + 1 zero file (8KB) + 1 repeat file (8KB) compressed with `-cF`; native extraction corrupted the random files starting at byte ~759. Fix: full-buffer cross-check between native output and legacy extract-bridge output (added to `RunLegacyCnExtractOrTest` in `sfx_archive.cpp`); only fires when no per-entry checksums are present (i.e. when native could produce silent garbage). Skippable via `NZ_DISABLE_LZPF_BRIDGE=1`. Same pattern as the CM cross-check (HUECO B fix). Verified byte-exact on the regression fixture `tests/fixtures/lzpf/regression_cF_multi.nz` and across the 15-fixture × 7-method cross-comparison suite (105/105 byte-exact). |
| 2026-06-04 | lzpf variant B hash-table init bug root-caused via GDB trace and fixed via real port. The cross-check from `ce232d2` was reverted (`refactor(lzpf): remove universal cross-check`). GDB trace on `linux32/nz` extracting the regression fixture showed that the legacy initializes the variant-B hash table to **3** (NOT 0 as previously assumed). C++ was initializing it to 0, causing silent corruption. Fix: change line 3013 to `std::int32_t{3}` for BOTH variants. Both `-cf` and `-cF` multi-file archives now decode byte-exact natively with NO legacy dependency. |
| 2026-06-02 | CM `-cc` decode: established the documented CM engine/dispatcher addresses (`0x0809e600`/`0x080a5c70`/`0x080aa850`) do not execute for `-cc` decode (all breakpoints unhit; dispatcher no-ops with method byte 0). Real decode routine still unlocated; byte-26 bug reframed as a deterministic prediction/weight-update formula error (bits 0–208 match legacy). |
| 2026-06-08 | **CM byte-26 divergence FIXED** — root cause was a one-line port error in `CM_Input_Bit`: `factors0_err` used truncating `(int32)factors[0] / 16` instead of the reference arithmetic shift `factors[0] >> 4` (differs for negative `factors[0]`, perturbing `factors0_err_flt` and flipping the `factor[7]` zeroing condition → wrong prediction from byte 26). Found via a per-bit `next_probability` differential trace against a compiled reference oracle (`encode_su/nzdec_v0` NZ_CM.cpp). The earlier "architecturally divergent / unlocated decode routine" theory was disproven — the port is faithful; it was just the shift. `nz_lzhd.cpp` model_d LUT init had a sibling rows/cols-swapped bug (`NzLzhdCreate` always SIGSEGV'd) — fixed `(12,1536)`→`(1536,12)`. |
| 2026-06-08 | **`-cc` fully native** — ported the CM post-filter pipeline: param2 RLE (`BwtRleExpander::DecodeU32` → `src/nz_postfilter.cpp`) and tt16 (`TextTransformNumber::Decode`, a number transform — NOT word-list as previously believed → `src/nz_texttransform_num.cpp`), wired into `TryDecodeLegacyCm` (CM→param2→param1→tt16→tt08→dece). `-cc` decodes byte-exact natively (no bridge) across source/numbers/dates/IPs/prose/markdown. Added `NZ_NO_BRIDGE=1` (hard-fail instead of silent bridge) + `tests/native_only_v2.sh` (honest no-bridge measurement). |
| 2026-06-08 | `-co/-cO` (optimum) found to use **DecLZ**, not BWT. Small blocks (flat framing) decode natively; large blocks use the same virtual-stream LZ framing as `-cd` (reference also SIGSEGVs) and bridge. Discovered non-CM codecs apply `kReorderAscii` before tt08. `-cd/-cD/-co/-cO` large all share the one virtual-stream-framing blocker. |
| 2026-06-08 | `-cc` completed for non-audio inputs: (1) **multi-chunk CM** — `TryDecodeLegacyCm` now loops over consecutive type-0 chunks (CM state persists; large `-cc` splits into several chunks, e.g. a 64 KB random file = 4 chunks); (2) **stored blocks** — `param6==0` means the payload is the raw output verbatim (incompressible data; the reference rejects these with `param6!=1`); (3) **param1 = AddBytesFilter** ported (`NzAddBytesFilter` in `nz_postfilter.cpp`, delta filter, wired after param2). `-cc` byte-exact native on a 13/13 comprehensive sweep; `native_only_v2` `-cc` 8/10→9/10 (only the stereo audio-CM variant remains). |
| 2026-06-20 | **`-cd` large-file LZ window solved.** The cross-chunk window is a single **per-archive ring**, not a fixed 64 KB — confirmed via GDB (`obj+0x978`). Sizes are not powers of two, so the ring helpers were switched from bitmask to **modular wrap** (`nz_cd_tokens.cpp`). Large files split output into **1 MB streams** that match into each other through the ring, so the ring now **persists across streams**: new `NzCdDecodeStream` takes a caller-owned ring + `ring_pos` (in/out) + file-absolute output offset, and the dispatcher allocates it once. `TryDecodeLegacyLzhd` also **self-verifies the decode against the stored per-file checksum** (bridges on mismatch — no silent corruption). The earlier "vtable double-buffer window / fixed 64 KB ring" theory was superseded. |
| 2026-06-20 | **`-cf` (lzpf A) stereo prefilter closed end-to-end → native byte-exact.** `stereo_lms_cf.nz` (both blocks) now decodes byte-exact to `stereo_lms.wav` (`-cf` `native_only_v2` 9/10→10/10, total ~57/80). Reverse-engineered the full `FUN_080a5330` stereo flow via GDB stage-capture: residuals are PLANAR, decoded by **two per-channel `DecodeArithBuffer` calls** (each reads its own Huffman header; one `n_elems` call mis-located the side stream by ~1.4 KB); predictor-init = leading bit G (`iStack_50078`, LMS gate) + per-channel `[active(1), order(3)]`; **per-channel LPC** with two persistent predictors (`pred`/`pred2`); inter-channel LMS `FUN_08096e20`; `FUN_080a50c0` reconstruction (`ReconstructStereoSamples`, L/R + mid/side). The old "interleaved split / raw-bytecode block-1" diagnosis was wrong — both blocks are stereo-prefilter. `-cF` (lzpf B vtable arith) stereo still bridges. |
| 2026-06-20 | **`-cd` ring-size formula corrected → multi-stream fully native, no wrap.** GDB on `FUN_08099050` (obj+0x978) across text50/source.cpp/big_code/repeat_3M gives ring = `1/3/19/46 × 64 KB` = **`round(total_output / 0x10000) · 0x10000`** (min 64 KB), NOT the `(method_p1+1)·0x10000` lzpf rule (which under-sized the ring for large files, e.g. 43×64 KB vs the real 46×64 KB for a 3 MB repeat file, forcing a wrap the binary never does). The encoder sizes the ring to hold the whole compact recon, so the cursor (obj+0x980) advances monotonically and never wraps. With the correct size, all multi-stream large files — 2–3.5 MB code/text/base64 and a 3 MB heavily-repetitive file — decode byte-exact natively (verified 6/6 on a varied size/compressibility sweep). `-cd` `native_only_v2` 9/10, suite 2553/2553, zero regression. |

## License

The reconstruction code in this repository is original work released under the **MIT License**.

NanoZip 0.09a binaries are not included and remain the property of their author. This project contains no extracted binary data, no verbatim decompiled output, and no proprietary assets. The C++ code is an independent reimplementation derived from behavioral observation and dynamic tracing.
