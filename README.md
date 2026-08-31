# nanozip-re

Reverse engineering reconstruction of the **NanoZip 0.09a** archiver CLI (`nz`) in C++17 — without SFX, without the original binary at runtime for supported methods.

NanoZip is a high-performance archiver (circa 2010) with several unique compression algorithms: `nz_lzpf`, `nz_lzhd`, `nz_optimum1/2`, and `nz_cm`. The original binaries are stripped Linux ELF (32-bit and 64-bit) with no public source.

📖 **[Wiki](https://github.com/YadeWira/nanozip-re/wiki)** — per-codec status detail, reverse-engineering notes, and the full day-by-day changelog live there. This README stays a short overview.

---

## Goals

- Reconstruct the full `l / t / x / a / s` CLI in C++ with byte-exact output.
- Native (no original binary at runtime) decoding for all compression methods.
- Document every reverse-engineered finding so the knowledge is not lost.

## Decode coverage (measured, no bridge)

The honest metric is how much decodes **byte-exact with no original binary at runtime**.
`tests/native_only_v2.sh` runs extraction under `NZ_NO_BRIDGE=1` (which disables the
legacy `nz` fallback entirely) and diffs against the legacy oracle. On a mixed
corpus (random, text, source, repeats, zeros, audio; 10 fixtures × 8 methods):

| method | native byte-exact | method | native byte-exact |
|--------|-------------------|--------|-------------------|
| `-cn` (store)      | 10/10 | `-cd` (lzhd)        | 9/10 |
| `-cf` (lzpf A)     | 10/10 | `-cD` (lzhd strong) | 9/10 |
| `-cF` (lzpf B)     | 10/10 | `-co` (optimum1)    | 9/10 |
| `-cc` (cm)         |  9/10 | `-cO` (optimum2)    | 10/10 |

**≈ 76/80 (95%) byte-exact native, zero bridge.** `-cn`/`-cf`/`-cF`/`-cc` are native for typical real inputs.
`-cd`/`-cD` are native for LZ, block-RLE, raw-store, pure-literal, exe, the text pipeline, multi-chunk text, large
multi-stream files, and parallel containers — bridging only on rare shared CM/BWT sub-chunks. `-co`/`-cO` are
native for single-container AND parallel-container LZ/CM content and for `decr_param==0` (BWT) blocks in both
shapes — raw-stored BWT output and the 256-bucket MTF/arithmetic entropy layer — bridging on BWT `param14`/`param15`
plus the BWT-only `param14`/`param15` follow-on transforms. **The whole post-filter chain is now native** -- param2, param1, all six text-transform bits, and the `dece` x86 exe-filter -- so no unported post-filter remains. `decr_param==2` audio blocks decode natively too — `-cO` is
byte-exact on stereo and mono at 8/16/24-bit and on multi-block files. The remaining 4 are all one audio fixture,
on the codecs whose audio shape the reference decoder itself gets wrong. Counts vary ±1 because the corpus uses
random fixtures.

See the wiki's **[Component Status](https://github.com/YadeWira/nanozip-re/wiki/Component-Status)** page for the
full per-codec breakdown, known gaps, and roadmap to 100%.

> The older `tests/native_only.sh` is a **false positive**: it checks byte-exact
> equality but does NOT verify the bridge was avoided (`FindLegacyBackend` silently
> finds a system `nz` in `$PATH`). Use `native_only_v2.sh` + `NZ_NO_BRIDGE=1` for the
> real figure.

## Architecture

```
nz_recon CLI
├── sfx_archive.cpp    — core: archive format, dispatcher, native decoders
├── sfx_cli.cpp        — CLI parsing (l/t/x/a/s + switches)
├── lzpf_arith.cpp     — lzpf arith primitives (BitReader, Huffman, LZ77 A/B)
├── nz_cm.cpp          — CM decoder: ported from nzdec_v0 NZ_CM.cpp (context mixer, range coder, all tables)
├── nz_lzhd.cpp        — lzhd decoder: ported from nzdec_v0 NZ_LZ.cpp (DecLZ, PAQ context mixer, 12-bit arith)
├── nz_optimum_lz.cpp  — real -co (nz_optimum1) LZ/CM engine
├── nz_optimum2_lz.cpp — real -cO (nz_optimum2) LZ/CM engine
├── linux32_cm_map.cpp — cm context-mixer vtable mapping (linux32 ELF offsets)
└── include/
    ├── lzpf_arith.h
    ├── nz_cm.h        — CM decoder public API
    ├── nz_lzhd.h      — lzhd decoder public API
    └── nz_sfx/        — internal headers
```

**Decode layers (priority order)**: (1) **Native** — pure C++ reconstruction, no original binary; (2) **Extract
bridge** — shells out to the original `nz -x` in a tmpdir, the automatic fallback whenever native decode declines
or a checksum mismatch is detected; (3) **Compat** — forwards unknown CLI switches to the original binary
(CLI-level only, not decode). The legacy **compression** bridge is fully disabled
(`IsInternalLegacyCompressionBridgeCompressor` returns `false` unconditionally) — codecs the native encoder can't
handle produce an explicit error rather than silently invoking the original binary. `NZ_NO_BRIDGE=1` disables the
extract bridge too, turning a missing native path into a hard error — this is what `native_only_v2.sh` uses to
measure honestly.

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

# Native-only validation: the honest NZ_NO_BRIDGE=1 measurement (see the
# table above).
./tests/native_only_v2.sh

# Real-world corpus sweep: same NZ_NO_BRIDGE=1 methodology, but over an
# arbitrary directory of REAL files instead of a small synthetic fixture
# set. Point NZ_REAL_CORPUS at a directory (a file-format sample
# collection works well); failures are grouped by the native binary's
# own decline reason, not just by fixture name. This is how several real
# bugs were found in code previously believed "done" — see the wiki
# changelog's 2026-07-29/2026-07-30 entries.
NZ_REAL_CORPUS=/path/to/real/files ./tests/real_corpus_sweep.sh
```

## Reverse engineering approach

Ghidra (headless decompile) + GDB (dynamic tracing against the real `linux32/nz` binary) + reference-source diffs
where a reference exists (`encode_su/nzdec_v0.7z`, incomplete coverage). See the wiki's
**[Reverse Engineering Notes](https://github.com/YadeWira/nanozip-re/wiki/Reverse-Engineering-Notes)** for the
tools, workflow, and every specific finding (addresses, formulas, table contents).

## License

The reconstruction code in this repository is original work released under the **MIT License**.

NanoZip 0.09a binaries are not included and remain the property of their author. This project contains no extracted binary data, no verbatim decompiled output, and no proprietary assets. The C++ code is an independent reimplementation derived from behavioral observation and dynamic tracing.
