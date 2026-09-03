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
corpus (random, text, source, repeats, zeros, audio, a mixed audio/text/high-entropy
file, and a 1.1 MB mixed-entropy file; 12 fixtures × 8 methods):

| method | native byte-exact | method | native byte-exact |
|--------|-------------------|--------|-------------------|
| `-cn` (store)      | 12/12 | `-cd` (lzhd)        | 12/12 |
| `-cf` (lzpf A)     | 12/12 | `-cD` (lzhd strong) | 12/12 |
| `-cF` (lzpf B)     | 12/12 | `-co` (optimum1)    | 12/12 |
| `-cc` (cm)         | 12/12 | `-cO` (optimum2)    | 12/12 |

**96/96 (100%) byte-exact native, zero bridge** on this fixture set — see the wide real-world sweep
below for the numbers that actually characterise the decode. The whole post-filter chain is native —
param2, param1, **all seven** text-transform bits the encoder emits (including `0x40`, the PGN/chess
transform, which the community reference never implemented either),
and the `dece` x86 exe-filter — and so is every block/chunk kind the four `0x2b`-family
codecs emit, including the prefilter sub-chunk and `decr_param==2` audio blocks. `-co`/`-cO` decode
single-container and parallel-container LZ/CM content plus `decr_param==0` (BWT) blocks in both shapes (raw-stored
output, the 256-bucket MTF/arithmetic entropy layer, and buckets the encoder stored verbatim) with the BWT-only
`param14`/`param15` follow-ons.

On a 61-file real-world corpus (`tests/real_corpus_sweep.sh`, same corpus for every codec):
**488/488**, every codec 61/61. That corpus is now saturated, so it cannot detect anything on its own —
the honest figure comes from the wider sweep below.

`tests/multifile_v2.sh` covers what neither of those can: they build **one-file** archives and compare **one**
extracted file. It runs **all twelve** compressor selectors the binary's own usage lists — `-cdp`/`-cdP`/`-cDp`/`-cDP`
are encoder-parallelism variants of `-cd`/`-cD`, and testing only eight of them hid a real bug — across nine
archive shapes, comparing whole extracted **trees** (contents, permissions *and* timestamps), plus extraction under
the metadata switches and 72 listings. Each shape forces a different branch: distinct versus repeated permissions,
70 equal modes, setuid/sticky, an all-0600 input (whose permission record the encoder omits entirely), a
multi-block mix, a `-r` recursive tree, a `-p4` single-file container and a `-p4` **multi-file** one.
**108/108 extract · 36/36 switches · 12/12 in a bare user environment · 72/72 listings.**

That suite is also where a *flaky* case turned out to be a real defect. NanoZip is multi-threaded by
default, and each worker writes its own self-describing record run into the container — in
**thread-scheduling order**, not stream order. About one archive in twenty came out with the runs
reordered, which this decoder rejected outright as a corrupt header. A flaky test is a defect report:
re-running until green would have buried a layout that a user hits 5% of the time.

### Measured the way a user runs it

Every suite sets `NZ_NO_BRIDGE=1`. That is the honest way to measure *native* decode, but it is not
how anyone who downloads a binary runs it — and the difference mattered: with the bridge merely
*enabled* and no legacy binary reachable, the CM path treated "the cross-check could not run" as
"unverified" and declined, so **`-cc` archives failed by default for every user** while the suites
reported them green. `tests/multifile_v2.sh` now also runs a copy of the binary under `env -i`,
with no variables set and no legacy `nz` anywhere near it, and compares against the oracle.

### The console is the original's, byte for byte

Everything the decoder prints is matched against `nz` on a 36-case matrix (usage, help, info, list,
test, extract, filters, `-v`, `-sp`, `-o`, missing and foreign files, truncated and corrupted
archives, self-extracting `.exe`, the archive-name rule) with stdout, stderr and the created files
compared byte for byte; the only differences left are the program name in the usage text, the
thread-dependent order of the per-worker lines on a parallel container, and the encode commands.
Measured behaviour that was not obvious: the exit status is **always 0** (set `NZ_STRICT_EXIT=1`
for real codes); `.nz` is appended to the archive name unless it ends in `.nz` or `.exe`; a
self-extracting `.exe` opens by seeking past the PE image; the `[N MB]` figure on the compressor
line is the codec's memory-usage method transcribed (window and table sizes, to the byte); a
checksum mismatch prints `[stored computed]` and continues; a failed decode is `Archive corrupted.
Error decoding (code 100)`, or 25600 when the archive is cut short; the progress line shows the
cumulative megabytes and re-prints the name only when the file changes; names over 40 columns are
shown as `...` plus their last 37 characters.

### Robustness against input that is not a valid archive

Fuzzed with 761 cases under AddressSanitizer + UBSan — truncations, single-bit flips weighted
toward the header, corruption runs, and non-archives renamed `.nz`. That found an out-of-bounds
**write** (a transform that ignored its output capacity), a 214-second denial of service ending in
a segfault on a 191-byte mutated archive, an out-of-bounds read on a corrupt Huffman table, and two
signed-overflow sites. All fixed; **761/761 clean**. Worst corrupt case 3.7 s, a non-archive
refused in ~10 ms.

The reusable invariant from that: **bound decode work against the archive's DECLARED OUTPUT, per
entry, not per call** — a valid decode needs exactly 8 bit decodes per output byte no matter how
the chunks are cut, and a per-call bound still lets a corrupt header multiply the work by inventing
chunks.

### Known decode failures, on a corpus large enough to measure them

A 61-file corpus at 488/488 proves nothing by itself; an earlier release quoted one at 479/480 while
`-cO` was in fact failing about **7.5% of real files**, because that corpus happened to contain exactly
one of them. The figure below therefore comes from a **fresh 155-file real-world corpus** (63 MB across
eight format categories), swept with all eight codecs: **1240/1240 byte-exact, zero bridge**.

| method | pass | fail | | method | pass | fail |
|--------|------|------|---|--------|------|------|
| `-cn`  | 155  | 0    | | `-cd`  | 155  | 0    |
| `-cf`  | 155  | 0    | | `-cD`  | 155  | 0    |
| `-cF`  | 155  | 0    | | `-co`  | 155  | 0    |
| `-cc`  | 155  | 0    | | `-cO`  | 155  | 0    |

The last cause standing on this corpus, **the image model, is ported** (`NzImageModel`, `nz_audio.cpp`).
NanoZip's encoder runs four image detectors (BMP, and the same model is reached by PGM/PPM/TGA and
uncompressed TIFF) and puts a recognised block on `decr_param = 3`; every codec then decodes it with
the same function — the CM family's mode 3, `-cd/-cD`'s `0xf` sub-chunk, `-cf/-cF`'s prefilter-slot
block with bit 3 set. The community reference treats that value as ordinary CM without reset, which
is why every uncompressed bitmap failed its checksum in every codec. The model is the audio
decoder's two-dimensional sibling: per-channel LMS planes and the same residual coder, a four-stage
sign-sign cascade fed by the four rows above, and an eight-mode pixel predictor over the left,
above, above-left and above-right neighbours. It decodes byte-exact in all seven codecs on 37 real
BMPs, on 8/16/24/32-bit and PGM/PPM/TGA/TIFF images, and in mixed archives with audio and text.

The BMP sweep also surfaced two `-co/-cO` declines outside this corpus that never entered the image
model, and both were one cause, now fixed: a BWT block's `param15` pass names its match sources as
absolute offsets into everything decoded so far — the *pre-post-filter* stream the LZ window holds,
not the final output. The port sourced them from the final output, which the `param1` delta filter had
already rewritten almost byte for byte, so the copied bytes were wrong and so was the window the next
LZ block read. Found by dumping the original's window at the failing block's entry and asking where
its bytes came from: its own window, where ours came from the file.

The `-cd`/`-cD` cluster that stood here earlier the same day (12 failures) was three causes, all now
closed: the prefilter state was not reset after a pure-literal LZ chunk (the original resets on every
LZ chunk); the LZ ring was sized `round(total / 64 KB)` where the real rule is `bytefloat(p1 + 1)` —
the same mantissa/exponent byte the `-cc` window and the lzpf dictionary use — for single-container
and per-stream parallel rings alike; and a match reaching back across the ring end is copied
*linearly* into the zeroed slack past the ring, not modulo the ring.

`-cO`'s own literal model — the long-standing failure this project quoted for months — is **closed**. It
was two ring-lifetime bugs: the wrap's LZP-table sweep started 64 bytes too low, leaving its last 16
entries uncleared for the life of the archive, and the window-feed path collapsed four cases into one, so
a feed crossing the ring end left the cursor in the wrong place and skipped the reset. Because that table
feeds exactly one of eight mixer inputs, a stale entry moved a single probability by about 1% and flipped
a bit only where the coder already sat on a decision boundary — one wrong byte with tens of thousands of
byte-exact bytes on either side.

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

# Multi-file archives: whole-tree comparison (contents, mode and mtime)
# across archive shapes and metadata switches. The single-file suites
# above cannot see this class of bug.
./tests/multifile_v2.sh

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
