# nanozip-re

A byte-exact, native C++17 reimplementation of the **NanoZip 0.09 alpha** archiver's decoder (`nz`
commands `l`, `t`, `x`), with a console identical to the original's. No original binary is needed or
used at runtime.

NanoZip (Sami Runsas, 2008–2011) is a closed-source archiver with five compressors of its own —
`nz_lzpf`, `nz_lzhd`, `nz_lzhds`, `nz_optimum1/2`, `nz_cm` — plus audio and image models, text
transforms and an x86 filter. Only stripped Linux and Windows binaries of the last alpha exist.

📖 **[Wiki](https://github.com/YadeWira/nanozip-re/wiki)** · 📋 **[Original quirks catalogue](docs/ORIGINAL_QUIRKS.md)** · ⬇️ **[Releases](https://github.com/YadeWira/nanozip-re/releases)**

## Why

NanoZip's author died more than a decade ago; 0.09 alpha is the last build he published, and the
closed binary is all that exists of the format. This project is preservation: an executable
specification that keeps `.nz` archives readable once that binary no longer runs.

The rule that follows is **fidelity first**. Format and output bytes are identical, always; console,
messages and switches are identical except where timing makes them unobservable; behaviour is
identical *including the alpha's defects*, so the two binaries can be compared on equal terms and
every difference is a bug on this side. The defects are catalogued in
[docs/ORIGINAL_QUIRKS.md](docs/ORIGINAL_QUIRKS.md); which to keep and which to fix is a decision for
the community once the decoder is complete. Until then the only escape hatches are environment
variables (`NZ_SAFE=1`, `NZ_STRICT_EXIT=1`), never new switches, and the few deliberate departures
(a path-traversal guard, no crash on an archive of empty files, no infinite prompt on a closed stdin)
are marked `[pending]` in the catalogue.

## Status

Everything is measured against the original binary as the oracle: it compresses the fixtures, its
extraction is the reference, and stdout/stderr/exit status/written trees are compared byte for byte.

| what | result |
|---|---|
| Synthetic fixtures, 8 codecs (`tests/native_only_v2.sh`) | 96/96 byte-exact |
| Multi-file archives, 12 selectors × 9 shapes, whole trees + listings (`tests/multifile_v2.sh`) | 144/144 + 72/72 |
| Real-world corpus, 61 files × 8 codecs (`tests/real_corpus_sweep.sh`) | 488/488 |
| Real-world corpus, 155 files × 8 codecs | 1240/1240 |
| Stratified sweep, 3037 real files × 8 codecs (`tests/corpus_select.sh` + `sweep_run.sh`) | 24 272/24 272 byte-exact (6 decode bugs found and fixed on the way) |
| Release package, 52 archives (incl. parallel containers of every codec), all four binaries | 100/100 hashes |
| Console matrices (36 + 77 + 77 cases, pty prompt harness) | identical except progress-redraw timing and the encode commands |
| Damaged archives, 8 codecs × 6 corruptions | 42/48 identical trees |
| Fuzzing, ASan + UBSan, 1358 corrupt and non-archive inputs (`~/.cache/nzre_tools/fuzz/fuzz.sh`) | 1358/1358 clean, worst case 8.1 s (a 4-stream `-cc` archive under ASan) |
| Decode speed vs the original, 137 MB mixed tar × 6 codecs and a 2.29 GB archive ([Performance](https://github.com/YadeWira/nanozip-re/wiki/Performance)) | faster on `-co`, `-cd`, `-cf` and the 2.29 GB test; 1.07× on `-cO`, 1.16× `-cc`, 1.3× `-cD` |

Decoding of parallel (`-pN`) archives is multi-threaded (one thread per worker stream, `-t<n>` caps
it). Four static binaries per release (Linux and Windows, 64- and 32-bit), verified on a real Windows
machine. Details: [Decode Coverage](https://github.com/YadeWira/nanozip-re/wiki/Decode-Coverage),
[Console Parity](https://github.com/YadeWira/nanozip-re/wiki/Console-Parity),
[Component Status](https://github.com/YadeWira/nanozip-re/wiki/Component-Status),
[Changelog](https://github.com/YadeWira/nanozip-re/wiki/Changelog).

**Not there yet:** encode (`a`, `s`) and self-extractor creation (`w32c`). Known limits: the
`IO-out` footer figure and the progress redraw count are timing-dependent; the output is assembled in
memory and written after the decode (the 32-bit builds cannot decode archives above 2 GB); format constructs the encoder never emits (`0xd`/`0xe` sub-chunks, image
predictor modes other than 2) are ported but unexercised.

## Usage

```
nz_recon x -y archive.nz        # extract (-y: overwrite without asking)
nz_recon l archive.nz           # list
nz_recon t archive.nz           # test: decode and verify, write nothing
nz_recon x -y -oout/ archive.nz # into a directory; -sp strips paths; -x<glob> excludes
```

Switches, messages, prompts and the exit status follow the original exactly (exit status is always 0,
as in the original). Environment variables, all optional:

| variable | effect |
|---|---|
| `NZ_SAFE=1` | on a damaged archive write only entries whose checksum verifies, skip the rest with the `Checksum mismatch` line, exit 2 (the original writes whatever it decoded) |
| `NZ_STRICT_EXIT=1` | distinct exit codes for damage and usage errors |
| `NZ_THREADS=n` | decode thread count (default: `-t<n>`, else the CPU count) |
| `NZ_TRACE_CONSTRUCTS=1` | print each format construct met, once (`[construct] k=v` on stderr) |

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
```

Produces `bin/nz_recon`. Static release builds: `g++ -std=c++17 -O2 -DNDEBUG -Iinclude -static -pthread -o nz_recon src/*.cpp` (and the mingw-w64 equivalents for Windows).

## Tests

See [tests/README.md](tests/README.md). The regression set before every commit: `tests/native_only_v2.sh`,
`tests/multifile_v2.sh`, `tests/real_corpus_sweep.sh` (needs the original binary at `../linux32/nz`
or `NZ_LEGACY_ORACLE`), plus the release-package hash check and the console matrices kept with the
project's private tooling.

## How it was done

Ghidra (headless decompile), GDB tracing against the real `linux32/nz` (golden vectors, watchpoints,
per-stage dumps), differential decoding between codecs that share a front end, and diffs against the
community reference decoder where it exists (`encode_su/nzdec_v0`, incomplete). The tools, workflow
and every finding (addresses, formulas, table contents) are in the wiki's
[Reverse Engineering Notes](https://github.com/YadeWira/nanozip-re/wiki/Reverse-Engineering-Notes);
the source layout is in [Architecture](https://github.com/YadeWira/nanozip-re/wiki/Architecture).

## License

The reconstruction code in this repository is original work released under the **MIT License**.

NanoZip 0.09a binaries are not included and remain the property of their author. This project
contains no extracted binary data, no verbatim decompiled output, and no proprietary assets. The C++
code is an independent reimplementation derived from behavioral observation and dynamic tracing.
