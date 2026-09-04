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
| Self-extracting `.exe` archives of the eight codecs (`tests/sfx_exe.sh`) | 8/8 byte-exact |
| Shapes measured one by one: 70 000 entries, the same file twice, a `-pN` container of duplicates, files of 0 bytes, names of 250 characters | listings, trees, modes and timestamps identical to the original |
| Real-world corpus, 61 files × 8 codecs (`tests/real_corpus_sweep.sh`) | 488/488 |
| Real-world corpus, 155 files × 8 codecs | 1240/1240 |
| Stratified sweep, 3037 real files × 8 codecs (`tests/corpus_select.sh` + `sweep_run.sh`) | 24 272/24 272 byte-exact (6 decode bugs found and fixed on the way) |
| Release package, 71 archives (incl. single- and multi-file parallel containers and self-extracting `.exe`s of every codec), all four binaries | 183/183 hashes |
| Console matrices, 182 cases, and the pty prompt harness (`tests/parity/`) | 90 byte-identical, 86 differing only in status-line writes (how many `N MB` figures fit depends on the seconds the decode crosses, and the original's footer adds an `IO-out` clause), and 6 real: two are the compression commands the encode phase will bring, four are the documented departures ([quirks 3, 28, 29](docs/ORIGINAL_QUIRKS.md)) |
| Directory trees: deep paths, symlinks, unreadable files, setuid/sticky modes, UTF-8 and space names, extreme timestamps, `-fo` (`tests/sweep_dirs.sh`) | 16/16 archives extract identically (contents, mode, mtime, links) |
| Archives made by the **Windows** original, 8 codecs, and our Windows build's console against it (`tests/windows_original.sh` through wine, `tests/parity/windows_vm_check.ps1` on a real Windows 10 machine) | 24/24 through wine; on Windows 47/48 identical and one progress-tick difference, contents, sizes and the restored file **attributes** included |
| The `[N MB]` memory figure, `-co`/`-cO`/`-cc` at six `-m` settings | identical to the original in all 18 |
| Damaged archives, 8 codecs × 6 corruptions (`x`, `l`, `t`) (`tests/parity/corrupt_compare_all.sh`) | 42/48 identical trees on the release fixtures and 47/48 on the ones the harness builds; the `Archive corrupted` / `Internal error` report identical in 38/48 (`l`: 47/48); the rest are the original's crashes and uninitialised memory ([quirks 26, 27, 47](docs/ORIGINAL_QUIRKS.md)) and four `-cf`/`-cF` garbage divergences |
| Damaged **parallel** containers, 8 codecs × 7 corruptions, single- and multi-file (`x`) | 104/112 identical trees (holes, short files, files created and left empty exactly where the original's workers leave them, [quirk 41](docs/ORIGINAL_QUIRKS.md)); report line identical in 99/112, the rest being `-cd`/`-cD` and `-cO` detection differences, one segfault of the original and the plain-vs-shifted code of four early failures |
| Fuzzing, ASan + UBSan, 1358 corrupt and non-archive inputs (`~/.cache/nzre_tools/fuzz/fuzz.sh`) | 1358/1358 clean, worst case 8.1 s (a 4-stream `-cc` archive under ASan) |
| Decode speed vs the original, 137 MB mixed tar × 6 codecs and a 2.29 GB archive ([Performance](https://github.com/YadeWira/nanozip-re/wiki/Performance)) | faster on `-co`, `-cd`, `-cf` and the 2.29 GB test; 1.07× on `-cO`, 1.16× `-cc`, 1.3× `-cD` |

Decoding of parallel (`-pN`) archives is multi-threaded (one thread per worker stream, `-t<n>` caps
it). Four static binaries per release (Linux and Windows, 64- and 32-bit), verified on a real Windows
machine. The archive itself is mapped, not copied into the heap. Details: [Decode Coverage](https://github.com/YadeWira/nanozip-re/wiki/Decode-Coverage),
[Console Parity](https://github.com/YadeWira/nanozip-re/wiki/Console-Parity),
[Component Status](https://github.com/YadeWira/nanozip-re/wiki/Component-Status),
[Changelog](https://github.com/YadeWira/nanozip-re/wiki/Changelog).

**Not there yet:** encode (`a`, `s`) and self-extractor creation (`w32c`). Known limits: the
`IO-out` footer figure and the progress redraw count are timing-dependent; a single-stream archive is
assembled in memory and written after the decode, and a parallel one is written by its worker streams as
each finishes, like the original, but every worker still holds its whole stream (a 16-stream 2.5 GB
archive peaks at 6.7 GB of RAM), so the 32-bit builds cannot decode archives above about 1 GB; format
constructs the encoder never emits (`0xd`/`0xe` sub-chunks, image predictor modes other than 2) are
ported but unexercised.

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

Produces `bin/nz_recon`. Static release builds: `g++ -std=c++17 -O2 -DNDEBUG -Iinclude -static -pthread -o nz_recon src/*.cpp` (and the mingw-w64 equivalents for Windows). The 32-bit builds add `-m32 -msse2`: the SSE2 paths (audio predictor, `-cO` mixer) are compiled only when the target has SSE2, and on a 137 MB mixed tar that is a 19 % shorter `-cO` decode for a Pentium 4-class minimum (the original needed MMX).

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
