# nanozip-re

A native C++17 reimplementation of the **NanoZip 0.09 alpha** archiver `nz`, decoder and encoder, with
a console identical to the original's. It lists, tests and extracts (`l`, `t`, `x`) archives of all
eight compressor settings byte-exact, and it compresses (`a`, `s`, `w32c`) with all eight, writing the
original's archive byte for byte on most inputs measured so far; the exceptions are under
[Known limits](#known-limits). No original binary is needed or used at runtime, except that `w32c`
copies the original's `nz_w32c.sfx` stub (see [Usage](#usage)).

NanoZip (Sami Runsas, 2008–2011) is a closed-source archiver with five compressors of its own —
`nz_lzpf`, `nz_lzhd`, `nz_lzhds`, `nz_optimum1/2`, `nz_cm` — plus audio and image models, text
transforms and an x86 filter. Only stripped Linux and Windows binaries of the last alpha exist.

📖 **[Wiki](https://github.com/YadeWira/nanozip-re/wiki)** · 📋 **[Original quirks catalogue](docs/ORIGINAL_QUIRKS.md)** · ⬇️ **[Releases](https://github.com/YadeWira/nanozip-re/releases)**

<!-- TEMPORARY notice (v0.17.0-pre / v0.17.1-pre, 2026-09-23): remove when the maintainer decides -->
> **Temporary notice.** Two kinds of archive written by `a` or `w32c` with `-co`, `-cO` or `-cc` (`-co` is the
> default) may be unreadable, by this port and by the original: multi-file archives from v0.15.2-pre to v0.16.0-pre,
> and, from v0.15.0-pre (`-cc`) or v0.15.1-pre (`-co`, `-cO`) to v0.17.0-pre, archives of an input of 8 MB or more
> made with more than one thread, or of any input with `-p2` or more. Test them with `nz-re t` and re-create any that fail from the source files with
> v0.17.1-pre or later ([release notes](https://github.com/YadeWira/nanozip-re/releases/tag/v0.17.1-pre)).
<!-- end of TEMPORARY notice -->

## Why

NanoZip's author supposedly died around 2013; 0.09 alpha is the last build he published, and the
closed binary is all that exists of the format. This project is preservation: an executable
specification that keeps `.nz` archives readable once that binary no longer runs.

The rule that follows is **fidelity first**. Format and output bytes are identical, always; console,
messages and switches are identical except where timing makes them unobservable; behaviour is
identical *including the alpha's defects*, so the two binaries can be compared on equal terms and
every difference is a bug on this side. The defects are catalogued in
[docs/ORIGINAL_QUIRKS.md](docs/ORIGINAL_QUIRKS.md) (77 numbered items); which to keep and which to fix
is a decision for the community once the encoder is complete. The decode phase closed with v0.9.9-pre;
every release stays a pre-release until the encoder is complete too. Meanwhile the only escape hatches are environment
variables (`NZ_SAFE=1`, `NZ_STRICT_EXIT=1`), never new switches, and the few deliberate departures (a
path-traversal guard, no crash on an archive of empty files, no infinite prompt on a closed stdin)
are marked `[pending]` in the catalogue.

## Status

The original binary is the oracle. For decoding, it compresses the fixtures, its extraction is the
reference, and stdout/stderr/exit status/written trees are compared byte for byte. For compression,
its own `a` on the same inputs with the same switches (`-t1`) is the reference, archive against archive.

### Decode

| what | result |
|---|---|
| Synthetic fixtures, 12 × 8 codecs (`tests/native_only_v2.sh`) | 96/96 byte-exact (2026-09-23) |
| Multi-file archives, 12 selectors × 9 shapes, trees + listings (`tests/multifile_v2.sh`); multi-block `-t1` attribute records (`tests/parity/multiblock_attrs.sh`) | 144/144 + 72/72; 105/105, the original's `l` mode shift reproduced ([quirk 76](docs/ORIGINAL_QUIRKS.md)) (2026-09-23) |
| Release verification package: 87 `.nz` and 8 self-extracting `.exe` archives (all eight codecs, single- and multi-file, parallel containers, a `-co` archive with a stored LZ block), plus one whose stored name is not valid UTF-8, checked by content | 245/245 checks on each of the four v0.17.3-pre binaries, the Windows two on a real Windows 10 (2026-09-23) |
| Real files: 61 × 8 codecs (`tests/real_corpus_sweep.sh`), 155 × 8, a stratified 3037 × 8, and 744 file × codec pairs of 20-300 MB | 488/488, 1240/1240, 24 272/24 272, and no open failure (2026-09-02 to 2026-09-05) |
| One entry over 4 GB: a reporter's 4.6 GB `-cO` archive, and a 4.5 GB entry written by the original with each codec | all eight codecs `t` OK and extract byte-identically on a 64-bit build (v0.14.0-pre); a 32-bit build decodes the 4.6 GB archive too, checksum verified (v0.14.2-pre) |
| Every checksum setting × 8 codecs × single and parallel containers (`tests/checksum_modes.sh`) | 240/240 (2026-09-23) |
| Archives made by the **Windows** original, 8 codecs (`tests/windows_original.sh` through wine, `tests/parity/windows_vm_check.ps1` on Windows 10) | 24/24 through wine; on Windows 47/48 identical, one progress-tick difference, file attributes included (2026-09-04) |
| Damaged and truncated archives, 8 codecs (`tests/parity/`) | 48 damaged variants of the fixtures the harness builds (`make_fixtures.sh`): 47/48 identical file sets, report lines identical in `x` 34/48, `l` 47/48, `t` 34/48; on the release package's fixtures v0.14.2-pre gave 42/48 and `x` 38/48, and `-cf`/`-cF` gave 9/12 identical file sets there on 2026-09-22, before 5be60d5 moved their single containers to the streaming path; file filters on a damaged archive 8/8 (`filter_checksum.sh`); 105/152 identical reports over 19 cut points in the release run (103 to 105 across that night's runs), ours stable run to run, the original's not on two cut `-cd` archives (2026-09-23); damaged parallel containers, five `-p4` fixtures × seven damages: 34/35 extract the original's tree, reports identical in v0.16.0-pre, v0.17.0-pre and v0.17.1-pre (2026-09-23). The rest include the original's crashes, uninitialised memory and garbage decodes ([quirks 26, 27, 47, 51](docs/ORIGINAL_QUIRKS.md)) |
| Writing the files (`tests/parity/sink_files.sh`): many files, name collisions, empty entries, a full disk; 4 codecs, single and `-p4` | 28/28 identical (2026-09-23); a 3000-file archive extracts whole on Windows 10. `-forceout` over a parallel container still differs; there the original's own result varies run to run |
| Fuzzing, ASan + UBSan, corrupt and non-archive inputs | 2242 inputs: 0 sanitizer findings, 0 timeouts, 0 signals; 31 end in the reproduced `Internal error` exit (255) (2026-09-23) |
| Console (`tests/parity/`) | 35-case CLI matrix: two known differences, `argv[0]` in the usage line and a progress interleaving (v0.15.1-pre); `a` and `s` at four budgets × three codecs identical (v0.15.0-pre); banner core count and `Threads:` identical (v0.15.3-pre) |

### Encode

| what | result |
|---|---|
| Encode oracle (`tests/encode/oracle.sh`): all eight compressors; the `-s`, `-r`, `-sp`, `-x`, `-pN`, checksum and metadata switches; block and piece boundaries; empty, text, random, ELF, audio, image, CRLF, PGN and block-RLE inputs | 135/135 archives byte-identical, 135/135 read back by the other binary in both directions; consoles identical in 134/135, the other differing only in extra progress redraws of ours; which case differs changes from run to run (2026-09-23, v0.17.1-pre) |
| 45 BMP/TGA/TIFF/PNM images | `-cn`, `-cF`, `-cD` 45/45 (v0.16.0-pre); `-cf`, `-cd`, `-cc` 45/45, `-co` 44/45, `-cO` 43/45 (2026-09-22) |
| 127 mixed real files | `-co` 126/127, `-cO` 126/127, `-cc` 126/127 (2026-09-23) |
| 294 corpus files at `-m4m`; 45 groups of four consecutive corpus files | `-co` 292, `-cO` 292, `-cc` 294, 0 declined; groups 45/44/45 of 45 (last measured at v0.15.2-pre) |
| Multi-file archives of real size: five shapes, from two 3 MB files to an 18-file tree, × 8 codecs (`tests/encode/multifile_sizes.sh`) | 40/40 byte-identical at `-t1` and read by the original, which also reads the default-thread-count archives (2026-09-23) |
| Above the automatic split (8 MB): `a -t4` of 20 MB × 8 codecs read back and extracted by the original, with its compressor count; `-t1 -p3`/`-p16` for `-co`/`-cO`/`-cc`; the original's `-cc -p12`/`-p16` read at `-t1` (`tests/encode/parallel_readback.sh`) | 16/16 (v0.17.0-pre: 6/16) (2026-09-23) |
| `-cd` across the 128 MB window (`tests/encode/large_window.sh`), and real files to 328 MB | byte-identical, memory line included, from 132 087 807 bytes to 328 MB; `-cD` too (2026-09-23) |
| Real audio, mixed-type and image files | 54 audio, 64 mixed-type and 24 image files byte-identical under `-cf`, `-cF`, `-cd` (v0.10.0-pre) and `-cD` (v0.11.0-pre) |
| Memory budgets (`-m`) | 100/100 archives identical over five codecs × twenty budgets (v0.11.0-pre); `-co` sizing 552/552 points (v0.14.0-pre); `-cc` sizing 91/91 and 16/64/256 MB × 3 codecs × 5 files 45/45 (v0.15.0-pre) |
| Other builds | 32-bit Linux writes the 64-bit build's bytes on the 294 files (v0.15.0-pre); both Windows builds against the Windows original, 7 files × 3 codecs: 21/21 each (v0.15.1-pre) |
| Round trip through the original | the original extracts every archive written for the image and mixed corpora and matches the source, except a name containing `[1]`, which it cannot extract from its own archive either: it reads `[...]` as a character class (2026-09-22) |

### Speed

128 MB of distinct real corpus files (text, documents, images, executables, audio), one thread
(`-t1`), best of 2, v0.17.0-pre, measured 2026-09-23. nz-re's time divided by the original's.
**Single-threaded, this port compresses slower than the original on every method; it decompresses
level with it on `-cn` and `-cF` and slower on the rest.**

| method | compress | decompress |
|---|---|---|
| `-cn` | 1.70× | 1.02× |
| `-cf` | 1.65× | 1.16× |
| `-cF` | 1.64× | 0.99× |
| `-cd` | 1.47× | 1.59× |
| `-cD` | 1.80× | 1.41× |
| `-co` | 1.85× | 1.31× |
| `-cO` | 1.54× | 1.19× |
| `-cc` | 1.29× | 1.08× |

Every extraction matched the source. The `-cn`, `-cf`, `-cF`, `-cD` and `-cc` archives are the
original's bytes. The `-cd` one was not, at v0.17.0-pre: from an input of 132 087 808 bytes the `-cd`
window rounds to 128 MB, and a window that size gives the original's match finder a second table the
port did not have. Fixed in v0.17.1-pre: byte-identical from just below that size up to 328 MB. The
`-co` and `-cO` archives differ from the original's; on a 16 MB fixture the difference is the last
block only ([quirk 72](docs/ORIGINAL_QUIRKS.md), below), and on this one it has not been traced.

Parallel (`-pN`) archives decode on one thread per worker stream (`-t<n>` caps it). Method and full
tables: [Performance](https://github.com/YadeWira/nanozip-re/wiki/Performance). Details: [Decode Coverage](https://github.com/YadeWira/nanozip-re/wiki/Decode-Coverage),
[Console Parity](https://github.com/YadeWira/nanozip-re/wiki/Console-Parity), [Component Status](https://github.com/YadeWira/nanozip-re/wiki/Component-Status), [Changelog](https://github.com/YadeWira/nanozip-re/wiki/Changelog).

### Known limits

- **A few `-co`/`-cO`/`-cc` archives are not the original's bytes** (counts above); the ones checked
  round-trip. Three traced cases (`i19_lighthouse_rgb48.ppm`, `150_menu.tbk_` at `-m4m`, the 16 MB
  fixture's last block) are [quirk 72](docs/ORIGINAL_QUIRKS.md): the original keeps param14's hash tables
  in the block buffer's tail, so each pass starts on the last one's leftovers; partial emulation does not
  converge, so it is left unreproduced on purpose. Also open: `i36_fax2d.tif` under `-cO` (our match
  finder returns candidates the original's does not) and `081_AWSOFTWA.PLA_` (param1's first probes
  read the previous block's bytes in the original, zeros here, [quirk 75](docs/ORIGINAL_QUIRKS.md)).
  The 127-file mixed corpus differences are not attributed here; on 2026-09-19 the two outside the
  parser class were a clean `-co` decline (`PowerPacker.pp`, which needed the stored LZ form and is
  byte-identical since 2026-09-23) and the `[1]` name.
- **The stored LZ block form** (the raw block the original writes when its LZ engine cannot shrink
  one) is written since v0.17.3-pre; before, `-co` declined the inputs that need it
  (a 12 MB folder of 21 corpus files, an 8 MB slice of real data). Up to v0.17.2-pre this port also
  could not DECODE some original `-co` archives: a stored block that reaches the end of the window's
  ring, whose 32 KB pieces do not happen to end where the port's window feed left the cursor, followed
  by an LZ block (`tests/encode/stored_lz_block.sh`).
- **Declines.** A block `a` cannot write is declined in one line and no archive is left behind; an
  existing archive of the same name is left as it was (before v0.17.1-pre it was truncated first, and
  a decline deleted it). Every coded
  `-co`/`-cO` LZ or BWT block is decoded back and compared before it is committed (a stored block is
  copied raw) (the LZ payload
  through a second engine, the BWT payload through the bucket decoder), which the original does not do;
  that is about 10 % of a `-co` image encode. The check reads the block, not the file table, so it
  missed the multi-file table defect fixed in v0.17.0-pre (e7c8973) and the parallel-container header
  fixed in v0.17.1-pre. Image and audio blocks, and the `-cc`, lzpf and lzhd writers, are not read back.
- **Threads.** `-t` above 1 still compresses on one thread (stated at v0.10.0-pre and v0.11.0-pre), and `a` lays the
  archive out the `-t1` way at every thread count. From 8 MB of input it splits into worker streams by
  the original's rule (since v0.17.1-pre: `-cn`, `-cO` and `-cc` keep one compressor unless the input is
  mostly media files), and it writes them one after another. The original's own output above one thread changes
  from run to run ([quirk 58](docs/ORIGINAL_QUIRKS.md)), so a byte comparison needs `-t1` on both sides.
- **Decode memory** is above the original's: 128 MB of real files, `-t1` (v0.17.0-pre), `-cd` 359 MB
  (original 109 MB), `-cD` 352 MB (109), `-cf` 179 MB (133), `-cF` 239 MB (195). `-cf`/`-cF` single
  containers stream to disk one data record at a time, as the original does, except under `NZ_SAFE=1`
  or when checksums cannot be judged entry by entry (those still buffer the whole output); the rest
  of their gap is the flat mapping of the archive.
- **Console.** The banner's MHz field is a measured figure in the original, not the clock, and is not
  matched. On a mapped archive the footer's `IO-in` figure is the mapping call (0.00 s, an enormous
  rate) where the original times a read.
- **Unexercised.** Format constructs the original's encoder never emits (`0xd`/`0xe` sub-chunks, image
  predictor modes other than 2) are ported but unexercised.

## Usage

```
nz-re x -y archive.nz            # extract (-y: overwrite without asking)
nz-re l archive.nz               # list
nz-re t archive.nz               # test: decode and verify, write nothing
nz-re x -y -oout/ archive.nz     # into a directory; -sp strips paths; -x<glob> excludes
nz-re a archive.nz files...      # compress with the default compressor, -co (nz_optimum1)
nz-re a -cd -r archive.nz dir    # choose one of -cn -cf -cF -cd -cD -co -cO -cc; -r recurses
nz-re a -cO -m1.2g archive.nz f  # -m: memory budget (default 512m)
nz-re s -cc files...             # simulate: compress and report the size, write nothing
nz-re w32c archive files...      # self-extractor archive.exe: nz_w32c.sfx + the archive
```

Switches, messages, prompts and the exit status follow the original exactly (exit status is always 0,
as in the original); `nz-re help` lists the advanced options, and `*`, `?` and (since v0.17.0-pre)
`[...]` in names match as in the original. `w32c` reads the original's `nz_w32c.sfx` from the directory
of the `nz-re` binary; the stub is not included here. Before v0.13.0-pre the binary was called
`nz_recon`. Environment variables, all optional:

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

Produces `bin/nz-re`; Release is the default build type since v0.15.0-pre (a build with no `-O` flag
ran 4-5× slower). Each release ships four static binaries (Linux and Windows, 64- and 32-bit) with
`SHA256SUMS.txt`, built as `g++ -std=c++17 -O2 -DNDEBUG -D_FILE_OFFSET_BITS=64 -Iinclude -static -pthread -o nz-re src/*.cpp` (and the mingw-w64 equivalents for Windows). `-D_FILE_OFFSET_BITS=64` is required: with a 32-bit `off_t` an archive over 2 GB cannot even be measured, so the code refuses to compile without it.

**Minimum Windows version: Vista (NT 6.0).** The `.exe` builds pin `_WIN32_WINNT=0x0600` and declare
subsystem 6.00, so an older machine gets a clean refusal. They import only `kernel32.dll` and
`msvcrt.dll`; their only Vista-era entry points are the four `CONDITION_VARIABLE` functions libstdc++ pulls
in through `<filesystem>`. Older Windows cannot be tested here, so it is not claimed. Linux builds have no such floor.

The 32-bit builds add `-m32 -msse2`, which compiles the SSE2 paths (audio predictor, `-cO` mixer): a 19 % shorter `-cO` decode on a 137 MB mixed tar, for a Pentium 4-class minimum (the original needed MMX).

## Tests

See [tests/README.md](tests/README.md). The regression set before every commit: `tests/native_only_v2.sh`,
`tests/multifile_v2.sh`, `tests/real_corpus_sweep.sh` and, for compression, `tests/encode/oracle.sh`
(the last two need the original binary at `../linux32/nz`, or `NZ_LEGACY_ORACLE` / `NZ_ORIG`), plus
the release-package hash check and the console matrices kept with the project's private tooling.

## How it was done

Ghidra (headless decompile), GDB tracing against the real `linux32/nz` (golden vectors, watchpoints,
per-stage dumps), differential decoding between codecs that share a front end, and diffs against the
community reference decoder where it exists (`encode_su/nzdec_v0`, incomplete). Encoder differences
were run down the same way, the same state dumped from both binaries and diffed. The tools,
workflow and every finding (addresses, formulas, table contents) are in the wiki's
[Reverse Engineering Notes](https://github.com/YadeWira/nanozip-re/wiki/Reverse-Engineering-Notes);
the source layout is in [Architecture](https://github.com/YadeWira/nanozip-re/wiki/Architecture).

## License

The reconstruction code in this repository is original work released under the **MIT License**.

NanoZip 0.09a binaries are not included and remain the property of their author. This project
contains no extracted binary data, no verbatim decompiled output, and no proprietary assets. The C++
code is an independent reimplementation derived from behavioral observation and dynamic tracing.
