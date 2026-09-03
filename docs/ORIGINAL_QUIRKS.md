# Quirks, defects and loose ends of the original `nz` 0.09 alpha

NanoZip never had a stable release: 0.09 alpha (2011) is the last build Sami Runsas
published, and it still carries the rough edges of an alpha. This page collects the ones
measured while making nanozip-re behave like the original — every item below was observed on
`nz 0.09 alpha/Linux32` (and, where noted, on the Windows build), not inferred from the
decompile. It is meant as a reference for anyone writing a compatible tool: some of these
must be *reproduced* to stay compatible, others are best left behind.

**Policy (2026-09-03):** nanozip-re reproduces the original first, defects included, so that the two
binaries can be compared on equal terms; which of these defects to keep and which to fix is a decision
for the community once the decoder is complete, and it will be taken with this list in hand. Until
then the only escape hatches are environment variables (`NZ_SAFE=1`, `NZ_STRICT_EXIT=1`), never new
switches. The verdict column says what nanozip-re does today.

| # | Area | What the original does | nanozip-re |
|---|------|------------------------|------------|
| 1 | exit status | **Always 0**, on every path: unknown command, missing archive, foreign file, corrupt data, checksum mismatch. Scripts cannot tell success from failure. | Reproduced. `NZ_SAFE=1` or `NZ_STRICT_EXIT=1` return 2 for damaged or undecodable content (`NZ_STRICT_EXIT` also gives distinct codes for usage errors). Pending the community's decision. |
| 2 | damaged archives | Writes whatever it decoded. Output is flushed per codec block (`-co`/`-cO`/`-cc`: the block is a whole type group up to the window, so a 6 MB text file yields nothing; `-cc` blocks of ~2 MB flush individually), per 1 MB stream for `-cd`/`-cD`, per member for `-cf`/`-cF`. When a block fails: the files of the blocks before it are on disk, the file the failing block starts with is **created empty** (a file it cut mid-way keeps the bytes of the earlier blocks), nothing is warned per file — only `Archive corrupted. Error decoding (code N)`. When decoding completes but a checksum fails: the wrong file is written, `Checksum mismatch [stored computed]: file` is printed and the footer follows. | Reproduced: 40 of 48 one-byte corruptions/truncations across eight codecs leave the same tree. The rest differ in the garbage each decoder produces (audio blocks, `-cf` LZ), a block-level check of the original on stored/BWT blocks that is not identified yet (see 25), and the store-truncation case (see 26). `NZ_SAFE=1` writes only checksum-verified entries, skips the rest with the mismatch line, exits 2. |
| 3 | overwrite prompt | `Overwrite <file> (Yes/No/Always)?` reads a raw key. When stdin is not a terminal (pipe, `/dev/null`, a script) the read fails and the prompt is **re-printed forever**, at full speed — 1.7 GB of prompt text per minute in our test, until the disk fills. `-y` avoids it. | Reads a line; end of input counts as *No*. |
| 4 | error codes | The code after `Error decoding` is not one number: measured 100 (block-level check), 25600 and 26112 (`-co` engine, 100·256 and 102·256), 5 and 6 (`-cd`/`-cD`), 4, 512, 1024, 1536 (`-cf`/`-cF`), and a truncated archive gives 25600 through the same engine path. A clean-but-short `-cd` decode says `Archive corrupted. Unexpected end of file.` instead. One `-cF` corruption produced **no message at all** (files written, silent stop). | 100, or 25600 when the input is cut short; the `-cd` "Unexpected end of file." message. The other codes need the original's detection points, not yet ported. |
| 5 | archive name | `.nz` is appended unless the name already ends in `.nz` or `.exe`, **case-sensitively**: `m.NZ` becomes `m.NZ.nz`, `m.EXE` becomes `m.EXE.nz`. `-nofilenameext` disables it. | Reproduced. |
| 6 | foreign files | A file that is not an archive is probed by reading record headers; when the first record type happens to be 14 the *next* byte is reported as a version number: `Archive file is made with incompatible version (1.12)` for a text file starting with `Nano…`, `(0.97)` for the four bytes `Nano`. Random data usually gets `File is not a NanoZip archive.`, but not always. | Reproduced (the probe is ported), since the message text is part of the interface. |
| 7 | `-` switch | Documented in the usage text as "stop scanning switches", but on `l`/`t`/`x` a lone `-` is rejected: `Unknown argument: -`. | Reproduced. |
| 8 | switch values | Values must be attached: `-o out` makes `out` the archive name (so `Archive: out.nz` / `Cannot open archive!`), `-x` alone is `Unknown argument: -x`. `-m` accepts decimals (`-m1.5g`) but `-mfoo` is rejected; `-p`, `-m`, `-o`, `-t`, `-br`, `-bw` may be empty and are then ignored. | Reproduced. |
| 9 | switches anywhere | Switches are recognised in any position after the command: `x archive -y` overwrites, `x archive -v` shows the verbose header. A file argument beginning with `-` therefore cannot be given. | Reproduced. |
| 10 | `l` ignores file arguments | `l archive some/file` lists the whole archive; the arguments are silently dropped. | Reproduced. |
| 11 | `-swapinout` / `-forceout` | Benchmark helpers with odd corner cases: with no file argument `-swapinout` makes the archive name `*` (`Archive: *.nz`), and `-forceout` writes every extracted entry to a file literally named `*`. | Reproduced. |
| 12 | `-t<n>` on decode | Caps the reported `Threads:` value; `-t0` and values above the CPU count mean "auto". It does not appear to change the decode itself. | Reproduced (and it also caps the decoder's own thread pool). |
| 13 | `Compressor #k` order | On a multi-threaded (`-pN`) archive the per-worker lines come out in **thread-scheduling order**, different from one run to the next, interleaved with the progress redraws. | Deterministic stream order (0..N-1). Only difference left on those archives. |
| 14 | container record order | The metadata records of the worker streams are likewise written in the order the threads finished, not stream order: a decoder that assumes stream 0 comes first mis-parses about one archive in twenty. | Handled (was a bug here once). |
| 15 | progress line | Redrawn from a ~0.5 s timer, only when the megabyte figure or the current file changed; the figure is *cumulative* over the whole archive, rounded (`0 MB` … `3 MB`); names over 40 columns are shown as `...` plus their last 37 characters; the name/figure/backspace choreography is fixed. The number of redraws therefore varies between two runs of the same command. | Same rules; the redraw count still differs by timing. |
| 16 | `IO-out` in the footer | `IO-in: 0.00s, 51 MB/s. IO-out: 0.00s, 738 MB/s` appears only when the write phase happened to take measurable time; on a fast machine the same archive shows it in one run and not the next. | Not reproduced (timing-dependent). |
| 17 | `[N MB]` figure | The compressor line's memory figure is the codec's own memory-usage method, which mixes window size, table sizes and fixed allocations (e.g. `nz_cm [419 MB]` at the default `-m512m`, `nz_lzpf_large [68 MB]` even for a 20-byte input); it says nothing about what the *decoder* will use. | Reproduced to the byte (transcribed formulas). |
| 18 | `-v` on decode | Adds only ` IO-buffers: 0+1 MB.` (`t`) / ` IO-buffers: 0+4 MB.` (`x`) to the compressor line and exact byte counts to `l`; nothing else is more verbose. | Reproduced. |
| 19 | listing units | The `size` column steps up to the next unit once the value exceeds *nine* of the current one (9216 B prints as bytes, 9300 as `9 KB`; exactly 9 MB prints as `9216 KB`) and rounds rather than truncates. | Reproduced. |
| 20 | self-extractors | `l`/`x`/`t` accept a `.exe` made with `w32c`: the opener parses the PE header and seeks past the image. A PE whose section table it cannot read yields `File is not a NanoZip archive.`. | Reproduced (PE offset ported). |
| 21 | checksum coverage | With `-pN` (the default above ~8 MB) a file that spans several worker streams has **no whole-file checksum** — each stream checksums only its slice, and `l` shows `n/a`. | Same; slices are verified individually. |
| 22 | `decr_param 3` | The block type the image model uses (uncompressed BMP/PGM/PPM/TGA/TIFF) is decoded by the original; the community reference decoder (`nzdec_v0`) treats it as ordinary CM and fails every such file — a documentation gap of the format, not a defect of `nz`, but the source of most third-party decoding failures. | Ported. |
| 23 | 32-bit memory | The 32-bit Linux build decodes multi-gigabyte archives fine (it streams); it prints `Out of memory!` when the *compressor's* model does not fit. | Our 32-bit builds hold the decoded stream in memory and print `Out of memory!` on archives whose content does not fit; use the 64-bit build for those. |
| 25 | stored/BWT block check | A flipped byte inside a *stored* `-cc` block or a raw BWT `-co` block is caught before anything is written (`code 100`). The block header carries a `staged` byte per stage whose function is still unknown (the community reference decoder skips them); it is not a sum of the stage bytes nor any common 8-bit CRC. | The BWT case is caught by requiring the inverse permutation to close its cycle; the stored `-cc` case is not caught (the wrong file is written with a `Checksum mismatch` line). |
| 26 | truncated store archive | `-cn` archive cut at 85 %: all five files are created at **full size**, the cut one and every later one filled with garbage, four `Checksum mismatch` lines (three computed as `ffffffff`), exit 0. | `Data corrupted while reading headers!`, nothing written. Not worth reproducing. |
| 27 | `-cD` crash | One corruption made the original abort with `*** glibc detected *** ... free(): invalid pointer` (heap corruption in the decoder), then still print `Archive corrupted. Error decoding (code 6)`. | Declines cleanly (fuzzed: 761/761 clean). |
| 24 | `a` on the current directory | `a archive.nz` with no file arguments quietly archives whatever is in the current directory (in our test: the shell's own redirect target). | Not applicable (encode not implemented; an error is printed). |

## Things that are *not* defects but surprise people

- **Compression is not reproducible byte-for-byte across thread counts**: the same input
  compressed with `-p1` and with the default gives different archives (different stream
  splits). Decoding either is fine.
- **The window size is a byte, not a number**: `bytefloat(p1 + 1)` in 64 KB units (a 4-bit
  mantissa and exponent) is what every codec derives its window/dictionary/ring from, so
  the actual window is rarely exactly what `-m` asked for.
- **The version string is a record**: an archive begins with a type-14 record holding
  `NanoZip 0.09 alpha` and a type-30 record holding the byte 9; the "incompatible version"
  message reports that byte divided by 100.

## How these were measured

Two harnesses drive the original and nanozip-re through identical invocations and compare
stdout, stderr, exit status and the tree of written files (mode, timestamp, size, path):
`matrix.sh` (36 command/format cases) and `matrix2.sh` (78 switch cases), plus
`corrupt_compare_all.sh` (one flipped byte at five offsets and a truncation, on a five-file archive
of every codec, 48 cases). They live with the project's private tooling and are described in the
wiki's Reverse-Engineering-Notes.
