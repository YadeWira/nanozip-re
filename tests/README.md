# Tests

Everything here measures the native decoder against the original `nz` 0.09a (`../linux32/nz`,
the oracle: it compresses the fixtures and its own extraction is the reference output). There is
no bridge of any kind; the environment variables about bridges that older scripts export are
ignored by the binary.

## Regression suites (run before every commit)

| script | what it checks |
|---|---|
| `native_only_v2.sh` | 12 synthetic fixtures × 8 codecs, byte-diffed against the original; includes a hand-built BWT-with-entropy-layer case. Headline: 96/96. |
| `multifile_v2.sh` | Multi-file archives: whole-tree compare (contents, mode, mtime) over 12 compressor selectors × 9 shapes, metadata switches (`-nt -np -nm -hn -hc -hC`), 72 `l` listings. Pins the metadata record layout. 144 + 72. |
| constructs (`NZ_TRACE_CONSTRUCTS=1`) | Each distinct format construct the decoder meets, once per process: sub-chunk kinds, image modes, text-transform bits, block kinds, container shape (single/parallel, streams, one/many files), store reassembly, the winning lzpf dictionary candidate, and BWT rank prefixes of 20 bits or more. The verification package exercises 68 of them. |
| `sweep_dirs.sh` | Directory trees: deep paths, empty files, UTF-8 and space names, symlinks (file/dir/absolute), an unreadable file, setuid/sticky modes, extreme timestamps; every codec plus `-fo`, compared against the original's own extraction (contents, mode, mtime, links). 16/16. |
| `env_switches.sh` | `NZ_SAFE`, `NZ_STRICT_EXIT`, `NZ_THREADS`: exit codes and trees on a damaged and an intact parallel archive. 8/8. |
| `sfx_exe.sh` | Self-extracting archives: the original's `w32c` builds one `.exe` per codec (PE stub + archive), and `l`/`t`/`x` are compared against it. 8/8 byte-exact. |
| `real_corpus_sweep.sh` | Real-world files: every file in `$NZ_REAL_CORPUS` compressed by the original under all 8 codecs and decoded by both. Resumable (`NZ_RESULTS_TSV`), shardable (`NZ_SHARD=i/N`), directory fixtures (`NZ_DIR_MODE=1`), per-call `NZ_TIMEOUT`. Collects `[construct]` lines (see below). |
| `stress_matrix.sh` | 5 consecutive runs × 8 codecs over single/multi/multi-block shapes: a non-determinism tripwire. |
| `smoke_suite.sh` | CLI basics (no args, unknown command/switch), file errors, extraction metadata smoke. |
| `coverage_matrix.sh` | `l`/`t`/`x` matrix over a corpus built by the original. |
| `test_lzpf_arith.cpp`, `test_optimum_lz.cpp`, `test_optimum2_lz.cpp` | Unit tests against GDB-captured golden vectors (lzpf bit reader/Huffman/LZ77, `-co` and `-cO` engines). |

`~/.cache/nzre_tools/release_verify_pkg/check.sh <binary>` (47 archives, 95 hashes) is the release gate;
`~/.cache/nzre_tools/cli_parity/` holds the console-parity matrices (`matrix.sh`, `matrix2.sh`,
`matrix3.sh`, `pty_prompt.py`) and `corrupt_compare_all.sh` (damaged-archive parity, 48 cases).

## The wide sweep

```bash
tests/corpus_select.sh /tmp/nzre_corpus            # ~3000 stratified files from the sample collection
tests/sweep_run.sh /tmp/nzre_corpus 8 /tmp/nzre_sweep/results.tsv   # 8 background shards, resumable
tests/sweep_report.py /tmp/nzre_sweep/results.tsv /tmp/nzre_corpus/MANIFEST.tsv
```

Do not rebuild `bin/nz_recon` while shards run (it invents failures). To rerun only the failures
after a fix: `grep -v FAIL results.tsv > r && mv r results.tsv`, then `sweep_run.sh` again.

`NZ_TRACE_CONSTRUCTS=1` makes the decoder print one `[construct] key=value` line per distinct
format construct it meets (sub-chunk kinds, image-model modes, text-transform bits, block kinds,
mid-stream checksum records); the sweep aggregates them into a "constructs observed" table so a
release can say what was exercised. `tests/gen_image_variants.py <dir>` writes BMP/PGM/PPM/PBM/TGA/
TIFF variants that trigger the image detectors.

## Speed and debug builds

`tests/bench_vs_original.sh` builds a ~140 MB mixed tar from a sample collection, has the original
compress it in the six codecs and times `t` for both binaries (the numbers on the wiki's Performance
page). `tests/debug_build_check.sh` syntax-checks the trace/dump switches, which compile in only with
`-DNZOPT_DEBUG` (the `-cO` model-write watch with `-DNZO2_WATCH`) and are off in every normal build.

## RE helpers

`legacy_optimum_trace_path.sh`, `legacy_optimum_path_matrix.py`, `legacy_stream_dump.py`,
`legacy_optimum_raw_wrapper.sh`, `legacy_optimum_bwt_tail_primary.sh`: tracing and record dumps
of the original, used while porting; not assertions.
