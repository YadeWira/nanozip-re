# NanoZip RE workflow (CLI reconstruction)

Rewritten 2026-09-04. The original version of this page described a decoder that could still fall
back to an "extract bridge" or a "gdb bridge" -- a real `nz` consulted at runtime -- and measured
itself in percentages of methods that avoided them. None of that exists any more: no code path looks
for or runs an original binary, every codec decodes natively, and the measurements are byte-exactness
counts instead. What follows is how the work is actually done now.

## Operational goal

Reconstruct NanoZip 0.09a's `l`, `t`, `x` (and later `a`, `s`, `w32c`) byte for byte, in this order:

1. **Decode**, one engine at a time, byte-exact against the original on real archives.
2. **Console**, byte-identical: the same lines, the same order, the same figures.
3. **Encode**, once the decode is complete: an archive this port writes must be the archive the
   original writes.

## How a claim is measured

The original at `work/linux32/nz` is the oracle for everything (the 64-bit build of 2011 segfaults on
a current kernel, so it is not usable). A statement about behaviour is worth making only if a harness
reproduces it:

- `tests/native_only_v2.sh` -- 12 synthetic fixtures x 8 codecs, byte-diffed. 96/96.
- `tests/multifile_v2.sh` -- multi-file trees and listings over 12 selectors x 9 shapes. 144 + 72.
- `tests/real_corpus_sweep.sh` -- real files from a local corpus, compressed by the original under
  every codec and decoded by both. Resumable, shardable; `NZ_RECON` pins a frozen binary so a rebuild
  cannot mix two binaries into one verdict.
- `tests/sfx_exe.sh`, `tests/sweep_dirs.sh`, `tests/env_switches.sh` -- self-extractors, directory
  trees with symlinks and odd modes, the environment switches.
- `tests/parity/` -- the console matrices, the pty prompt driver and the damaged-archive comparisons,
  with a fixture builder that makes its archives with the original.
- `~/.cache/nzre_tools/release_verify_pkg/check.sh` -- 71 archives / 183 hashes, run against all four
  release binaries (the Windows pair on a real Windows machine).

Anything a harness cannot reach is stated as such, in
[docs/ORIGINAL_QUIRKS.md](ORIGINAL_QUIRKS.md) or on the wiki's Component-Status page.

## Tools used

- RE/inspection:
  - `rizin/radare2`, `gdb` (batch), `xxd`, `strace`, `rg`.
- Behaviour validation:
  - `work/linux32/nz` as the oracle (`work/linux64/nz` segfaults on a current kernel).
- Reconstruction:
  - `cmake`, `g++`.

## Base flow (one iteration)

1. Build (`cmake --build build -j8`), then run the suites above -- never rebuild while a sweep runs.
2. Pick a failing archive and reduce it: which codec, which block, which stage. The per-block check
   bytes name the stage; `NZOPT_TRACE_TDO`, `NZOPT_TRACE_STG`, `NZOPT_TRACE_BWT`, `NZOPT_TRACE_LZPF`
   and the `NZOPT_DUMP_*` variables dump the buffers around it.
3. Get the original's answer for the same bytes: extract with it and compare at the offset the trace
   names, or read the value out of the running binary with GDB (`~/.cache/nzre_tools/cli_parity/`
   holds the scripts: breakpoint helpers, hardware watchpoints on a worker's status word, golden
   vectors).
4. Fix, re-run every suite, and add a fixture so the case cannot regress silently.
5. Write the finding down: a comment where the code needs it, a quirk entry if the original is at
   fault, a Changelog row, and a memory note for the next session.

## Environment switches (this port's, not the original's)

| variable | effect |
|---|---|
| `NZ_SAFE=1` | on a damaged archive write only entries whose checksum verifies |
| `NZ_STRICT_EXIT=1` | exit 2 on a damaged archive instead of the original's 0 |
| `NZ_THREADS=n` | cap the worker threads of a parallel container (`-t<n>` does the same) |
| `NZ_TRACE_CONSTRUCTS=1` | print each distinct format construct met, once |
| `NZ_VERBOSE_NATIVE=1` | say why an engine declined |

## Tools

- Reverse engineering: Ghidra headless (`work/ghidra_scripts/DecompAt.java`, `Xrefs.java`,
  `AllFuncs.java`), `objdump`, `gdb` in batch mode, `strace`, `xxd`.
- Performance: `perf` with the per-function mapping in `~/.cache/nzre_tools/perf/`.
- Fuzzing: `~/.cache/nzre_tools/fuzz/fuzz.sh` (ASan + UBSan over mutated archives; exit 255 is the
  original's reproduced `Internal error` path, not a crash).
