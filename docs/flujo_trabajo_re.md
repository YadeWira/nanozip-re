# NanoZip RE Workflow (CLI reconstruction)

Cutoff date: 2026-04-03

## Operational goal

Reconstruct `l/t/x/a/s` of NanoZip 0.09a without SFX, prioritizing:

1. real usage compatibility (`l/t/x` working on legacy archives);
2. format traceability (header, table, metadata, payload);
3. progressive replacement of compat/bridges with pure C++ decode.

## Percentage definitions

- `usage_real_percent`:
  - percentage of `-c*` methods that pass `l/t/x` with correct output;
  - includes bridge/compat paths when activated.
- `native_only_percent`:
  - percentage of `-c*` methods that pass `l/t/x` without emitting `[compat]`;
  - may still use the `extract bridge` or `gdb bridge`.
- `native_pure_percent` (recommended manual measurement):
  - same criterion as above, but with bridges disabled:
  - `NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1`.
- `encode_real_percent`:
  - percentage of `-c*` methods where `a/s` followed by `t/x` of the produced archive passes correctly.
- `encode_native_no_compat_percent`:
  - percentage of `-c*` methods where `a/s` does not emit `[compat]`.
- `encode_native_no_compat_bridge_percent`:
  - percentage of `-c*` methods where `a/s` emits neither `[compat]` nor `[bridge]`.

## Tools used

- RE/inspection:
  - `rizin/radare2`, `gdb` (batch), `xxd`, `strace`, `rg`.
- Behavior validation:
  - `work/linux64/nz`, `work/linux32/nz` as oracle.
- Reconstruction:
  - `cmake`, `g++`.

## Base flow (standard iteration)

1. Build the reconstructed binary.
2. Measure the coverage baseline (`coverage_matrix.sh`).
3. Re-run the baseline with bridges disabled to measure pure progress.
4. Take a `.nz` sample and extract its internal stream to form format hypotheses.
5. Implement the subcase in C++ parser/decode (always conservative).
6. Run regression:
   - `l/t/x` on the test corpus;
   - `cmp` of extracted files vs originals;
   - full coverage matrix.
7. Document the finding and leave a concrete next step.

## Reference commands

Build:

```bash
cd work/reconstruccion
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
cp build-release/nz_recon bin/nz_recon
cp build-release/nz_sfx_recon bin/nz_sfx_recon
```

Normal coverage:

```bash
cd work/reconstruccion
./tests/coverage_matrix.sh
```

Coverage without bridges (purity):

```bash
cd work/reconstruccion
NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 ./tests/coverage_matrix.sh
```

Legacy stream dump:

```bash
cd work/reconstruccion
./tests/legacy_stream_dump.py /path/to/archive.nz
```

`-co/-cO` runtime path trace in the legacy backend:

```bash
cd work/reconstruccion
./tests/legacy_optimum_trace_path.sh /path/to/archive.nz
```

Runtime path matrix vs native purity (sample batch):

```bash
cd work/reconstruccion
./tests/legacy_optimum_path_matrix.py '/tmp/nz_co_grid/*.nz' '/tmp/nz_co_pairs/*.nz'
```

## Legacy decode paths (real order)

For `t/x` of legacy archives:

1. native header + table + metadata parser;
2. if the payload is not native:
   - `extract bridge` (uses the legacy backend in a temp dir, no ptrace);
   - then `gdb bridge` (if available);
3. if both fail:
   - `[compat]` fallback to the legacy backend.

## `a/s` compression paths (real state)

- `-cn`: native C++ compression/writing.
- legacy methods (`-cf/-cF/-cd/-cD/-co/-cO/-cc`):
  - by default: native `native-first` writer with RE wrappers:
    - `cf/cF`: `literal-only`;
    - `cd/cD`: `literal-wrapper` (`[varint][0x00][raw]`);
    - `co/cO`: BWT wrapper (`[u32 size][bwt_last][u24 primary]`, 32 KiB limit in native writer);
    - `cc`: `raw-wrapper` (`[u32 size][raw]`).
  - if the native writer fails and the bridge is enabled: fallback to the legacy backend (marked `[bridge]`, without the prior `[compat]` marker);
  - `NZ_DISABLE_COMPRESS_BRIDGE=1`: disables the bridge fallback and forces strictly native output (error if the wrapper does not apply).
  - supports `-h*` (with `-hf -> Fletcher32` mapping in the legacy header).

## Operational environment variables

- `NZ_LEGACY_BACKEND`:
  - path to the `nz` backend (file or containing directory).
- `NZ_LEGACY_BRIDGE_BACKEND`:
  - path to the linux32 backend for the `gdb bridge`.
- `NZ_DISABLE_EXTRACT_BRIDGE`:
  - disables the extract bridge.
- `NZ_DISABLE_GDB_BRIDGE`:
  - disables the gdb/ptrace bridge.
- `NZ_DISABLE_COMPRESS_BRIDGE`:
  - disables the `a/s` compression bridge fallback for legacy methods and forces strictly native output.

## Current state per `-c` method

- `cn`: pure native.
- `cd/cD`: pure native in the observed literal-only subcase; native RE wrapper writer available.
- `cc`:
  - pure native in the `literal-wrapper` subcase (`[u32 size][raw][trailer]`);
  - native `raw-wrapper` writer available;
  - real compressed streams still require bridge/compat.
- `cf/cF`: pure literal-only; native literal writer available; real compressed streams still pending.
- `co/cO`:
  - native BWT-wrapper decoder observed on small samples;
  - native `raw-wrapper` subcase decoder observed on incompressible entries;
  - native BWT-wrapper writer available (32 KiB limit);
  - general real compressed streams still pending (bridge/compat).

## Implementation principle

Always validate subcases with strong structural checks:

1. coherent stream layout (`stream_tag`, lengths, limits);
2. expected total size (`total_data_size`);
3. per-entry consistency (never read out of range);
4. safe fallback to bridge/compat when the checks do not hold.

## Immediate backlog

1. Port the real `cf/cF` compressed path (RE core `0x08097570/0x08097e20`).
2. Complete the pure `co/cO` decoder for the general real compressed streams still pending:
   - prefilter `0x0809a250` on the `0x080aa850 -> 0x0809a250 -> 0x0809d370` path;
   - alternate repetitive path `0x080aa850 -> 0x080acaf0 -> 0x080ace10 -> 0x080accd0`.
   - note: the direct BWT path `0x080aa850 -> 0x0809d370` already has native coverage on observed wrappers (including `primary` in trailer16@+5).
3. Extend the pure `cc` decoder to real compressed streams.
4. Complete the multi-file legacy metadata parser (timestamps/permissions/checksum per entry).
