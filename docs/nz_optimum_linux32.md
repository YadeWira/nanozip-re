# NanoZip 0.09a Linux32 - RE notes for `-co/-cO/-cc`

Status of this iteration:

- `-cc`:
  - `literal-wrapper` subcase already detected in the native parser:
    - `stream = [u32 raw_size][raw_payload][trailer]`
    - activates when `raw_size == total_data_size`.
  - examples where it applies:
    - `test_cc.nz` (5-byte payload)
    - `/tmp/nz_cov2/cc.nz` (8244-byte payload)
  - examples where it does not apply (still bridge/compat):
    - `/tmp/nz_probe_alg/repa_cc.nz` (real 4096-byte compressed stream of repeated data)

- `-co/-cO`:
  - small subcase already supported in pure native:
    - `stream = [u32 raw_size][bwt_last(raw_size)][u24 primary_index][trailer]`
    - validated on `test_co.nz` and `test_cO.nz` without bridges.
  - BWT subcase with 16-byte trailer supported in pure native:
    - `stream = [u32 raw_size][bwt_last(raw_size)][trailer16]`
    - `primary_index` in `trailer[5..7]` (u24 little-endian).
    - validated without bridges on 8 KiB samples (`rand8k/mix8k`, `-co/-cO`).
  - `raw-wrapper` subcase (incompressible) supported in pure native:
    - `stream = [u32 raw_size][raw_payload][trailer]`
    - activates when `raw_size == total_data_size` and validates checksums per entry.
    - validated without bridges:
      - `/tmp/nz_co_lpaq_probe/legacy_co_combo.nz`
      - `/tmp/nz_co_lpaq_probe/legacy_cO_combo.nz`
  - real compressed streams observed (not literal).
  - small samples (`test_co.nz`, `test_cO.nz`) show a pattern compatible with BWT+metadata:
    - initial `u32` equal to original size (e.g. `05 00 00 00`)
    - BWT-style block for `hola\n`: `61 6c 0a 6f 68` (`al\noh`)
    - observed primary index (`00 00 02`).
  - compressed multi-file samples (e.g. `/tmp/nz_co_analysis/co.nz`) still lack a pure decoder.
  - additional confirmation (`/tmp/nz_co_probe/co.nz`, `stream_bytes=8267`):
    - apparent prefix: `u32 n = 8241`, followed by `n` bytes and `u24=308`;
    - 19 bytes of trailer remain:
      - `co`: `20000003de272f004908000000000000000000`
      - `cO`: `20000003de272f014908000000000000000000`
    - `co` and `cO` differ in 1 trailer byte (`00` vs `01`), consistent with a method variant;
    - applying `InverseBwt` directly over those `n` bytes **does not** reconstruct the original payload,
      so the large block is not just `[bwt_last][primary]` raw.
  - contrast with `lpaq1v2..lpaq8` (32-bit build, corpus `/tmp/nz_co_analysis/co.nz`):
    - both `raw` and `bwt_last` inputs were tried with memory `0..9`;
    - there were candidates with near payload size (`8240..8243`) but **0 exact matches**;
    - common prefix with the legacy body: `0` bytes in the best cases.
    - conclusion: the real `-co` body does not match byte-for-byte with the direct output of those lpaq versions in standard mode.

## Confirmed runtime call-chain (real `-co/-cO`)

`gdb` traces on the current samples show that, inside `0x080aa850`, there are distinct active paths:

1. direct BWT path:
   - `0x080aa850 -> 0x0809d370` (without prefilter);
   - used by BWT wrappers (includes the `trailer16 primary@+5` subtype).
2. BWT path with prefilter:
   - `0x080aa850 -> 0x0809a250 -> 0x0809d370`;
   - used in compressed multi-file streams (real `co/cO` still pending).
3. alternate repetitive-data path:
   - `0x080aa850 -> 0x080acaf0 -> 0x080ace10 -> 0x080accd0`;
   - still pending in pure C++.

Note:

- `0x080abca0` still exists in the optimum/cm family, but it is not the main path observed in the current `co/cO` corpus.

## Reference samples (dump)

- `test_co.nz`:
  - `stream_bytes=25`
  - `head=05000000616c0a6f68000002dc7402...`
- `/tmp/nz_cov2/co.nz`:
  - `stream_bytes=8268`
  - `head=32200000a4dd6533...`
  - `tail=...b440000134200000033794a6005f08000000000000000000`
- `/tmp/nz_probe_alg/repa_co.nz`:
  - `stream_bytes=28`
  - `head=040000005ef277dd010140000000036e7d9e01010000000300000000`
- `/tmp/nz_probe_alg/repa_cc.nz`:
  - `stream_bytes=47`
  - `head=17000000beeb672bf3789693...`
  - `tail=...000140000000036e7d4101010000000300000000`

Next technical goal:

1. map the arguments and state of `0x080aa850` -> `0x080abca0` (stack + `ctx` offsets) in the path that ends at `0x080aab2f`;
2. identify the meaning of `u32 n`, `u24` and the 19-byte trailer in large blocks;
3. implement an incremental block decoder;
4. validate against corpus:
   - `test_co.nz`, `test_cO.nz`
   - `/tmp/nz_cov2/co.nz`, `/tmp/nz_cov2/cO.nz`
   - repetitive cases `repa_co`, `repa2_co`.

## Runtime reclassification (current pass)

Automated tracing (`tests/legacy_optimum_trace_path.sh`) was added and run over the `co/cO` corpus (`/tmp/nz_co_grid`, `/tmp/nz_co_pairs`, `/tmp/nz_co_analysis`, `/tmp/nz_co_small`, `/tmp/nz_co_lpaq_probe`).

Paths observed in `linux32/nz`:

1. `b98a0 -> b1950 -> aa850`:
   - simple wrapper subcase;
   - already resolved in pure native (no `[compat]`).
2. `b98a0 -> b1950 -> aa850 -> acaf0`:
   - alternate compressed subcase (frequent in repetitive data);
   - still pending in pure C++ (today it falls back to compat).
3. `b98a0 -> b1950 -> aa850 -> a9d370`:
   - main compressed subcase (frequent);
   - already covered in pure native for the current batch.
4. `b98a0 -> b1950 -> aa850 -> a9a250 -> a9d370`:
   - heavier subcase (e.g. `/tmp/nz_co_analysis/co.nz`);
   - still pending in pure C++ (today it falls back to compat).

Counts in a classification run (86 samples):

- `aa850 -> a9d370`: 44
- `aa850 -> acaf0`: 26
- `aa850` (only): 10
- `aa850 -> a9a250 -> a9d370`: 2

Cross-check with `nz_recon` without bridges (`NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1`):

- `aa850` (only) path: `t/x` without `[compat]`;
- `a9d370` path: `t/x` without `[compat]`;
- `acaf0` and `a9a250+a9d370` paths: `t/x` correct but with `[compat]`.

Direct implication:

- the pure `-co/-cO` blocker is no longer attacked via `0x080abca0` for the current main corpus;
- the C++ port must prioritize `0x0809d370` (and its prefilter `0x0809a250` when applicable), then `0x080acaf0`/`0x080ace10`/`0x080accd0`.
