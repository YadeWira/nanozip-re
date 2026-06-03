# LPAQ (1v2..8) vs NanoZip 0.09a - Quick technical comparison

## Samples compared

- LPAQ: `lpaq1v2, lpaq2, lpaq3, lpaq3a, lpaq4, lpaq5, lpaq6, lpaq7, lpaq8`
- NanoZip: `work/linux64/nz`, `work/linux32/nz`, locally generated `.nz` samples

## Strong findings

1) File signature/format mismatch:

- LPAQ source uses header `pQ` + version byte (`1..8`) in `fprintf(out, "pQ...")`.
- NanoZip `.nz` uses header:
  - `ae 01`
  - `"NanoZip 0.09 alpha"`

2) Product model mismatch:

- LPAQ: single compressor per version (`lpaqN`), `.lpq` extension/logic.
- NanoZip: multi-method archiver with internal selector:
  - `nz_lzpf`, `nz_lzpf_large`
  - `nz_lzhd`, `nz_lzhd_parallel`, `nz_lzhd_parallel_extra`
  - `nz_lzhds`, `nz_lzhds_parallel`, `nz_lzhds_parallel_extra`
  - `nz_optimum1`, `nz_optimum2`, `nz_cm`

3) Direct textual evidence of LPAQ reuse in NanoZip binary: not observed.

- `strings` of NanoZip does not show `lpaq`, `Mahoney`, `Ratushnyak`, or `Not a lpaqX file` messages.

## Observed similarities

- The LPAQ family implements classic context mixing (StateMap/APM/Mixer/MatchModel + arithmetic coder).
- NanoZip has a `nz_cm` method, which by name suggests "context mixing".

## Operational conclusion

- Hypothesis "NanoZip = optimized LPAQ" as a total claim: **not supported** by current evidence.
- Hypothesis "NanoZip reuses LPAQ/PAQ ideas in one part (likely `nz_cm`)": **plausible**.

## Recommended next validation

- Isolate via RE the `nz_cm` pipeline and compare internal structure against LPAQ:
  - states/probabilities,
  - predictor mixing,
  - arithmetic coder,
  - tables/transitions.

## New from rescan (Linux32)

- In `fcn.08092470` the real per-method switch was confirmed with selector `ctx+0x24` and 8 cases.
- Index `7` (canonical name `nz_cm`) enters the family `fcn.080ab9c0` with `mode=2`.
- Indices `5` and `6` (`nz_optimum1`, `nz_optimum2`) use the same family `fcn.080ab9c0` with `mode=0/1`.
- Implication: PAQ/LPAQ-style analysis must first concentrate on `fcn.080ab9c0` and its call graph.

## Technical refinement: `nz_cm` internals

Summary of the already-mapped block (`fcn.080ab9c0` + `fcn.080bfcc0`):

- `mode=2` (`nz_cm`) creates additional state compared to `mode=0/1`.
- Two engine implementations selected by flag:
  - `alloc(0x3f700)` + vtable `0x08132e08`
  - `alloc(0x1082c40)` + vtable `0x08132e48`
- The memory estimator (`0x080aafb0`) uses a composite formula with fixed overhead `0x8b600` and extras `0x1000`/`0x80000`.

Matches with LPAQ (architecture level):

- presence of large modeling paths with context tables;
- separation of auxiliary buffers and prediction state;
- MB-order memory cost pattern for the CM path.

Differences vs LPAQ 7/8 (implementation level):

- LPAQ source exposes a direct structure (`StateMap/APM/Mixer/MatchModel`, `MEM`, `x1/x2`).
- NanoZip uses a multi-mode/multi-vtable family integrated with other methods (`optimum1/2/cm`) and a different layout.
- There is no direct 1:1 correspondence between offsets/constructors of `080ab9c0` and LPAQ classes.

Hypothesis state:

- "NanoZip == optimized LPAQ" as exact equivalence: **not supported**.
- "NanoZip `nz_cm` takes PAQ/LPAQ ideas and mixes them with a proprietary architecture": **supported** by current evidence.
