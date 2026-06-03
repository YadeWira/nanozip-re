# NanoZip Linux32: internal core of `nz_cm` (`fcn.080ab9c0` family)

Base analyzed: `work/linux32/nz` (ELF32 static, stripped).

## 1) Real entry of `nz_cm`

From the main dispatcher (`fcn.08092470`):

- `idx 7` (canonical name `nz_cm`) enters `fcn.080ab9c0` with `mode=2`.
- `idx 5/6` (`nz_optimum1/2`) enter the same family with `mode=0/1`.

This confirms that `nz_cm` is a sub-mode of the `080ab9c0` family, not a separate path.

## 2) Family constructor: `fcn.080ab9c0`

General pattern:

1. Initializes internal block `ctx+0x40` via `fcn.080bfcc0(...)`.
2. Fixes the high-level vtable in `ctx`:
   - `ctx->vptr = 0x08132ea8` (`mov dword [ebx], 0x8132ea8`).
3. Initializes/clears auxiliary structures:
   - region in `ctx+0x38c40` (call to `fcn.080a90b0`),
   - pointers `ctx+0x8b5f4/0x8b5f8/0x8b5fc`.
4. Reserves auxiliary buffers:
   - fixed buffer of `0x80000` bytes (`ctx+0x8b5f8`),
   - buffer of `0x1000` bytes (`ctx+0x8b5fc`) when `mode>1`.
5. Selects the main engine by `byte [ctx+0x38c18] & 1`:
   - bit=1 -> `alloc(0x1082c40)`, ctor `fcn.080b90a0`, vtable `0x08132e48`.
   - bit=0 -> `alloc(0x3f700)`, ctor `fcn.080bcb50`, vtable `0x08132e08`.
   - pointer stored in `ctx+0x8b5c0`.

Family destructor: `fcn.080ab090` (frees `ctx+0x8b5c0`, `ctx+0x8b5f8`, `ctx+0x8b5fc`, then destroys `ctx+0x38c40`).

## 3) Deep setup per mode: `fcn.080bfcc0`

`fcn.080bfcc0` receives `mode` (arg2) and builds most of the working state:

- Reserves a base block proportional to the input parameter (`dict*5 + 0x100887`, aligned).
- Initializes substructures at offsets `+0x10`, `+0x28`, `+0x38`, `+0x50`.
- Prepares tables/buffers and validates a threshold (`dict > 0x0fffff`, otherwise aborts).

Branches by `mode`:

- `mode=0`:
  - base path with `fcn.080b1600(..., 0x40, 0x11, 3, 4)`.
- `mode=1`:
  - intermediate path with derived parameters (`0x60`, `1`, `3`, `8`),
  - sets state byte `ctx+0x38bd8 = 3`.
- `mode=2` (`nz_cm`):
  - heavier path (`0x80`, `1`, `3`, `16`),
  - creates an extra object via `fcn.080b5810(...)` and stores it in `ctx+0x38bd0`.

Practical conclusion: `mode=2` does not just "tune parameters"; it adds an additional substructure.

## 4) Observed relevant vtables

Table at `0x08132e08` (compact engine):

- `0x080a0750, 0x080a0770, 0x0809e5c0, ...`

Table at `0x08132e48` (large engine):

- `0x080a9060, 0x080a9080, 0x080a5d50, ...`

Table at `0x08132ea8` (high-level object of this family):

- `0x080aafb0, 0x080ab090, 0x080ab140, 0x080aaf70, 0x080ab160, 0x080aa850, ...`

## 5) Engine memory estimator (`0x080aafb0`)

`0x080aafb0` sums memory of subcomponents:

- `fcn.080c0070(ctx+0x40)` +
- `fcn.080b6160(ctx+0x38c40)` (constant `0x210000`) +
- virtual memory of the object at `ctx+0x8b5c0` (indirect call to vtable+8) +
- fixed block per implementation selector:
  - `0x3f700` (compact engine) or
  - `0x1082c40` (large engine) +
- conditional extras:
  - `0x1000` if `ctx+0x8b5fc` exists,
  - `0x80000` if `ctx+0x8b5f8` exists,
  - `0x8b600` base overhead.

Observed shortcut:

- when large engine + both extras active, returns `base + 0x118f240`.
- `0x118f240 == 0x1082c40 + 0x1000 + 0x80000 + 0x8b600`.

## 6) Point comparison with LPAQ

What this path does bring close to a PAQ/LPAQ-style family:

- there is a specific sub-mode (`mode=2`) heavier than the others that adds extra state;
- use of large tables and per-byte/context probability state;
- presence of memory paths in the order of several MB for modeling.

What does NOT match "pure LPAQ" literally:

- multi-engine architecture (`optimum1/2/cm`) inside the same constructor;
- two engine implementations selected by flag (`0x3f700` vs `0x1082c40`);
- internal layout and constants that do not map 1:1 to LPAQ classes (`StateMap/APM/Mixer/MatchModel`) by name/structure.

Operational conclusion:

- `nz_cm` is compatible with the hypothesis "optimized CM with PAQ/LPAQ ideas",
- but there is no evidence of a direct line-by-line copy of `lpaq7/8`.

## 7) Vtable interface (progress)

The main interface at `0x08132ea8` was mapped:

- `0x080aafb0` -> memory estimator
- `0x080ab090` -> destructor
- `0x080ab140` -> deleting-dtor
- `0x080aaf70` -> reset/reinit
- `0x080ab160` -> parameter parsing/loading
- `0x080aa850` -> main operational routine

Full detail:

- `work/reconstruccion/docs/nz_cm_vtable_linux32.md`
