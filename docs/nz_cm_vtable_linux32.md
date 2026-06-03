# NanoZip Linux32: vtable interface of the `nz_cm` family (`0x08132ea8`)

Base: `work/linux32/nz`.

## 1) Main vtable

Vtable at `0x08132ea8` (high-level object of the `fcn.080ab9c0` family):

- `+0x00 -> 0x080aafb0`
- `+0x04 -> 0x080ab090`
- `+0x08 -> 0x080ab140`
- `+0x0c -> 0x080aaf70`
- `+0x10 -> 0x080ab160`
- `+0x14 -> 0x080aa850`

Assignment xrefs:

- ctor: `0x080aba14` (`mov [ebx], 0x8132ea8`)
- dtor: `0x080ab09f` (`mov [ebx], 0x8132ea8`)

## 2) Suggested semantics per method

`0x080aafb0` (`vtable+0x00`):

- Estimates total memory of the instance.
- Uses:
  - `fcn.080c0070(ctx+0x40)`,
  - `fcn.080b6160(ctx+0x38c40)` (`0x210000`),
  - virtual `subengine+8`,
  - fixed/conditional blocks (`0x3f700`/`0x1082c40`, `0x1000`, `0x80000`, `0x8b600`).

Suggested name: `nz_cm_family_estimate_memory`.

`0x080ab090` (`vtable+0x04`):

- Non-deleting destructor.
- Frees `ctx+0x8b5c0`, `ctx+0x8b5f8`, `ctx+0x8b5fc` and resets `ctx+0x38c40`.

Suggested name: `nz_cm_family_dtor`.

`0x080ab140` (`vtable+0x08`):

- Deleting-dtor wrapper (`call 0x080ab090` + free).

Suggested name: `nz_cm_family_delete`.

`0x080aaf70` (`vtable+0x0c`):

- Reinit/rewind of active state.
- Calls:
  - `fcn.080c0130(ctx+0x40)` (reset of main sub-state),
  - `fcn.080b6170(ctx+0x38c40)` (deep reset of tables),
  - `vcall [ctx+0x8b5c0] + 0x18` if there is a sub-engine.
- Returns `ctx`.

Suggested name: `nz_cm_family_reset`.

`0x080ab160` (`vtable+0x10`):

- Parameter parser/loader for the instance from stream (`arg_84h`).
- Performs many bounded reads via `fcn.080917d0` and loads flags/fields into:
  - `0x8b5c4..0x8b5cd`,
  - `0x8b5da` (word),
  - `0x8b5d0`, `0x8b5d4`, `0x8b5dc`,
  - `0x8b5f4` (size adjustment),
  - ranges in `ctx+0x4a0` and `ctx+0x38c00`.
- Returns `0` on valid path or internal error codes (`6,8,9,11,13,15,16`).

Suggested name: `nz_cm_family_load_params`.

`0x080aa850` (`vtable+0x14`):

- Main operational routine (uses fields loaded by `0x080ab160`).
- Walks several branches according to flags `0x8b5c*` and executes modeling/encoding subroutines.
- Uses `fcn.080c0220` as repeated comparator/checkpoint with internal codes (`0x64..0x6f`).
- Uses vcall of the sub-engine at offsets `+0x0c`, `+0x10`, `+0x1c`, `+0x20`.
- Returns `0` or an error code.

Suggested name: `nz_cm_family_process`.

## 3) Key support helpers

`fcn.080917d0`:

- Bounded copy of bytes from descriptor (`arg_20h`) to destination buffer.
- Decrements remaining (`[desc+4]`).
- Returns the amount copied.

Suggested name: `nz_stream_read_clamped`.

`fcn.080c0220`:

- Validates an expected byte against stream/state (returns mismatch 0/1).
- Used in a chain by `0x080aa850` for consistency checkpoints.

Suggested name: `nz_cm_check_byte`.

## 4) Sub-engines (secondary vtable)

Concrete engines assigned in `ctx+0x8b5c0`:

- compact: vtable `0x08132e08` (`alloc 0x3f700`)
- large: vtable `0x08132e48` (`alloc 0x1082c40`)

Observed virtual offsets in use:

- `+0x08` (memory contribution),
- `+0x18` (reset/reinit),
- `+0x0c`, `+0x10`, `+0x1c`, `+0x20` (used from `0x080aa850`).

Direct mapping by implementation:

- compact vtable `0x08132e08`:
  - `+0x04 -> 0x080a0770` (dtor)
  - `+0x08 -> 0x0809e5c0` (mem contribution)
  - `+0x0c -> 0x0809e5a0`
  - `+0x10 -> 0x0809e4e0`
  - `+0x18 -> 0x0809e5d0` (reset)
  - `+0x1c -> 0x080a0740`
  - `+0x20 -> 0x080a0520`

- large vtable `0x08132e48`:
  - `+0x04 -> 0x080a9080` (dtor)
  - `+0x08 -> 0x080a5d50` (mem contribution)
  - `+0x0c -> 0x080a5d30`
  - `+0x10 -> 0x080a5c70`
  - `+0x18 -> 0x080a5d60` (reset)
  - `+0x1c -> 0x080a9050`
  - `+0x20 -> 0x080a87a0`
