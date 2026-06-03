# NanoZip 0.09a Linux32 - RE of `nz_lzpf` (`-cf`/`-cF`)

Base analyzed: `work/linux32/nz`

## Context

In the current reconstruction, `-cn` is already processed natively and `-cf/-cF`:
- pure native: `literal-only` subcase
- extract bridge (no ptrace): decodes the observed compressed payload using the legacy backend in a temp dir
- `gdb` bridge over the linux32 backend: observed compressed payload (without a complete algebraic reimplementation of the core).
This document summarizes the RE mapping of the `nz_lzpf` block to enable a real native decoder.

## Constructor/family

- lzpf/lzpf_large family constructor: `fcn.08098050` (called from the dispatcher `fcn.08092470`).
- lzpf base-object constructor: `fcn.080972d0`.
- In `fcn.080972d0` the vtable is installed at `0x08132c68`.

## Vtable `0x08132c68` (`nz_lzpf` object)

Observed entries:

1. `0x08097550`
2. `0x080972d0`
3. `0x08097340`
4. `0x080974f0`
5. `0x08097280`
6. `0x08097e20`

Functional hypothesis (from behavior and xrefs):

1. `0x08097550`: memory estimator (uses `0x08097510` + `0x200000`).
2. `0x080972d0`: object ctor/reinit.
3. `0x08097340`: destructor/release wrapper.
4. `0x080974f0`: partial reset/reinit wrapper.
5. `0x08097280`: limits load/config (reads `ctx+4`, validates `<= 0x100044`, calls `0x080917d0`).
6. `0x08097e20`: main process routine (encode/decode wrapper).

## Process core

- `fcn.08097e20` prepares state and working buffers.
- `fcn.08097e20` calls `fcn.08097570` (large core, ~2.2 KB of code).
- `fcn.08097570` contains:
  - varint parsing with the continuation-bit pattern (similar to the already-reconstructed legacy parser),
  - branches with copy/match and context tables,
  - several error paths returning codes that `0x08097e20` remaps.

### Calling convention finding (important)

`0x08097570` does **not** behave as a normal 5-argument cdecl.

In real call-sites (`0x08097edb`, `0x08097f4d`) we see:

- only one explicit argument is passed: `mov [esp], eax; call 0x08097570`
- the rest of the state is consumed from stack offsets already prepared by `0x08097e20`.

Implication for the C++ port:

- it is not convenient to translate `0x08097570` standalone as a "clean" function;
- the pair `0x08097e20 + 0x08097570` should be ported first as a single decode pipeline.

## Confirmed stack layout (gdb + objdump)

Sample used:

- `/tmp/nz_cf_probe/cf_repA.nz` (`-cf`, 4096 x `A`).

In `0x08097e20` (caller) two call-sites to `0x08097570` are observed:

- `0x08097edb`
- `0x08097f4d`

Before the `call`, the caller prepares:

- `[esp+0x00] = ctx` (`ebx+0x40`)
- `[esp+0x04] = state_ptr` (`&local_0x38`)
- `[esp+0x08] = out_ptr`
- `[esp+0x0c] = out_len_ptr` (`&local_0x7c`)

In the callee (`0x08097570`) those slots are consumed as:

- `[esp+0xa4]`: `ctx`
- `[esp+0xa0]`: `state_ptr`
- `[esp+0xa8]`: `out_ptr`
- `[esp+0xac]`: `out_len_ptr`

(`push ebp/edi/esi/ebx` + `sub esp,0x8c` shift the offsets.)

Runtime observations:

- `ctx+0x1c`: pointer to the compressed stream.
- `ctx+0x20`: pending stream bytes.
- `ctx+0x24..0x40`: continuity state between blocks (filled at `0x08097d9f` and reused at `0x08097dfa`).
- `eax` return of `0x08097570`: intermediate codes remapped by `0x08097e20`.

## Return codes (partial)

In `fcn.08097e20` a remap of the return value of `0x08097570` is observed:

- `eax == 1`  -> returns `2`
- `eax == 2`  -> returns `3`
- `eax == 3`  -> returns `4`
- default error path -> `5`
- limit checks in the loop -> `6` or `7`
- path with `[vtable+0x0c]` callback and `xor ebx, ebx` -> `0` (success)

Exact mapping pending (next step): label each code with its cause (`corrupt input`, `short buffer`, etc.).

## Observed `-cf` stream format

Real compressed samples (not literal-only):

- `4096 x 'A'` -> `cf_repA.nz` (71 bytes)
- `AB` repeated -> `cf_repAB.nz` (72 bytes)
- `ABC` repeated -> `cf_repABC.nz` (73 bytes)
- repetitive text -> `cf_english.nz` (85 bytes)

Stable pattern in the payload:

- stream varint prefix with low nibble `0` (`stream_tag`, `stream_bytes = tag >> 4`)
- compressed body (no longer matches `bitlen = total_size*8+1` of the literal-only case)

Example `cf_repA.nz` (body):

- `80 01 83 ff 00 06 00 2f 2f cf c7 fd 6f ff 60 de 90 40`

This confirms that the literal-only subcase does not cover real `-cf` and that the next step must implement a decoder from `0x08097570`.

## Next technical plan

1. Re-label blocks in `0x08097570` (token read, match copy, literal output, end control).
2. Extract pseudocode of the key blocks and translate them to pure C++.
3. Integrate the decoder in `TryParseLegacyCnArchive` / `RunLegacyCnExtractOrTest` for `method_p0 == 1/2`.
4. Validate against:
   - small samples (`cf_repA`, `cf_repAB`, `cf_repABC`, `cf_english`)
   - large samples (`big_cf.nz`).
