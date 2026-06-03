# NanoZip Linux32: real dispatch of `nz_cm`

Base analyzed: `work/linux32/nz` (ELF32, static, stripped).

## 1) Real method switch (compression pipeline)

In `fcn.08092470`:

- `0x0809272b`: `mov ebp, dword [ebx + 0x24]`
- `0x0809272e`: `jmp dword [ebp*4 + 0x8132b38]`

Jump table (`0x08132b38`, 8 entries):

- `idx0 -> 0x080927f2`
- `idx1 -> 0x080927ee`
- `idx2 -> 0x080927c6`
- `idx3 -> 0x080927c2`
- `idx4 -> 0x0809279a`
- `idx5 -> 0x08092796`
- `idx6 -> 0x08092735`
- `idx7 -> 0x08092829`

## 2) Paths per case (constructor/engine)

- `idx0` (`0x080927f2`): small inline object with vtable `0x08132b88`.
- `idx1` (`0x080927ee`): `ebp=0` -> `0x080927cb` -> `call fcn.08098050`.
- `idx2` (`0x080927c6`): `ebp=1` -> `0x080927cb` -> `call fcn.08098050`.
- `idx3` (`0x080927c2`): `ebp=0` -> `0x0809279f` -> `call fcn.08099d90`.
- `idx4` (`0x0809279a`): `ebp=1` -> `0x0809279f` -> `call fcn.08099d90`.
- `idx5` (`0x08092796`): `ebp=0` -> `0x0809273a` -> `call fcn.080ab9c0`.
- `idx6` (`0x08092735`): `ebp=0`, then `add ebp,1` (`0x08092737`) -> `call fcn.080ab9c0`.
- `idx7` (`0x08092829`): `ebp=1`, then `add ebp,1` (`0x08092737`) -> `call fcn.080ab9c0`.

Mode interpretation for `fcn.080ab9c0`:

- `idx5 -> mode 0`
- `idx6 -> mode 1`
- `idx7 -> mode 2`

## 3) Canonical names 0..7

In `fcn.080ad740` (name selector) + table `0x08166080`:

- `0 -> none`
- `1 -> nz_lzpf`
- `2 -> nz_lzpf_large`
- `3 -> nz_lzhd`
- `4 -> nz_lzhds`
- `5 -> nz_optimum1`
- `6 -> nz_optimum2`
- `7 -> nz_cm`

## 4) Final mapping method -> engine

- `0 none -> case0 -> vtable 0x08132b88`
- `1 nz_lzpf -> case1 -> fcn.08098050(mode0)`
- `2 nz_lzpf_large -> case2 -> fcn.08098050(mode1)`
- `3 nz_lzhd -> case3 -> fcn.08099d90(mode0)`
- `4 nz_lzhds -> case4 -> fcn.08099d90(mode1)`
- `5 nz_optimum1 -> case5 -> fcn.080ab9c0(mode0)`
- `6 nz_optimum2 -> case6 -> fcn.080ab9c0(mode1)`
- `7 nz_cm -> case7 -> fcn.080ab9c0(mode2)`

## 5) Operational conclusion

`nz_cm` is not an isolated path: it enters the `fcn.080ab9c0` constructor family, but with `mode=2`.
PAQ/LPAQ comparison must focus on this family (`fcn.080ab9c0` and its callees), not on `fcn.08098050` or `fcn.08099d90`.

Complementary documents:

- `work/reconstruccion/docs/nz_cm_core_linux32.md` (constructor internals, vtables, memory).
- `work/reconstruccion/docs/nz_cm_vtable_linux32.md` (vtable method contract and stream/check helpers).
