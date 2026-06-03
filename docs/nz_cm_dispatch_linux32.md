# NanoZip Linux32: despacho real de `nz_cm`

Base analizada: `work/linux32/nz` (ELF32, static, stripped).

## 1) Switch real de metodo (pipeline de compresion)

En `fcn.08092470`:

- `0x0809272b`: `mov ebp, dword [ebx + 0x24]`
- `0x0809272e`: `jmp dword [ebp*4 + 0x8132b38]`

Tabla de salto (`0x08132b38`, 8 entradas):

- `idx0 -> 0x080927f2`
- `idx1 -> 0x080927ee`
- `idx2 -> 0x080927c6`
- `idx3 -> 0x080927c2`
- `idx4 -> 0x0809279a`
- `idx5 -> 0x08092796`
- `idx6 -> 0x08092735`
- `idx7 -> 0x08092829`

## 2) Rutas por caso (constructor/motor)

- `idx0` (`0x080927f2`): objeto pequeno inline con vtable `0x08132b88`.
- `idx1` (`0x080927ee`): `ebp=0` -> `0x080927cb` -> `call fcn.08098050`.
- `idx2` (`0x080927c6`): `ebp=1` -> `0x080927cb` -> `call fcn.08098050`.
- `idx3` (`0x080927c2`): `ebp=0` -> `0x0809279f` -> `call fcn.08099d90`.
- `idx4` (`0x0809279a`): `ebp=1` -> `0x0809279f` -> `call fcn.08099d90`.
- `idx5` (`0x08092796`): `ebp=0` -> `0x0809273a` -> `call fcn.080ab9c0`.
- `idx6` (`0x08092735`): `ebp=0`, luego `add ebp,1` (`0x08092737`) -> `call fcn.080ab9c0`.
- `idx7` (`0x08092829`): `ebp=1`, luego `add ebp,1` (`0x08092737`) -> `call fcn.080ab9c0`.

Interpretacion de modo para `fcn.080ab9c0`:

- `idx5 -> mode 0`
- `idx6 -> mode 1`
- `idx7 -> mode 2`

## 3) Nombres canonicos 0..7

En `fcn.080ad740` (selector de nombre) + tabla `0x08166080`:

- `0 -> none`
- `1 -> nz_lzpf`
- `2 -> nz_lzpf_large`
- `3 -> nz_lzhd`
- `4 -> nz_lzhds`
- `5 -> nz_optimum1`
- `6 -> nz_optimum2`
- `7 -> nz_cm`

## 4) Mapeo final metodo -> motor

- `0 none -> case0 -> vtable 0x08132b88`
- `1 nz_lzpf -> case1 -> fcn.08098050(mode0)`
- `2 nz_lzpf_large -> case2 -> fcn.08098050(mode1)`
- `3 nz_lzhd -> case3 -> fcn.08099d90(mode0)`
- `4 nz_lzhds -> case4 -> fcn.08099d90(mode1)`
- `5 nz_optimum1 -> case5 -> fcn.080ab9c0(mode0)`
- `6 nz_optimum2 -> case6 -> fcn.080ab9c0(mode1)`
- `7 nz_cm -> case7 -> fcn.080ab9c0(mode2)`

## 5) Conclusion operativa

`nz_cm` no es un camino aislado: entra en la familia de constructor `fcn.080ab9c0`, pero con `mode=2`.
La comparacion PAQ/LPAQ debe centrarse en esta familia (`fcn.080ab9c0` y sus llamados), no en `fcn.08098050` ni `fcn.08099d90`.

Documento complementario:

- `work/reconstruccion/docs/nz_cm_core_linux32.md` (internals de constructor, vtables y memoria).
- `work/reconstruccion/docs/nz_cm_vtable_linux32.md` (contrato de metodos vtable y helpers de stream/check).
