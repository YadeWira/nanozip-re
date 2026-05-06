# NanoZip 0.09a Linux32 - RE de `nz_lzpf` (`-cf`/`-cF`)

Base analizada: `work/linux32/nz`

## Contexto

En la reconstruccion actual, `-cn` ya se procesa nativamente y `-cf/-cF`:
- nativo puro: subcaso `literal-only`
- bridge de extracción (sin ptrace): decode de payload comprimido observado usando backend legado en temporal
- bridge `gdb` sobre backend linux32: payload comprimido observado (sin reimplementacion algebraica completa del core).
Este documento resume el mapeo RE del bloque `nz_lzpf` para habilitar decoder nativo real.

## Constructor/familia

- Constructor de familia lzpf/lzpf_large: `fcn.08098050` (llamado desde dispatcher `fcn.08092470`).
- Constructor de objeto base lzpf: `fcn.080972d0`.
- En `fcn.080972d0` se instala vtable en `0x08132c68`.

## Vtable `0x08132c68` (objeto `nz_lzpf`)

Entradas observadas:

1. `0x08097550`
2. `0x080972d0`
3. `0x08097340`
4. `0x080974f0`
5. `0x08097280`
6. `0x08097e20`

Hipotesis funcional (por comportamiento y xrefs):

1. `0x08097550`: estimador de memoria (usa `0x08097510` + `0x200000`).
2. `0x080972d0`: ctor/reinit del objeto.
3. `0x08097340`: wrapper destructor/release.
4. `0x080974f0`: wrapper de reset/reinit parcial.
5. `0x08097280`: carga/config de limites (lee `ctx+4`, valida `<= 0x100044`, llama `0x080917d0`).
6. `0x08097e20`: rutina principal de proceso (encode/decode wrapper).

## Core de proceso

- `fcn.08097e20` prepara estado y buffers de trabajo.
- `fcn.08097e20` invoca `fcn.08097570` (core grande, ~2.2 KB de codigo).
- `fcn.08097570` contiene:
  - parseo de varints con patron de continuation bit (similar a parser legacy ya reconstruido),
  - ramas con copy/match y tablas de contexto,
  - varias rutas de error devolviendo codigos que `0x08097e20` remapea.

### Hallazgo de calling convention (importante)

`0x08097570` **no** se comporta como cdecl normal de 5 argumentos.

En call-sites reales (`0x08097edb`, `0x08097f4d`) se observa:

- solo se pasa un argumento explicito: `mov [esp], eax; call 0x08097570`
- el resto del estado se consume desde offsets de stack ya preparados por `0x08097e20`.

Implicacion para port C++:

- no conviene traducir `0x08097570` aislada como funcion "limpia";
- conviene portar primero el par `0x08097e20 + 0x08097570` como pipeline unico de decode.

## Layout de stack confirmado (gdb + objdump)

Muestra usada:

- `/tmp/nz_cf_probe/cf_repA.nz` (`-cf`, 4096 x `A`).

En `0x08097e20` (caller) se observan dos call-sites a `0x08097570`:

- `0x08097edb`
- `0x08097f4d`

Antes del `call`, el caller prepara:

- `[esp+0x00] = ctx` (`ebx+0x40`)
- `[esp+0x04] = state_ptr` (`&local_0x38`)
- `[esp+0x08] = out_ptr`
- `[esp+0x0c] = out_len_ptr` (`&local_0x7c`)

En el callee (`0x08097570`) esos slots se consumen como:

- `[esp+0xa4]`: `ctx`
- `[esp+0xa0]`: `state_ptr`
- `[esp+0xa8]`: `out_ptr`
- `[esp+0xac]`: `out_len_ptr`

(`push ebp/edi/esi/ebx` + `sub esp,0x8c` desplazan los offsets).

Observaciones de runtime:

- `ctx+0x1c`: puntero a stream comprimido.
- `ctx+0x20`: bytes pendientes de stream.
- `ctx+0x24..0x40`: estado de continuidad entre bloques (se rellena en `0x08097d9f` y se reusa en `0x08097dfa`).
- retorno `eax` de `0x08097570`: codigos intermedios remapeados por `0x08097e20`.

## Codigos de retorno (parcial)

En `fcn.08097e20` se observa remapeo de retorno de `0x08097570`:

- `eax == 1`  -> retorna `2`
- `eax == 2`  -> retorna `3`
- `eax == 3`  -> retorna `4`
- ruta default de error -> `5`
- checks de limites en bucle -> `6` o `7`
- ruta con callback `[vtable+0x0c]` y `xor ebx, ebx` -> `0` (exito)

Mapeo exacto pendiente (siguiente etapa): etiquetar cada codigo con causa (`input corrupto`, `buffer corto`, etc.).

## Formato de stream `-cf` observado

Muestras reales comprimidas (no literal-only):

- `4096 x 'A'` -> `cf_repA.nz` (71 bytes)
- `AB` repetido -> `cf_repAB.nz` (72 bytes)
- `ABC` repetido -> `cf_repABC.nz` (73 bytes)
- texto repetitivo -> `cf_english.nz` (85 bytes)

Patron estable en payload:

- prefijo varint de stream con nibble bajo `0` (`stream_tag`, `stream_bytes = tag >> 4`)
- cuerpo comprimido (ya no coincide con `bitlen = total_size*8+1` del caso literal-only)

Ejemplo `cf_repA.nz` (cuerpo):

- `80 01 83 ff 00 06 00 2f 2f cf c7 fd 6f ff 60 de 90 40`

Esto confirma que el subcaso literal-only no cubre `-cf` real y que el siguiente paso debe implementar decoder desde `0x08097570`.

## Plan tecnico siguiente

1. Re-etiquetar bloques en `0x08097570` (lectura tokens, match copy, salida literal, control de fin).
2. Extraer pseudocodigo de bloques clave y traducir a C++ puro.
3. Integrar decoder en `TryParseLegacyCnArchive` / `RunLegacyCnExtractOrTest` para `method_p0 == 1/2`.
4. Validar contra:
   - muestras chicas (`cf_repA`, `cf_repAB`, `cf_repABC`, `cf_english`)
   - muestras grandes (`big_cf.nz`).
