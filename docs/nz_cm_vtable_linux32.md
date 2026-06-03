# NanoZip Linux32: interfaz vtable de la familia `nz_cm` (`0x08132ea8`)

Base: `work/linux32/nz`.

## 1) Tabla vtable principal

Vtable en `0x08132ea8` (objeto alto nivel de la familia `fcn.080ab9c0`):

- `+0x00 -> 0x080aafb0`
- `+0x04 -> 0x080ab090`
- `+0x08 -> 0x080ab140`
- `+0x0c -> 0x080aaf70`
- `+0x10 -> 0x080ab160`
- `+0x14 -> 0x080aa850`

Xrefs de asignacion:

- ctor: `0x080aba14` (`mov [ebx], 0x8132ea8`)
- dtor: `0x080ab09f` (`mov [ebx], 0x8132ea8`)

## 2) Semantica sugerida por metodo

`0x080aafb0` (`vtable+0x00`):

- Estima memoria total de la instancia.
- Usa:
  - `fcn.080c0070(ctx+0x40)`,
  - `fcn.080b6160(ctx+0x38c40)` (`0x210000`),
  - virtual `subengine+8`,
  - bloques fijos/condicionales (`0x3f700`/`0x1082c40`, `0x1000`, `0x80000`, `0x8b600`).

Nombre sugerido: `nz_cm_family_estimate_memory`.

`0x080ab090` (`vtable+0x04`):

- Destructor no-deleting.
- Libera `ctx+0x8b5c0`, `ctx+0x8b5f8`, `ctx+0x8b5fc` y resetea `ctx+0x38c40`.

Nombre sugerido: `nz_cm_family_dtor`.

`0x080ab140` (`vtable+0x08`):

- Wrapper de deleting-dtor (`call 0x080ab090` + free).

Nombre sugerido: `nz_cm_family_delete`.

`0x080aaf70` (`vtable+0x0c`):

- Reinit/rewind de estado activo.
- Llama:
  - `fcn.080c0130(ctx+0x40)` (reset de subestado principal),
  - `fcn.080b6170(ctx+0x38c40)` (reset profundo de tablas),
  - `vcall [ctx+0x8b5c0] + 0x18` si hay submotor.
- Retorna `ctx`.

Nombre sugerido: `nz_cm_family_reset`.

`0x080ab160` (`vtable+0x10`):

- Parser/loader de parametros para la instancia desde stream (`arg_84h`).
- Hace muchas lecturas acotadas con `fcn.080917d0` y carga flags/campos en:
  - `0x8b5c4..0x8b5cd`,
  - `0x8b5da` (word),
  - `0x8b5d0`, `0x8b5d4`, `0x8b5dc`,
  - `0x8b5f4` (ajuste de tamano),
  - rangos en `ctx+0x4a0` y `ctx+0x38c00`.
- Retorna `0` en ruta valida o codigos de error internos (`6,8,9,11,13,15,16`).

Nombre sugerido: `nz_cm_family_load_params`.

`0x080aa850` (`vtable+0x14`):

- Rutina operativa principal (usa campos cargados por `0x080ab160`).
- Recorre varias ramas segun flags `0x8b5c*` y ejecuta subrutinas de modelado/codificacion.
- Usa `fcn.080c0220` como comparador/checkpoint repetido con codigos internos (`0x64..0x6f`).
- Usa vcalls del submotor en offsets `+0x0c`, `+0x10`, `+0x1c`, `+0x20`.
- Retorna `0` o codigo de error.

Nombre sugerido: `nz_cm_family_process`.

## 3) Helpers clave de soporte

`fcn.080917d0`:

- Copia acotada de bytes desde descriptor (`arg_20h`) a buffer destino.
- Decrementa remanente (`[desc+4]`).
- Retorna cantidad copiada.

Nombre sugerido: `nz_stream_read_clamped`.

`fcn.080c0220`:

- Valida un byte esperado contra stream/estado (retorna mismatch 0/1).
- Usado en cadena por `0x080aa850` para checkpoints de consistencia.

Nombre sugerido: `nz_cm_check_byte`.

## 4) Submotores (vtable secundaria)

Motores concretos asignados en `ctx+0x8b5c0`:

- compacto: vtable `0x08132e08` (`alloc 0x3f700`)
- grande: vtable `0x08132e48` (`alloc 0x1082c40`)

Offsets virtuales observados en uso:

- `+0x08` (memory contribution),
- `+0x18` (reset/reinit),
- `+0x0c`, `+0x10`, `+0x1c`, `+0x20` (usados desde `0x080aa850`).

Mapeo directo por implementacion:

- vtable compacta `0x08132e08`:
  - `+0x04 -> 0x080a0770` (dtor)
  - `+0x08 -> 0x0809e5c0` (mem contribution)
  - `+0x0c -> 0x0809e5a0`
  - `+0x10 -> 0x0809e4e0`
  - `+0x18 -> 0x0809e5d0` (reset)
  - `+0x1c -> 0x080a0740`
  - `+0x20 -> 0x080a0520`

- vtable grande `0x08132e48`:
  - `+0x04 -> 0x080a9080` (dtor)
  - `+0x08 -> 0x080a5d50` (mem contribution)
  - `+0x0c -> 0x080a5d30`
  - `+0x10 -> 0x080a5c70`
  - `+0x18 -> 0x080a5d60` (reset)
  - `+0x1c -> 0x080a9050`
  - `+0x20 -> 0x080a87a0`
