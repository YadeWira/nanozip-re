# NanoZip Linux32: nucleo interno de `nz_cm` (familia `fcn.080ab9c0`)

Base analizada: `work/linux32/nz` (ELF32 static, stripped).

## 1) Entrada real de `nz_cm`

Desde el dispatcher principal (`fcn.08092470`):

- `idx 7` (nombre canonico `nz_cm`) entra en `fcn.080ab9c0` con `mode=2`.
- `idx 5/6` (`nz_optimum1/2`) entran en la misma familia con `mode=0/1`.

Esto confirma que `nz_cm` es un submodo de la familia `080ab9c0`, no un camino separado.

## 2) Constructor de familia: `fcn.080ab9c0`

Patron general:

1. Inicializa bloque interno `ctx+0x40` via `fcn.080bfcc0(...)`.
2. Fija vtable de alto nivel en `ctx`:
   - `ctx->vptr = 0x08132ea8` (`mov dword [ebx], 0x8132ea8`).
3. Inicializa/limpia estructuras auxiliares:
   - region en `ctx+0x38c40` (llamada a `fcn.080a90b0`),
   - punteros `ctx+0x8b5f4/0x8b5f8/0x8b5fc`.
4. Reserva buffers auxiliares:
   - buffer fijo de `0x80000` bytes (`ctx+0x8b5f8`),
   - buffer de `0x1000` bytes (`ctx+0x8b5fc`) en `mode>1`.
5. Elige motor principal segun `byte [ctx+0x38c18] & 1`:
   - bit=1 -> `alloc(0x1082c40)`, ctor `fcn.080b90a0`, vtable `0x08132e48`.
   - bit=0 -> `alloc(0x3f700)`, ctor `fcn.080bcb50`, vtable `0x08132e08`.
   - puntero guardado en `ctx+0x8b5c0`.

Destructor de la familia: `fcn.080ab090` (libera `ctx+0x8b5c0`, `ctx+0x8b5f8`, `ctx+0x8b5fc`, luego destruye `ctx+0x38c40`).

## 3) Setup profundo por modo: `fcn.080bfcc0`

`fcn.080bfcc0` recibe `mode` (arg2) y construye la mayor parte del estado de trabajo:

- Reserva bloque base proporcional a parametro de entrada (`dict*5 + 0x100887`, alineado).
- Inicializa subestructuras en offsets `+0x10`, `+0x28`, `+0x38`, `+0x50`.
- Prepara tablas/buffers y valida umbral (`dict > 0x0fffff`, si no aborta).

Ramas por `mode`:

- `mode=0`:
  - ruta base con `fcn.080b1600(..., 0x40, 0x11, 3, 4)`.
- `mode=1`:
  - ruta intermedia con parametros derivados (`0x60`, `1`, `3`, `8`),
  - marca byte de estado `ctx+0x38bd8 = 3`.
- `mode=2` (`nz_cm`):
  - ruta mas pesada (`0x80`, `1`, `3`, `16`),
  - crea objeto extra por `fcn.080b5810(...)` y lo guarda en `ctx+0x38bd0`.

Conclusion practica: `mode=2` no solo "ajusta parametros"; agrega una subestructura adicional.

## 4) Vtables relevantes observadas

Tabla en `0x08132e08` (motor compacto):

- `0x080a0750, 0x080a0770, 0x0809e5c0, ...`

Tabla en `0x08132e48` (motor grande):

- `0x080a9060, 0x080a9080, 0x080a5d50, ...`

Tabla en `0x08132ea8` (objeto alto nivel de esta familia):

- `0x080aafb0, 0x080ab090, 0x080ab140, 0x080aaf70, 0x080ab160, 0x080aa850, ...`

## 5) Estimacion de memoria del motor (`0x080aafb0`)

`0x080aafb0` suma memoria de subcomponentes:

- `fcn.080c0070(ctx+0x40)` +
- `fcn.080b6160(ctx+0x38c40)` (constante `0x210000`) +
- memoria virtual del objeto en `ctx+0x8b5c0` (llamada indirecta a vtable+8) +
- bloque fijo por selector de implementacion:
  - `0x3f700` (motor compacto) o
  - `0x1082c40` (motor grande) +
- extras condicionales:
  - `0x1000` si existe `ctx+0x8b5fc`,
  - `0x80000` si existe `ctx+0x8b5f8`,
  - `0x8b600` base de overhead.

Atajo observado:

- cuando motor grande + ambos extras activos, retorna `base + 0x118f240`.
- `0x118f240 == 0x1082c40 + 0x1000 + 0x80000 + 0x8b600`.

## 6) Comparacion puntual con LPAQ

Lo que SI acerca esta ruta a una familia tipo PAQ/LPAQ:

- existe un submodo especifico (`mode=2`) mas pesado que agrega estado extra;
- uso de tablas grandes y estado de probabilidad por bytes/contextos;
- presencia de rutas de memoria del orden de varios MB para modelado.

Lo que NO encaja con "LPAQ puro" literal:

- arquitectura multi-motor (`optimum1/2/cm`) dentro del mismo constructor;
- dos implementaciones de motor seleccionadas por flag (`0x3f700` vs `0x1082c40`);
- layout y constantes internas que no mapean 1:1 a clases LPAQ (`StateMap/APM/Mixer/MatchModel`) por nombre/estructura.

Conclusión operativa:

- `nz_cm` es compatible con la hipotesis "CM optimizado con ideas PAQ/LPAQ",
- pero no hay evidencia de copia directa linea-a-linea de `lpaq7/8`.

## 7) Interfaz vtable (avance)

Se mapeo la interfaz principal en `0x08132ea8`:

- `0x080aafb0` -> estimador de memoria
- `0x080ab090` -> destructor
- `0x080ab140` -> deleting-dtor
- `0x080aaf70` -> reset/reinit
- `0x080ab160` -> carga/parseo de parametros
- `0x080aa850` -> rutina operativa principal

Detalle completo:

- `work/reconstruccion/docs/nz_cm_vtable_linux32.md`
