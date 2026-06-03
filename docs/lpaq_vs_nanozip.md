# LPAQ (1v2..8) vs NanoZip 0.09a - Comparacion tecnica rapida

## Muestras comparadas

- LPAQ: `lpaq1v2, lpaq2, lpaq3, lpaq3a, lpaq4, lpaq5, lpaq6, lpaq7, lpaq8`
- NanoZip: `work/linux64/nz`, `work/linux32/nz`, samples `.nz` generados localmente

## Hallazgos fuertes

1) Firma/formato de archivo no coincide:

- LPAQ en fuente usa header `pQ` + byte de version (`1..8`) en `fprintf(out, "pQ...")`.
- NanoZip `.nz` usa header:
  - `ae 01`
  - `"NanoZip 0.09 alpha"`

2) Modelo de producto no coincide:

- LPAQ: compresor unico por version (`lpaqN`), extension/logica `.lpq`.
- NanoZip: archivador multi-metodo con selector interno:
  - `nz_lzpf`, `nz_lzpf_large`
  - `nz_lzhd`, `nz_lzhd_parallel`, `nz_lzhd_parallel_extra`
  - `nz_lzhds`, `nz_lzhds_parallel`, `nz_lzhds_parallel_extra`
  - `nz_optimum1`, `nz_optimum2`, `nz_cm`

3) Evidencia textual directa de reutilizacion LPAQ en binario NanoZip: no observada.

- En `strings` de NanoZip no aparecen `lpaq`, `Mahoney`, `Ratushnyak`, ni mensajes `Not a lpaqX file`.

## Similitudes observadas

- La familia LPAQ implementa context mixing clasico (StateMap/APM/Mixer/MatchModel + arithmetic coder).
- En NanoZip existe un metodo `nz_cm`, que por nombre sugiere "context mixing".

## Conclusión operativa

- Hipotesis "NanoZip = LPAQ optimizado" como afirmacion total: **no soportada** por la evidencia actual.
- Hipotesis "NanoZip reutiliza ideas de LPAQ/PAQ en una parte (probablemente `nz_cm`)": **plausible**.

## Siguiente validacion recomendada

- Aislar por RE el pipeline de `nz_cm` y comparar estructura interna contra LPAQ:
  - estados/probabilidades,
  - mezcla de predictores,
  - codificador aritmetico,
  - tablas/transiciones.

## Novedad del reescaneo (Linux32)

- En `fcn.08092470` se confirmo el switch real por metodo con selector `ctx+0x24` y 8 casos.
- El indice `7` (nombre canonico `nz_cm`) entra en la familia `fcn.080ab9c0` con `mode=2`.
- Los indices `5` y `6` (`nz_optimum1`, `nz_optimum2`) usan la misma familia `fcn.080ab9c0` con `mode=0/1`.
- Implicacion: el analisis tipo PAQ/LPAQ debe concentrarse primero en `fcn.080ab9c0` y su grafo de llamados.

## Refinamiento tecnico: `nz_cm` por dentro

Resumen del bloque ya trazado (`fcn.080ab9c0` + `fcn.080bfcc0`):

- `mode=2` (`nz_cm`) crea estado adicional respecto a `mode=0/1`.
- Hay 2 implementaciones de motor seleccionadas por flag:
  - `alloc(0x3f700)` + vtable `0x08132e08`
  - `alloc(0x1082c40)` + vtable `0x08132e48`
- El estimador de memoria (`0x080aafb0`) usa formula compuesta con overhead fijo `0x8b600` y extras `0x1000`/`0x80000`.

Coincidencias con LPAQ (nivel arquitectura):

- presencia de rutas de modelado grandes con tablas de contexto;
- separacion de buffers auxiliares y estado de prediccion;
- patron de costos de memoria en MB para la ruta CM.

Diferencias contra LPAQ 7/8 (nivel implementacion):

- LPAQ en fuente expone estructura directa (`StateMap/APM/Mixer/MatchModel`, `MEM`, `x1/x2`).
- NanoZip usa una familia multi-modo/multi-vtable integrada con otros metodos (`optimum1/2/cm`) y layout distinto.
- No hay correspondencia 1:1 directa entre offsets/constructores de `080ab9c0` y clases LPAQ.

Estado de hipotesis:

- "NanoZip == LPAQ optimizado" como equivalencia exacta: **no soportada**.
- "NanoZip `nz_cm` toma ideas PAQ/LPAQ y las mezcla con una arquitectura propia": **soportada** por la evidencia actual.
