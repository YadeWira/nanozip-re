# NanoZip 0.09a Linux32 - Notas RE `-co/-cO/-cc`

Estado de esta iteracion:

- `-cc`:
  - subcaso `literal-wrapper` ya detectado en parser nativo:
    - `stream = [u32 raw_size][raw_payload][trailer]`
    - se activa cuando `raw_size == total_data_size`.
  - ejemplos donde aplica:
    - `test_cc.nz` (payload de 5 bytes)
    - `/tmp/nz_cov2/cc.nz` (payload de 8244 bytes)
  - ejemplos donde no aplica (sigue bridge/compat):
    - `/tmp/nz_probe_alg/repa_cc.nz` (stream comprimido real de 4096 bytes repetidos)

- `-co/-cO`:
  - subcaso chico ya soportado en nativo puro:
    - `stream = [u32 raw_size][bwt_last(raw_size)][u24 primary_index][trailer]`
    - validado en `test_co.nz` y `test_cO.nz` sin bridges.
  - subcaso BWT con trailer de 16 bytes soportado en nativo puro:
    - `stream = [u32 raw_size][bwt_last(raw_size)][trailer16]`
    - `primary_index` en `trailer[5..7]` (u24 little-endian).
    - validado sin bridges en muestras 8KiB (`rand8k/mix8k`, `-co/-cO`).
  - subcaso `raw-wrapper` (incompresible) soportado en nativo puro:
    - `stream = [u32 raw_size][raw_payload][trailer]`
    - se activa cuando `raw_size == total_data_size` y valida checksums por entrada.
    - validado sin bridges:
      - `/tmp/nz_co_lpaq_probe/legacy_co_combo.nz`
      - `/tmp/nz_co_lpaq_probe/legacy_cO_combo.nz`
  - streams comprimidos reales observados (no literal).
  - muestras chicas (`test_co.nz`, `test_cO.nz`) muestran un patron compatible con BWT+metadata:
    - `u32` inicial igual a tamaño original (ej. `05 00 00 00`)
    - bloque tipo BWT para `hola\\n`: `61 6c 0a 6f 68` (`al\\noh`)
    - indice primario observado (`00 00 02`).
  - muestras multiarchivo comprimidas (ej. `/tmp/nz_co_analysis/co.nz`) aun no tienen decoder puro.
  - confirmacion adicional (`/tmp/nz_co_probe/co.nz`, `stream_bytes=8267`):
    - prefijo aparente: `u32 n = 8241`, seguido por `n` bytes y `u24=308`;
    - quedan 19 bytes de trailer:
      - `co`: `20000003de272f004908000000000000000000`
      - `cO`: `20000003de272f014908000000000000000000`
    - `co` y `cO` difieren en 1 byte del trailer (`00` vs `01`), consistente con variante del metodo;
    - aplicar `InverseBwt` directo sobre esos `n` bytes **no** reconstruye el payload original,
      por lo que el bloque grande no es solo `[bwt_last][primary]` crudo.
  - contraste con `lpaq1v2..lpaq8` (build 32-bit, corpus `/tmp/nz_co_analysis/co.nz`):
    - se probaron entradas `raw` y `bwt_last` con memoria `0..9`;
    - hubo candidatos con tamaño de payload cercano (`8240..8243`) pero **0 coincidencias exactas**;
    - prefijo común con el body legacy: `0` bytes en los mejores casos.
    - conclusión: el body `-co` real no coincide byte-a-byte con salida directa de esas versiones lpaq en modo estándar.

## Call-chain runtime confirmado (`-co/-cO` real)

Trazas `gdb` en muestras actuales muestran que, dentro de `0x080aa850`, hay rutas activas distintas:

1. ruta BWT directa:
   - `0x080aa850 -> 0x0809d370` (sin prefiltro);
   - usada por wrappers BWT (incluye subtipo `trailer16 primary@+5`).
2. ruta BWT con prefiltro:
   - `0x080aa850 -> 0x0809a250 -> 0x0809d370`;
   - usada en streams multiarchivo comprimidos (`co/cO` reales pendientes).
3. ruta alterna repetitivos:
   - `0x080aa850 -> 0x080acaf0 -> 0x080ace10 -> 0x080accd0`;
   - aun pendiente en C++ puro.

Nota:

- `0x080abca0` sigue existiendo en la familia optimum/cm, pero no es la ruta principal observada en el corpus `co/cO` de esta pasada.

## Muestras de referencia (dump)

- `test_co.nz`:
  - `stream_bytes=25`
  - `head=05000000616c0a6f68000002dc7402...`
- `/tmp/nz_cov2/co.nz`:
  - `stream_bytes=8268`
  - `head=32200000a4dd6533...`
  - `tail=...b440000134200000033794a6005f08000000000000000000`
- `/tmp/nz_probe_alg/repa_co.nz`:
  - `stream_bytes=28`
  - `head=040000005ef277dd010140000000036e7d9e01010000000300000000`
- `/tmp/nz_probe_alg/repa_cc.nz`:
  - `stream_bytes=47`
  - `head=17000000beeb672bf3789693...`
  - `tail=...000140000000036e7d4101010000000300000000`

Proximo objetivo tecnico:

1. mapear argumentos y estado de `0x080aa850` -> `0x080abca0` (stack + offsets `ctx`) en la ruta que termina en `0x080aab2f`;
2. identificar el significado de `u32 n`, `u24` y trailer de 19 bytes en bloques grandes;
3. implementar decoder incremental por bloques;
4. validar contra corpus:
   - `test_co.nz`, `test_cO.nz`
   - `/tmp/nz_cov2/co.nz`, `/tmp/nz_cov2/cO.nz`
   - casos repetitivos `repa_co`, `repa2_co`.

## Reclasificacion runtime (pasada actual)

Se agrego trazado automatizado (`tests/legacy_optimum_trace_path.sh`) y se corrio sobre corpus `co/cO` (`/tmp/nz_co_grid`, `/tmp/nz_co_pairs`, `/tmp/nz_co_analysis`, `/tmp/nz_co_small`, `/tmp/nz_co_lpaq_probe`).

Rutas observadas en `linux32/nz`:

1. `b98a0 -> b1950 -> aa850`:
   - subcaso wrapper simple;
   - en reconstruccion actual ya se resuelve nativo puro (sin `[compat]`).
2. `b98a0 -> b1950 -> aa850 -> acaf0`:
   - subcaso comprimido alterno (frecuente en repetitivos);
   - sigue pendiente en C++ puro (hoy cae a compat).
3. `b98a0 -> b1950 -> aa850 -> a9d370`:
   - subcaso comprimido principal (frecuente);
   - ya cubierto en nativo puro para el lote actual.
4. `b98a0 -> b1950 -> aa850 -> a9a250 -> a9d370`:
   - subcaso mas pesado (ej. `/tmp/nz_co_analysis/co.nz`);
   - sigue pendiente en C++ puro (hoy cae a compat).

Conteo en corrida de clasificacion (86 muestras):

- `aa850 -> a9d370`: 44
- `aa850 -> acaf0`: 26
- `aa850` (solo): 10
- `aa850 -> a9a250 -> a9d370`: 2

Cruce con `nz_recon` sin bridges (`NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1`):

- ruta `aa850` (solo): `t/x` sin `[compat]`;
- ruta `a9d370`: `t/x` sin `[compat]`;
- rutas `acaf0` y `a9a250+a9d370`: `t/x` correctos pero con `[compat]`.

Implicacion directa:

- el bloqueo de `-co/-cO` puro ya no se ataca via `0x080abca0` para el corpus principal actual;
- el port C++ debe priorizar `0x0809d370` (y su prefiltro `0x0809a250` cuando aplica), luego `0x080acaf0`/`0x080ace10`/`0x080accd0`.
