# Reconstruccion de NanoZip (CLI)

Este directorio contiene una reconstruccion en C++ del CLI de NanoZip 0.09a enfocada en uso general de archivado, con la excepcion solicitada de **no crear SFX**.

## Estado actual

Implementado en `nz_recon`:

- Comandos: `a`, `l`, `t`, `s`, `x`, `info`, `help`.
- `w32c` detectado y bloqueado explícitamente (omitido por diseño).
- Parser de switches principales (`-c*`, `-h*`, `-r`, `-sp`, `-nt`, `-np`, `-nm`, `-o`, `-x`, `-v`, `-y`, `-nofilenameext`).
- Formato de archivo reconstruido (`NZR1`) con:
  - magic/header NanoZip (`0xAE 0x01` + `NanoZip 0.09 alpha`)
  - tabla de entradas
  - metadata básica (nombre, tamaño, permisos, timestamp, checksum)
  - extracción/test/listado funcionales.
- Modo interno de compresión nativo: **store** (`-cn`).
- Compresión `a/s` para métodos legacy (`-cf/-cF/-cd/-cD/-co/-cO/-cc`) operativa mediante bridge interno al backend legado (traza `[bridge]`, no `[compat]`) por defecto.
- Modo opcional experimental para `a/s` con métodos legacy (activar `NZ_DISABLE_COMPRESS_BRIDGE=1`): writer nativo de wrappers RE.
  - `-cf/-cF`: `literal-only`.
  - `-cd/-cD`: `literal-wrapper` (`[varint][0x00][raw]`).
  - `-co/-cO`: wrapper BWT (`[u32 size][bwt_last][u24 primary]`), límite actual 32 KiB en writer nativo.
  - `-cc`: `raw-wrapper` (`[u32 size][raw]`).
  - soporta `-h*` en header legacy (con mapeo `-hf -> Fletcher32` del formato legacy).
  - Nota: actualmente validado con `nz_recon` (`l/t/x`); el backend original puede rechazar estos archivos en `t/x`.
- Parser nativo de `.nz` legacy (familias de stream `0x2b/0x3b/0x4b`):
  - `l` nativo para variantes observadas (`-cn`, `-cf/-cF`, `-cd/-cD`, `-co/-cO`, `-cc`).
  - `t`/`x` nativo para `-cn` (incluyendo variantes de header observadas).
  - `t`/`x` nativo parcial para `-cf/-cF` en streams `literal-only` (payload sin compresion efectiva dentro de stream legacy).
  - `t`/`x` nativo parcial para `-cd/-cD` en streams `literal-only` observados.
  - `t`/`x` nativo parcial para `-co/-cO` en substream BWT observado en archivos chicos (`[u32 size][bwt_last][u24 primary_index][trailer]`).
  - `t`/`x` nativo parcial para `-co/-cO` en substream `raw-wrapper` observado en entradas incomprimibles (`[u32 raw_size][raw_payload][trailer]`).
  - `t`/`x` nativo parcial para `-cc` en substream `literal-wrapper` observado (`[u32 raw_size][raw_payload][trailer]`).
  - soporte de metadata/checksum observado (`-hn`, `-hc`, `-hC`, `-hf`, `-np`, `-nt`, `-nm`) en flujo de lectura.
  - verificacion de checksum en `-cn` para `crc16`, `crc32` y variante legacy `fletcher32` (mode `0x05`).
- En extracción (`x`), se re-aplican permisos y `mtime` cuando la metadata está disponible (formato reconstruido y subcasos legacy parseables).
- Capa de compatibilidad opcional: cuando el formato/compresor no está reconstruido, reenvía al backend legado `work/linux64/nz` si existe.
  - Detección automática de backend: `NZ_LEGACY_BACKEND`, `work/linux64/nz`, `work/linux32/nz`, `linux64/nz`, `linux32/nz` o `nz` en `PATH`.
- Bridges opcionales de decode para streams comprimidos legacy (modo `t/x`):
  - `extract bridge` (prioridad 1): usa backend legado para extraer en temporal y reconstruir payload internamente; evita dependencia de `ptrace`.
  - `gdb bridge` (prioridad 2): si hay `linux32/nz` + `gdb` + ptrace disponible, puede decodificar por traza controlada.
  - variables:
    - `NZ_DISABLE_EXTRACT_BRIDGE`: desactiva `extract bridge`.
    - `NZ_LEGACY_BRIDGE_BACKEND`: ruta al backend linux32 (archivo o directorio que contiene `nz`).
    - `NZ_DISABLE_GDB_BRIDGE`: desactiva este bridge y fuerza comportamiento anterior.
    - `NZ_DISABLE_COMPRESS_BRIDGE`: desactiva bridge de compresión para métodos legacy (`-cf/-cF/-cd/-cD/-co/-cO/-cc`) y usa writer nativo experimental por wrapper.

## Limitaciones actuales

- `a/s` en métodos legacy usa bridge por defecto; el writer nativo opcional (sin bridge) aún emite wrappers RE, no el stream comprimido legacy completo.
- Variante estéreo de prefilter+arith (`is_stereo`) y decodificador paralelo lzhd (`FUN_080b50b0`) pendientes.
- En legacy multi-archivo, el parseo de metadata (permisos/timestamps/checksums) sigue siendo parcial.
- CM `tt_flags=0x10` (word-list transform): no nativo; usa extract bridge. **Bloqueador real = bug en el CM decoder**, no en el transform. Verificado con ground truth via gdb sobre `linux32/nz` (break en transform `0x080a3340`, dump de su buffer de entrada = salida real del CM): ese stream es 99.95% texto legible, mientras `NzCmDecode` diverge en el byte 26 (bit 5) y produce basura. El transform es secundario (su salida ≈ texto original; substitución casi sin cambio de tamaño con tokens `0/1/2`). Pendiente: corregir la etapa de mezcla en `nz_cm.cpp` (mixer lineal / modelg APM / cmc) usando el oracle dorado capturado.

## Milestones nativos completados

| Fecha | Hito |
|-------|------|
| 2026-04-24 | lzpf arith primitives completos; `DecodeLz77VariantA/B` byte-exact |
| 2026-05-05 | Hash table init bug fijo (0→3); window_capacity correcto; 8/8 métodos native_strict 100% |
| 2026-05-07 | CM decoder nativo (NZ_CM.cpp, 1100 LOC); lzpf prefilter+arith mono byte-exact; lzhd DecLZ (PAQ+12-bit arith, 680 LOC) |
| 2026-05-09 | Parser archivos paralelos (`-pN`) fijo; writer codec chunk fijo (encode_ok 5/8 → 8/8) |
| 2026-05-10 | CM TextTransformer (tt_flags=0x08): `NzTextTransformDict` portado de `TransformText_1_Dictionary`; tablas extraídas de binario linux32; archivos texto byte-exact en `-cc` |
| 2026-05-10 | CM `tt_flags=0x10` (word-list transform): identificado `TransformText` secundario en `0x8058580`; no nativo aún — `TryDecodeLegacyCm` declina y extrae vía `extract bridge`; todos los métodos 8/8 en fuente C++ byte-exact |
| 2026-06-01 | CM `tt_flags=0x10`: diagnóstico corregido — el bloqueador es un **bug en `NzCmDecode`** (no el transform). Ground truth via gdb (`0x080a3340`) → oracle dorado; harness standalone reproduce divergencia determinista en byte 26 bit 5; params descartados (sweep). Mapeado el árbol decode del transform (`fcn.080a3340`/`a28a0`/`a1b60`) para portar una vez corregido el CM |

## Build

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
```

Binarios generados:

- `build-release/nz_recon`
- `build-release/nz_sfx_recon` (alias de compatibilidad de nombre)

## Ejemplos

Crear archivo (store interno):

```bash
./build-release/nz_recon a -cn backup file1.txt file2.txt
```

Listar:

```bash
./build-release/nz_recon l backup.nz
```

Probar integridad:

```bash
./build-release/nz_recon t backup.nz
```

Extraer:

```bash
./build-release/nz_recon x -o./out backup.nz
```

## Medición rápida de cobertura

Para medir porcentaje práctico (con fallback legado) y porcentaje nativo:

```bash
./tests/coverage_matrix.sh
```

Salida esperada:

- `usage_real_percent`: métodos que pasan `l/t/x` con salida correcta (incluye fallback).
- `native_only_percent`: métodos que pasan `l/t/x` sin usar `[compat]`.
- `encode_real_percent`: métodos `-c*` donde `a/s` + `t/x` sobre el archivo generado pasan correctamente.
- `encode_native_no_compat_percent`: métodos `-c*` de `a/s` sin `[compat]`.
- `encode_native_no_compat_bridge_percent`: métodos `-c*` de `a/s` sin `[compat]` ni `[bridge]`.

Para medir avance C++ puro (sin bridges):

```bash
NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 ./tests/coverage_matrix.sh
```

Para medir compresión sin bridge interno (writer nativo experimental):

```bash
NZ_DISABLE_COMPRESS_BRIDGE=1 ./tests/coverage_matrix.sh
```

## Documentación RE

- Flujo operativo completo: `docs/flujo_trabajo_re.md`
- LZPF (`-cf/-cF`): `docs/nz_lzpf_linux32.md`
- Optimum/CM (`-co/-cO/-cc`): `docs/nz_optimum_linux32.md`
