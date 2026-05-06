# Flujo de Trabajo RE de NanoZip (Reconstruccion CLI)

Fecha de corte: 2026-04-03

## Objetivo operativo

Reconstruir `l/t/x/a/s` de NanoZip 0.09a sin SFX, priorizando:

1. compatibilidad real de uso (`l/t/x` funcionando en archivos legacy);
2. trazabilidad del formato (header, tabla, metadata, payload);
3. reemplazo progresivo de compat/bridges por decode C++ puro.

## Definiciones de porcentaje

- `usage_real_percent`:
  - porcentaje de metodos `-c*` que pasan `l/t/x` con salida correcta;
  - incluye rutas de bridge/compat cuando se activan.
- `native_only_percent`:
  - porcentaje de metodos `-c*` que pasan `l/t/x` sin emitir `[compat]`;
  - puede incluir decode por `extract bridge` o `gdb bridge`.
- `native_pure_percent` (medicion manual recomendada):
  - mismo criterio anterior, pero desactivando bridges:
  - `NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1`.
- `encode_real_percent`:
  - porcentaje de metodos `-c*` donde `a/s` y luego `t/x` del archivo generado pasan correctamente.
- `encode_native_no_compat_percent`:
  - porcentaje de metodos `-c*` donde `a/s` no emite `[compat]`.
- `encode_native_no_compat_bridge_percent`:
  - porcentaje de metodos `-c*` donde `a/s` no emite `[compat]` ni `[bridge]`.

## Herramientas usadas

- RE/inspeccion:
  - `rizin/radare2`, `gdb` (batch), `xxd`, `strace`, `rg`.
- validacion de comportamiento:
  - `work/linux64/nz`, `work/linux32/nz` como oraculo.
- reconstruccion:
  - `cmake`, `g++`.

## Flujo base (iteracion estandar)

1. Construir binario reconstruido.
2. Medir baseline de cobertura (`coverage_matrix.sh`).
3. Repetir baseline con bridges desactivados para medir avance puro.
4. Tomar muestra `.nz` y extraer stream interno para hipotesis de formato.
5. Implementar subcaso en parser/decode C++ (siempre conservador).
6. Ejecutar regresion:
   - `l/t/x` en corpus de prueba;
   - `cmp` de archivos extraidos vs originales;
   - matriz de cobertura completa.
7. Documentar hallazgo y dejar siguiente paso concreto.

## Comandos de referencia

Build:

```bash
cd work/reconstruccion
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
cp build-release/nz_recon bin/nz_recon
cp build-release/nz_sfx_recon bin/nz_sfx_recon
```

Cobertura normal:

```bash
cd work/reconstruccion
./tests/coverage_matrix.sh
```

Cobertura sin bridges (pureza):

```bash
cd work/reconstruccion
NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 ./tests/coverage_matrix.sh
```

Dump de stream legacy:

```bash
cd work/reconstruccion
./tests/legacy_stream_dump.py /ruta/al/archivo.nz
```

Traza de ruta runtime `-co/-cO` en backend legacy:

```bash
cd work/reconstruccion
./tests/legacy_optimum_trace_path.sh /ruta/al/archivo.nz
```

Matriz de rutas runtime vs pureza nativa (lote de muestras):

```bash
cd work/reconstruccion
./tests/legacy_optimum_path_matrix.py '/tmp/nz_co_grid/*.nz' '/tmp/nz_co_pairs/*.nz'
```

## Rutas de decode legacy (orden real)

Para `t/x` de archivos legacy:

1. parser nativo de header + tabla + metadata;
2. si payload no nativo:
   - `extract bridge` (usa backend legacy en dir temporal, sin ptrace);
   - luego `gdb bridge` (si disponible);
3. si ambos fallan:
   - fallback `[compat]` al backend legacy.

## Rutas de compresion `a/s` (estado real)

- `-cn`: compresion/escritura nativa en C++.
- metodos legacy (`-cf/-cF/-cd/-cD/-co/-cO/-cc`):
  - por defecto: writer nativo `native-first` por wrappers RE:
    - `cf/cF`: `literal-only`;
    - `cd/cD`: `literal-wrapper` (`[varint][0x00][raw]`);
    - `co/cO`: wrapper BWT (`[u32 size][bwt_last][u24 primary]`, limite 32 KiB en writer nativo);
    - `cc`: `raw-wrapper` (`[u32 size][raw]`).
  - si writer nativo falla y bridge esta habilitado: fallback a backend legacy (marca `[bridge]`, sin pre-forward `[compat]`);
  - `NZ_DISABLE_COMPRESS_BRIDGE=1`: desactiva fallback bridge y fuerza salida estrictamente nativa (error si el wrapper no aplica).
  - soporta `-h*` (con mapeo `-hf -> Fletcher32` en header legacy).

## Variables de entorno operativas

- `NZ_LEGACY_BACKEND`:
  - ruta a backend `nz` (archivo o directorio contenedor).
- `NZ_LEGACY_BRIDGE_BACKEND`:
  - ruta al backend linux32 para `gdb bridge`.
- `NZ_DISABLE_EXTRACT_BRIDGE`:
  - desactiva puente de extraccion.
- `NZ_DISABLE_GDB_BRIDGE`:
  - desactiva puente por gdb/ptrace.
- `NZ_DISABLE_COMPRESS_BRIDGE`:
  - desactiva fallback bridge de compresion `a/s` para metodos legacy y fuerza resultado estrictamente nativo.

## Estado actual por metodo `-c`

- `cn`: nativo puro.
- `cd/cD`: nativo puro en subcaso literal-only observado; writer nativo de wrapper RE disponible.
- `cc`:
  - nativo puro en subcaso `literal-wrapper` (`[u32 size][raw][trailer]`);
  - writer nativo `raw-wrapper` disponible;
  - en streams comprimidos reales aun requiere bridge/compat.
- `cf/cF`: literal-only puro; writer nativo literal disponible; streams comprimidos reales aun pendientes.
- `co/cO`:
  - decoder nativo del wrapper BWT observado en muestras chicas;
  - decoder nativo del subcaso `raw-wrapper` observado en entradas incomprimibles;
  - writer nativo BWT-wrapper disponible (limite 32 KiB);
  - streams comprimidos reales generales aun pendientes (bridge/compat).

## Principio de implementacion

Siempre validar subcasos con checks estructurales fuertes:

1. layout coherente de stream (`stream_tag`, longitudes, limites);
2. tamaño total esperado (`total_data_size`);
3. consistencia por entradas (nunca leer fuera de rango);
4. fallback seguro a bridge/compat cuando no se cumple.

## Backlog inmediato

1. Port de `cf/cF` comprimido real (core RE `0x08097570/0x08097e20`).
2. Completar decoder puro de `co/cO` para streams comprimidos generales pendientes:
   - prefiltro `0x0809a250` en ruta `0x080aa850 -> 0x0809a250 -> 0x0809d370`;
   - ruta alterna repetitivos `0x080aa850 -> 0x080acaf0 -> 0x080ace10 -> 0x080accd0`.
   - nota: la ruta BWT directa `0x080aa850 -> 0x0809d370` ya tiene cobertura nativa en wrappers observados (incluyendo `primary` en trailer16@+5).
3. Extender decoder puro de `cc` para streams comprimidos reales.
4. Completar parseo de metadata multi-archivo legacy (timestamps/permisos/checksum por entrada).
