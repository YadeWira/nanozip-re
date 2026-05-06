# Tests

Cobertura actual automatizada:

- `smoke_suite.sh`:
  - parseo CLI base (sin args, comando desconocido, faltantes);
  - errores de archivo (`Cannot open`, `not nanozip`, version incompatible);
  - smoke de metadata de extraccion (`perm` + `mtime`) para formato reconstruido.
- `coverage_matrix.sh`:
  - matriz de `l/t/x` sobre corpus generado por backend legado;
  - matriz de `a/s` por metodo `-c*` con clasificacion por `[compat]`/`[bridge]`;
  - resumen de porcentajes de uso real y nivel nativo.
- `legacy_optimum_raw_wrapper.sh`:
  - regression del subcaso `-co/-cO` raw-wrapper observado en entradas incomprimibles;
  - fuerza `NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1`;
  - exige `t/x` sin `[compat]` y `cmp` de payload extraido.
- `legacy_optimum_bwt_tail_primary.sh`:
  - regression del subtipo BWT donde `primary index` viene en trailer de 16 bytes (`offset +5`, LE u24);
  - cubre `-co` y `-cO` con payloads single-file de 8 KiB;
  - exige `t/x` sin `[compat]` con bridges desactivados.
- `legacy_optimum_trace_path.sh`:
  - traza de ruta interna en backend legacy (`linux32/nz`) para `-co/-cO`;
  - reporta hit-order de funciones clave (`aa850`, `a9d370`, `a9a250`, `acaf0`, etc.);
  - util para clasificar stream subtipos antes de portar decoder C++.
- `legacy_optimum_path_matrix.py`:
  - clasifica un lote de `.nz` por ruta interna (`legacy_optimum_trace_path.sh`);
  - cruza cada grupo contra `nz_recon` con bridges de extraccion desactivados;
  - resume por grupo `t_ok/x_ok` y presencia de `[compat]`.

## Scripts utiles

- Smoke suite:

```bash
./smoke_suite.sh
```

- Matriz de cobertura:

```bash
./coverage_matrix.sh
```

- Regression optimum raw-wrapper:

```bash
./legacy_optimum_raw_wrapper.sh
```

- Regression optimum BWT trailer-primary:

```bash
./legacy_optimum_bwt_tail_primary.sh
```

- Medicion sin bridges (avance C++ puro):

```bash
NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 ./coverage_matrix.sh
```

- Medicion de compresion con fallback bridge desactivado (modo nativo estricto):

```bash
NZ_DISABLE_COMPRESS_BRIDGE=1 ./coverage_matrix.sh
```

- Dump de stream legacy para RE:

```bash
./legacy_stream_dump.py /ruta/archivo.nz
```

- Traza de ruta runtime `-co/-cO` en backend legacy:

```bash
./legacy_optimum_trace_path.sh /ruta/archivo.nz
```

- Matriz de rutas runtime vs pureza C++ (`-co/-cO`):

```bash
./legacy_optimum_path_matrix.py '/tmp/nz_co_grid/*.nz' '/tmp/nz_co_pairs/*.nz'
```
