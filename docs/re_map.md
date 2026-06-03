# Mapeo RE -> Codigo reconstruido

Base: `work/w32sfx/nz_w32c_unpacked.exe`

## Parser CLI y despacho

- `fcn.00401342` -> `ParseCli` + `main` switch
- `fcn.004044a4` -> `RunList` wrapper (`l`)
- `fcn.004044c0` -> `RunExtractOrTest` wrapper (`x/t`)
- `fcn.00403370` -> `RunExtractOrTest` / `RunList` core placeholder

## Validacion de archivo `.nz`

- `fcn.0042ad80` -> `ValidateArchiveHeader`
  - `Cannot open archive!`
  - `File is not a NanoZip archive.`
  - `Archive file is made with incompatible version (%u.%02u).`

## Helpers de memoria/objetos observados en RE

Estos quedan documentados para la siguiente etapa de reconstruccion:

- `fcn.004180f4` -> `nz_alloc_or_abort` (pendiente)
- `fcn.00417b58` -> `nz_queue_ctor_mutexes` (pendiente)
- `fcn.00417c10` -> `nz_queue_alloc_and_init` (pendiente)
- `fcn.0041714e` -> `nz_pair_set_default_ptr` (pendiente)
- `fcn.00402a90` -> `nz_ctx_slot_init_and_alloc` (pendiente)
- `fcn.00401c7e` -> `nz_ctx_slot_release_and_destroy` (pendiente)
- `fcn.00416efa` -> `nz_vcall_release_if_not_null` (pendiente)

## Linux32 core (metodos de compresion)

Base: `work/linux32/nz`

- Dispatcher real: `fcn.08092470` con switch por `ctx+0x24`.
- Constructors por familia:
  - `fcn.08098050` (indices 1/2: `nz_lzpf`, `nz_lzpf_large`)
  - `fcn.08099d90` (indices 3/4: `nz_lzhd`, `nz_lzhds`)
  - `fcn.080ab9c0` (indices 5/6/7: `nz_optimum1`, `nz_optimum2`, `nz_cm`)
- `nz_cm` confirmado en `index 7 -> fcn.080ab9c0(mode=2)`.

### Mapeo sugerido (familia `080ab9c0`)

- `fcn.080ab9c0` -> `nz_cm_family_ctor`
- `fcn.080ab090` -> `nz_cm_family_dtor`
- `fcn.080ab140` -> `nz_cm_family_delete`
- `fcn.080aaf70` -> `nz_cm_family_reset`
- `fcn.080ab160` -> `nz_cm_family_load_params`
- `fcn.080aa850` -> `nz_cm_family_process`
- `fcn.080bfcc0` -> `nz_cm_family_init_core_by_mode`
- `fcn.080aafb0` -> `nz_cm_family_estimate_memory`
- `fcn.080b90a0` -> `nz_cm_big_engine_ctor`
- `fcn.080bcb50` -> `nz_cm_small_engine_ctor`
- `fcn.080b5810` -> `nz_cm_mode2_extra_obj_ctor`
- `fcn.080b5440` -> `nz_cm_mode2_extra_obj_init_tables`
- `fcn.080917d0` -> `nz_stream_read_clamped`
- `fcn.080c0220` -> `nz_cm_check_byte`

## Linux32 lzpf (`-cf/-cF`)

Base: `work/linux32/nz`

- Constructor familia lzpf/lzpf_large: `fcn.08098050`
- Vtable lzpf principal: `0x08132c68`
- Core proceso lzpf:
  - wrapper: `fcn.08097e20`
  - core: `fcn.08097570`

Documento tecnico detallado:

- `docs/nz_lzpf_linux32.md`
