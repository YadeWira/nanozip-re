cmake_minimum_required(VERSION 3.16)
project(nanozip_reconstruction LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RECON_SOURCES
    src/main.cpp
    src/sfx_cli.cpp
    src/sfx_archive.cpp
    src/linux32_cm_map.cpp
    src/lzpf_arith.cpp
    src/nz_cm.cpp
    src/nz_lzhd.cpp
    src/nz_cd_tokens.cpp
    src/nz_cd_texttransform_dict.cpp
    src/nz_lzhds.cpp
    src/nz_text_transform.cpp
    src/nz_tt_chess.cpp
    src/nz_postfilter.cpp
    src/nz_bwt.cpp
    src/nz_audio.cpp
    src/nz_exefilter.cpp
    src/nz_texttransform_num.cpp
    src/nz_optimum_lz.cpp
    src/nz_optimum_lz_tables.cpp
    src/nz_optimum2_lz.cpp
    src/nz_optimum2_lz_tables.cpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(nz_recon ${RECON_SOURCES})
add_executable(nz_sfx_recon ${RECON_SOURCES})

target_include_directories(nz_recon PRIVATE include)
target_include_directories(nz_sfx_recon PRIVATE include)

if(MSVC)
    target_compile_options(nz_recon PRIVATE /W4)
    target_compile_options(nz_sfx_recon PRIVATE /W4)
else()
    target_compile_options(nz_recon PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(nz_sfx_recon PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Optional unit-test binary for the lzpf arith primitives.
add_executable(test_lzpf_arith
    tests/test_lzpf_arith.cpp
    src/lzpf_arith.cpp
    src/nz_cd_tokens.cpp
    src/nz_cd_texttransform_dict.cpp
    src/nz_lzhds.cpp
    # nz_cd_tokens' text pipeline calls the shared tt 0x40 transform, which
    # lives in its own dependency-free unit for exactly this reason
    src/nz_tt_chess.cpp
)
target_include_directories(test_lzpf_arith PRIVATE include)
if(NOT MSVC)
    target_compile_options(test_lzpf_arith PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Standalone isolation test for the -co (nz_optimum1) LZ/CM engine port,
# validated against captured golden vectors before being wired into the live
# dispatcher.
add_executable(test_optimum_lz
    tests/test_optimum_lz.cpp
    src/nz_optimum_lz.cpp
    src/nz_optimum_lz_tables.cpp
    src/nz_cm.cpp
)
target_include_directories(test_optimum_lz PRIVATE include)
if(NOT MSVC)
    target_compile_options(test_optimum_lz PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Standalone isolation test for the -cO (nz_optimum2) LZ/CM engine port,
# validated against captured golden vectors before being wired into the live
# dispatcher (mirrors test_optimum_lz's own convention).
add_executable(test_optimum2_lz
    tests/test_optimum2_lz.cpp
    src/nz_optimum2_lz.cpp
    src/nz_optimum2_lz_tables.cpp
    src/nz_optimum_lz_tables.cpp
    src/nz_cm.cpp
)
target_include_directories(test_optimum2_lz PRIVATE include)
if(NOT MSVC)
    target_compile_options(test_optimum2_lz PRIVATE -Wall -Wextra -Wpedantic)
endif()
