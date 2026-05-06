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
)

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
)
target_include_directories(test_lzpf_arith PRIVATE include)
if(NOT MSVC)
    target_compile_options(test_lzpf_arith PRIVATE -Wall -Wextra -Wpedantic)
endif()
