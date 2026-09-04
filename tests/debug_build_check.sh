#!/bin/bash
# The trace/dump switches of the decoders compile in only with -DNZOPT_DEBUG
# (and the -cO model-write watch with -DNZO2_WATCH). They are off in every
# normal build, so this syntax-checks them so they cannot rot unnoticed.
# usage: tests/debug_build_check.sh   (from the repository root)
set -e
cd "$(dirname "$0")/.."
g++ -std=c++17 -O2 -DNDEBUG -DNZOPT_DEBUG -DNZO2_WATCH -Iinclude -fsyntax-only src/*.cpp
echo "ok: debug build paths compile (-DNZOPT_DEBUG -DNZO2_WATCH)"
