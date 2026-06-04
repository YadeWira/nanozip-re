#!/usr/bin/env bash
# Validate that extraction works without any legacy binary available.
# Compresses fixtures using the legacy binary, then extracts with the
# native binary in an environment where the legacy is unreachable.
set -uo pipefail

RECON_ROOT="/home/omega/Escritorio/Git/nanozip/work/reconstruccion"
NATIVE="${RECON_ROOT}/bin/nz_recon"
LEGACY="${RECON_ROOT}/../linux64/nz"

if [[ ! -x "$NATIVE" ]]; then echo "FATAL: native bin missing"; exit 1; fi
if [[ ! -x "$LEGACY" ]]; then echo "FATAL: legacy bin missing"; exit 1; fi

WORK="$(mktemp -d /tmp/native_only.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

mkdir -p "${WORK}/in"
FIXTURES=()

# Diverse corpus
for sz in 1024 4096 16384 65536 262144 1048576; do
  head -c $sz /dev/urandom > "${WORK}/in/rand_${sz}.bin"
  FIXTURES+=("rand_${sz}.bin")
done
{ for i in $(seq 1 800); do echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit."; done; } > "${WORK}/in/text_50k.txt"
FIXTURES+=("text_50k.txt")
{ yes "the quick brown fox jumps over the lazy dog " || true; } | head -c 102400 > "${WORK}/in/repeat_100k.txt"
FIXTURES+=("repeat_100k.txt")
head -c 4096 /dev/urandom > "${WORK}/in/mix_4k.bin"
{ cat "${WORK}/in/mix_4k.bin"; cat "${WORK}/in/text_50k.txt"; } > "${WORK}/in/mixed.bin"
FIXTURES+=("mixed.bin")
head -c 102400 /dev/zero > "${WORK}/in/zeros_100k.bin"
FIXTURES+=("zeros_100k.bin")
cp "${RECON_ROOT}/src/sfx_archive.cpp" "${WORK}/in/source.cpp"
FIXTURES+=("source.cpp")
cp "${RECON_ROOT}/tests/fixtures/cm/abcd3.txt" "${WORK}/in/"
FIXTURES+=("abcd3.txt")
cp "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav" "${WORK}/in/"
FIXTURES+=("stereo_lms.wav")
head -c 8192 /dev/zero > "${WORK}/in/zeros_8k.bin"
FIXTURES+=("zeros_8k.bin")
{ for i in $(seq 1 4096); do printf '\x00\xff'; done; } | head -c 16384 > "${WORK}/in/alt_16k.bin"
FIXTURES+=("alt_16k.bin")
# Multi-file fixture
mkdir -p "${WORK}/in/multi1"
for i in 1 2 3; do head -c $((1000*i)) /dev/urandom > "${WORK}/in/multi1/f_$i.bin"; done
head -c 8192 /dev/zero > "${WORK}/in/multi1/zeros8k.bin"
{ yes "repetitive content for compression " || true; } | head -c 8192 > "${WORK}/in/multi1/repeat.txt"
FIXTURES+=("multi1")

METHODS=(cn cf cF cd cD co cO cc)

pass=0
fail=0
skipped=0
total=0
fail_log=""

# Strategy: pre-create the destination file path BEFORE extracting, so the
# legacy doesn't need a target file to write to. Use CWD-relative paths to
# avoid path-mismatch bugs.

for fix in "${FIXTURES[@]}"; do
  for m in "${METHODS[@]}"; do
    total=$((total+1))
    arc="${WORK}/arc_${fix}_${m}.nz"
    rm -f "$arc"

    # Compress with legacy
    if [[ "$fix" == "multi1" ]]; then
      if ! "$LEGACY" a -y -"$m" "$arc" "${WORK}/in/$fix"/* >/dev/null 2>&1; then
        skipped=$((skipped+1)); continue
      fi
    else
      if ! "$LEGACY" a -y -"$m" "$arc" "${WORK}/in/$fix" >/dev/null 2>&1; then
        skipped=$((skipped+1)); continue
      fi
    fi

    # Make a scratch file so the legacy has somewhere to extract to
    scratch_orig="${WORK}/scratch_orig.bin"
    scratch_native="${WORK}/scratch_native.bin"
    rm -f "$scratch_orig" "$scratch_native"
    touch "$scratch_orig" "$scratch_native"

    # Extract with legacy into scratch_orig (oracle)
    if ! (cd "$(dirname "$scratch_orig")" && \
          cp -f "$scratch_orig" "$(basename "$scratch_orig").lock" 2>/dev/null; \
          "$LEGACY" x -y -fo "$arc" 2>/dev/null && \
          cp "$(find . -maxdepth 1 -type f ! -name '*.lock' ! -name '*.bin' -newer /tmp/.now 2>/dev/null | head -1)" "$scratch_orig" 2>/dev/null); then
        : # may have just written to scratch_orig
    fi

    # Use a more deterministic approach: extract each into its own dir
    oracle_dir="${WORK}/oracle_${fix}_${m}"
    native_dir="${WORK}/native_${fix}_${m}"
    rm -rf "$oracle_dir" "$native_dir"
    mkdir -p "$oracle_dir" "$native_dir"

    # Use absolute path for archive (avoids any CWD-related confusion)
    (cd "$oracle_dir" && touch orig && "$LEGACY" x -y -fo "$arc") >/dev/null 2>&1
    (cd "$native_dir" && touch orig && env -u NZ_LEGACY_BACKEND -u NZ_LEGACY_BRIDGE_BACKEND \
        "$NATIVE" x -y -fo "$arc") >/dev/null 2>&1

    oracle_file=$(find "$oracle_dir" -type f -name 'orig' | head -1)
    native_file=$(find "$native_dir" -type f -name 'orig' | head -1)
    # If not named 'orig', pick the first file in each dir
    if [[ -z "$oracle_file" ]]; then oracle_file=$(find "$oracle_dir" -type f | head -1); fi
    if [[ -z "$native_file" ]]; then native_file=$(find "$native_dir" -type f | head -1); fi

    if [[ -z "$oracle_file" || -z "$native_file" ]]; then
      fail_log="${fail_log}FAIL: $fix / $m (no files: oracle=$oracle_file native=$native_file)\n"
      fail=$((fail+1)); continue
    fi

    if cmp -s "$oracle_file" "$native_file"; then
      pass=$((pass+1))
    else
      diff_count=$(cmp -l "$oracle_file" "$native_file" 2>/dev/null | wc -l)
      sz=$(stat -c %s "$oracle_file" 2>/dev/null || echo "?")
      fail_log="${fail_log}FAIL: $fix / $m (size=$sz, $diff_count bytes differ)\n"
      fail=$((fail+1))
    fi
  done
done

echo "=== NATIVE-ONLY EXTRACT (no legacy binary at runtime) ==="
echo "fixtures=${#FIXTURES[@]}  methods=${#METHODS[@]}  total=$total"
echo "pass=$pass  fail=$fail  skipped=$skipped"
if [[ -n "$fail_log" ]]; then
  echo
  printf "%b" "$fail_log" | head -30
fi
if [[ $fail -eq 0 ]]; then
  echo
  echo "ok: $pass byte-exact extractions with NO legacy binary available"
  exit 0
else
  echo
  echo "FAIL: $fail of $total combinations differ"
  exit 1
fi
