#!/usr/bin/env bash
# Stress regression test: exercise all 8 methods against large single-file,
# multi-file, and multi-file+multi-block scenarios. Lock in the block-parser
# fix and multi-file payload-detection fix.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RECON_BIN="${RECON_ROOT}/bin/nz_recon"
if [[ ! -x "${RECON_BIN}" ]]; then
  RECON_BIN="${RECON_ROOT}/build/nz_recon"
fi
if [[ ! -x "${RECON_BIN}" ]]; then
  RECON_BIN="${RECON_ROOT}/build-release/nz_recon"
fi
if [[ ! -x "${RECON_BIN}" ]]; then
  echo "error: nz_recon not found" >&2
  exit 1
fi

LEGACY_BIN="${NZ_LEGACY_BACKEND:-}"
if [[ -n "${LEGACY_BIN}" && -d "${LEGACY_BIN}" ]]; then
  LEGACY_BIN="${LEGACY_BIN%/}/nz"
fi
if [[ -z "${LEGACY_BIN}" ]]; then
  for c in "${RECON_ROOT}/../linux64/nz" "${RECON_ROOT}/../linux32/nz"; do
    if [[ -x "${c}" ]]; then
      LEGACY_BIN="${c}"
      break
    fi
  done
fi
if [[ -z "${LEGACY_BIN}" || ! -x "${LEGACY_BIN}" ]]; then
  echo "error: legacy backend not found (set NZ_LEGACY_BACKEND)" >&2
  exit 1
fi

TMP="$(mktemp -d /tmp/nz_stress.XXXXXX)"
trap 'rm -rf "${TMP}"' EXIT

# Scenario 1: single 5MB random file
mkdir -p "${TMP}/s1_in" "${TMP}/s1_out"
head -c 5242880 /dev/urandom > "${TMP}/s1_in/huge.bin"

# Scenario 2: multi-file (3 files, 2.5MB total) forcing multi-block split
mkdir -p "${TMP}/s2_in" "${TMP}/s2_out"
head -c 1048576 /dev/urandom > "${TMP}/s2_in/rand_1M.bin"
head -c 524288 /dev/zero > "${TMP}/s2_in/zeros_512K.bin"
{ yes "stress pattern 1234" || true; } | head -c 1048576 > "${TMP}/s2_in/repeats_1M.txt"

# Scenario 3: many small files (15 files, varying sizes)
mkdir -p "${TMP}/s3_in" "${TMP}/s3_out"
for i in $(seq 1 15); do
  head -c $((200 + i * 100)) /dev/urandom > "${TMP}/s3_in/small_${i}.bin"
done

methods=(cn cf cF cd cD co cO cc)
fail=0
total=0

run_scenario() {
  local label="$1"
  local in_dir="$2"
  local out_dir="$3"
  for m in "${methods[@]}"; do
    total=$((total + 1))
    local arc="${out_dir}/${m}.nz"
    rm -f "${arc}"
    "${LEGACY_BIN}" a -$m "${arc}" "${in_dir}"/* >/dev/null 2>&1 || {
      echo "FAIL [${label}/${m}]: legacy compress failed"
      fail=$((fail + 1))
      continue
    }
    local ex_dir="${out_dir}/ex_${m}"
    rm -rf "${ex_dir}"
    mkdir -p "${ex_dir}"
    (cd "${ex_dir}" && "${RECON_BIN}" x "${arc}" >/dev/null 2>&1) || {
      echo "FAIL [${label}/${m}]: nz_recon x rc=$?"
      fail=$((fail + 1))
      continue
    }
    local mismatch=0
    for f in "${in_dir}"/*; do
      local bn="$(basename "${f}")"
      local found="$(find "${ex_dir}" -name "${bn}" -type f | head -1)"
      if [[ -z "${found}" ]] || ! cmp -s "${found}" "${f}"; then
        mismatch=$((mismatch + 1))
      fi
    done
    if [[ ${mismatch} -gt 0 ]]; then
      echo "FAIL [${label}/${m}]: ${mismatch} files mismatch"
      fail=$((fail + 1))
    fi
  done
}

run_scenario "single-5M" "${TMP}/s1_in" "${TMP}/s1_out"
run_scenario "multi-3x2.5M" "${TMP}/s2_in" "${TMP}/s2_out"
run_scenario "many-15" "${TMP}/s3_in" "${TMP}/s3_out"

if [[ ${fail} -eq 0 ]]; then
  echo "ok: stress_matrix (${total}/${total} passed)"
  exit 0
else
  echo "stress_matrix: ${fail}/${total} failed"
  exit 1
fi
