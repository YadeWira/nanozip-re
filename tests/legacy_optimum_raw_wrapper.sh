#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RECON_BIN="${RECON_ROOT}/bin/nz_recon"
if [[ ! -x "${RECON_BIN}" ]]; then
  RECON_BIN="${RECON_ROOT}/build-release/nz_recon"
fi
if [[ ! -x "${RECON_BIN}" ]]; then
  echo "error: nz_recon not found (expected bin/nz_recon or build-release/nz_recon)" >&2
  exit 1
fi

LEGACY_BIN="${NZ_LEGACY_BACKEND:-}"
if [[ -n "${LEGACY_BIN}" && -d "${LEGACY_BIN}" ]]; then
  LEGACY_BIN="${LEGACY_BIN%/}/nz"
fi
if [[ -z "${LEGACY_BIN}" ]]; then
  for c in "${RECON_ROOT}/../linux64/nz" "${RECON_ROOT}/../linux32/nz" "nz"; do
    if command -v "${c}" >/dev/null 2>&1; then
      LEGACY_BIN="$(command -v "${c}")"
      break
    fi
    if [[ -x "${c}" ]]; then
      LEGACY_BIN="${c}"
      break
    fi
  done
fi
if [[ -z "${LEGACY_BIN}" || ! -x "${LEGACY_BIN}" ]]; then
  echo "error: legacy backend not found (set NZ_LEGACY_BACKEND=/path/to/nz)" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/nz_opt_raw.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/in" "${TMP_DIR}/out"

generate_candidate() {
  printf 'AAAAABBBBBCCCCCDDDDDEEEEE\n' > "${TMP_DIR}/in/prefix.txt"
  head -c 8192 /dev/urandom > "${TMP_DIR}/in/rand.bin"
  cat "${TMP_DIR}/in/prefix.txt" "${TMP_DIR}/in/rand.bin" > "${TMP_DIR}/in/mix.bin"
  cat "${TMP_DIR}/in/prefix.txt" "${TMP_DIR}/in/mix.bin" > "${TMP_DIR}/in/combo.bin"
}

co_ready=0
for attempt in $(seq 1 24); do
  generate_candidate
  arc_probe="${TMP_DIR}/probe_co.nz"
  "${LEGACY_BIN}" a -y -co "${arc_probe}" "${TMP_DIR}/in/combo.bin" >/dev/null 2>&1
  set +e
  probe_out="$(NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 "${RECON_BIN}" t "${arc_probe}" 2>&1)"
  probe_rc=$?
  set -e
  if [[ ${probe_rc} -eq 0 ]] && ! grep -q "\\[compat\\]" <<<"${probe_out}"; then
    co_ready=1
    break
  fi
done

if [[ ${co_ready} -ne 1 ]]; then
  echo "FAIL: could not generate a deterministic co raw-wrapper case after 24 attempts" >&2
  exit 1
fi

echo "method|test_rc|x_rc|test_compat|x_compat|x_ok"
for m in co cO; do
  arc="${TMP_DIR}/${m}.nz"
  "${LEGACY_BIN}" a -y -"${m}" "${arc}" "${TMP_DIR}/in/combo.bin" >/dev/null 2>&1

  set +e
  tout="$(NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 "${RECON_BIN}" t "${arc}" 2>&1)"
  trc=$?
  xout="$(NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 "${RECON_BIN}" x -y -o"${TMP_DIR}/out/${m}" "${arc}" 2>&1)"
  xrc=$?
  set -e

  test_compat=0
  x_compat=0
  grep -q "\\[compat\\]" <<<"${tout}" && test_compat=1 || true
  grep -q "\\[compat\\]" <<<"${xout}" && x_compat=1 || true

  x_ok=0
  out_file="$(find "${TMP_DIR}/out/${m}" -type f -name combo.bin | head -n1 || true)"
  if [[ -n "${out_file}" ]] && cmp -s "${TMP_DIR}/in/combo.bin" "${out_file}"; then
    x_ok=1
  fi

  echo "${m}|${trc}|${xrc}|${test_compat}|${x_compat}|${x_ok}"

  if [[ ${trc} -ne 0 || ${xrc} -ne 0 || ${test_compat} -ne 0 || ${x_compat} -ne 0 || ${x_ok} -ne 1 ]]; then
    echo "FAIL: ${m} optimum raw-wrapper native decode regression" >&2
    echo "--- t output ---" >&2
    echo "${tout}" >&2
    echo "--- x output ---" >&2
    echo "${xout}" >&2
    exit 1
  fi
done

echo "ok: legacy_optimum_raw_wrapper"
