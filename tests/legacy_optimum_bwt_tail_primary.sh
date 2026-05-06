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
  for c in "${RECON_ROOT}/../linux32/nz" "${RECON_ROOT}/../linux64/nz" "nz"; do
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

TMP_DIR="$(mktemp -d /tmp/nz_opt_bwt_tail.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/in" "${TMP_DIR}/out"

head -c 8192 /dev/urandom > "${TMP_DIR}/in/rand8k.bin"
cat "${TMP_DIR}/in/rand8k.bin" > "${TMP_DIR}/in/mix8k.bin"
printf 'nanozip-optimum-tail-primary\n' >> "${TMP_DIR}/in/mix8k.bin"

echo "method|input|t_rc|x_rc|compat_t|compat_x|cmp_ok"
for m in co cO; do
  for input in rand8k.bin mix8k.bin; do
    arc="${TMP_DIR}/${m}_${input}.nz"
    "${LEGACY_BIN}" a -y -"${m}" "${arc}" "${TMP_DIR}/in/${input}" >/dev/null 2>&1

    set +e
    t_out="$(NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 "${RECON_BIN}" t "${arc}" 2>&1)"
    t_rc=$?
    set -e
    mkdir -p "${TMP_DIR}/out/${m}_${input}"
    set +e
    x_out="$(NZ_DISABLE_EXTRACT_BRIDGE=1 NZ_DISABLE_GDB_BRIDGE=1 "${RECON_BIN}" x -y -o"${TMP_DIR}/out/${m}_${input}" "${arc}" 2>&1)"
    x_rc=$?
    set -e

    compat_t=0
    compat_x=0
    grep -q "\\[compat\\]" <<<"${t_out}" && compat_t=1 || true
    grep -q "\\[compat\\]" <<<"${x_out}" && compat_x=1 || true

    extracted="$(find "${TMP_DIR}/out/${m}_${input}" -type f -name "${input}" | head -n1 || true)"
    cmp_ok=0
    if [[ -n "${extracted}" ]] && cmp -s "${TMP_DIR}/in/${input}" "${extracted}"; then
      cmp_ok=1
    fi

    echo "${m}|${input}|${t_rc}|${x_rc}|${compat_t}|${compat_x}|${cmp_ok}"

    if [[ ${t_rc} -ne 0 || ${x_rc} -ne 0 || ${compat_t} -ne 0 || ${compat_x} -ne 0 || ${cmp_ok} -ne 1 ]]; then
      echo "error: native decode check failed for -${m} ${input}" >&2
      exit 1
    fi
  done
done
