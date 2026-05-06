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

TMP_DIR="$(mktemp -d /tmp/nz_smoke.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

CAPTURE_OUT=""
CAPTURE_RC=0

run_capture() {
  set +e
  CAPTURE_OUT="$("$@" 2>&1)"
  CAPTURE_RC=$?
  set -e
}

assert_rc() {
  local want="$1"
  local name="$2"
  if [[ "${CAPTURE_RC}" -ne "${want}" ]]; then
    echo "FAIL(${name}): rc=${CAPTURE_RC}, expected=${want}" >&2
    echo "${CAPTURE_OUT}" >&2
    exit 1
  fi
}

assert_contains() {
  local needle="$1"
  local name="$2"
  if ! grep -Fq "${needle}" <<<"${CAPTURE_OUT}"; then
    echo "FAIL(${name}): missing expected text: ${needle}" >&2
    echo "${CAPTURE_OUT}" >&2
    exit 1
  fi
}

echo "[smoke] cli + errores de header/version"

run_capture "${RECON_BIN}"
assert_rc 0 "usage_no_args"
assert_contains "usage:" "usage_no_args"

run_capture "${RECON_BIN}" zzz
assert_rc 1 "unknown_command"
assert_contains "Unknown command zzz" "unknown_command"

run_capture "${RECON_BIN}" l
assert_rc 1 "missing_archive"
assert_contains "archive name missing" "missing_archive"

run_capture "${RECON_BIN}" info
assert_rc 0 "info"
assert_contains "Host information" "info"

run_capture "${RECON_BIN}" w32c
assert_rc 2 "w32c_omitted"
assert_contains "SFX creation is intentionally omitted" "w32c_omitted"

run_capture "${RECON_BIN}" l "${TMP_DIR}/missing.nz"
assert_rc 1 "cannot_open"
assert_contains "Cannot open archive!" "cannot_open"

printf 'not-a-nanozip\n' > "${TMP_DIR}/plain.bin"
run_capture "${RECON_BIN}" l "${TMP_DIR}/plain.bin"
assert_rc 1 "not_nanozip"
assert_contains "File is not a NanoZip archive." "not_nanozip"

printf '\xAE\x01NanoZip 1.10 alpha' > "${TMP_DIR}/incompatible.nz"
run_capture "${RECON_BIN}" l "${TMP_DIR}/incompatible.nz"
assert_rc 1 "incompatible_version"
assert_contains "incompatible version (1.10)" "incompatible_version"

echo "[smoke] metadata de extraccion (perm + mtime)"

src="${TMP_DIR}/src.txt"
printf 'metadata-check\n' > "${src}"
chmod 0750 "${src}"
touch -m -d "@1700000000" "${src}"

arc="${TMP_DIR}/meta.nz"
run_capture "${RECON_BIN}" a -y -cn -sp "${arc}" "${src}"
assert_rc 0 "add_meta"

out_root="${TMP_DIR}/out"
run_capture "${RECON_BIN}" x -y -o"${out_root}" "${arc}"
assert_rc 0 "extract_meta"

dst="${out_root}/src.txt"
if [[ ! -f "${dst}" ]]; then
  echo "FAIL(extract_meta): output file missing: ${dst}" >&2
  exit 1
fi

src_mode="$(stat -c '%a' "${src}")"
dst_mode="$(stat -c '%a' "${dst}")"
if [[ "${src_mode}" != "${dst_mode}" ]]; then
  echo "FAIL(metadata_mode): src=${src_mode} dst=${dst_mode}" >&2
  exit 1
fi

src_mtime="$(stat -c '%Y' "${src}")"
dst_mtime="$(stat -c '%Y' "${dst}")"
delta_mtime=$((src_mtime - dst_mtime))
if (( delta_mtime < 0 )); then
  delta_mtime=$(( -delta_mtime ))
fi
if (( delta_mtime > 1 )); then
  echo "FAIL(metadata_mtime): src=${src_mtime} dst=${dst_mtime} delta=${delta_mtime}" >&2
  exit 1
fi

if [[ -x "${RECON_ROOT}/build/test_lzpf_arith" ]]; then
  echo "[smoke] lzpf arith primitives"
  if ! "${RECON_ROOT}/build/test_lzpf_arith" >/dev/null; then
    echo "FAIL(lzpf_arith)" >&2
    exit 1
  fi
fi

echo "ok: smoke_suite"
