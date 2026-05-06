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

TMP_DIR="$(mktemp -d /tmp/nz_cov.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/in" "${TMP_DIR}/out"

printf 'AAAAABBBBBCCCCCDDDDDEEEEE\n' > "${TMP_DIR}/in/a.txt"
# Deterministic 8KB "random-ish" fixture: AES-CTR of zero bytes with a fixed key.
# Using openssl avoids a urandom source of flakiness in the coverage metrics.
set +o pipefail
openssl enc -aes-256-ctr -K 00000000000000000000000000000000000000000000000000000000deadbeef \
  -iv 00000000000000000000000000000000 -in /dev/zero 2>/dev/null \
  | head -c 8192 > "${TMP_DIR}/in/rand.bin"
set -o pipefail
cat "${TMP_DIR}/in/a.txt" "${TMP_DIR}/in/rand.bin" > "${TMP_DIR}/in/mix.bin"

methods=(cn cf cF cd cD co cO cc)
methods_ok=0
methods_total=0
native_methods=0
native_strict_methods=0
bridge_methods=0
compat_methods=0
encode_ok=0
encode_native_no_compat=0
encode_native_no_compat_bridge=0

echo "method|list_rc|test_rc|x_rc|list_compat|test_compat|x_compat|x_bridge|x_ok"
for m in "${methods[@]}"; do
  methods_total=$((methods_total + 1))
  arc="${TMP_DIR}/${m}.nz"
  "${LEGACY_BIN}" a -y -"${m}" "${arc}" "${TMP_DIR}/in/a.txt" "${TMP_DIR}/in/mix.bin" >/dev/null 2>&1

  set +e
  lout="$("${RECON_BIN}" l "${arc}" 2>&1)"
  lrc=$?
  tout="$("${RECON_BIN}" t "${arc}" 2>&1)"
  trc=$?
  set -e
  mkdir -p "${TMP_DIR}/out/${m}"
  set +e
  # -v so both [compat] and [bridge] diagnostics are emitted for honest bucketing
  xout="$("${RECON_BIN}" x -y -v -o"${TMP_DIR}/out/${m}" "${arc}" 2>&1)"
  xrc=$?
  set -e

  xa="$(find "${TMP_DIR}/out/${m}" -type f -name a.txt | head -n1 || true)"
  xb="$(find "${TMP_DIR}/out/${m}" -type f -name mix.bin | head -n1 || true)"
  x_ok=1
  [[ -n "${xa}" ]] && cmp -s "${TMP_DIR}/in/a.txt" "${xa}" || x_ok=0
  [[ -n "${xb}" ]] && cmp -s "${TMP_DIR}/in/mix.bin" "${xb}" || x_ok=0

  list_compat=0
  test_compat=0
  x_compat=0
  x_bridge=0
  grep -q "\\[compat\\]" <<<"${lout}" && list_compat=1 || true
  grep -q "\\[compat\\]" <<<"${tout}" && test_compat=1 || true
  grep -q "\\[compat\\]" <<<"${xout}" && x_compat=1 || true
  grep -q "\\[bridge\\]" <<<"${xout}" && x_bridge=1 || true

  echo "${m}|${lrc}|${trc}|${xrc}|${list_compat}|${test_compat}|${x_compat}|${x_bridge}|${x_ok}"

  if [[ ${lrc} -eq 0 && ${trc} -eq 0 && ${xrc} -eq 0 && ${x_ok} -eq 1 ]]; then
    methods_ok=$((methods_ok + 1))
  fi
  if [[ ${list_compat} -eq 0 && ${test_compat} -eq 0 && ${x_compat} -eq 0 ]]; then
    native_methods=$((native_methods + 1))
  fi
  # strict native = no compat AND no bridge on extract; list/test paths don't use bridge
  if [[ ${list_compat} -eq 0 && ${test_compat} -eq 0 && ${x_compat} -eq 0 && ${x_bridge} -eq 0 ]]; then
    native_strict_methods=$((native_strict_methods + 1))
  fi
  if [[ ${x_compat} -eq 1 ]]; then
    compat_methods=$((compat_methods + 1))
  elif [[ ${x_bridge} -eq 1 ]]; then
    bridge_methods=$((bridge_methods + 1))
  fi
done

usage_pct=$((methods_ok * 100 / methods_total))
native_pct=$((native_methods * 100 / methods_total))
native_strict_pct=$((native_strict_methods * 100 / methods_total))
bridge_pct=$((bridge_methods * 100 / methods_total))
compat_pct=$((compat_methods * 100 / methods_total))
echo
echo "methods_ok=${methods_ok}/${methods_total}"
echo "usage_real_percent=${usage_pct}"
echo "native_only_percent=${native_pct}"
echo "native_strict_percent=${native_strict_pct}"
echo "bridge_percent=${bridge_pct}"
echo "compat_percent=${compat_pct}"

echo
echo "encode_method|add_rc|sim_rc|t_rc|x_rc|add_compat|add_bridge|sim_compat|sim_bridge|x_ok"
for m in "${methods[@]}"; do
  enc_arc="${TMP_DIR}/enc_${m}.nz"
  set +e
  add_out="$("${RECON_BIN}" a -y -"${m}" "${enc_arc}" "${TMP_DIR}/in/a.txt" "${TMP_DIR}/in/mix.bin" 2>&1)"
  add_rc=$?
  sim_out="$("${RECON_BIN}" s -"${m}" "${TMP_DIR}/enc_${m}_sim.nz" "${TMP_DIR}/in/a.txt" "${TMP_DIR}/in/mix.bin" 2>&1)"
  sim_rc=$?
  set -e

  add_compat=0
  add_bridge=0
  sim_compat=0
  sim_bridge=0
  grep -q "\\[compat\\]" <<<"${add_out}" && add_compat=1 || true
  grep -q "\\[bridge\\]" <<<"${add_out}" && add_bridge=1 || true
  grep -q "\\[compat\\]" <<<"${sim_out}" && sim_compat=1 || true
  grep -q "\\[bridge\\]" <<<"${sim_out}" && sim_bridge=1 || true

  t_rc=1
  x_rc=1
  x_ok=0
  if [[ ${add_rc} -eq 0 && -f "${enc_arc}" ]]; then
    set +e
    t_out="$("${RECON_BIN}" t "${enc_arc}" 2>&1)"
    t_rc=$?
    set -e
    mkdir -p "${TMP_DIR}/enc_out/${m}"
    set +e
    x_out="$("${RECON_BIN}" x -y -o"${TMP_DIR}/enc_out/${m}" "${enc_arc}" 2>&1)"
    x_rc=$?
    set -e
    xa="$(find "${TMP_DIR}/enc_out/${m}" -type f -name a.txt | head -n1 || true)"
    xb="$(find "${TMP_DIR}/enc_out/${m}" -type f -name mix.bin | head -n1 || true)"
    x_ok=1
    [[ -n "${xa}" ]] && cmp -s "${TMP_DIR}/in/a.txt" "${xa}" || x_ok=0
    [[ -n "${xb}" ]] && cmp -s "${TMP_DIR}/in/mix.bin" "${xb}" || x_ok=0
  fi

  echo "${m}|${add_rc}|${sim_rc}|${t_rc}|${x_rc}|${add_compat}|${add_bridge}|${sim_compat}|${sim_bridge}|${x_ok}"

  if [[ ${add_rc} -eq 0 && ${sim_rc} -eq 0 && ${t_rc} -eq 0 && ${x_rc} -eq 0 && ${x_ok} -eq 1 ]]; then
    encode_ok=$((encode_ok + 1))
  fi
  if [[ ${add_compat} -eq 0 && ${sim_compat} -eq 0 ]]; then
    encode_native_no_compat=$((encode_native_no_compat + 1))
  fi
  if [[ ${add_compat} -eq 0 && ${sim_compat} -eq 0 && ${add_bridge} -eq 0 && ${sim_bridge} -eq 0 ]]; then
    encode_native_no_compat_bridge=$((encode_native_no_compat_bridge + 1))
  fi
done

encode_pct=$((encode_ok * 100 / methods_total))
encode_native_no_compat_pct=$((encode_native_no_compat * 100 / methods_total))
encode_native_no_compat_bridge_pct=$((encode_native_no_compat_bridge * 100 / methods_total))
echo
echo "encode_ok=${encode_ok}/${methods_total}"
echo "encode_real_percent=${encode_pct}"
echo "encode_native_no_compat_percent=${encode_native_no_compat_pct}"
echo "encode_native_no_compat_bridge_percent=${encode_native_no_compat_bridge_pct}"
