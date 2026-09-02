#!/usr/bin/env bash
# native_only_v2.sh — HONEST native-decode measurement (HANDOFF §12, Phase 8.3).
#
# The original native_only.sh is a false positive: it unsets NZ_LEGACY_BACKEND
# but the native binary still discovers work/linux64/nz via relative-path search
# (and /usr/bin/nz via $PATH on machines that have it), so the extract bridge
# fires silently and every combo "passes" without proving native decode.
#
# This version sets NZ_NO_BRIDGE=1, which makes FindLegacyBackend* return {} and
# turns a missing native path into a hard error. The legacy binary is used ONLY
# to (a) create the test archives and (b) produce the oracle output. The native
# binary must reproduce that output with NO legacy fallback. Per-method results
# show exactly which codecs are truly native.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NATIVE="${RECON_ROOT}/bin/nz_recon"
# linux32/nz is the primary RE reference and the only legacy binary that runs on
# modern hosts (linux64/nz, the 2011 static x86-64 build, segfaults here).
LEGACY="${RECON_ROOT}/../linux32/nz"
[[ -n "${NZ_LEGACY_ORACLE:-}" ]] && LEGACY="${NZ_LEGACY_ORACLE}"

if [[ ! -x "$NATIVE" ]]; then echo "FATAL: native bin missing ($NATIVE)"; exit 1; fi
if [[ ! -x "$LEGACY" ]]; then echo "FATAL: legacy bin missing ($LEGACY)"; exit 1; fi

WORK="$(mktemp -d /tmp/native_only_v2.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/in"

FIXTURES=()
for sz in 1024 4096 65536 262144; do
  head -c $sz /dev/urandom > "${WORK}/in/rand_${sz}.bin"; FIXTURES+=("rand_${sz}.bin")
done
{ for i in $(seq 1 800); do echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit."; done; } > "${WORK}/in/text_50k.txt"; FIXTURES+=("text_50k.txt")
{ yes "the quick brown fox jumps over the lazy dog " || true; } | head -c 102400 > "${WORK}/in/repeat_100k.txt"; FIXTURES+=("repeat_100k.txt")
head -c 102400 /dev/zero > "${WORK}/in/zeros_100k.bin"; FIXTURES+=("zeros_100k.bin")
cp "${RECON_ROOT}/src/sfx_archive.cpp" "${WORK}/in/source.cpp"; FIXTURES+=("source.cpp")
[[ -f "${RECON_ROOT}/tests/fixtures/cm/abcd3.txt" ]] && { cp "${RECON_ROOT}/tests/fixtures/cm/abcd3.txt" "${WORK}/in/"; FIXTURES+=("abcd3.txt"); }
[[ -f "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav" ]] && { cp "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav" "${WORK}/in/"; FIXTURES+=("stereo_lms.wav"); }

# Audio + text + high-entropy + audio + text, in one file. Every fixture above is a
# SINGLE kind of data, and that is exactly what they cannot cover: the -cd/-cD chunk
# pipeline carries state across chunk boundaries, and the shapes that carry it -- a
# 0xc prefilter sub-chunk, and a FULL stored chunk (header size field == 0) -- only
# ever appear directly before a MODELLED chunk when the input changes character
# mid-file. Two such cross-chunk state bugs were live while this suite reported -cd
# and -cD at a clean 10/10; this fixture fails on either of them.
# openssl supplies the high-entropy block because it is DETERMINISTIC -- with
# /dev/urandom the chunk layout, and so the coverage, would vary run to run.
if [[ -f "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav" ]] && command -v openssl >/dev/null 2>&1; then
  { cat "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav"
    for i in $(seq 1 600); do echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit."; done
    head -c 40960 /dev/zero | openssl enc -aes-256-ctr -pass pass:nzre-mixed -nosalt 2>/dev/null
    cat "${RECON_ROOT}/tests/fixtures/lzpf/stereo_lms.wav"
    for i in $(seq 1 600); do echo "the quick brown fox jumps over the lazy dog"; done
  } > "${WORK}/in/mixed_audio_text_229k.bin"
  FIXTURES+=("mixed_audio_text_229k.bin")
fi

# A 1.1 MB file mixing high-entropy and compressible data. Every fixture above is
# small, and size is exactly what this one is for: only at this scale does the
# encoder pick a BWT block WITH its entropy layer and leave one of the block's
# 256 buckets large and incompressible, which it then STORES VERBATIM (the
# bucket table writes in==0 to say so). Reading that as a literal zero left the
# bucket's bytes unaccounted for and the next bucket parsed garbage -- `-co` (the
# DEFAULT compressor) and `-cO` declined on an ordinary mixed file, and nothing
# in this suite or the 60-file real corpus was big enough to notice.
# openssl keeps it DETERMINISTIC; /dev/urandom would move the block boundaries
# run to run.
if command -v openssl >/dev/null 2>&1; then
  { head -c 1048576 /dev/zero | openssl enc -aes-256-ctr -pass pass:nzre-bwt -nosalt 2>/dev/null
    for i in $(seq 1 3000); do echo "trailer line $i, compressible, for the bwt bucket case"; done
  } > "${WORK}/in/mixed_entropy_1m.bin"
  FIXTURES+=("mixed_entropy_1m.bin")
fi

METHODS=(cn cf cF cd cD co cO cc)

declare -A M_PASS M_FAIL M_SKIP
for m in "${METHODS[@]}"; do M_PASS[$m]=0; M_FAIL[$m]=0; M_SKIP[$m]=0; done
fail_log=""

for fix in "${FIXTURES[@]}"; do
  for m in "${METHODS[@]}"; do
    arc="${WORK}/arc_${fix}_${m}.nz"; rm -f "$arc"
    if ! "$LEGACY" a -y -"$m" "$arc" "${WORK}/in/$fix" >/dev/null 2>&1; then
      M_SKIP[$m]=$((M_SKIP[$m]+1)); continue
    fi
    oracle_dir="${WORK}/oracle_${fix}_${m}"; native_dir="${WORK}/native_${fix}_${m}"
    rm -rf "$oracle_dir" "$native_dir"; mkdir -p "$oracle_dir" "$native_dir"

    (cd "$oracle_dir" && "$LEGACY" x -y -fo "$arc") >/dev/null 2>&1
    # Native extraction with NO bridge allowed.
    (cd "$native_dir" && NZ_NO_BRIDGE=1 "$NATIVE" x -y -fo "$arc") >/dev/null 2>&1

    oracle_file=$(find "$oracle_dir" -type f | head -1)
    native_file=$(find "$native_dir" -type f | head -1)
    if [[ -z "$oracle_file" ]]; then M_SKIP[$m]=$((M_SKIP[$m]+1)); continue; fi
    if [[ -n "$native_file" ]] && cmp -s "$oracle_file" "$native_file"; then
      M_PASS[$m]=$((M_PASS[$m]+1))
    else
      reason="no native output"
      [[ -n "$native_file" ]] && reason="$(cmp -l "$oracle_file" "$native_file" 2>/dev/null | wc -l) bytes differ"
      fail_log="${fail_log}FAIL: ${fix} / -${m} (${reason})\n"
      M_FAIL[$m]=$((M_FAIL[$m]+1))
    fi
  done
done

echo "=== NATIVE-ONLY DECODE (NZ_NO_BRIDGE=1, no legacy fallback) ==="
printf "%-6s %6s %6s %6s\n" "method" "pass" "fail" "skip"
tot_p=0; tot_f=0
for m in "${METHODS[@]}"; do
  printf "%-6s %6d %6d %6d\n" "-$m" "${M_PASS[$m]}" "${M_FAIL[$m]}" "${M_SKIP[$m]}"
  tot_p=$((tot_p+M_PASS[$m])); tot_f=$((tot_f+M_FAIL[$m]))
done
echo "----------------------------------"
printf "%-6s %6d %6d\n" "TOTAL" "$tot_p" "$tot_f"
if [[ -n "$fail_log" ]]; then echo; printf "%b" "$fail_log" | head -40; fi
[[ $tot_f -eq 0 ]] && { echo; echo "ok: $tot_p byte-exact native decodes, zero bridge"; exit 0; }
echo; echo "INFO: $tot_f combinations require the bridge (not yet native)"; exit 1
