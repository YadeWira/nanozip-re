#!/usr/bin/env bash
# real_corpus_sweep.sh -- honest native-decode measurement over a REAL-WORLD corpus.
#
# native_only_v2.sh measures against a small synthetic corpus (random bytes, lorem
# ipsum, zeros, one source file). That corpus is useful as a regression tripwire but
# it systematically misses codec paths real files take: it never sets tt_flags & 0x02
# (found the hard way -- 4 of 7 fresh real-text failures traced to that one unported
# bit while the synthetic suite reported a clean 67/80), it has exactly one audio
# sample, and no HTML/PDF/office/executable content at all.
#
# This script sweeps a directory of real files instead. Point NZ_REAL_CORPUS at it
# (default /tmp/nzre_work/realcorpus, populated by hand from a file-format sample
# collection). Every file is compressed with the legacy binary, extracted twice
# (legacy = oracle, native with NZ_NO_BRIDGE=1 = under test) and byte-compared.
#
# Output: per-method pass/fail/skip, plus a per-failure log with the native
# binary's own decline reason so gaps can be triaged by root cause rather than
# by fixture name.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NATIVE="${RECON_ROOT}/bin/nz_recon"
LEGACY="${RECON_ROOT}/../linux32/nz"
[[ -n "${NZ_LEGACY_ORACLE:-}" ]] && LEGACY="${NZ_LEGACY_ORACLE}"
CORPUS="${NZ_REAL_CORPUS:-/tmp/nzre_work/realcorpus}"

if [[ ! -x "$NATIVE" ]]; then echo "FATAL: native bin missing ($NATIVE)"; exit 1; fi
if [[ ! -x "$LEGACY" ]]; then echo "FATAL: legacy bin missing ($LEGACY)"; exit 1; fi
if [[ ! -d "$CORPUS" ]]; then echo "FATAL: corpus dir missing ($CORPUS)"; exit 1; fi

WORK="$(mktemp -d /tmp/real_sweep.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# Methods to sweep. Override with NZ_METHODS="cd cD co" for a focused run.
read -r -a METHODS <<< "${NZ_METHODS:-cn cf cF cd cD co cO cc}"
# Cap per-file size (bytes) so a sweep stays interactive; 0 = no cap.
MAXSZ="${NZ_MAX_FIXTURE:-0}"

mapfile -t FIXTURES < <(find "$CORPUS" -type f | sort)
if [[ ${#FIXTURES[@]} -eq 0 ]]; then echo "FATAL: no files under $CORPUS"; exit 1; fi

declare -A M_PASS M_FAIL M_SKIP
for m in "${METHODS[@]}"; do M_PASS[$m]=0; M_FAIL[$m]=0; M_SKIP[$m]=0; done
fail_log="${WORK}/failures.txt"; : > "$fail_log"

echo "=== REAL-CORPUS NATIVE DECODE (NZ_NO_BRIDGE=1) ==="
echo "corpus: $CORPUS (${#FIXTURES[@]} files)"
echo "methods: ${METHODS[*]}"
echo

for fix in "${FIXTURES[@]}"; do
  name="$(basename "$fix")"
  fsz=$(stat -c%s "$fix" 2>/dev/null || echo 0)
  if [[ "$MAXSZ" != "0" && "$fsz" -gt "$MAXSZ" ]]; then continue; fi
  rel="${fix#$CORPUS/}"
  for m in "${METHODS[@]}"; do
    arc="${WORK}/a.nz"; rm -f "$arc"
    if ! "$LEGACY" a -y -"$m" "$arc" "$fix" >/dev/null 2>&1; then
      M_SKIP[$m]=$((M_SKIP[$m]+1)); continue
    fi
    od="${WORK}/o"; nd="${WORK}/n"
    rm -rf "$od" "$nd"; mkdir -p "$od" "$nd"
    (cd "$od" && "$LEGACY" x -y -fo "$arc") >/dev/null 2>&1
    nerr="${WORK}/nerr.txt"
    (cd "$nd" && NZ_NO_BRIDGE=1 "$NATIVE" x -y -fo -v "$arc") >"$nerr" 2>&1
    ofile=$(find "$od" -type f | head -1)
    nfile=$(find "$nd" -type f | head -1)
    if [[ -z "$ofile" ]]; then M_SKIP[$m]=$((M_SKIP[$m]+1)); continue; fi
    if [[ -n "$nfile" ]] && cmp -s "$ofile" "$nfile"; then
      M_PASS[$m]=$((M_PASS[$m]+1))
    else
      M_FAIL[$m]=$((M_FAIL[$m]+1))
      if [[ -z "$nfile" ]]; then
        # Surface the native binary's own stated reason -- that is what makes a
        # failure triageable by root cause instead of by fixture name.
        reason="$(grep -iE 'declin|not reconstruct|not recognized|unsupported|corrupt' "$nerr" | head -1)"
        [[ -z "$reason" ]] && reason="no native output"
      else
        reason="$(cmp -l "$ofile" "$nfile" 2>/dev/null | wc -l) bytes differ"
      fi
      printf '%-6s %-52s %s\n' "-$m" "$rel" "$reason" >> "$fail_log"
    fi
  done
done

printf "%-6s %6s %6s %6s\n" "method" "pass" "fail" "skip"
tot_p=0; tot_f=0
for m in "${METHODS[@]}"; do
  printf "%-6s %6d %6d %6d\n" "-$m" "${M_PASS[$m]}" "${M_FAIL[$m]}" "${M_SKIP[$m]}"
  tot_p=$((tot_p+M_PASS[$m])); tot_f=$((tot_f+M_FAIL[$m]))
done
echo "----------------------------------"
printf "%-6s %6d %6d\n" "TOTAL" "$tot_p" "$tot_f"

if [[ -s "$fail_log" ]]; then
  echo
  echo "=== failures grouped by reason ==="
  awk '{ $1=$1; r=""; for(i=3;i<=NF;i++) r=r" "$i; print substr(r,2) }' "$fail_log" \
    | sort | uniq -c | sort -rn
  echo
  echo "=== failure detail ==="
  cat "$fail_log"
fi

[[ $tot_f -eq 0 ]] && { echo; echo "ok: $tot_p byte-exact native decodes, zero bridge"; exit 0; }
echo; echo "INFO: $tot_f combinations require the bridge (not yet native)"; exit 1
