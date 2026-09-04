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
# (default /tmp/nzre_work/realcorpus; tests/corpus_select.sh builds a stratified one
# from a file-format sample collection). Every file is compressed with the legacy
# binary, extracted twice (legacy = oracle, native = under test) and byte-compared.
#
# Output: per-method pass/fail/skip, plus a per-failure log with the native
# binary's own decline reason so gaps can be triaged by root cause rather than
# by fixture name.
#
# Environment (all optional):
#   NZ_REAL_CORPUS=dir     corpus root (files, or directories with NZ_DIR_MODE=1)
#   NZ_METHODS="cd cD co"  methods to sweep (default: all eight)
#   NZ_MAX_FIXTURE=bytes   skip fixtures larger than this (0 = no cap)
#   NZ_RESULTS_TSV=path    append "relpath<TAB>method<TAB>PASS|FAIL|SKIP<TAB>reason" per pair and
#                          SKIP pairs already present in the file (resumable; delete FAIL lines to
#                          rerun them). Constructs seen by the native decoder (NZ_TRACE_CONSTRUCTS)
#                          go to <path>.constructs as "relpath<TAB>method<TAB>key=value".
#   NZ_SHARD=i/N           take only fixtures with (index mod N) == i (0-based) -- run N copies
#   NZ_DIR_MODE=1          fixtures are DIRECTORIES: compressed with `a -y -r`, whole trees compared
#                          (contents via diff -r, plus mode/mtime/size listing)
#   NZ_TIMEOUT=secs        per-invocation timeout for both binaries (default 300)
#   NZ_LEGACY_ORACLE=path  the original nz binary (default ../linux32/nz)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NATIVE="${NZ_RECON:-${RECON_ROOT}/bin/nz_recon}"   # NZ_RECON pins a frozen copy: never
# rebuild bin/nz_recon while a sweep runs, or its verdicts mix two binaries.
LEGACY="${RECON_ROOT}/../linux32/nz"
[[ -n "${NZ_LEGACY_ORACLE:-}" ]] && LEGACY="${NZ_LEGACY_ORACLE}"
CORPUS="${NZ_REAL_CORPUS:-/tmp/nzre_work/realcorpus}"
RESULTS="${NZ_RESULTS_TSV:-}"
DIRMODE="${NZ_DIR_MODE:-0}"
TMO="${NZ_TIMEOUT:-300}"

if [[ ! -x "$NATIVE" ]]; then echo "FATAL: native bin missing ($NATIVE)"; exit 1; fi
if [[ ! -x "$LEGACY" ]]; then echo "FATAL: legacy bin missing ($LEGACY)"; exit 1; fi
if [[ ! -d "$CORPUS" ]]; then echo "FATAL: corpus dir missing ($CORPUS)"; exit 1; fi

# The 32-bit original cannot open files under /tmp/claude-*; keep the scratch in /tmp/nzre_*.
WORK="$(mktemp -d /tmp/nzre_sweep.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

read -r -a METHODS <<< "${NZ_METHODS:-cn cf cF cd cD co cO cc}"
MAXSZ="${NZ_MAX_FIXTURE:-0}"

if [[ "$DIRMODE" == "1" ]]; then
  mapfile -t FIXTURES < <(find "$CORPUS" -mindepth 1 -maxdepth 1 -type d | sort)
else
  mapfile -t FIXTURES < <(find "$CORPUS" -type f ! -name 'MANIFEST.tsv' | sort)
fi
if [[ ${#FIXTURES[@]} -eq 0 ]]; then echo "FATAL: no fixtures under $CORPUS"; exit 1; fi

# Sharding: keep fixtures whose 0-based index is congruent to i modulo N.
if [[ -n "${NZ_SHARD:-}" ]]; then
  si="${NZ_SHARD%/*}"; sn="${NZ_SHARD#*/}"
  mapfile -t FIXTURES < <(printf '%s\n' "${FIXTURES[@]}" | awk -v i="$si" -v n="$sn" '(NR-1) % n == i')
fi

# Resume: pairs already recorded in the results file are not rerun.
declare -A DONE
if [[ -n "$RESULTS" && -s "$RESULTS" ]]; then
  while IFS=$'\t' read -r r m s _; do DONE["$r|$m"]=$s; done < "$RESULTS"
fi
record() {  # record <rel> <method> <status> <reason>
  [[ -n "$RESULTS" ]] && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"
}
record_constructs() {  # record_constructs <rel> <method> <native stderr file>
  [[ -n "$RESULTS" ]] || return 0
  grep -a '^\[construct\] ' "$3" 2>/dev/null | sed "s/^\[construct\] //" | sort -u \
    | awk -v r="$1" -v m="$2" '{ printf "%s\t%s\t%s\n", r, m, $0 }' >> "${RESULTS}.constructs"
}

declare -A M_PASS M_FAIL M_SKIP
for m in "${METHODS[@]}"; do M_PASS[$m]=0; M_FAIL[$m]=0; M_SKIP[$m]=0; done
fail_log="${WORK}/failures.txt"; : > "$fail_log"

echo "=== REAL-CORPUS NATIVE DECODE ==="
echo "corpus: $CORPUS (${#FIXTURES[@]} fixtures${NZ_SHARD:+, shard $NZ_SHARD}${DIRMODE:+, dir mode})"
echo "methods: ${METHODS[*]}"
echo

# tree listing: mode, mtime, size, path -- what multifile_v2.sh compares as well
tree_of() { (cd "$1" && find . -mindepth 1 -printf '%m %TY-%Tm-%Td %TH:%TM:%TS %s %y %p\n' | sort); }

for fix in "${FIXTURES[@]}"; do
  rel="${fix#$CORPUS/}"
  if [[ "$DIRMODE" != "1" ]]; then
    fsz=$(stat -c%s "$fix" 2>/dev/null || echo 0)
    if [[ "$MAXSZ" != "0" && "$fsz" -gt "$MAXSZ" ]]; then continue; fi
  fi
  for m in "${METHODS[@]}"; do
    [[ -n "${DONE[$rel|$m]:-}" ]] && continue
    arc="${WORK}/a.nz"; rm -f "$arc"
    if [[ "$DIRMODE" == "1" ]]; then
      (cd "$(dirname "$fix")" && timeout "$TMO" "$LEGACY" a -y -r -"$m" "$arc" "$(basename "$fix")") >/dev/null 2>&1
    else
      timeout "$TMO" "$LEGACY" a -y -"$m" "$arc" "$fix" >/dev/null 2>&1
    fi
    if [[ ! -s "$arc" ]]; then
      M_SKIP[$m]=$((M_SKIP[$m]+1)); record "$rel" "$m" SKIP "legacy a failed"; continue
    fi
    od="${WORK}/o"; nd="${WORK}/n"
    rm -rf "$od" "$nd"; mkdir -p "$od" "$nd"
    (cd "$od" && timeout "$TMO" "$LEGACY" x -y -fo "$arc") >/dev/null 2>&1
    nerr="${WORK}/nerr.txt"
    (cd "$nd" && NZ_TRACE_CONSTRUCTS=1 timeout "$TMO" "$NATIVE" x -y -fo -v "$arc") >"$nerr" 2>&1
    record_constructs "$rel" "$m" "$nerr"
    if [[ -z "$(find "$od" -type f | head -1)" ]]; then
      M_SKIP[$m]=$((M_SKIP[$m]+1)); record "$rel" "$m" SKIP "legacy x wrote nothing"; continue
    fi
    if [[ "$DIRMODE" == "1" ]]; then
      same=0
      if diff -rq "$od" "$nd" >/dev/null 2>&1 && diff -q <(tree_of "$od") <(tree_of "$nd") >/dev/null 2>&1; then same=1; fi
      ofile=x; nfile="$(find "$nd" -type f | head -1)"
    else
      ofile=$(find "$od" -type f | head -1)
      nfile=$(find "$nd" -type f | head -1)
      same=0; [[ -n "$nfile" ]] && cmp -s "$ofile" "$nfile" && same=1
    fi
    if [[ $same -eq 1 ]]; then
      M_PASS[$m]=$((M_PASS[$m]+1)); record "$rel" "$m" PASS ""
    else
      M_FAIL[$m]=$((M_FAIL[$m]+1))
      if [[ -z "$nfile" ]]; then
        # Surface the native binary's own stated reason -- that is what makes a
        # failure triageable by root cause instead of by fixture name.
        reason="$(grep -a -iE 'declin|not reconstruct|not recognized|unsupported|corrupt' "$nerr" | head -1 | tr '\r' ' ' | sed 's/  */ /g')"
        [[ -z "$reason" ]] && reason="no native output"
      elif [[ "$DIRMODE" == "1" ]]; then
        reason="tree differs: $(diff -rq "$od" "$nd" 2>/dev/null | head -1 | cut -c1-80)"
      else
        reason="$(cmp -l "$ofile" "$nfile" 2>/dev/null | wc -l) bytes differ"
      fi
      printf '%-6s %-52s %s\n' "-$m" "$rel" "$reason" >> "$fail_log"
      record "$rel" "$m" FAIL "$reason"
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
echo; echo "INFO: $tot_f combinations are not native byte-exact"; exit 1
