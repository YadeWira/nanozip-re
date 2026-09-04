#!/usr/bin/env bash
# compare.sh -- compare a matrix run's per-case output between the two binaries,
# normalising the differences that are inherent rather than defects:
#   * the banner's platform word (Linux32 for the original here, Linux64 for a
#     64-bit build of this port) and the host line (CPU, MHz, free memory)
#   * timings, rates and the progress figures they drive (quirk: the redraw
#     count depends on how many whole seconds the decode crosses)
#   * the temporary directory a case ran in
#
# usage: tests/parity/compare.sh <matrix outdir>   (after matrix.sh/matrix2.sh/matrix3.sh)
set -u
OUT=${1:?usage: compare.sh <matrix outdir>}
norm() {
  tr '\r' '\n' < "$1" 2>/dev/null |
    sed -E -e 's/(NanoZip [0-9.]+ alpha\/)(Linux|Win)(32|64)/\1<PLATFORM>/' \
           -e 's/^[A-Za-z].*MHz\|.*MB$/<HOSTLINE>/' \
           -e 's/[0-9]+([.,][0-9]+)?s,/<T>s,/g' \
           -e 's/[0-9]+ (B|KB|MB|GB)\/s/<RATE>/g' \
           -e 's/[0-9]+ (B|KB|MB|GB)([ |]|$)/<SIZE>\2/g' \
           -e 's/\/tmp\/[A-Za-z0-9_.]+/<DIR>/g'
}
# A case whose only differing lines are progress figures or the IO-out clause is
# counted as "timing": how many "<N> MB" figures fit on the status line depends on
# how many whole seconds the decode crosses, and the original's footer adds an
# IO-out figure for the copy-out it overlaps with the decode. Both are documented
# as not reproduced (docs/ORIGINAL_QUIRKS.md).
same=0; timing=0; diffs=0
for c in "$OUT"/*/; do
  c=${c%/}; [ -d "$c/orig" ] || continue
  bad=""; only_timing=1
  for f in out err exit; do
    [ -f "$c/orig/$f" ] || continue
    if ! diff -q <(norm "$c/orig/$f") <(norm "$c/ours/$f") >/dev/null; then
      bad="$bad $f"
      if diff <(norm "$c/orig/$f") <(norm "$c/ours/$f") | grep -E '^[<>]' |
         grep -qvE '<SIZE>|IO-out|^[<>] *$'; then only_timing=0; fi
    fi
  done
  if [ -z "$bad" ]; then same=$((same+1))
  elif [ $only_timing = 1 ]; then timing=$((timing+1)); echo "timing $(basename "$c"):$bad"
  else diffs=$((diffs+1)); echo "DIFF $(basename "$c"):$bad"
  fi
done
echo "compare: $same identical, $timing timing-only, $diffs real differences (of $((same+timing+diffs)) cases)"
