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
           -e 's/\/tmp\/[A-Za-z0-9_.]+/<DIR>/g' \
           -e 's/^(usage: |e\.g\. )[^ ]+/\1<NZ>/'
}
# The status line is rewritten in place: every such write ends in backspaces, and
# the clear that precedes one is a run of spaces. How many of them a run emits
# depends on how many whole seconds the decode crosses, and the original's footer
# adds an IO-out clause for the copy-out it overlaps with the decode -- all of it
# documented as not reproduced. Dropping exactly those lines leaves the messages,
# which is what a comparison should be about.
msgs() {
  # The matrices already normalise their own timings, so match the clause, not
  # its placeholders: keep "IO-in: ...." and drop the "IO-out: ..." the original
  # adds for the copy-out it overlaps with the decode.
  # The "Compressor #k" lines come out in the order the workers first tick, which
  # is the scheduler's (quirk 43: six runs of the original on the same parallel
  # archive gave four different orders), so sort that block before comparing.
  norm "$1" | grep -v $'\010' | grep -vE '^ *$' | sed -E 's/^(IO-in:[^.]*\.).*/\1/' |
    awk '/^Compressor #/ { b[++n] = $0; next }
         { flush() ; print }
         END { flush() }
         function flush(   i, j, t) {
           for (i = 2; i <= n; i++) { t = b[i]; for (j = i - 1; j >= 1 && b[j] > t; j--) b[j+1] = b[j]; b[j+1] = t }
           for (i = 1; i <= n; i++) print b[i]
           n = 0
         }'
}

same=0; timing=0; diffs=0
for c in "$OUT"/*/; do
  c=${c%/}; [ -d "$c/orig" ] || continue
  bad=""; only_timing=1
  for f in out err exit; do
    [ -f "$c/orig/$f" ] || continue
    if ! diff -q <(norm "$c/orig/$f") <(norm "$c/ours/$f") >/dev/null; then
      bad="$bad $f"
      if ! diff -q <(msgs "$c/orig/$f") <(msgs "$c/ours/$f") >/dev/null; then only_timing=0; fi
    fi
  done
  if [ -z "$bad" ]; then same=$((same+1))
  elif [ $only_timing = 1 ]; then timing=$((timing+1)); echo "timing $(basename "$c"):$bad"
  else diffs=$((diffs+1)); echo "DIFF $(basename "$c"):$bad"
  fi
done
echo "compare: $same identical, $timing timing-only, $diffs real differences (of $((same+timing+diffs)) cases)"
