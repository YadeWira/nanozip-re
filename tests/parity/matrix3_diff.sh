#!/bin/bash
# matrix3_diff.sh <outdir> -- print only the cases whose out/err/exit/tree differ between orig and ours
O=$1; for d in "$O"/*/; do n=$(basename "$d"); [ -d "$d/orig" ] || continue; r=""
  for f in out err exit tree; do cmp -s "$d/orig/$f" "$d/ours/$f" || r="$r $f"; done
  [ -n "$r" ] && echo "$n:$r"; done
