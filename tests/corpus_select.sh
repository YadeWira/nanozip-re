#!/usr/bin/env bash
# corpus_select.sh -- build the stratified real-file corpus for real_corpus_sweep.sh.
#
# Copies (never touches in place) a sample of /mnt/OSR_D3/fileFormatSamples into
# $OUT/<category>/ and writes $OUT/MANIFEST.tsv (relpath, size, category, ext).
#
#   priority set, all of them : image/*.{pgm,ppm,pbm,tga,tif,tiff,bmp}, executable/*,
#                               audio+music *.wav *.aif*          (image model, exe filter, audio)
#   bulk, 40 KB .. 3 MB       : per-category quota, evenly strided, max 40 per extension
#   small, 4 KB .. 40 KB      : 15 per category                    (header / edge paths)
#   large, 3 MB .. 20 MB      : 4 per category                     (forces the -pN parallel split)
#
# usage: corpus_select.sh [OUT=/tmp/nzre_corpus] [SRC=/mnt/OSR_D3/fileFormatSamples/fileFormatSamples]
# env:   NZ_BULK_SCALE=0.5   scales every bulk quota (quick runs)
set -uo pipefail
OUT=${1:-/tmp/nzre_corpus}
SRC=${2:-/mnt/OSR_D3/fileFormatSamples/fileFormatSamples}
SCALE=${NZ_BULK_SCALE:-1}
[[ -d $SRC ]] || { echo "corpus source missing: $SRC" >&2; exit 1; }
case $OUT in /tmp/nzre_*|/tmp/nzre_*/*) ;; *) echo "refusing OUT outside /tmp/nzre_*: $OUT" >&2; exit 1;; esac
rm -rf "$OUT"; mkdir -p "$OUT"
MAN=$OUT/MANIFEST.tsv; : > "$MAN"

declare -A BULK=( [image]=500 [text]=500 [document]=300 [archive]=200 [audio]=250 [music]=150
                  [video]=150 [font]=150 [poly]=100 [other]=150 )
CATS="image text document archive audio music video font poly other executable"

# pick <n> files evenly from stdin (sorted list), copy them, tag with <band>
pick() {  # pick <cat> <band> <n>
  local cat=$1 band=$2 n=$3 list; list=$(sort)
  local total; total=$(printf '%s\n' "$list" | grep -c . || true)
  [[ $total -eq 0 || $n -eq 0 ]] && return 0
  local k=$(( total / n )); [[ $k -lt 1 ]] && k=1
  printf '%s\n' "$list" | awk -v k="$k" 'NR % k == 1 || k == 1' | head -n "$n" | while IFS= read -r f; do
    copy_one "$cat" "$band" "$f"
  done
}
copy_one() {  # copy_one <cat> <band> <path>
  local cat=$1 band=$2 f=$3 base ext dst
  base=$(basename "$f"); ext=${base##*.}; [[ $ext == "$base" ]] && ext=none; ext=${ext,,}
  dst="$OUT/$cat/$base"
  # keep names unique per category without renaming beyond a numeric suffix
  local i=1; while [[ -e $dst ]]; do dst="$OUT/$cat/${i}_$base"; i=$((i+1)); done
  mkdir -p "$OUT/$cat"; cp -- "$f" "$dst" || return 0
  printf '%s\t%s\t%s\t%s\t%s\n' "${dst#$OUT/}" "$(stat -c %s "$dst")" "$cat" "$ext" "$band" >> "$MAN"
}
# cap at 40 files per extension for the bulk band (priority set is exempt)
cap_ext() { awk -F/ '{ n=split($NF,p,"."); e=(n>1)?tolower(p[n]):"none"; c[e]++; if (c[e]<=40) print }'; }

echo "priority sets"
find "$SRC/image" -type f -size +4k -size -20480k \( -iname '*.pgm' -o -iname '*.ppm' -o -iname '*.pbm' \
     -o -iname '*.tga' -o -iname '*.tif' -o -iname '*.tiff' -o -iname '*.bmp' \) 2>/dev/null | sort \
  | while IFS= read -r f; do copy_one image priority "$f"; done
find "$SRC/executable" -type f -size +4k -size -20480k 2>/dev/null | sort \
  | while IFS= read -r f; do copy_one executable priority "$f"; done
for cat in audio music; do
  find "$SRC/$cat" -type f -size +4k -size -20480k \( -iname '*.wav' -o -iname '*.aif' -o -iname '*.aiff' \) 2>/dev/null | sort \
    | while IFS= read -r f; do copy_one "$cat" priority "$f"; done
done

for cat in $CATS; do
  [[ -d $SRC/$cat ]] || continue
  q=${BULK[$cat]:-0}; q=$(awk -v q="$q" -v s="$SCALE" 'BEGIN{printf "%d", q*s}')
  echo "$cat: bulk $q, small 15, large 4"
  find "$SRC/$cat" -type f -size +40k -size -3072k 2>/dev/null | sort | cap_ext | pick "$cat" bulk "$q"
  find "$SRC/$cat" -type f -size +4k  -size -40k    2>/dev/null | pick "$cat" small 15
  find "$SRC/$cat" -type f -size +3072k -size -20480k 2>/dev/null | pick "$cat" large 4
done
echo "files: $(wc -l < "$MAN")  bytes: $(awk -F'\t' '{s+=$2} END{print s}' "$MAN")  manifest: $MAN"
