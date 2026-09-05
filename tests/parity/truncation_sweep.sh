#!/bin/bash
# truncation_sweep.sh [outfile] -- the original vs ours on m_<codec>.nz of the verification package cut
# at 19 points per codec: one byte before the first data record's payload, at it, +4, +5 (the
# reader/decoder boundary, quirk 51) and at 15 percentages of the payload. Prints the corruption line
# of `t` from both and counts the identical ones. Every line starting with X is a difference.
# Usage: NZ_ORIG (default ../linux32/nz), NZ_RECON (default bin/nz_recon), NZ_PKG (default the package).
OUT=${1:-/tmp/nzre_trunc_sweep.txt}; : > "$OUT"
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz_recon}
PKG=${NZ_PKG:-$HOME/.cache/nzre_tools/release_verify_pkg/arc}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
W=$(mktemp -d /tmp/nzre_trsw.XXXXXX); trap 'rm -rf "$W"' EXIT
first_payload() {  # offset of the first main-stream type-0 record's payload
python3 - "$1" <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
def rv(p):
    cur=b[p]; p+=1; v=cur&0x7f; sh=7
    while cur&0x80:
        cur=b[p]; p+=1; v += ((cur&0x7f)+1)<<sh; sh+=7
    return v,p
p=b.index(b'alpha')+5
while p<len(b):
    r,p2=rv(p); ct=r&0xf; sz=r>>4; sid=0; p3=p2
    if ct==15:
        ext=b[p3]; p3+=1
        if ext>=0xf8: ext=(ext&7)+8*b[p3]+248; p3+=1
        ct=ext&0xf; sid=ext>>4
        if sid==0: ct+=15
    if ct==0 and sz>0 and sid==0: print(p3); sys.exit(0)
    p=p3+sz
print(-1)
PY
}
report() { tr '\r' '\n' | grep -E "corrupted|Internal|headers" | tail -1 | sed 's/Archive corrupted. //; s/! Please.*/!/'; }
for t in n c o Ou d Du f Fu; do a=$PKG/m_$t.nz; [ -f "$a" ] || continue
  off=$(first_payload "$a"); n=$(stat -c%s "$a")
  pts="$((off-1)) $off $((off+4)) $((off+5))"
  for pct in 1 2 5 10 20 30 40 50 60 70 80 85 90 95 99; do pts="$pts $(( off + (n-off)*pct/100 ))"; done
  for L in $pts; do head -c "$L" "$a" > "$W/p.nz"
    o=$(env -i PATH=/usr/bin:/bin timeout 60 "$ORIG" t "$W/p.nz" 2>&1 | report)
    u=$(env -i PATH=/usr/bin:/bin timeout 60 "$OURS" t "$W/p.nz" 2>&1 | report)
    m=" "; [ "$o" = "$u" ] || m="X"; printf "%s %-3s L=%-8d orig=%-34s ours=%s\n" "$m" $t "$L" "$o" "$u" >> "$OUT"
  done
done
echo "truncation_sweep: $(grep -c '^ ' "$OUT") identical of $(wc -l < "$OUT") (details in $OUT)"
