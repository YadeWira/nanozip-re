#!/bin/bash
# Original vs ours on damaged archives for EVERY codec: for each multi-file fixture m_<tag>.nz of the release
# package, flip one byte at 30/60/80/90/99 % and truncate at 85 %; extract with both; print exit code, files
# written / correct / wrong and the corrupt/mismatch lines. "files:same" means the same paths with the same
# sizes AND contents (what a faithful replica must achieve). Usage: corrupt_compare_all.sh [workdir] [tags...]
W=${1:-/tmp/nzre_corrupt_all}; shift; TAGS=${*:-"n c o Ou d Du f Fu"}
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-${OURS:-$HERE/bin/nz_recon}}
# Fixtures: tests/parity/make_fixtures.sh builds them with the original.
PKG=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
[ -d "$PKG" ] || { echo "SKIP: no fixtures in $PKG (run tests/parity/make_fixtures.sh)"; exit 0; }
rm -rf $W && mkdir -p $W
for tag in $TAGS; do
  A=$W/$tag; mkdir -p $A/src; cp $PKG/m_$tag.nz $A/multi.nz; (cd $A/src && $ORIG x -y ../multi.nz >/dev/null 2>&1)
  for spec in 0.30 0.60 0.80 0.90 0.99 trunc; do python3 - $A/multi.nz $A/c_$spec.nz $spec <<'PY'
import sys; b=bytearray(open(sys.argv[1],'rb').read()); f=sys.argv[3]
if f=='trunc': b=b[:len(b)*85//100]
else: b[int(len(b)*float(f))]^=0xff
open(sys.argv[2],'wb').write(b)
PY
    for who in orig ours; do bin=$ORIG; [ $who = ours ] && bin=$OURS; d=$A/r_${spec}_$who; mkdir -p $d
      (cd $d && env -i PATH=/usr/bin:/bin timeout 120 $bin x -y $A/c_$spec.nz >out.txt 2>&1; echo $? > exit)
      for cmd in l t; do (cd $d && env -i PATH=/usr/bin:/bin timeout 120 $bin $cmd $A/c_$spec.nz >out_$cmd.txt 2>&1; echo $? > exit_$cmd); done; done
  done
done
python3 - "$W" $TAGS <<'PY'
import hashlib, os, sys
W=sys.argv[1]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
def tree(d):
    t={}
    for r,_,fs in os.walk(d):
        for f in fs:
            if f.startswith('out') or f.startswith('exit'): continue   # the harness's own captures
            p=os.path.join(r,f); t[os.path.relpath(p,d)]=sha(p)
    return t
same=0; total=0
for tag in sys.argv[2:]:
    A=f'{W}/{tag}'; good=tree(A+'/src')
    for spec in ['0.30','0.60','0.80','0.90','0.99','trunc']:
        rows={}
        for who in ['orig','ours']:
            d=f'{A}/r_{spec}_{who}'; t=tree(d); rows[who]=t
            ok=[k for k,v in t.items() if good.get(k)==v]; bad=[k for k in t if good.get(k)!=t[k]]
            msg=[l.strip() for l in open(f'{d}/out.txt',errors='replace').read().replace('\r','\n').split('\n') if 'mismatch' in l or 'corrupt' in l or 'Internal error' in l]
            print(f'{tag:3} {spec:5} {who:4} exit={open(d+"/exit").read().strip()} written={len(t)} correct={len(ok)} wrong={len(bad)} :: {" | ".join(msg)}')
        total+=1; s = rows['orig']==rows['ours']; same+=s
        print(f'{tag:3} {spec:5} files:{"same" if s else "DIFF "+str(sorted(set(rows["orig"])^set(rows["ours"])) or [k for k in rows["orig"] if rows["orig"][k]!=rows["ours"].get(k)])}')
print(f'FILES SAME {same}/{total}')
# message parity: the corruption report lines of x, and of l / t, must be the same text (exit status is not
# compared: the original's crashes and its fatal exit are catalogued, see ORIGINAL_QUIRKS)
import re
def report(path):
    try: t=open(path,errors='replace').read()
    except FileNotFoundError: return '?'
    m=re.findall(r'Archive corrupted\. Error decoding \(code \d+\)|Archive corrupted\. Unexpected end of file\.|Internal error: \d+!|Data corrupted while reading headers!|File is not a NanoZip archive\.|Checksum mismatch \[[0-9a-f ]+\]: \S+', t)
    return ' | '.join(m) if m else '-'
for cmd,fn in (('x','out.txt'),('l','out_l.txt'),('t','out_t.txt')):
    same_m=0; tot_m=0; diffs=[]
    for tag in sys.argv[2:]:
        for spec in ['0.30','0.60','0.80','0.90','0.99','trunc']:
            a=report(f'{W}/{tag}/r_{spec}_orig/{fn}'); b=report(f'{W}/{tag}/r_{spec}_ours/{fn}')
            tot_m+=1
            if a==b: same_m+=1
            else: diffs.append(f'  {cmd} {tag}/{spec}: orig[{a}] ours[{b}]')
    print(f'MSG SAME ({cmd}) {same_m}/{tot_m}')
    for d in diffs: print(d)
PY
