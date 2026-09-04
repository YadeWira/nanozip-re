#!/bin/bash
# damaged PARALLEL containers: original vs ours, files written (size+sha) and report lines
W=${W:-/tmp/nzre_corrupt_pf}
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz_recon}
PKG=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
[ -d "$PKG" ] || { echo "SKIP: no fixtures in $PKG (run tests/parity/make_fixtures.sh)"; exit 0; }
TAGS=${*:-"pf_c pf_d pf_D_D pf_f pf_F_F"}; for tag in $TAGS; do
  A=$W/$tag; rm -rf $A; mkdir -p $A/src; cp $PKG/$tag.nz $A/p.nz; (cd $A/src && $ORIG x -y ../p.nz >/dev/null 2>&1)
  for spec in 0.30 0.50 0.60 0.80 0.90 0.99 trunc; do python3 - $A/p.nz $A/c_$spec.nz $spec <<'PY'
import sys; b=bytearray(open(sys.argv[1],'rb').read()); f=sys.argv[3]
if f=='trunc': b=b[:len(b)*85//100]
else: b[int(len(b)*float(f))]^=0xff
open(sys.argv[2],'wb').write(b)
PY
    for who in orig ours; do bin=$ORIG; [ $who = ours ] && bin=$OURS; d=$A/r_${spec}_$who; mkdir -p $d
      (cd $d && env -i PATH=/usr/bin:/bin timeout 120 $bin x -y $A/c_$spec.nz >out.txt 2>&1; echo $? > exit); done
  done
done
python3 - $W $TAGS <<'PY'
import hashlib,os,sys,re
W=sys.argv[1]
def files(d):
    t={}
    for r,_,fs in os.walk(d):
        for f in fs:
            if f.startswith('out') or f.startswith('exit'): continue
            p=os.path.join(r,f); b=open(p,'rb').read(); t[os.path.relpath(p,d)]=(len(b),hashlib.sha256(b).hexdigest()[:12])
    return t
def rep(p):
    t=open(p,errors='replace').read()
    m=re.findall(r'Archive corrupted\. Error decoding \(code \d+\)|Archive corrupted\. Unexpected end of file\.|Internal error: \d+!|Checksum mismatch \[[0-9a-f ]+\]: \S+',t)
    return ' | '.join(m) or '-'
same=tot=0
for tag in sys.argv[2:]:
    A=f'{W}/{tag}'; good=files(A+'/src')
    for spec in ['0.30','0.50','0.60','0.80','0.90','0.99','trunc']:
        rows={}
        for who in ['orig','ours']:
            d=f'{A}/r_{spec}_{who}'; t=files(d); rows[who]=t
            desc=' '.join(f'{k}:{v[0]}{"=" if good.get(k)==v else "!"}' for k,v in sorted(t.items()))
            print(f'{tag:6} {spec:5} {who:4} exit={open(d+"/exit").read().strip():3} [{desc}] :: {rep(d+"/out.txt")}')
        tot+=1; s=rows['orig']==rows['ours']; same+=s
        if not s: print(f'{tag:6} {spec:5} FILES DIFF')
print(f'FILES SAME {same}/{tot}')
PY
