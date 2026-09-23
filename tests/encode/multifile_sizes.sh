#!/usr/bin/env bash
# multifile_sizes.sh -- compression of SEVERAL files of real size, every codec.
#
# The encode oracle's multi-file inputs are small and every corpus sweep encodes
# one file per archive, so an archive in which a file spans more than one output
# block and another file follows was never written. It went wrong exactly there:
# `a -co` of two 3 MB files re-announced the first file in the second block's
# table and wrote its checksum twice, and NEITHER binary could read the archive
# (-cO and -cc too). The per-block read-back check cannot see the container.
#
# Per shape and codec: our `a -t1` archive against the original's, byte for byte;
# the original must read ours (`t`); and with the default thread count, where a
# byte comparison is meaningless (quirk 58), the original must still read ours.
#
# usage: tests/encode/multifile_sizes.sh [workdir]   (NZ_ORIG, NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_multifile_sizes}
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1

python3 - <<'PY'
import os, random
random.seed(20260922)
def text(n, k):
    words = ['the', 'block', 'table', 'record', 'stream', 'window', 'match', 'literal',
             'checksum', 'nanozip', 'archive', 'entry', 'offset', 'length', 'model', str(k)]
    out, size = [], 0
    while size < n:
        w = random.choice(words); out.append(w); size += len(w) + 1
    return (' '.join(out)[:n]).encode()
def binary(n, k):
    return bytes(((i * (k + 7)) ^ (i >> 5) ^ random.randrange(4)) % 256 for i in range(n))
def put(d, name, data):
    p = os.path.join(d, name); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'wb').write(data)
MB = 1 << 20
shapes = {
    'two_3mb':        [('a.bin', binary, 3 * MB), ('b.txt', text, 3 * MB)],
    'big_then_small': [('big.bin', binary, 3 * MB)] + [('s%02d.txt' % i, text, 20000 + i * 900) for i in range(12)],
    'small_big_small':[('s%02d.txt' % i, text, 30000) for i in range(6)] + [('mid.bin', binary, 2 * MB + 12345)] +
                      [('t%02d.txt' % i, text, 40000) for i in range(6)],
    'around_1mb':     [('x%d.bin' % i, binary, MB + (i - 2) * 4097) for i in range(5)],
    'tree':           [('d%d/f%02d.%s' % (i % 3, i, 'txt' if i % 2 else 'bin'), text if i % 2 else binary,
                        random.choice([700, 60000, 400000, 1500000])) for i in range(18)],
}
for name, files in shapes.items():
    for k, (fn, gen, n) in enumerate(files):
        put('src_' + name, fn, gen(n, k))
PY

ok=0; bad=0; fails=""
for sh in two_3mb big_then_small small_big_small around_1mb tree; do
  for c in cn cf cF cd cD co cO cc; do
    rm -f o.nz r.nz rd.nz
    ( cd "src_$sh" && "$ORIG" a -$c -t1 -r ../o.nz . </dev/null >/dev/null 2>&1 )
    ( cd "src_$sh" && "$OURS" a -$c -t1 -r ../r.nz . </dev/null >/dev/null 2>&1 )
    ( cd "src_$sh" && "$OURS" a -$c -r ../rd.nz . </dev/null >/dev/null 2>&1 )
    same=no; cmp -s o.nz r.nz && same=yes
    reads=no; "$ORIG" t r.nz 2>&1 | tr '\r\b' '\n\n' | grep -qiE 'corrupt|error|incompatible' || reads=yes
    readsd=no; "$ORIG" t rd.nz 2>&1 | tr '\r\b' '\n\n' | grep -qiE 'corrupt|error|incompatible' || readsd=yes
    if [ $same = yes ] && [ $reads = yes ] && [ $readsd = yes ]; then ok=$((ok+1))
    else bad=$((bad+1)); fails="$fails $sh/-$c(identical=$same,read=$reads,read-default-threads=$readsd)"; fi
  done
done
echo "multifile_sizes: $ok/$((ok+bad)) identical to the original and read back by it$fails"
[ "$bad" -eq 0 ]
