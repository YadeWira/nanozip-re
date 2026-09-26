#!/usr/bin/env bash
# parallel_determinism.sh -- `a` compresses the -pN worker streams on several
# threads and must write the same archive as on one.
#
# The worker COUNT is part of the format (it is -pN, or the automatic split's
# min(-t, host) from 8 MB); the POOL that runs them is not, so for every method:
#   a. `-p4 -t4` == `-p4 -t1` (one thread per worker vs the serial loop), on a
#      directory with text, random data, a binary, empty files, a one-byte file
#      and an unreadable one, sized so that worker boundaries fall inside files;
#   b. the automatic split: `-t4` == `NZ_THREADS=1 -t4` (same worker count,
#      pool of one);
#   c. two more `-t4` runs, and runs under MALLOC_PERTURB_=85 and
#      MALLOC_ARENA_MAX=1 (a read of stale heap would follow the scheduler);
#   d. the self-check passes on the threaded archive;
#   e. quirk 56 (the dictionary transform's table is filled once per process and
#      each worker inherits it from the workers before it in processing order
#      [1..N-1, 0]): `-p3 -t3` == `-p3 -t1` with the text in worker 0, 1, 2 or
#      all three. Those inputs must first be shown to depend on the inheritance:
#      with NZ_TEST_Q56_ISOLATED=1 (no job inherits) at least one of them must
#      come out different for each method that runs the transform, or the
#      "identical" proves nothing.
# With the original present (NZ_ORIG, default ../linux32/nz), the quirk-56
# archives are also compared with its `-p3 -t1`.
#
# A few minutes (-cc dominates).
# usage: tests/encode/parallel_determinism.sh [workdir]   (NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
OURS=${NZ_RECON:-$HERE/bin/nz-re}
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
W=${1:-/tmp/nzre_pardet}
chmod -R u+rwX "$W" 2>/dev/null; rm -rf "$W"; mkdir -p "$W/in/sub" "$W/q" || exit 1
cd "$W" || exit 1

# ---------------------------------------------------------------- inputs
# T: 3 MB of text (this repository's sources); R1, R2: 3 MB of random bytes.
find "$HERE/src" -name '*.cpp' | LC_ALL=C sort | xargs cat 2>/dev/null | head -c 3000000 > q/T
python3 -c "
import random
for n, s in (('q/R1', 11), ('q/R2', 12)):
    random.seed(s); open(n, 'wb').write(random.randbytes(3000000))
"
cat q/T q/R1 q/R2 > q/w0.bin; cat q/R1 q/T q/R2 > q/w1.bin; cat q/R1 q/R2 q/T > q/w2.bin; cat q/T q/T q/T > q/all.bin
# the directory: 9.4 MB, over the automatic split's 8 MB
head -c 4000000 q/T > in/text.txt
head -c 2500000 q/R1 > in/sub/rnd.bin
head -c 1500000 "$OURS" > in/sub/prog.bin
: > in/empty1; : > in/sub/empty2; printf 'x' > in/tiny
tail -c 1400000 q/T > in/zz_text2.txt
printf 'unreadable\n' > in/noread; chmod 000 in/noread
[ -r in/noread ] && rm -f in/noread   # running as root: no unreadable file then

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL $*"; }
footer() { tr '\r\b' '\n\n' < "$1" | grep -a '^Compressed ' | sed -E 's/ in [0-9].*//'; }
enc() {   # out.nz, then the env/switch words: runs `a` with the check off, console to out.nz.con
    local out=$1; shift
    rm -f "$out"
    env NZ_NO_SELFCHECK=1 "$@" "$out" in </dev/null > "$out.con" 2>&1
}

# ---------------------------------------------------------------- a-d
for c in cf cF cd cD co cO cc; do
    A="$OURS a -$c -r -y"
    enc s1.nz $A -p4 -t1
    enc s4.nz $A -p4 -t4
    if [ ! -s s1.nz ]; then bad "-$c: no serial archive: $(tail -2 s1.nz.con)"; continue; fi
    cmp -s s1.nz s4.nz && [ "$(footer s1.nz.con)" = "$(footer s4.nz.con)" ] && ok || bad "a -$c: -p4 -t4 differs from -p4 -t1"
    enc u1.nz NZ_THREADS=1 $A -t4
    enc u4.nz $A -t4
    cmp -s u1.nz u4.nz && ok || bad "b -$c: the automatic split at -t4 differs from its pool of one"
    for run in 2 3; do enc r$run.nz $A -t4; cmp -s u4.nz r$run.nz && ok || bad "c -$c: -t4 run $run differs"; done
    enc m1.nz MALLOC_PERTURB_=85 $A -t4;  cmp -s u4.nz m1.nz && ok || bad "c -$c: MALLOC_PERTURB_=85 changes the archive"
    enc m2.nz MALLOC_ARENA_MAX=1 $A -t4;  cmp -s u4.nz m2.nz && ok || bad "c -$c: MALLOC_ARENA_MAX=1 changes the archive"
    rm -f sc.nz
    NZ_TRACE_SELFCHECK=1 $A -p4 -t4 sc.nz in </dev/null > sc.con 2>&1
    grep -aq '^\[selfcheck\] ok ' sc.con && cmp -s sc.nz s1.nz && ok || bad "d -$c: $(grep -a 'selfcheck\|Self-check' sc.con | head -2)"
done

# ---------------------------------------------------------------- e: quirk 56
have_orig=0; [ -x "$ORIG" ] && have_orig=1
for c in cd cD co cO cc; do
    sensitive=0
    for f in w0 w1 w2 all; do
        rm -f q1.nz q3.nz qi.nz
        NZ_NO_SELFCHECK=1 "$OURS" a -$c -p3 -t1 q1.nz q/$f.bin </dev/null >/dev/null 2>&1
        NZ_NO_SELFCHECK=1 "$OURS" a -$c -p3 -t3 q3.nz q/$f.bin </dev/null >/dev/null 2>&1
        NZ_NO_SELFCHECK=1 NZ_TEST_Q56_ISOLATED=1 "$OURS" a -$c -p3 -t3 qi.nz q/$f.bin </dev/null >/dev/null 2>&1
        [ -s q1.nz ] && cmp -s q1.nz q3.nz && ok || bad "e -$c $f: -p3 -t3 differs from -p3 -t1"
        cmp -s q1.nz qi.nz || sensitive=$((sensitive+1))
        if [ $have_orig = 1 ]; then
            rm -f qo.nz
            env -i PATH=/usr/bin:/bin "$ORIG" a -$c -p3 -t1 qo.nz q/$f.bin </dev/null >/dev/null 2>&1
            cmp -s qo.nz q3.nz && ok || bad "e -$c $f: -p3 -t3 differs from the original's -p3 -t1"
        fi
    done
    [ $sensitive -gt 0 ] && ok || bad "e -$c: no input depends on the inheritance -- these cases prove nothing"
    echo "  -$c: $sensitive of 4 quirk-56 inputs depend on the inheritance"
done

chmod -R u+rwX "$W" 2>/dev/null
echo "parallel_determinism: $pass/$((pass+fail)) ok"
[ "$fail" -eq 0 ]
