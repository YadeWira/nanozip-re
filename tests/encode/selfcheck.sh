#!/usr/bin/env bash
# selfcheck.sh -- the whole-archive self-check `a` runs on what it has written.
#
# After the last byte is written and before the archive takes its name, `a`
# decodes the file in-process and compares every entry with what it read: names,
# sizes and a CRC-64 of the content. The per-block read-back never saw the
# container, which is how two releases shipped archives nothing could read.
#
# A. Silent: for every codec and the shapes that stress the comparison (a
#    directory with an empty and a one-byte file, -p3 worker slices, the same
#    file twice, -hn, w32c, every input excluded, with and without -p2), the
#    archive and the console
#    are the same with the check on and off (NZ_NO_SELFCHECK=1), and the trace
#    (NZ_TRACE_SELFCHECK=1) says "ok" with the entry count `l` reports.
# B. Caught: each injected fault (NZ_SELFCHECK_FAULT=flip|trunc|name, and hdr --
#    quirk 77's short worker header -- on the -pN containers) must first be shown
#    to break the archive with the check off (our `t` fails or `x` differs from
#    the input: a fault that breaks nothing proves nothing), and then be caught:
#    the failure line, no footer, no file left, exit 0 (quirk 1), 1 under
#    NZ_STRICT_EXIT.
# C. Replace: a failed check over an existing archive leaves it byte-identical
#    and no .nzre-part behind.
#
# No original needed. About a minute.
# usage: tests/encode/selfcheck.sh [workdir]   (NZ_RECON as elsewhere)
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
OURS=${NZ_RECON:-$HERE/bin/nz-re}
W=${1:-/tmp/nzre_selfcheck}
rm -rf "$W"; mkdir -p "$W/in/sub"; cd "$W" || exit 1

# inputs: text, random, an empty and a one-byte file, a binary in a subdirectory
head -c 200000 "$HERE/src/sfx_archive.cpp" > in/text.txt
python3 -c "import random; random.seed(7); open('in/rnd.bin','wb').write(bytes(random.getrandbits(8) for _ in range(120000)))"
: > in/empty.dat
printf 'x' > in/tiny
head -c 150000 "$OURS" > in/sub/prog.bin

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL $*"; }

norm() {   # the console's own lines, minus what timing decides (rates, times); the status
           # line's redraws depend on which second boundaries a run crosses, so they go
    tr '\r\b' '\n\n' < "$1" |
        grep -aE '^(Archive:|Threads:|Compressor #|Compressed |IO-|Warning|Cannot |Self-check|Note:|Error|This compressor|Out of memory|Overwrite)' |
        sed -E 's/in [0-9]+m? ?[0-9.]+s, [0-9.]+ ?[KMG]?B\/s/in T, R/; s/IO-(in|out): .*/IO/'
}
entries_of() { "$OURS" l "$1" </dev/null 2>/dev/null | tr '\r\b' '\n\n' | grep -a '^Total of' | awk '{print $3}'; }

# ---------------------------------------------------------------- A: silent
shapes=( "dir|-r x.nz in" "p3|-p3 -r x.nz in" "twice|x.nz in/text.txt in/text.txt" "hn|-hn -r x.nz in" "excl|-xin/* -r x.nz in" "excl-p2|-p2 -xin/* -r x.nz in" )
for c in cn cf cF cd cD co cO cc; do
    for sh in "${shapes[@]}"; do
        tag=${sh%%|*}; args=${sh#*|}
        rm -rf A B; mkdir A B
        ( cd A && NZ_TRACE_SELFCHECK=1 "$OURS" a -$c -t1 -y ${args//in/..\/in} </dev/null > con.txt 2> err.txt )
        ( cd B && NZ_NO_SELFCHECK=1 "$OURS" a -$c -t1 -y ${args//in/..\/in} </dev/null > con.txt 2> err.txt )
        tr=$(grep -a '^\[selfcheck\]' A/err.txt)
        n=$(entries_of A/x.nz)
        if ! cmp -s A/x.nz B/x.nz; then bad "A -$c $tag: the check changed the archive"
        elif [ "$(norm A/con.txt)" != "$(norm B/con.txt)" ]; then bad "A -$c $tag: the check changed the console"; diff <(norm A/con.txt) <(norm B/con.txt) | head -5
        elif ! echo "$tr" | grep -q "^\[selfcheck\] ok entries=$n "; then bad "A -$c $tag: no ok trace for $n entries: $tr"
        else ok; fi
    done
done
# a self-extractor, where the stub is there
if [ -f "$(dirname "$OURS")/nz_w32c.sfx" ]; then
    rm -rf A; mkdir A
    ( cd A && NZ_TRACE_SELFCHECK=1 "$OURS" w32c -co -t1 -r x.exe ../in </dev/null > con.txt 2> err.txt )
    grep -aq '^\[selfcheck\] ok entries=5 ' A/err.txt && ok || bad "A w32c: $(cat A/err.txt)"
fi

# ---------------------------------------------------------------- B: caught
broken() {   # 0 when the archive really is damaged: t fails, or x does not give the input back
    local a=$1
    "$OURS" t "$a" </dev/null 2>&1 | tr '\r\b' '\n\n' | grep -aq '^Decompressed' || return 0
    rm -rf X; mkdir X
    ( cd X && "$OURS" x -y "../$a" </dev/null >/dev/null 2>&1 )
    diff -rq in X/in >/dev/null 2>&1 && return 1 || return 0
}
caught() {   # codec, fault, extra switches
    local c=$1 f=$2; shift 2
    rm -f off.nz on.nz on.nz.nzre-part
    NZ_NO_SELFCHECK=1 NZ_SELFCHECK_FAULT=$f "$OURS" a -$c -t1 "$@" -r off.nz in </dev/null >/dev/null 2>&1
    if ! broken off.nz; then bad "B -$c $f: the injected fault did not break the archive -- this case proves nothing"; return; fi
    NZ_SELFCHECK_FAULT=$f "$OURS" a -$c -t1 "$@" -r on.nz in </dev/null > con.txt 2>&1; local rc=$?
    NZ_STRICT_EXIT=1 NZ_SELFCHECK_FAULT=$f "$OURS" a -$c -t1 "$@" -r on2.nz in </dev/null >/dev/null 2>&1; local strict=$?
    if ! tr '\r\b' '\n\n' < con.txt | grep -aq '^Self-check failed: the archive does not read back'; then bad "B -$c $f: not caught"
    elif tr '\r\b' '\n\n' < con.txt | grep -aq '^Compressed '; then bad "B -$c $f: a footer after a failed check"
    elif [ -e on.nz ] || [ -e on2.nz ]; then bad "B -$c $f: the rejected archive was left behind"
    elif [ $rc -ne 0 ] || [ $strict -ne 1 ]; then bad "B -$c $f: exit $rc (want 0), strict $strict (want 1)"
    else ok; fi
}
for c in cn cf cF cd cD co cO cc; do
    for f in flip trunc name; do caught $c $f; done
done
for c in co cO cc; do caught $c hdr -p3; done

# ---------------------------------------------------------------- C: replace
rm -f rep.nz rep.nz.nzre-part
"$OURS" a -cf -t1 rep.nz in/tiny </dev/null >/dev/null 2>&1
before=$(sha256sum rep.nz | cut -c1-64)
NZ_SELFCHECK_FAULT=flip "$OURS" a -co -t1 -y -r rep.nz in </dev/null >/dev/null 2>&1
after=$(sha256sum rep.nz 2>/dev/null | cut -c1-64)
if [ "$before" != "$after" ]; then bad "C: a failed check changed the archive it was replacing"
elif [ -e rep.nz.nzre-part ]; then bad "C: .nzre-part left behind"
else ok; fi
"$OURS" a -co -t1 -y -r rep.nz in </dev/null >/dev/null 2>&1
if [ "$(sha256sum rep.nz | cut -c1-64)" = "$before" ] || [ -e rep.nz.nzre-part ]; then bad "C: a passing check did not replace the archive"; else ok; fi

echo "selfcheck: $pass/$((pass+fail)) ok"
[ "$fail" -eq 0 ]
