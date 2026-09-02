#!/usr/bin/env bash
# multifile_v2.sh — native-decode measurement for MULTI-FILE archives.
#
# native_only_v2.sh and real_corpus_sweep.sh both build one-file archives and
# compare one extracted file. That blind spot was not theoretical: multi-file
# archives carried NO per-entry checksum (the metadata run was parsed by
# tag-sniffing heuristics that only understood the single-file layout), the
# per-entry verification in RunLegacyCnExtractOrTest is gated on having one,
# and so -co/-cO wrote WRONG BYTES for a multi-file archive without declining
# while both suites reported 88/88 and 479/480.
#
# This script closes that gap. For every (shape, method) it compares the whole
# extracted TREE -- contents, mode and mtime, not just the first file -- against
# the legacy binary, with NZ_NO_BRIDGE=1 so nothing can fall back. It also
# compares `l` output byte-for-byte across the metadata switches (-nt/-np/-hn/
# -hc/-hC), which is what pins the record layout itself.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NATIVE="${RECON_ROOT}/bin/nz_recon"
LEGACY="${RECON_ROOT}/../linux32/nz"
[[ -n "${NZ_LEGACY_ORACLE:-}" ]] && LEGACY="${NZ_LEGACY_ORACLE}"

if [[ ! -x "$NATIVE" ]]; then echo "FATAL: native bin missing ($NATIVE)"; exit 1; fi
if [[ ! -x "$LEGACY" ]]; then echo "FATAL: legacy bin missing ($LEGACY)"; exit 1; fi

WORK="$(mktemp -d /tmp/multifile_v2.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# ---------------------------------------------------------------- shapes ----
# Each shape is a directory under $WORK/shapes/<name>; SHAPE_FILES[<name>] is the
# space-separated argument list handed to `nz a`, relative to $WORK.
declare -A SHAPE_FILES
declare -A SHAPE_OPTS   # extra encoder flags for a shape (default none)
SHAPES=()

mk() { mkdir -p "$(dirname "${WORK}/$1")"; }

# small3: three tiny files, three DIFFERENT modes and three different mtimes.
# Distinct values are what force the per-entry encodings (zigzag mtime deltas,
# one permission run per file) instead of a single collapsed run.
mk shapes/small3/a.txt
printf 'alpha, the quick brown fox jumps over the lazy dog.\n' > "${WORK}/shapes/small3/a.txt"
printf 'beta, lorem ipsum dolor sit amet consectetur adipiscing elit.\n' > "${WORK}/shapes/small3/b.txt"
head -c 3000 /dev/zero | tr '\0' 'Q' > "${WORK}/shapes/small3/c.bin"
chmod 600 "${WORK}/shapes/small3/a.txt"
chmod 755 "${WORK}/shapes/small3/b.txt"
chmod 644 "${WORK}/shapes/small3/c.bin"
touch -d '2020-01-02 03:04:05' "${WORK}/shapes/small3/a.txt"
touch -d '2021-05-06 07:08:09' "${WORK}/shapes/small3/b.txt"
touch -d '2022-11-12 13:14:15' "${WORK}/shapes/small3/c.bin"
SHAPE_FILES[small3]="shapes/small3/a.txt shapes/small3/b.txt shapes/small3/c.bin"
SHAPES+=(small3)

# mixed5: five files of DIFFERENT character in one archive. A codec that carries
# state across members (every one of them does) can be byte-exact on each kind
# alone and still wrong when they follow each other.
mk shapes/mixed5/t.txt
{ for i in $(seq 1 400); do echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit."; done; } > "${WORK}/shapes/mixed5/t.txt"
head -c 40960 /dev/zero | openssl enc -aes-256-ctr -pass pass:nzre-mf -nosalt 2>/dev/null > "${WORK}/shapes/mixed5/e.bin" \
  || head -c 40960 /dev/urandom > "${WORK}/shapes/mixed5/e.bin"
head -c 20000 /dev/zero > "${WORK}/shapes/mixed5/z.bin"
# A ~330 KB compressible blob. Deliberately NOT a copy of a repo source file:
# whether this shape crosses the encoder's block boundary depends on its exact
# size, so a fixture that grows with the repo makes the pass count drift.
{ for i in $(seq 1 4200); do
    printf 'static int helper_%d(int a, int b) { return a * %d + b; }  /* padding padding */\n' "$i" "$i"
  done; } > "${WORK}/shapes/mixed5/src.cpp"
{ yes "the quick brown fox jumps over the lazy dog " || true; } | head -c 30000 > "${WORK}/shapes/mixed5/r.txt"
SHAPE_FILES[mixed5]="shapes/mixed5/t.txt shapes/mixed5/e.bin shapes/mixed5/z.bin shapes/mixed5/src.cpp shapes/mixed5/r.txt"
SHAPES+=(mixed5)

# nested: sub-directories, so the stored paths are not bare filenames.
mk shapes/nested/one/deep/x.txt
mkdir -p "${WORK}/shapes/nested/one/deep" "${WORK}/shapes/nested/two"
printf 'deep file\n' > "${WORK}/shapes/nested/one/deep/x.txt"
printf 'other file\n' > "${WORK}/shapes/nested/two/y.txt"
printf 'top file\n'   > "${WORK}/shapes/nested/z.txt"
SHAPE_FILES[nested]="shapes/nested/one/deep/x.txt shapes/nested/two/y.txt shapes/nested/z.txt"
SHAPES+=(nested)

# many70: 70 equal-mode files. The permission record collapses equal consecutive
# modes into runs of up to 121 entries; below 2 entries and above 121 it uses a
# different form, so a mid-range count is the one that exercises the run field.
mkdir -p "${WORK}/shapes/many70"
many_args=""
for i in $(seq 1 70); do
  printf 'file %d payload\n' "$i" > "${WORK}/shapes/many70/f${i}.txt"
  chmod 666 "${WORK}/shapes/many70/f${i}.txt"
  many_args="${many_args} shapes/many70/f${i}.txt"
done
SHAPE_FILES[many70]="${many_args}"
SHAPES+=(many70)

# equal600: every file mode 0600. The encoder then omits the permission record
# ENTIRELY (such an archive is byte-identical to the -np one) and the original
# drops the perm column from `l` -- absence means "no permissions stored", not
# "default permissions", and reading it the other way prints a column the
# original does not.
mkdir -p "${WORK}/shapes/equal600"
for i in 1 2 3; do printf 'six hundred %d\n' "$i" > "${WORK}/shapes/equal600/f${i}.txt"; chmod 600 "${WORK}/shapes/equal600/f${i}.txt"; done
SHAPE_FILES[equal600]="shapes/equal600/f1.txt shapes/equal600/f2.txt shapes/equal600/f3.txt"
SHAPES+=(equal600)

# setuid: modes >= 01000. Those never collapse into a run (the run field would
# be ambiguous against the mode), so each is written out separately even when
# repeated -- the opposite branch from many70.
mkdir -p "${WORK}/shapes/setuid"
for i in 1 2 3; do printf 'suid %d\n' "$i" > "${WORK}/shapes/setuid/f${i}.txt"; done
chmod 4755 "${WORK}/shapes/setuid/f1.txt"
chmod 2755 "${WORK}/shapes/setuid/f2.txt"
chmod 1777 "${WORK}/shapes/setuid/f3.txt"
SHAPE_FILES[setuid]="shapes/setuid/f1.txt shapes/setuid/f2.txt shapes/setuid/f3.txt"
SHAPES+=(setuid)

# recurse: a directory tree added with -r, so the stored paths come from a walk
# rather than from the argument list. The encoder reorders files by size, so the
# checksum/mtime/permission lists must be read in ITS order, not the caller's.
mkdir -p "${WORK}/shapes/recurse/tree/a/b/c" "${WORK}/shapes/recurse/tree/x"
for f in tree/top.txt tree/a/one.txt tree/a/b/two.txt tree/a/b/c/three.txt tree/x/four.txt; do
  printf 'content of %s, padded so the sizes differ a little\n' "$f" > "${WORK}/shapes/recurse/${f}"
done
SHAPE_FILES[recurse]="-r shapes/recurse/tree"
SHAPES+=(recurse)

# par1: a parallel (-pN) container. One 1 MB file is enough to make the encoder
# emit four streams, and a file split across streams has no whole-file checksum
# -- only a per-slice one. Adopting that slice value as the file's made every
# parallel archive decline; this shape is the guard for that.
mkdir -p "${WORK}/shapes/par1"
head -c 1000000 /dev/zero | openssl enc -aes-256-ctr -pass pass:nzre-par -nosalt 2>/dev/null > "${WORK}/shapes/par1/p.bin" \
  || head -c 1000000 /dev/urandom > "${WORK}/shapes/par1/p.bin"
SHAPE_FILES[par1]="shapes/par1/p.bin"
SHAPE_OPTS[par1]="-p4"
SHAPES+=(par1)

# NOTE: a parallel container holding SEVERAL files still declines on extract
# (its per-stream slice framing is not reconstructed); it is deliberately not a
# shape here, so a green run means green.

METHODS=(cn cf cF cd cD co cO cc)
# Metadata switches: no timestamps, no permissions, and the four checksum modes.
OPTSETS=("" "-nt" "-np" "-nt -np" "-hn" "-hc" "-hC")

# Signature of an extracted tree: path, octal mode, size and mtime of every
# file, plus its content hash. Comparing only contents would miss a permission
# or timestamp that the metadata run restores wrongly.
tree_sig() {
  ( cd "$1" && find . -type f -printf '%p %m %s %T@\n' | sort ) 2>/dev/null
  ( cd "$1" && find . -type f -print0 | sort -z | xargs -0 md5sum 2>/dev/null )
}

pass=0; fail=0; skip=0; fail_log=""
declare -A M_PASS M_FAIL
for m in "${METHODS[@]}"; do M_PASS[$m]=0; M_FAIL[$m]=0; done

# ------------------------------------------------- phase 1: extract trees ----
for shape in "${SHAPES[@]}"; do
  for m in "${METHODS[@]}"; do
    arc="${WORK}/mf_${shape}_${m}.nz"; rm -f "$arc"
    if ! ( cd "$WORK" && "$LEGACY" a -y -"$m" ${SHAPE_OPTS[$shape]:-} "$arc" ${SHAPE_FILES[$shape]} ) >/dev/null 2>&1; then
      skip=$((skip+1)); continue
    fi
    od="${WORK}/o_${shape}_${m}"; nd="${WORK}/n_${shape}_${m}"
    rm -rf "$od" "$nd"; mkdir -p "$od" "$nd"
    ( cd "$od" && "$LEGACY" x -y -fo "$arc" ) >/dev/null 2>&1
    ( cd "$nd" && NZ_NO_BRIDGE=1 "$NATIVE" x -y -fo "$arc" ) >/dev/null 2>&1

    if [[ -z "$(find "$od" -type f | head -1)" ]]; then skip=$((skip+1)); continue; fi
    if [[ "$(tree_sig "$od")" == "$(tree_sig "$nd")" ]]; then
      pass=$((pass+1)); M_PASS[$m]=$((M_PASS[$m]+1))
    else
      fail=$((fail+1)); M_FAIL[$m]=$((M_FAIL[$m]+1))
      nfiles=$(find "$nd" -type f | wc -l)
      if [[ "$nfiles" -eq 0 ]]; then reason="declined (no output)"; else
        reason="tree differs ($(diff <(tree_sig "$od") <(tree_sig "$nd") | grep -c '^[<>]') lines)"
      fi
      fail_log="${fail_log}FAIL extract: ${shape} / -${m} (${reason})\n"
    fi
  done
done

# ---------------------------------------------------- phase 2: `l` output ----
# The listing is where the metadata run is visible directly: a wrong checksum, a
# wrong mode, a shifted timestamp or a column that should not be there all show
# up here, and none of them would fail phase 1 for a codec that declines.
lpass=0; lfail=0
for shape in "${SHAPES[@]}"; do
  for opts in "${OPTSETS[@]}"; do
    arc="${WORK}/lst_${shape}_$(echo "$opts" | tr -d ' -').nz"; rm -f "$arc"
    if ! ( cd "$WORK" && "$LEGACY" a -y -cf ${SHAPE_OPTS[$shape]:-} ${opts} "$arc" ${SHAPE_FILES[$shape]} ) >/dev/null 2>&1; then
      continue
    fi
    if diff <( "$LEGACY" l "$arc" 2>/dev/null ) <( "$NATIVE" l "$arc" 2>/dev/null ) >/dev/null 2>&1; then
      lpass=$((lpass+1))
    else
      lfail=$((lfail+1))
      fail_log="${fail_log}FAIL list: ${shape} / '${opts:-default}'\n$(diff <( "$LEGACY" l "$arc" 2>/dev/null ) <( "$NATIVE" l "$arc" 2>/dev/null ) | head -6)\n"
    fi
  done
done

echo "=== MULTI-FILE NATIVE DECODE (NZ_NO_BRIDGE=1, no legacy fallback) ==="
echo "shapes: ${SHAPES[*]}"
printf "%-6s %6s %6s\n" "method" "pass" "fail"
for m in "${METHODS[@]}"; do printf "%-6s %6d %6d\n" "-$m" "${M_PASS[$m]}" "${M_FAIL[$m]}"; done
echo "----------------------------------"
printf "%-14s %6d %6d  (skip %d)\n" "EXTRACT TOTAL" "$pass" "$fail" "$skip"
printf "%-14s %6d %6d\n" "LIST TOTAL" "$lpass" "$lfail"
if [[ -n "$fail_log" ]]; then echo; printf "%b" "$fail_log" | head -60; fi
if [[ $fail -eq 0 && $lfail -eq 0 ]]; then
  echo; echo "ok: $pass multi-file trees + $lpass listings byte-exact, zero bridge"; exit 0
fi
echo; echo "INFO: $((fail+lfail)) multi-file combinations not yet native"; exit 1
