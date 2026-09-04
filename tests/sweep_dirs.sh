#!/usr/bin/env bash
# sweep_dirs.sh -- directory trees: the shapes a file-by-file corpus never covers.
#
# Builds trees with deep paths, empty files, UTF-8 and space names, symlinks
# (to a file, to a directory, absolute), an unreadable file, setuid/sticky modes
# and extreme timestamps; archives each with the ORIGINAL under every codec
# (`a -r`, plus one `-fo` run) and compares our extraction against the
# original's: contents, mode, mtime and what is present at all.
#
# What the original does with these (measured 2026-09-04, quirk 30 and 45):
#   symlinks           SKIPPED, silently -- neither the target nor the link
#   unreadable files   SKIPPED, silently (a 0000 file never reaches the archive)
#   setuid/sticky      kept (a 04755 file lists as "4755")
#   directories        created 0700 on extraction whatever the umask
#
# usage: tests/sweep_dirs.sh [workdir]
set -u
W=${1:-/tmp/nzre_sweep_dirs}
HERE=$(cd "$(dirname "$0")/.." && pwd)
ORIG=${NZ_ORIG:-$HERE/../linux32/nz}
OURS=${NZ_RECON:-$HERE/bin/nz_recon}
[ -x "$OURS" ] || { echo "FAIL: no $OURS"; exit 1; }
[ -x "$ORIG" ] || { echo "SKIP: no original at $ORIG"; exit 0; }

rm -rf "$W"; mkdir -p "$W"
build_tree() { # $1 = root
  local r=$1
  mkdir -p "$r/deep/a/b/c" "$r/sub dir" "$r/empty_dir"
  printf 'hello\n' > "$r/f.txt"
  printf '' > "$r/zero.bin"
  head -c 3000 /dev/urandom > "$r/deep/a/b/c/leaf.bin"
  head -c 40000 /dev/urandom | base64 > "$r/sub dir/text.txt"
  printf 'x\n' > "$r/name with spaces.txt"
  printf 'y\n' > "$r/acentos-ñ-ünïcode.txt"
  printf 'z\n' > "$r/unreadable.bin"; chmod 0000 "$r/unreadable.bin"
  chmod 04755 "$r/f.txt"; chmod 01644 "$r/deep/a/b/c/leaf.bin"
  ln -sf f.txt "$r/link_to_file"; ln -sf deep "$r/link_to_dir"; ln -sf /etc/hostname "$r/abs_link"
  touch -d @100000000 "$r/deep/a/b/c/leaf.bin"
  touch -d @2000000000 "$r/sub dir/text.txt"
}
build_tree "$W/src"

# What the original itself puts on disk is the reference, so extract with both.
tree_state() { # $1 = dir -> "relpath mode mtime size sha" per file, sorted
  ( cd "$1" 2>/dev/null || return 0
    find . \( -type f -o -type l \) -printf '%P\n' 2>/dev/null | sort | while IFS= read -r f; do
      if [ -L "$f" ]; then printf '%s LINK -> %s\n' "$f" "$(readlink "$f")"; continue; fi
      printf '%s %s %s %s %s\n' "$f" "$(stat -c %a "$f")" "$(stat -c %Y "$f")" \
             "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -c1-16)"
    done )
}

pass=0; fail=0
for spec in n:-cn c:-cc d:-cd Du:-cD f:-cf Fu:-cF o:-co Ou:-cO; do
  tag=${spec%%:*}; opt=${spec#*:}
  for extra in "" "-fo"; do
    name="$tag${extra:+_fo}"
    ( cd "$W" && env -i PATH=/usr/bin:/bin "$ORIG" a "$opt" $extra -r "d_$name.nz" src >/dev/null 2>&1 )
    [ -f "$W/d_$name.nz" ] || { echo "FAIL $name: the original did not build the archive"; fail=$((fail+1)); continue; }
    for who in orig ours; do
      bin=$ORIG; [ $who = ours ] && bin=$OURS
      d="$W/x_${name}_$who"; rm -rf "$d"; mkdir -p "$d"
      ( cd "$d" && env -i PATH=/usr/bin:/bin "$bin" x -y $extra "$W/d_$name.nz" >/dev/null 2>&1 )
    done
    if diff <(tree_state "$W/x_${name}_orig") <(tree_state "$W/x_${name}_ours") >/dev/null; then
      pass=$((pass+1))
    else
      echo "FAIL $name:"; diff <(tree_state "$W/x_${name}_orig") <(tree_state "$W/x_${name}_ours") | head -6 | sed 's/^/    /'
      fail=$((fail+1))
    fi
  done
done
echo "sweep_dirs: $pass/$((pass+fail)) archives extract identically (contents, mode, mtime, symlinks)"
[ $fail -eq 0 ]
