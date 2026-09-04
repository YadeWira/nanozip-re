#!/bin/bash
# matrix3.sh -- CLI parity round 3: shapes and situations matrix.sh/matrix2.sh never covered.
# usage: matrix3.sh <outdir>   (fixtures from build_fixtures3.sh in /tmp/nzre_fx3, plus release_verify_pkg/arc)
# Each case: fresh dir per binary, env -i (+ per-case env), stdin </dev/null, stdout capped at 1 MB,
# saves out/err/exit and a tree listing (mode mtime size type path). Compare with matrix3_diff.sh.
OUT=$1; [[ -n $OUT ]] || { echo "usage: matrix3.sh <outdir>"; exit 1; }
case $OUT in /tmp/nzre_*) ;; *) echo "outdir must be under /tmp/nzre_* (the 32-bit original cannot open /tmp/claude-*)"; exit 1;; esac
HERE=$(cd "$(dirname "$0")/../.." && pwd); ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-${OURS:-$HERE/bin/nz_recon}}
P=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}; FX3=/tmp/nzre_fx3; FXO=~/.cache/nzre_tools/cli_parity/fixtures
rm -rf "$OUT"; mkdir -p "$OUT/fx"; FX=$OUT/fx
cp $P/m_o.nz $FX/multi.nz; cp $P/m_n.nz $FX/store.nz
# long.nz: deep directories and a name past the 40-column rule, built here.
( cd $FX && d="a_very_long_directory_name_number_one/and_another_very_long_one_number_two" && mkdir -p "$d" \
  && printf 'long\n' > "$d/a_file_with_a_deliberately_long_name_for_the_40_column_rule.txt" \
  && env -i PATH=/usr/bin:/bin $ORIG a -co -r long.nz a_very_long_directory_name_number_one >/dev/null 2>&1 \
  && rm -rf a_very_long_directory_name_number_one )
cp $FX3/*.nz $FX/ 2>/dev/null
cp $P/m_o.nz $FX/UP.NZ; cp $P/m_o.nz $FX/UP.EXE
# damaged archives from corrupt_compare_all (o = -co): flip at 60 % and truncation
python3 - "$FX" <<'PY'
import sys; F=sys.argv[1]; b=bytearray(open(F+'/multi.nz','rb').read()); n=len(b)
c=bytearray(b); c[int(n*0.60)]^=0xff; open(F+'/dmg60.nz','wb').write(c); open(F+'/trunc.nz','wb').write(b[:n*85//100])
PY
CASEENV=""
run() {  # run <name> <args...>   (CASEENV="K=V K=V" adds environment; PRE="cmd" runs in the case dir first)
  local name=$1; shift
  for who in orig ours; do
    local d=$OUT/$name/$who; mkdir -p "$d"; local bin=$ORIG; [[ $who = ours ]] && bin=$OURS
    local args=(); for a in "$@"; do args+=("${a//@FX@/$FX}"); done
    [[ -n ${PRE:-} ]] && (cd "$d" && eval "$PRE") >/dev/null 2>&1
    (cd "$d" && env -i PATH=/usr/bin:/bin HOME=/tmp TERM=dumb $CASEENV timeout 60 "$bin" "${args[@]}" </dev/null 2>"$d/err" | head -c 1000000 >"$d/out"; echo "${PIPESTATUS[0]}" >"$d/exit")
    (cd "$d" && find . -mindepth 1 ! -name out ! -name err ! -name exit -printf '%m %TY-%Tm-%Td %TH:%TM %s %y %p\n' | sort >"$d/tree")
    # normalise: banner line 2 (host), timings, rates, our own path prefix
    for f in out err; do sed -i -E "s#$d#<D>#g; s#$OUT#<OUT>#g; s/[0-9]+\.[0-9]+s/<T>s/g; s/[0-9]+ [KMG]?B\/s/<R>/g; 2s/^Intel.*//; s/^Intel\(R\).*MHz.*$/<HOSTLINE>/; s/NanoZip 0.09 alpha\/Linux(32|64)/NanoZip 0.09 alpha\/LinuxNN/" "$d/$f"; done
  done
  echo "$name"
}
# --- listings
run l_long l @FX@/long.nz
run l_long_v l -v @FX@/long.nz
run l_names l @FX@/names.nz
run l_names_v l -v @FX@/names.nz
run l_fo l -fo @FX@/modes_fo.nz
run l_modes l @FX@/modes.nz
run l_mtimes l @FX@/mtimes.nz
run l_mtimes_v l -v @FX@/mtimes.nz
run l_empties l @FX@/empties.nz
run l_links l @FX@/links.nz
run l_dmg l @FX@/dmg60.nz
run l_trunc l @FX@/trunc.nz
run t_dmg t @FX@/dmg60.nz
run t_trunc t @FX@/trunc.nz
run l_two l @FX@/multi.nz @FX@/store.nz
run l_hostile l @FX@/hostile_dotdot.nz
# --- commands
run cmd_xx xx @FX@/multi.nz
run cmd_empty '' @FX@/multi.nz
run cmd_s s @FX@/new.nz @FX@/multi.nz
run cmd_w32c w32c @FX@/multi.nz
run cmd_w32c_noarc w32c
run x_UPNZ x -y @FX@/UP.NZ
run x_UPEXE x -y @FX@/UP.EXE
# --- switches
run x_forcemem x -y -forcemem @FX@/multi.nz
run x_continue x -y -continue @FX@/multi.nz
run x_pause x -y -pause @FX@/multi.nz
run x_xat x -y -x@nolist @FX@/multi.nz
run x_xtwice x -y -xmulti/e.txt -xmulti/b.bin @FX@/multi.nz
run x_xnomatch x -y -xnothing/* @FX@/multi.nz
run x_filt_nomatch x -y @FX@/multi.nz nothing/*
run x_filt_dstar x -y @FX@/multi.nz 'multi/**'
run x_filt_slash x -y @FX@/multi.nz /multi/e.txt
run x_filt_dotdot x -y @FX@/multi.nz ../multi/e.txt
run x_filt_colon x -y @FX@/multi.nz 'multi:e.txt'
run x_filt_store x -y @FX@/store.nz 'multi/*.txt'
run x_sp_dup x -y -sp @FX@/dup.nz
run x_sp_dup_o x -y -sp -oout @FX@/dup.nz
run l_sp l -sp @FX@/dup.nz
run t_sp t -sp @FX@/dup.nz
PRE="printf 'file' > out" run x_o_isfile x -y -oout @FX@/multi.nz
PRE="mkdir ro && chmod 555 ro" run x_o_readonly x -y -oro @FX@/multi.nz
run x_o_dot x -y -o. @FX@/multi.nz
run x_o_dotdot x -y -o.. @FX@/multi.nz
run x_o_root x -y -o/ @FX@/multi.nz
PRE="mkdir real && ln -s real lnk" run x_o_symlink x -y -olnk @FX@/multi.nz
PRE="mkdir -p multi && chmod 555 multi" run x_dir_readonly x -y @FX@/multi.nz
PRE="mkdir -p multi/e.txt" run x_file_is_dir x -y @FX@/multi.nz
# --- shapes
run x_empties x -y @FX@/empties.nz
run x_mixed x -y @FX@/mixed.nz
run x_dup x -y @FX@/dup.nz
run x_links x -y @FX@/links.nz
run x_names x -y @FX@/names.nz
run x_names_co x -y @FX@/names_co.nz
run x_names_hn x -y @FX@/names_hn.nz
run x_modes x -y @FX@/modes.nz
run x_modes_fo x -y -fo @FX@/modes_fo.nz
run x_mtimes x -y @FX@/mtimes.nz
run x_hostile_dotdot x -y @FX@/hostile_dotdot.nz
run x_hostile_abs x -y @FX@/hostile_abs.nz
run t_hostile_dotdot t @FX@/hostile_dotdot.nz
# --- environment
CASEENV="" run env_noterm x -y @FX@/multi.nz
CASEENV="TERM=xterm" run env_xterm x -y @FX@/multi.nz
CASEENV="COLUMNS=40" run env_cols40 t @FX@/long.nz
CASEENV="COLUMNS=200" run env_cols200 t @FX@/long.nz
CASEENV="TZ=UTC" run env_tz_utc l @FX@/mtimes.nz
CASEENV="TZ=Asia/Kolkata" run env_tz_kolkata l @FX@/mtimes.nz
CASEENV="TZ=America/Sao_Paulo" run env_tz_saopaulo l @FX@/mtimes.nz
CASEENV="TZ=UTC" run env_tz_utc_x x -y @FX@/mtimes.nz
CASEENV="LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8" run env_lang_de l @FX@/mtimes.nz
CASEENV="LANG=C.UTF-8 LC_ALL=C.UTF-8" run env_utf8_names x -y @FX@/names.nz
CASEENV=""
echo done
