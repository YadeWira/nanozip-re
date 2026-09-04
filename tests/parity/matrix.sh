#!/bin/bash
# usage: matrix.sh <outdir>  -- runs each case with ORIG and OURS in fresh dirs, saves out/err/exit
OUT=$1; HERE=$(cd "$(dirname "$0")/../.." && pwd); ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz_recon}
P=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}; FX=$OUT/fx; rm -rf $OUT; mkdir -p $FX
# Every fixture is built here with the ORIGINAL, so a clean clone can run this.
cp $P/m_o.nz $FX/multi.nz; cp $P/pf_o.nz $FX/par.nz
( cd $FX && printf 'single\n' > single.txt && env -i PATH=/usr/bin:/bin $ORIG a -co single.nz single.txt >/dev/null 2>&1 && rm -f single.txt )
( cd $FX && printf 'sfx payload\n' > s.txt && env -i PATH=/usr/bin:/bin $ORIG w32c -co sfx.exe s.txt >/dev/null 2>&1 && rm -f s.txt )
( cd $FX && d="a_very_long_directory_name_number_one/and_another_very_long_one_number_two" && mkdir -p "$d" \
  && printf 'long\n' > "$d/a_file_with_a_deliberately_long_name_for_the_40_column_rule.txt" \
  && env -i PATH=/usr/bin:/bin $ORIG a -co -r long.nz a_very_long_directory_name_number_one >/dev/null 2>&1 \
  && rm -rf a_very_long_directory_name_number_one )
# hdr_ok.nz: a valid header whose payload is cut off completely.
python3 - "$FX/multi.nz" "$FX/hdr_ok.nz" <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
open(sys.argv[2],'wb').write(b[:64])
PY
cp $FX/multi.nz $FX/m.bin; head -c 5000 /dev/urandom > $FX/garbage.nz; printf 'hello\n' > $FX/hello.txt
run() { # name, then args (ARC tokens expanded)
  name=$1; shift
  for who in orig ours; do
    d=$OUT/$name/$who; mkdir -p $d; bin=$ORIG; [ $who = ours ] && bin=$OURS
    args=(); for a in "$@"; do args+=("${a//@FX@/$FX}"); done
    ( cd $d && env -i PATH=/usr/bin:/bin HOME=$d TERM=dumb timeout 60 $bin "${args[@]}" </dev/null >$d/out 2>$d/err; echo $? > $d/exit )
    # normalise banner line 2 (CPU/MHz/mem) and elapsed times
    sed -i -E '2s/^Intel.*$/<HOSTLINE>/; s/[0-9]+\.[0-9]+s/<T>s/g; s/[0-9]+ [KMG]?B\/s/<R>/g' $d/out $d/err
  done
}
run noargs
run help help
run info info
run list_multi l @FX@/multi.nz
run list_single l @FX@/single.nz
run list_par l @FX@/par.nz
run list_v l -v @FX@/multi.nz
run test_multi t @FX@/multi.nz
run test_single t @FX@/single.nz
run x_multi x @FX@/multi.nz
run x_single x @FX@/single.nz
run x_par x @FX@/par.nz
run x_y x -y @FX@/multi.nz
run x_opath x -oout_dir @FX@/multi.nz
run x_onefile x @FX@/multi.nz nz_meta_c.txt
run x_missing x @FX@/nope.nz
run x_garbage x @FX@/garbage.nz
run t_garbage t @FX@/garbage.nz
run l_garbage l @FX@/garbage.nz
run x_textfile x @FX@/hello.txt
run badcmd q @FX@/multi.nz
run badopt x -zz @FX@/multi.nz
run x_noarc x
run l_noarc l
run a_nofiles a @FX@/new.nz
run a_missing a @FX@/new2.nz @FX@/nope.txt
run x_sp x -sp @FX@/multi.nz
run x_v x -v @FX@/multi.nz
run t_v t -v @FX@/multi.nz
run x_sfx x @FX@/sfx.exe
run l_sfx l @FX@/sfx.exe
run t_long t @FX@/long.nz
run t_hdrok t @FX@/hdr_ok.nz
run l_ext l @FX@/m.bin
run x_filter x @FX@/multi.nz 'multi/*'
echo done
