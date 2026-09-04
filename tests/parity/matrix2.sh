#!/bin/bash
# switch/command matrix: ORIG vs OURS, fresh dir per case; captures out/err/exit + file tree with mode+mtime
OUT=$1; HERE=$(cd "$(dirname "$0")/../.." && pwd); ORIG=${NZ_ORIG:-$HERE/../linux32/nz}; OURS=${NZ_RECON:-$HERE/bin/nz_recon}
P=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}; FX=$OUT/fx; rm -rf $OUT; mkdir -p $FX
cp $P/m_o.nz $FX/multi.nz; cp $P/s_o.nz $FX/single.nz; cp $P/m_n.nz $FX/store.nz
run() { name=$1; shift
  for who in orig ours; do
    d=$OUT/$name/$who; mkdir -p $d/pre; bin=$ORIG; [ $who = ours ] && bin=$OURS
    args=(); for a in "$@"; do args+=("${a//@FX@/$FX}"); done
    # pre-existing file for overwrite tests
    case $name in x_y|x_after|x_after2) mkdir -p $d/multi && printf 'OLD' > $d/multi/e.txt;; esac
    ( cd $d && env -i PATH=/usr/bin:/bin HOME=$d TERM=dumb timeout 30 $bin "${args[@]}" </dev/null 2>$d/err | head -c 1000000 >$d/out; echo ${PIPESTATUS[0]} > $d/exit
      find . -type f ! -name out ! -name err ! -name exit ! -name tree -printf '%m %TY-%Tm-%Td %TH:%TM %s %p\n' | sort > $d/tree )
    sed -i -E '2s/^Intel.*$/<HOSTLINE>/; s/[0-9]+\.[0-9]+s/<T>s/g; s/[0-9]+ [KMG]?B\/s/<R>/g; s#'"$d"'#<DIR>#g' $d/out $d/err
  done; }
# general switches on x
run x_r        x -y -r @FX@/multi.nz
run x_t4       x -y -t4 @FX@/multi.nz
run x_t0       x -y -t0 @FX@/multi.nz
run x_tbad     x -y -tx @FX@/multi.nz
run x_br       x -y -br1m @FX@/multi.nz
run x_bw       x -y -bw2m @FX@/multi.nz
run x_brbad    x -y -br @FX@/multi.nz
run x_hn       x -y -hn @FX@/multi.nz
run x_hc       x -y -hc @FX@/multi.nz
run x_hC       x -y -hC @FX@/multi.nz
run x_hf       x -y -hf @FX@/multi.nz
run x_hz       x -y -hz @FX@/multi.nz
run x_nt       x -y -nt @FX@/multi.nz
run x_np       x -y -np @FX@/multi.nz
run x_nm       x -y -nm @FX@/multi.nz
run x_sp       x -y -sp @FX@/multi.nz
run x_o_attached x -y -oout_dir @FX@/multi.nz
run x_o_sep    x -y -o out_dir @FX@/multi.nz
run x_o_slash  x -y -oout_dir/ @FX@/multi.nz
run x_o_abs    x -y -o@FX@/../absout @FX@/multi.nz
run x_o_nested x -y -oa/b/c @FX@/multi.nz
run x_xattached x -y -xmulti/e.txt @FX@/multi.nz
run x_x_sep    x -y -x multi/e.txt @FX@/multi.nz
run x_xglob    x -y '-x*.txt' @FX@/multi.nz
run x_xdir     x -y '-xmulti/sub/*' @FX@/multi.nz
run x_y        x -y @FX@/multi.nz
run x_v        x -y -v @FX@/multi.nz
run x_vv       x -y -v -v @FX@/multi.nz
run x_cO       x -y -cO @FX@/multi.nz
run x_cn       x -y -cn @FX@/multi.nz
run x_cz       x -y -cz @FX@/multi.nz
run x_p2       x -y -p2 @FX@/multi.nz
run x_m64      x -y -m64m @FX@/multi.nz
run x_mbad     x -y -mfoo @FX@/multi.nz
run x_se       x -y -se @FX@/multi.nz
run x_ss       x -y -ss @FX@/multi.nz
run x_sz       x -y -sz @FX@/multi.nz
run x_fo       x -y -fo @FX@/multi.nz
run x_swapinout x -y -swapinout @FX@/multi.nz
run x_forceout x -y -forceout @FX@/multi.nz
run x_nofnext  x -y -nofilenameext @FX@/multi.nz
run x_nofnext2 x -y -nofilenameext @FX@/multi
run x_dash     x -y - @FX@/multi.nz
run x_dashfile x -y - @FX@/multi.nz -weird
run x_after    x @FX@/multi.nz -y
run x_after2   x @FX@/multi.nz -v -y
run x_Y        x -y -Y @FX@/multi.nz
run x_yy       x -y -yy @FX@/multi.nz
run x_dd       x -y --y @FX@/multi.nz
run x_empty    x -y '' @FX@/multi.nz
run x_filt_exact x -y @FX@/multi.nz multi/e.txt
run x_filt_glob  x -y @FX@/multi.nz 'multi/*.txt'
run x_filt_star  x -y @FX@/multi.nz '*'
run x_filt_q     x -y @FX@/multi.nz 'multi/?.txt'
run x_filt_dir   x -y @FX@/multi.nz multi/sub
run x_filt_dirsl x -y @FX@/multi.nz multi/sub/
run x_filt_base  x -y @FX@/multi.nz e.txt
run x_filt_two   x -y @FX@/multi.nz multi/e.txt multi/b.bin
run x_filt_x     x -y '-xmulti/e.txt' @FX@/multi.nz 'multi/*'
run x_filt_case  x -y @FX@/multi.nz MULTI/E.TXT
# t / l with switches
run t_v        t -v @FX@/multi.nz
run t_hn       t -hn @FX@/multi.nz
run t_filt     t @FX@/multi.nz multi/e.txt
run t_x        t '-x*.txt' @FX@/multi.nz
run l_filt     l @FX@/multi.nz multi/e.txt
run l_glob     l @FX@/multi.nz '*.txt'
run l_x        l '-x*.txt' @FX@/multi.nz
run l_v_filt   l -v @FX@/multi.nz 'multi/sub/*'
run l_y        l -y @FX@/multi.nz
run l_r        l -r @FX@/multi.nz
run l_store    l @FX@/store.nz
run l_two      l @FX@/multi.nz @FX@/single.nz
run l_bad      l -zz @FX@/multi.nz
run info_extra info foo bar
run help_extra help -x
run x_store    x -y @FX@/store.nz
run t_store    t @FX@/store.nz
echo done
