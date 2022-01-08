#! /bin/bash
# usage: ./test_off_packet.sh [tag]

outdir=$1
site=$3
url=$4
stime=$5
tag=$(hostname)_${site}_http_${stime}
aria2_out=$outdir/aria2_${tag}.txt

echo Start: $(date -Iseconds) >> ${aria2_out} 
aria2c $url -x 10 --continue=false | tee -a ${aria2_out}
rm -v ubuntu-16.04.6-server-i386.iso*
