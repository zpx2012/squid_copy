#! /bin/bash
# usage: ./test_rcvbuf_once.sh

outdir=~/rs/$(date -u +%Y-%m-%d)
mkdir -p $outdir
stime=$(date -u +%Y%m%d%H%M)
curl_out=$outdir/curl_$(hostname)_terran_http_${stime}.txt
normal_out=$outdir/normal_$(hostname)_terran_http_${stime}.txt
ss_out=$outdir/ss_$(hostname)_terran_http_${stime}.txt
ss_whole_out=$outdir/sswhole_$(hostname)_terran_http_${stime}.txt

echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $ss_out
echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $curl_out
screen -dmS ss bash -c "while true; do date -Ins >> ${ss_out}; ss -ptm -4 state established >> ${ss_whole_out}; echo >> ${ss_whole_out}; ss -ptm -4 state established | grep rb167772176 >> ${ss_out}; echo >> ${ss_out}; sleep 0.1; done"
screen -dmS normal bash -c "curl http://terran.cs.ucr.edu/my.mp4 -o /dev/null 2>&1 | tee ${normal_out}"
curl http://terran.cs.ucr.edu/my.mp4 -o /dev/null -x http://127.0.0.1:3128 --speed-time 20 2>&1 | tee ${curl_out}
screen -S ss -X quit
screen -S normal -X quit