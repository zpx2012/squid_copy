#! /bin/bash
# usage: ./test_off_packet.sh [tag]

mkdir -p ~/rs/off_packet_plot/
outdir=~/rs/off_packet_plot/$(date -u +%Y-%m-%d)
mkdir -p $outdir
stime=$(date -u +%Y%m%d%H%M)
tag=$(hostname)_terran_http_${1}_${stime}
curl_out=$outdir/curl_${tag}.txt
normal_out=$outdir/normal_${tag}.txt
ss_out=$outdir/ss_${tag}.txt
ss_whole_out=$outdir/sswhole_${tag}.txt

echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $ss_out
echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $curl_out
screen -dmS ss bash -c "while true; do date -Ins >> ${ss_out}; ss -ptm -4 state established >> ${ss_whole_out}; echo >> ${ss_whole_out}; ss -ptm -4 state established | grep rb167772176 >> ${ss_out}; echo >> ${ss_out}; sleep 0.1; done"
echo Start: $(date +'%Y-%m-%d %H:%M:%S') >> $normal_out
echo Start: $(date +'%Y-%m-%d %H:%M:%S') >> $curl_out 
screen -dmS normal bash -c "curl http://terran.cs.ucr.edu/my.mp4 -o /dev/null 2>&1 | tee -a ${normal_out}"
curl http://terran.cs.ucr.edu/my.mp4 -o /dev/null -x http://127.0.0.1:3128 --speed-time 20 2>&1 | tee -a ${curl_out}

bash ~/squid_copy/src/optimack/test/ks.sh ss
bash ~/squid_copy/src/optimack/test/ks.sh normal
mv ~/off_packet.csv $outdir/off_packet_${tag}.csv
mv ~/rwnd.csv $outdir/rwnd_${tag}.csv
mv ~/adjust_rwnd.csv $outdir/adjust_rwnd_${tag}.csv