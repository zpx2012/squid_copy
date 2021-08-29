#! /bin/bash
# usage: ./test_rcvbuf_once.sh


# site='142.93.117.107'
# site='138.68.49.206' #SF-HTTP-SV
site='67.205.159.15' #NY-HTTP-SV
url="http://$site/ubuntu-16.04.6-server-i386.iso"
# url="http://$site/ubuntu-16.04.6-server-i386.template"
# url="http://$site/md5sums.gz"

mkdir -p ~/rs/ABtest_onerun/
outdir=~/rs/ABtest_onerun/$(date +%Y-%m-%d)
mkdir -p $outdir

stime=$(date +%Y%m%d%H%M)
tag=$(hostname)_${site}_rcvbuf_$1_${stime}

stime=$(date -u +%Y%m%d%H%M)
curl_out=$outdir/curl_${tag}.txt
normal_out=$outdir/normal_${tag}.txt
ss_out=$outdir/ss_${tag}.txt
ss_whole_out=$outdir/sswhole_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt
tcpdump_out=$outdir/tcpdump_${tag}.pcap

function cleanup()
{
    sudo /usr/local/squid/sbin/squid -k interrupt
    sleep 5
    if screen -ls | grep 'squid'; 
    then
        # exit
        sudo /usr/local/squid/sbin/squid -k kill
    fi
    sudo killall squid
    bash ~/squid_copy/src/optimack/test/ks.sh td
    bash ~/squid_copy/src/optimack/test/ks.sh ss
    sudo iptables -F
    sudo iptables -t mangle -F
    rm /usr/local/squid/var/logs/cache.log
}

function INT_handler()
{
    cleanup
    exit
}

trap INT_handler SIGINT

screen -dmS td tcpdump -w $tcpdump_out -s 96 host $site
screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N 2>&1 >$squid_log"
sleep 2

echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $ss_out
echo "/proc/sys/net/core/rmem_max:" $(cat /proc/sys/net/core/rmem_max) >> $curl_out

screen -dmS ss bash -c "while true; do date -Ins >> ${ss_whole_out}; ss -o state established '( dport = 80 )' -tnm >> ${ss_whole_out}; echo >> ${ss_whole_out}; sleep 0.01; done"
# screen -dmS ss bash -c "while true; do date -Ins >> ${ss_out}; ss -ptm -4 state established >> ${ss_whole_out}; echo >> ${ss_whole_out}; ss -ptm -4 state established | grep rb167772176 >> ${ss_out}; echo >> ${ss_out}; sleep 0.1; done"
# screen -dmS normal bash -c "curl http://terran.cs.ucr.edu/my.mp4 -o /dev/null 2>&1 | tee ${normal_out}"
curl $url -o /dev/null -x http://127.0.0.1:3128 --speed-time 200 2>&1 | tee ${curl_out}
cleanup