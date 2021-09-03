#! /bin/bash
# usage: ./test_off_packet.sh [tag]

# site='142.93.117.107'
# site='138.68.49.206' #SF-HTTP-SV
#site='67.205.159.15' #NY-HTTP-SV
# url="http://$site/ubuntu-16.04.6-server-i386.template"
# url="http://$site/md5sums.gz"

# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# url='http://mirror.math.princeton.edu/pub/ubuntu/indices/md5sums.gz'
# site='mirror.math.princeton.edu'

site=$3
url=$4

mkdir -p ~/rs/ABtest_onerun/
outdir=~/rs/ABtest_onerun/$(date +%Y-%m-%d)/
mkdir -p $outdir
stime=$(date +%Y%m%d%H%M%S)
tag=$(hostname)_${site}_http_${2}_${stime}
squid_out=$outdir/curl_squid_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt
tcpdump_out=$outdir/tcpdump_${tag}.pcap

inf=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
sudo ethtool -K $inf tso off gso off gro off

function cleanup()
{
    sleep 2
    sudo /usr/local/squid/sbin/squid -k interrupt
    sleep 5
    if screen -ls | grep 'squid'; 
    then
        # exit
        sudo /usr/local/squid/sbin/squid -k kill
    fi
    sudo killall squid
    bash ~/squid_copy/src/optimack/test/ks.sh normal
    bash ~/squid_copy/src/optimack/test/ks.sh td
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


screen -dmS td tcpdump -w $tcpdump_out -s 600 host $site and tcp port 80
screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N 2>&1 >$squid_log"
sleep 2

echo Start: $(date -Iseconds) >> $normal_out
echo Start: $(date -Iseconds) >> $squid_out 
screen -dmS normal bash -c "curl -LJ4vk $url -o /dev/null 2>&1 | tee -a ${normal_out}"
curl -LJ4vk $url -o /dev/null -x http://127.0.0.1:3128 --speed-time 120 2>&1 | tee -a ${squid_out}
cleanup

if grep -q "left intact" $squid_out;
then
    rm $tcpdump_out
    # screen -dmS tshark bash -c "tshark -r $tcpdump_out -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y 'tcp.srcport eq 80' > ${tcpdump_out}.tshark; rm $tcpdump_out"
# elif grep -q "curl: (28) Operation too slow" $squid_out; 
then
    cat ${squid_log} >> ${squid_log}_e28
    mv /var/optack.log $outdir/optack_e28_${tag}.log
    mv ${tcpdump_out} ${tcpdump_out}_e28
elif grep -q "curl: (18)" $squid_out ;
then
    cat ${squid_log} >> ${squid_log}_e18
    mv /var/optack.log $outdir/optack_e18_${tag}.log
    mv ${tcpdump_out} ${tcpdump_out}_e18
    mv /usr/local/squid/var/cache/squid/core $outdir/core_e18_${tag}
fi
