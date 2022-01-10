#! /bin/bash
# usage: ./test_off_packet.sh [tag]

outdir=$1
site=$3
url=$4
stime=$(date +%Y%m%d%H%M%S)

tag=$(hostname)_${site}_http_ackpace${7}+${6}optim+1range_${stime}
squid_out=$outdir/curl_squid_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt
# tcpdump_out=$outdir/tcpdump_${tag}.pcap

inf=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
sudo ethtool -K $inf tso off gso off gro off
sudo sysctl -w net.ipv4.tcp_timestamps=0
ulimit -c unlimited
rm /var/optack.log

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

sed -i "s/define BACKUP_MODE .*/define BACKUP_MODE 0/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define RANGE_MODE .*/define RANGE_MODE 1/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define CONN_NUM .*/define CONN_NUM $6/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define ACKPACING .*/define ACKPACING $7/g" ~/squid_copy/src/optimack/Optimack.cc
cd ~/squid_copy/
#./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
make install

# screen -dmS td tcpdump -w $tcpdump_out -s 200 host $site and tcp port 80
screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N 2>&1 >$squid_log"
sleep 2

echo Start: $(date -Iseconds) >> $squid_out 
curl -LJ4vk $url -o /dev/null -x http://127.0.0.1:3128 --speed-time 360 2>&1 | tee -a ${squid_out}
echo >> $squid_out
echo >> $squid_out
cleanup

if grep -q "left intact" $squid_out;
then
    # rm $tcpdump_out
    # screen -dmS tshark bash -c "tshark -r $tcpdump_out -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y 'tcp.srcport eq 80' > ${tcpdump_out}.tshark; rm $tcpdump_out"
elif grep -q "curl: (28) Operation too slow" $squid_out; 
then
    cat ${squid_log} >> ${squid_log}_e28
    mv /var/optack.log $outdir/optack_e28_${tag}.log
    mv ${tcpdump_out} ${tcpdump_out}_e28
elif grep -q "curl: (18)" $squid_out ;
then
    cat ${squid_log} >> ${squid_log}_e18
#    mv /var/optack.log $outdir/optack_e18_${tag}.log
    mv ${tcpdump_out} ${tcpdump_out}_e18
    mv /usr/local/squid/var/cache/squid/core $outdir/core_e18_${tag}
fi
