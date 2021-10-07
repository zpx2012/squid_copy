#!/bin/bash

# site='67.205.159.15' #NY-HTTP-SV
# url="http://$site/ubuntu-16.04.6-server-i386.template"
# url="http://$site/md5sums.gz"

# url='http://terran.cs.ucr.edu/sdk-tools-linux-3859397.zip'
# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'

# url='http://mirrors.cat.pdx.edu/ubuntu-releases/16.04.6/ubuntu-16.04.6-server-i386.template'
# site='mirrors.cat.pdx.edu'

# url='http://mirror.internet.asn.au/pub/ubuntu/releases/16.04.6/ubuntu-16.04.6-server-i386.template'
# site='mirror.internet.asn.au'

# url='http://mirror.easyname.at/ubuntu-releases/16.04.6/ubuntu-16.04.6-server-i386.template'
# site='mirror.easyname.at'

# url='http://167.172.22.132/ubuntu-16.04.6-server-i386.template'
# site='NY-DGO-O2C'

mkdir -p ~/rs/ABtest_onerun/
outdir=~/rs/ABtest_onerun/$(date +%Y-%m-%d)
mkdir -p $outdir

stime=$(date +%Y%m%d%H%M)
tag=$(hostname)_${site}_ACKP1500_6conn_succrate_${stime}
log=$outdir/curl_squid_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
nfq_out=$outdir/nfq_${tag}.txt
mtr_out=$outdir/mtr_modified_tcp_0.01_100_${tag}.txt
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
    echo $(date -u --rfc-3339=ns): Stop squid 2>&1 | tee -a $log
    bash ~/squid_copy/src/optimack/test/ks.sh squid
    # bash ~/squid_copy/src/optimack/test/ks.sh normal
    # bash ~/squid_copy/src/optimack/test/ks.sh nfq_check
    # bash ~/squid_copy/src/optimack/test/ks.sh loss_rate
    # bash ~/squid_copy/src/optimack/test/ks.sh mtr
    bash ~/squid_copy/src/optimack/test/ks.sh td
    sudo iptables -F
    sudo iptables -t mangle -F
    rm /usr/local/squid/var/logs/cache.log
    # rm -v /tmp/*.pcapng
}

function INT_handler()
{
    cleanup
    rm $curl_singlerun
    exit
}

trap INT_handler SIGINT

i=0
while true; do
    screen -dmS td tcpdump -w $tcpdump_out -s 96 host $site

    echo $(date --rfc-3339=ns): Start squid | tee ${squid_log}
    screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N >> ${squid_log}"
    sleep 2
    
    # screen -dmS nfq_check bash -c "while true; do echo Start: $(date -u --rfc-3339=ns) >> ${nfq_out}; cat /proc/net/netfilter/nfnetlink_queue >> ${nfq_out}; echo >> ${nfq_out}; sleep 0.1; done"

    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    echo Start: $(date --rfc-3339=second) 2>&1 | tee -a $log
    start=$(date +%s.%N)
    curl -LJ4vk -o /dev/null -x http://127.0.0.1:3128 --speed-time 600 $url 2>&1 | tee -a $curl_singlerun
    cat $curl_singlerun >> $log
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    echo $(date --rfc-3339=ns): Curl download end, duration $duration 2>&1 | tee -a $log

    sleep 2
    cleanup

    echo "squid_log:" ; tail -100 ${squid_log}; echo;
    # echo >> $log
    # cat ${squid_log} >> $log
    if grep -q "range_recv thread starts" ${squid_log} ;
    then
        mv /var/optack.log $outdir/optack_${stime}.log
        ((i++))
        if (( i > 6 ));
        then
            exit
        fi
    else
        rm $tcpdump_out
    fi

    rm $curl_singlerun

    ps -ef | grep squid 2>&1 | tee -a $log
    echo | tee -a $log
    echo | tee -a $log
done
