#!/bin/bash

# url='http://terran.cs.ucr.edu/sdk-tools-linux-3859397.zip'
# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
site='mirrors.mit.edu'

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

mkdir -p ~/rs/large_file_succ_rate/
outdir=~/rs/large_file_succ_rate/$(date -u +%Y-%m-%d)
mkdir -p $outdir

stime=$(date -u +%Y%m%d%H%M)
tag=$(hostname)_${site}_ACKP2000_6conn_succrate_${stime}
log=$outdir/curl_squid_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
nfq_out=$outdir/nfq_${tag}.txt
mtr_out=$outdir/mtr_modified_tcp_0.01_100_${tag}.txt

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
    bash ~/squid_copy/src/optimack/test/ks.sh normal
    # bash ~/squid_copy/src/optimack/test/ks.sh nfq_check
    bash ~/squid_copy/src/optimack/test/ks.sh loss_rate
    bash ~/squid_copy/src/optimack/test/ks.sh mtr
    sudo iptables -F
    sudo iptables -t mangle -F
    # rm -v /tmp/*.pcapng
}

function INT_handler()
{
    cleanup
    rm $curl_singlerun
    exit
}

trap INT_handler SIGINT

while true; do
    screen -dmS normal bash -c "echo Start: $(date --rfc-3339=second) >> ${normal_out}; curl -v --limit-rate 500k --speed-time 120 $url -o /dev/null 2>&1 | tee -a ${normal_out}"
    # screen -dmS mtr bash -c "while true; do sudo ~/mtr-modified/mtr -zwnr4 -i 0.01 -c 100 -P 80 $site | tee -a $mtr_out; done"
    # screen -dmS loss_rate bash ~/squid_copy/src/optimack/test/ping.sh $site $outdir $stime

    echo $(date --rfc-3339=ns): Start squid | tee ${squid_log}
    screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N >> ${squid_log}"
    sleep 2
    
    # screen -dmS nfq_check bash -c "while true; do echo Start: $(date -u --rfc-3339=ns) >> ${nfq_out}; cat /proc/net/netfilter/nfnetlink_queue >> ${nfq_out}; echo >> ${nfq_out}; sleep 0.1; done"

    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    echo Start: $(date --rfc-3339=second) 2>&1 | tee -a $log
    start=$(date +%s.%N)
    curl -LJ4vk -o /dev/null -x http://127.0.0.1:3128 -m 600 $url 2>&1 | tee -a $curl_singlerun
    cat $curl_singlerun >> $log
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    echo $(date --rfc-3339=ns): Curl download end, duration $duration 2>&1 | tee -a $log

    sleep 2
    cleanup

    echo "squid_log:" ; tail -100 ${squid_log}; echo;
    # echo >> $log
    # cat ${squid_log} >> $log

    if grep -q "Packet lost on all connections" ${squid_log} ;
    then
        mv ~/rs/seq_gaps_count.csv  $outdir/seq_gaps_count_lost_all_bash_$(date -Iseconds).csv
        mv ~/rs/seq_gaps.csv  $outdir/seq_gaps_lost_all_bash_$(date -Iseconds).csv
    # else
    #     echo >> $outdir/seq_gaps_count.csv
    #     echo >> $outdir/seq_gaps_count.csv
    #     cat ~/rs/seq_gaps_count.csv >> $outdir/seq_gaps_count.csv       
    fi

    # if grep -q "curl: (28) Operation too slow" $curl_singlerun ; 
    # then
    #     mv ~/rs/exp.log $outdir/exp_idle.log
    #     mv ~/rs/optack.log $outdir/optack_idle.log
    # elif grep -q "curl: (18)" $curl_singlerun ;
    # then
    #     mv ~/rs/exp.log $outdir/exp_lost_all_$(date -Iseconds).log
    #     mv ~/rs/optack.log $outdir/optack_lost_all_$(date -Iseconds).log    
    #     if ! grep -q "cat /proc/net/netfilter/nfnetlink_queue" $squid_log ;
    #     then
    #         echo Error: No print | tee -a $log 
    #         mv ~/rs/exp.log $outdir/exp_28_noprint.log
    #         mv ~/rs/optack.log $outdir/optack_28_noprint.log
    #     fi
    # fi

    # elif grep -q "intact"  $curl_singlerun ;
    # then
    #     mv ~/rs/seq.csv $outdir/seq_success.csv
    #     mv ~/rs/ack.csv $outdir/ack_success.csv
    # fi
    rm $curl_singlerun


    # sleep 5
    # echo $(date -u --rfc-3339=ns): Wait 5s for squid to stop 2>&1 | tee -a $log
    ps -ef | grep squid 2>&1 | tee -a $log
    echo | tee -a $log
    echo | tee -a $log
done
	
#~/rs/large_file_succ_rate/2021-03-14/curl_squid_SH-OPTACK_mirror.easyname.at_ACKP2000_15conn_bottleneck_202103140729.txt
