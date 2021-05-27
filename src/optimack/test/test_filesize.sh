#!/bin/bash

log=~/rs/ABtest_onerun/filesize_$(date -u +%m%d%H%M).txt
cat $1 | while IFS=',' read url size; do
    screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N"
    echo $(date -u --rfc-3339=ns): Start squid 2>&1 | tee -a $log
    sleep 2

    echo $(date -u --rfc-3339=ns): Curl download start - Proxy mode 2>&1 | tee -a $log
    start=$(date +%s.%N)
    curl -LJ4k -o /dev/null -x http://127.0.0.1:3128 --speed-time 10 $url 2>&1 | tee -a $curl_singlerun
    cat $curl_singlerun >> $log
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    echo $duration, $size >> filesize_result.txt
    echo $(date -u --rfc-3339=ns): Curl download end, duration $duration 2>&1 | tee -a $log
    
    sudo /usr/local/squid/sbin/squid -k interrupt
    sleep 5
    if screen -ls | grep 'squid'; 
    then
        sudo /usr/local/squid/sbin/squid -k kill
    fi
    sudo killall squid
    echo $(date -u --rfc-3339=ns): Stop squid 2>&1 | tee -a $log
    
    sudo iptables -F
    sleep 5
    echo $(date -u --rfc-3339=ns): Wait 29s for squid to stop 2>&1 | tee -a $log
    ps -ef | grep squid 2>&1 | tee -a $log
done

	