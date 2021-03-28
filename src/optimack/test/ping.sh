#! /bin/bash
#ping.sh [ip/hostname] [outdir] [starttime]

log=${2}/ping_$(hostname)_${1}_${3}.txt
while true;do
    echo $(date -u --rfc-3339=ns): Start ping 2>&1 | tee -a $log
    ping -W 10 -c 200 -i 0.01 -q $1 2>&1 | tee -a $log
    echo >> $log
done