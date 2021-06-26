#!/bin/bash

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'

sed -i "s/define ACKPACING .*/define ACKPACING 3000/g" ~/squid_copy/src/optimack/Optimack.cc

nums=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
i=0
while true; do
    echo $(date -Iseconds): Slowdown test
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    echo
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; 
    then
        sed -i "s/define CONN_NUM .*/define CONN_NUM ${nums[i]}/g" ~/squid_copy/src/optimack/Optimack.cc
        cd ~/squid_copy/
        make install
        echo
        echo ${nums[i]}optim+1range_ackpace3000
        bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh ${nums[i]}optim+1range
        i=$(((i+1)%${#nums[@]}))
    else
        sleep 120
    fi
    rm $curl_singlerun
done