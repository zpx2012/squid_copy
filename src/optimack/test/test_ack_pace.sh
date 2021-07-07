#!/bin/bash

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'

sed -i "s/define CONN_NUM .*/define CONN_NUM 8/g" ~/squid_copy/src/optimack/Optimack.cc

ackpaces=(250 500 750 1000 1250 1500 1750 2000 2250 2500 2750 3000)
i=0
while true; do
    echo $(date -Iseconds): Slowdown test
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    echo
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; 
    then
        sed -i "s/define ACKPACING .*/define ACKPACING ${ackpaces[i]}/g" ~/squid_copy/src/optimack/Optimack.cc
        cd ~/squid_copy/
        #./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
        make install
        echo 
        echo ackpace${ackpaces[i]}_8optim+1range
        bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh ackpace${ackpaces[i]}_8optim+1range
        echo
        i=$(((i+1)%${#ackpaces[@]}))
    else
        sleep 120
    fi
    rm $curl_singlerun
done