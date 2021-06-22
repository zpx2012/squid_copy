#!/bin/bash

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'


while true; do
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; 
    then
        for i in 1 2 3 4 5 6 7; do
            sed -i "s/define CONN_NUM .*/define CONN_NUM $i/g" ~/squid_copy/src/optimack/Optimack.cc
            cd ~/squid_copy/
            make install
            bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh ${i}optim+1range
        done
    else
        sleep 120
    fi
    rm $curl_singlerun
done