#!/bin/bash

site='142.93.117.107'
# site='138.68.49.206' #SF-HTTP-SV
#site='67.205.159.15' #NY-HTTP-SV
# url="http://$site/ubuntu-16.04.6-server-i386.template"
url="http://$site/md5sums.gz"

# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'


nums=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
ackpaces=(200 222 250 286 333 400 500 667 1000 2000 3333 10000)
# ackpaces=(250 500 750 1000 1250 1500 1750 2000 2250 2500 2750 3000)

i=0

sed -i "s/define BACKUP_MODE .*/define BACKUP_MODE 0/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define RANGE_MODE .*/define RANGE_MODE 1/g" ~/squid_copy/src/optimack/Optimack.cc

while true; do
    # echo $(date -Iseconds): Slowdown test
    # curl_singlerun=curl_proxy_singlerun_$(date +%s)
    # curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    # echo
    # if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; then
        if [ $((i % 2)) -eq 0 ]; then
            sed -i "s/define ACKPACING .*/define ACKPACING 1500/g" ~/squid_copy/src/optimack/Optimack.cc
            sed -i "s/define CONN_NUM .*/define CONN_NUM ${nums[i/2%${#nums[@]}]}/g" ~/squid_copy/src/optimack/Optimack.cc
            cd ~/squid_copy/
            #./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
            make install
            echo
            echo ${nums[i/2%${#nums[@]}]}optim+1range_ackpace1500
            bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh conn_num_ackpace1500 ${nums[i/2%${#nums[@]}]}optim+1range_ackpace1500 $site $url
        else
            sed -i "s/define CONN_NUM .*/define CONN_NUM 5/g" ~/squid_copy/src/optimack/Optimack.cc
            sed -i "s/define ACKPACING .*/define ACKPACING ${ackpaces[i/2%${#ackpaces[@]}]}/g" ~/squid_copy/src/optimack/Optimack.cc
            cd ~/squid_copy/
            #./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
            make install
            echo
            echo ackpace${ackpaces[i/2%${#ackpaces[@]}]}_5optim+1range
            bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh ackpace_5optim ackpace${ackpaces[i%${#ackpaces[@]}]}_5optim+1range $site $url
        fi
        i=$((i+1))
    # else
    #     sleep 120
    # fi
    echo
    rm $curl_singlerun
done
