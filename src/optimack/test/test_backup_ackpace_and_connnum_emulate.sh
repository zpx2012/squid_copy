#!/bin/bash

# site='142.93.117.107'
#site='138.68.49.206' #SF-HTTP-SV
site='67.205.159.15' #NY-HTTP-SV
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


nums=(1 2 3 4 5 6 7 8) #9 10 11 12 13 14 15 16
# ackpaces=(200 222 250 286 333 400 500 667 1000 2000 3333 10000)
ackpaces=(250 500 750 1000 1250 1500 1750 2000 2250 2500 2750 3000)
i=0

function one_round_test(){
    cur_num=${nums[i%${#nums[@]}]}
    sed -i "s/define ACKPACING .*/define ACKPACING 1000/g" ~/squid_copy/src/optimack/Optimack.cc
    sed -i "s/define CONN_NUM .*/define CONN_NUM ${cur_num}/g" ~/squid_copy/src/optimack/Optimack.cc
    cd ~/squid_copy/
    make install
    echo
    echo ${cur_num}optim+1range_ackpace1000_$1
    bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh conn_num_ackpace1000_$1 ${cur_num}optim+1range_ackpace1000_$1 $site $url
        
    cur_ackpace=${ackpaces[i%${#ackpaces[@]}]}
    sed -i "s/define CONN_NUM .*/define CONN_NUM 5/g" ~/squid_copy/src/optimack/Optimack.cc
    sed -i "s/define ACKPACING .*/define ACKPACING ${cur_ackpace}/g" ~/squid_copy/src/optimack/Optimack.cc
    cd ~/squid_copy/
    make install
    echo
    echo ackpace${cur_ackpace}_5optim+1range_$1
    bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh ackpace_5optim_$1 ackpace${cur_ackpace}_5optim+1range_$1 $site $url

}

while true; do
    sed -i "s/define BACKUP_MODE .*/define BACKUP_MODE 1/g" ~/squid_copy/src/optimack/Optimack.cc
    sed -i "s/define RANGE_MODE .*/define RANGE_MODE 0/g" ~/squid_copy/src/optimack/Optimack.cc
    one_round_test "backup"

    sed -i "s/define BACKUP_MODE .*/define BACKUP_MODE 0/g" ~/squid_copy/src/optimack/Optimack.cc
    sed -i "s/define RANGE_MODE .*/define RANGE_MODE 1/g" ~/squid_copy/src/optimack/Optimack.cc
    one_round_test "range"

    i=$((i+1))

    echo
    rm $curl_singlerun
done
