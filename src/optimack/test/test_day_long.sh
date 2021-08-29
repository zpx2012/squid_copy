#!/bin/bash

# site='142.93.117.107'
# site='138.68.49.206' #SF-HTTP-SV
site='67.205.159.15' #NY-HTTP-SV
# url="http://$site/ubuntu-16.04.6-server-i386.template"
url="http://$site/ubuntu-16.04.6-server-i386.iso"
# url="http://$site/md5sums.gz"

# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'

sed -i "s/define CONN_NUM .*/define CONN_NUM $1/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define ACKPACING .*/define ACKPACING $2/g" ~/squid_copy/src/optimack/Optimack.cc
cd ~/squid_copy/
#./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
make install

while true; do
    echo $(date -Iseconds): Slowdown test
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    echo
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; 
    then
        echo
        echo ${1}optim+1range_ackpace${2}
        bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh daylong_${1}optim_ackpace${2} daylong_${1}optim+1range_ackpace${2} $site $url
        echo
    else
        sleep 120
    fi
    rm $curl_singlerun
done