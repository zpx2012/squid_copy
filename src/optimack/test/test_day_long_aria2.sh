#! /bin/bash
# usage: ./test_off_packet.sh [tag]

sudo apt-get install -y aria2

url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'


mkdir -p ~/rs/ABtest_onerun/
outdir=~/rs/ABtest_onerun/$(date +%Y-%m-%d)
mkdir -p $outdir
stime=$(date +%Y%m%d%H%M%S)
tag=$(hostname)_${site}_http_${stime}
squid_out=$outdir/curl_squid_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
aria2_out=$outdir/aria2_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt


function INT_handler()
{
    exit
}

trap INT_handler SIGINT


while true;do

    echo $(date -Iseconds): Slowdown test
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 20 $url 2>&1 | tee $curl_singlerun
    echo
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; then
        echo Start: $(date -Iseconds) >> $normal_out
        screen -dmS normal bash -c "while true; do curl -LJ4vk $url -o /dev/null 2>&1 | tee -a ${normal_out};done"

        echo Start: $(date -Iseconds) >> ${aria2_out} 
        aria2c $url -x 10 --continue=false | tee -a ${aria2_out}
        rm -v ubuntu-16.04.5-server-i386.iso*

        # bash ~/squid_copy/src/optimack/test/ks.sh normal
        # screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N >> ${squid_log}"
        # sleep 2

        # echo Start: $(date -Iseconds) >> $squid_out 
        # curl -LJ4vk $url -o /dev/null -x http://127.0.0.1:3128 -m 120 2>&1 | tee -a ${squid_out}
        # cleanup
    else
        sleep 300
    fi
done
