#! /bin/bash
# usage: ./test_off_packet.sh [tag]

sudo apt-get install -y aria2

# site='142.93.117.107'
# site='138.68.49.206' #SF-HTTP-SV
# site='67.205.159.15' #NY-HTTP-SV
# site='143.198.65.98' #SF1-4G
# site='161.35.100.102' #NY2-4G
# url="http://$site/ubuntu-16.04.6-server-i386.template"
# url="http://$site/ubuntu-16.04.6-server-i386.iso"
# url="http://$site/md5sums.gz"

url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'

mode=$1
con_num=$2
ackpace=$3

mkdir -p ~/rs/ABtest_onerun/
outdir=~/rs/ABtest_onerun/$(date +%Y-%m-%d)
mkdir -p $outdir
stime=$(date +%Y%m%d%H%M%S)


function INT_handler()
{
    bash ~/squid_copy/src/optimack/test/ks.sh normal
    bash ~/squid_copy/src/optimack/test/ks.sh ping
    exit
}

trap INT_handler SIGINT

screen -dmS normal bash ~/squid_copy/src/optimack/test/test_daylong_normal_only.sh $outdir ${mode} $site $url $stime
screen -dmS ping bash ~/squid_copy/src/optimack/test/ping.sh $site $outdir $stime

while true;do
    echo $(date -Iseconds): Slowdown test
    curl_singlerun=curl_proxy_singlerun_$(date +%s)
    curl -LJ4vk -o /dev/null -m 10 $url 2>&1 | tee $curl_singlerun
    echo
    if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; 
    then
        bash ~/squid_copy/src/optimack/test/test_daylong_run_${mode}_once.sh $outdir ackpace${ackpace}+${con_num}optim+1range $site $url $stime $con_num $ackpace
    else
        sleep 300
    fi
done
