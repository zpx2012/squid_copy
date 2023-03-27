#！/bin/bash

function one_round(){
    domain=$1
    out_dir=$2
    output_file=$3

    # python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file normal

    # ~/squid_only/sbin/squid
    # python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file squid
    # ~/squid_only/sbin/squid -k shutdown
    # ~/squid_only/sbin/squid -k kill
    # killall squid  
    
    screen -dmS proxy bash -c "~/squid/sbin/squid -N >> $out_dir/squid_output_${domain}_$(date +%Y-%m-%dT%H:%M:%S).txt"
    python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file proxy
    screen -S proxy -X quit
    ~/squid/sbin/squid -k shutdown
    ~/squid/sbin/squid -k kill
    killall squid
}

outdir=~/rs/browser/$(date +%Y-%m-%d)/
mkdir -p $outdir
outputfile=browser_alexa_$(date +%Y-%m-%dT%H:%M:%S).txt
url='https://mirrors.mit.edu/ubuntu/ls-lR.gz'

while true;
do
    # echo $(date -Iseconds): Slowdown test
    # curl_singlerun=curl_proxy_singlerun_$(date +%s)
    # curl -LJ4k -o /dev/null -m 20 --limit-rate 800k $url 2>&1 | tee $curl_singlerun
    # echo
    # if python ~/squid_copy/src/optimack/test/is_slowdown.py $curl_singlerun | grep -q "True"; then
        for d in www.videolan.org;
        # for d in www.videolan.org www.go.com www.nginx.org; www.videolan.org
        # for d in www.gnu.org www.ebay.com www.ted.com;
        do
            one_round $d $outdir $outputfile
            break
        done
    # else
    #     echo "not in slow down, sleep for 120s"
    #     sleep 300
    # fi
done