#！/bin/bash

function one_round(){
    domain=$1
    out_dir=$2
    output_file=$3

    python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file normal

    ~/squid_only/sbin/squid
    python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file squid
    ~/squid_only/sbin/squid -k shutdown
    ~/squid_only/sbin/squid -k kill
    killall squid  
    
    screen -dmS proxy bash -c "~/squid/sbin/squid -N >> $out_dir/squid_output_${domain}_$(date +%Y-%m-%dT%H:%M:%S).txt"
    python3 ~/squid_copy/src/optimack/test/test_alexa_top_50_single.py $domain $out_dir $output_file proxy
    screen -S proxy -X quit
    # ~/squid/sbin/squid -k shutdown
    # ~/squid/sbin/squid -k kill
    killall squid
}

iptables -F
iptables -F -t mangle

outdir=~/rs/browser/$(date +%Y-%m-%d)/
mkdir -p $outdir
outputfile=browser_alexa_$(date +%Y-%m-%dT%H:%M:%S).txt
while true;
do
    for d in www.videolan.org;
    # for d in www.gnu.org www.ebay.com www.ted.com;
    do
        one_round $d $outdir $outputfile
    done
done