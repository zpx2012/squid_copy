# outdir config_str site url stime

outdir=$1
site=$3
url=$4
stime=$5
tag=$(hostname)_${site}_http_${2}_${stime}
normal_out=$outdir/curl_normal_${tag}.txt

while true; do
    echo Start: $(date -Iseconds) >> $normal_out
    curl -LJ4vk $url --limit-rate 500k -o /dev/null 2>&1 | tee -a ${normal_out}
    echo >> ${normal_out}
done