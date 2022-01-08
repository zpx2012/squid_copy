# outdir config_str site url stime

outdir=$1
site=$3
url=$4
stime=$5
tag=$(hostname)_${site}_http_${2}_${stime}

while true; do
    bash ~/squid_copy/src/optimack/test/run_squid_once.sh $1 $2 $3 $4 $5
done