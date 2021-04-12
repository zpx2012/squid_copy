#! /bin/bash

outdir=$1
pcap_file=$2
tshark_file=${pcap_file}.tshark

cd $outdir
tshark -r ${pcap_file} -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y "tcp.srcport eq 80 and (tcp.len > 0 or tcp.flags.fin == 1)" > ${tshark_file}
rm -v ${pcap_file}
python ~/squid_copy/src/optimack/test/possibility.py . ${tshark_file}