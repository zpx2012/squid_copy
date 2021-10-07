import csv, os, pandas as pd, sys, numpy as np

def parse_info_file(infile):
    dict_ = {}
    with open(infile, 'r') as inf:
        for line in inf.read().splitlines():
            cells = line.split(': ')
            if len(cells) == 2:
                dict_[cells[0]] = cells[1]
    return dict_

# print(parse_seq_file(sys.argv[1]))
if __name__ == '__main__':
    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        with open(root+'/info_files_result_%s.csv' % sys.argv[2], 'w') as outf:
            outf.writelines('timestamp,hostname,conn_num,ack_pace(us),ip,duration(s),overrun_count,overrun_penalty(s),we2squid_loss_count,we2squid_loss_penalty,range_timeout_count,range_timeout_penalty,mode,all_lost_bytes,range_requested(byte)\n')# we2squid_loss_bytes,
            for f in sorted(files):
                extension = '.txt'
                if f.startswith('info') and f.endswith(extension):
                    fcells = f.split(extension)[0].split('_')
                    time_str = fcells[-1]
                    hostname = fcells[-2]
                    dict_ = parse_info_file(root+'/'+f)
                    if dict_ and dict_['Request']: #and dict_['IP'] in ['142.93.117.107', '138.68.49.206', '67.205.159.15'] '/pub/ubuntu/indices/md5sums.gz' in 
                        print(time_str+', '+hostname)
                        outf.writelines(','.join([time_str[:16], hostname, dict_['Num of Conn'], dict_['ACK Pacing'], dict_['IP'], dict_['Duration'].strip('s'), dict_['Overrun count'], dict_['Overrun penalty'], dict_['We2Squid loss count'], dict_['We2Squid loss penalty'], dict_['Range timeout count'], dict_['Range timeout penalty'], ])) #dict_['Packet lost between us and squid'], 
                        if dict_.has_key('Mode'):
                            outf.writelines(',' + dict_['Mode'] + ',')
                            if dict_['Mode'] == 'range':
                                outf.writelines(','.join([dict_['Packet lost on all'], dict_['Range requested']]))
                        outf.writelines('\n')
            break
