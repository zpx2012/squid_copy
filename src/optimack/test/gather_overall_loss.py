import csv, os, pandas as pd, sys, numpy as np
from datetime import datetime

def parse_loss_file(infile):
    max_num = 0
    with open(infile, 'r') as inf:
        for i, line in enumerate(inf.read().splitlines()):
            if float(line) == 0.0:
                max_num = i
                break
    return max_num

# print(parse_seq_file(sys.argv[1]))
if __name__ == '__main__':
    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        with open('overall_loss.csv', 'w') as outf:
            outf.writelines('time,hostname,overall_lost_byte,overall_lost_rate\n')
            for f in sorted(files):
                extension = '_avg.csv'
                if f.startswith('tcpdump') and f.endswith(extension):
                    print("Parse: %s" % f)
                    time_str = f.split(extension)[0].split('_')[-1]
                    time_str = datetime.strptime(time_str, "%Y%m%d%H%M").strftime('%Y-%m-%dT%H:%M')
                    hostname = f.split(extension)[0].split('_')[1]
                    list_ = [time_str, hostname]
                    with open(infile, 'r') as inf:
                        for i, line in enumerate(inf.read().splitlines()):
                            cells = line.split(': ')
                            list_.append(cells[1])
                    outf.writelines(','.join(list_)+'\n')
            break
