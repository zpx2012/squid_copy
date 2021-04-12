import csv, os, pandas as pd, sys, numpy as np

def parse_seq_file(infile):
    max_num = 0
    with open(infile, 'r') as inf:
        for line in inf.read().splitlines():
            if 'Netfilter Queue too full' in line:
                print(line)
            cells = line.split(', ')
            if len(cells) == 2:
                max_num = max(max_num,int(cells[1]))
    return max_num

# print(parse_seq_file(sys.argv[1]))
if __name__ == '__main__':
    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        with open('num_conn_needed.csv', 'w') as outf:
            for f in sorted(files):
                extension = '.csv'
                if f.startswith('seq_gaps_count') and f.endswith(extension):
                    time_str = f.split(extension)[0].split('_')[-1]
                    max_num = parse_seq_file(root+'/'+f)
                    print(time_str+', '+str(max_num))
                    outf.writelines(time_str+', '+str(max_num))
            break
