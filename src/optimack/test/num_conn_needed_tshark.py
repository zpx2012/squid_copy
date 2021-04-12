import csv, os, pandas as pd, sys, numpy as np

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
        with open('num_conn_needed_tshark.csv', 'w') as outf:
            for f in sorted(files):
                extension = '_prob.csv'
                if f.startswith('tcpdump') and f.endswith(extension):
                    time_str = f.split(extension)[0].split('_')[-1]
                    max_num = parse_loss_file(root+'/'+f)
                    print(time_str+', '+str(max_num))
                    outf.writelines(time_str+', '+str(max_num)+'\n')
            break
