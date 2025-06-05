import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np, re
from datetime import datetime, timedelta

pd.options.mode.chained_assignment = None

def load_dataframe(in_file):
    df = pd.read_csv(in_file, sep=',',error_bad_lines=False).dropna(how='any')#.drop_duplicates(subset=['is_range','conn','seq_start','seq_end'], keep='first')
    df['time'] = pd.to_numeric(df['time'],errors='ignore')
    df['seq_start'] = pd.to_numeric(df['seq_start'],errors='ignore')
    df['seq_end'] = pd.to_numeric(df['seq_end'],errors='ignore')
    return df

def find_process_file(search_dir, input_file):
    curl_file_time = datetime.strptime(input_file.split(".txt")[0].split('_')[-1], '%Y%m%d%H%M%S')
    for root, dirs, files in os.walk(os.path.expanduser(search_dir)): 
        for finfo in sorted(files):
            if finfo.startswith("processed_seq") and finfo.endswith(".csv"):
                input_file_time = datetime.strptime(finfo.split(".csv")[0].split('_')[-1], '%Y%m%d%H%M%S')
                if curl_file_time <= input_file_time and input_file_time - curl_file_time < timedelta(0,30):
                    print("Found: %s" % finfo)
                    return finfo
    return None


def get_configs_filename(in_file):
    output = [0, 0, 0]
    fname_fields = in_file.split('.txt')[0].split('_')
    for fname_field in fname_fields:
        if 'range' in fname_field:
            sub_fields = fname_field.split('+')
            output[0] = int(sub_fields[0].strip('optim'))
            num_str = sub_fields[1].strip('range')
            output[1] = int(num_str.split('*')[0])
            output[2] = int(num_str.split('*')[1])
    return output


def get_total_recvbytes(dirc, in_file, goodbytes):
    tshark_file = in_file.replace('curl_squid', 'tcpdump').replace('.txt', '.pcap.tshark')
    with open(os.path.join(dirc, tshark_file), 'r') as inf:
        lines = inf.read().splitlines()
        fields = lines[0].split(',')
        if len(fields) == 8:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', names = ['time','ipid','src_ip','srcport','tcplen','seq','ack','ooo']) #'dstport','rwnd'
    #df_tshark = df_tshark[df_tshark.srcport == 80]
            return df_tshark[df_tshark.seq <= goodbytes]['tcplen'].sum()
        elif len(fields) == 10:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', names = ['time','ipid','src_ip','srcport','dstport','tcplen','seq','ack','rwnd','ooo']) #'dstport','rwnd'
            df_tshark = df_tshark[df_tshark.srcport == 80]
            return df_tshark[df_tshark.seq <= goodbytes]['tcplen'].sum()


in_dir = os.path.expanduser(sys.argv[1])
out_file = sys.argv[2] + "_" + os.path.basename(os.path.abspath(in_dir)) + "_group_throughput.csv"
lossrate = sys.argv[2].split("loss")[0]
tag_fields = sys.argv[2].split('_')
optim_num, fix_num = 0,0
fix_kw = ''
kw_dict = {'group':1, 'thread':2}
for field in tag_fields:
    if 'optim' in field:
        subfields = field.split('optim')
        optim_num = int(subfields[0])
        if 'thread' in subfields[1]:
            fix_kw = 'thread'
        elif 'group' in subfields[1]:
            fix_kw = 'group'
        fix_num = int(subfields[1].split(fix_kw)[0])
print(optim_num, fix_kw, fix_num)

cols = ['thread_num', 'range','range_sum','optim','curl','goodbytes','recvedbytes', 'effi', 'filename']
df_output = pd.DataFrame(columns = cols)
with open(out_file, 'w') as outf:
    for root, dirs, files in os.walk(in_dir):
        for in_file in files:
            # print("Process: " + in_file)
            if(in_file.startswith('curl_squid') and in_file.endswith('.txt')) and sys.argv[2] in in_file:
                configs = get_configs_filename(in_file)
                # print(configs, optim_num, configs[kw_dict[fix_kw]], fix_num, configs[0] == optim_num, configs[kw_dict[fix_kw]] == fix_num)
                if configs[0] == optim_num and configs[kw_dict[fix_kw]] == fix_num and (configs[1] < 12):
                    print("Process: " + in_file)
                    process_file = find_process_file(in_dir, in_file)
                    total_goodbytes = 87548090
                    if process_file:
                        with open(os.path.join(root, in_file), 'r') as inf:
                            lines = list(filter(None, inf.read().splitlines()))
                            for line in lines[::-1]:
                                if 'curl: (18)' in line:
                                    continue
                                elif 'curl: (28)' in line:
                                    lr = re.findall(r'\d+', line)
                                    total_goodbytes = int(lr[2])

                        if not total_goodbytes:
                            continue

                        total_recvbytes = get_total_recvbytes(root, in_file, total_goodbytes)
                        # print(total_recvbytes)
                        df = load_dataframe(process_file)
                        df = df[ df['seq_start'] <= total_goodbytes ]
                        # 1. check if duration is larger than 59
                        duration = df['time'].iloc[-1] - df['time'].iloc[0]
                        #print(duration_real)
                        #duration = 60

                        df_optim = df[ df.is_range == 'optim_recv']
                        df_optim['byte'] = (df_optim['seq_end'] - df_optim['seq_start'])*8
                        optim_bytes = df_optim['byte'].sum()
                        optim_thrpt = optim_bytes/1024.0/duration

                        df_range = df[ df.is_range == 'range_recv' ]
                        df_range['bytes'] = (df_range['seq_end'] - df_range['seq_start'])*8
                        df_range_sum = df_range.groupby(by=['conn'], as_index=False).sum()
                        range_thrpt = df_range_sum['bytes'].sum()/1024.0/duration

                        df_range_sum['range'] = df_range_sum['bytes']/1024.0/duration
                        df_range_sum['thread_num'] = configs[(kw_dict[fix_kw]+2)%2+1]
                        df_range_sum['optim'] = optim_thrpt
                        df_range_sum['range_sum'] = range_thrpt
                        df_range_sum['curl'] = (optim_thrpt+range_thrpt)/1000.0
                        df_range_sum['goodbytes'] = total_goodbytes
                        df_range_sum['recvedbytes'] = total_recvbytes
                        df_range_sum['effi'] = total_goodbytes*100.0/total_recvbytes
                        df_range_sum['filename'] = in_file
                        df_output = pd.concat([df_output, df_range_sum[cols]])

                        print(optim_thrpt, range_thrpt, optim_thrpt+range_thrpt, duration)
                            
        break
                            
print(df_output)
df_output = df_output[ df_output.range > 0 ]
#df_output = df_output[ df_output.thread_num % 2 == 0]
df_output.to_csv(out_file, encoding='utf-8',index=False)

fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(14,5))
#for cl in ['range_sum''curl']:
axes1 = df_output.boxplot(ax=axes[0], column='curl', by='thread_num', showmeans=True)
#.title("Optim = 2, Group = 6, Loss Rate = 20%," + cl)
#plt.suptitle('')
axes1.set_ylim(0, 11)
axes1.set_xlabel('')
axes1.set_ylabel('Goodput(Mpbs)')
axes1.set_title("Overall Goodput")

axes2 = df_output.boxplot(ax=axes[1], column='range_sum', by='thread_num', showmeans=True)
axes2.set_ylim(0, 1500)
axes2.set_xlabel('')
axes2.set_ylabel('Goodput(Kpbs)')
axes2.set_title("Sum of Range Goodput")

axes3 = df_output.boxplot(ax=axes[2], column='effi', by='thread_num', showmeans=True)
axes3.set_ylim(0, 100)
axes3.set_xlabel('')
axes3.set_ylabel('Efficiency(%)')
axes3.set_title("Efficiency")

xlabels = {'group':'Number of Threads Inside Each Group', 'thread': 'Number of Group'}

fig.add_subplot(111, frameon=False)
plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
plt.grid(False)
plt.xlabel(xlabels[fix_kw]) #Groups, 
fig.suptitle("Optim = %d, %s = %d, Loss Rate = %s" % (optim_num, fix_kw.capitalize(), fix_num, lossrate) + '%')
plt.savefig(out_file.replace('.csv', 'curl_range_sum.png'), bbox_inches="tight")

