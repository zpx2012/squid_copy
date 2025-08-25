import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np, re, statistics
from datetime import datetime, timedelta
from matplotlib.offsetbox import AnchoredText

pd.options.mode.chained_assignment = None

def load_dataframe(in_file):
    df = pd.read_csv(in_file, sep=',').dropna(how='any')#.drop_duplicates(subset=['is_range','conn','seq_start','seq_end'], keep='first'),error_bad_lines=False
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


import pandas as pd

def calculate_loss_rate_from_file(df):
    """
    Calculates the packet loss rate from a tshark capture file in CSV format.

    Args:
        file_path (str): The path to the CSV file.

    Returns:
        float: The estimated loss rate, or None if calculation is not possible.
    """
    try:

        # Data cleaning: convert columns to numeric, coercing errors
        for col in ['data_len', 'tcp_seq_rel']:
            df[col] = pd.to_numeric(df[col], errors='coerce')

        # Drop rows where essential data is missing
        df.dropna(subset=['data_len', 'tcp_seq_rel', 'src_ip'], inplace=True)

        # Cast to integer types
        df['data_len'] = df['data_len'].astype(int)
        df['tcp_seq_rel'] = df['tcp_seq_rel'].astype(int)


        # Let's determine the server's IP.
        server_ip = df.groupby('src_ip')['data_len'].sum().idxmax()
        print(f"Identified server IP: {server_ip}")

        # Filter for packets sent by the server and with data
        server_df = df[(df['src_ip'] == server_ip) & (df['data_len'] > 0)].copy()

        if server_df.empty:
            print("No data packets from the server found.")
            return None

        # Create a list of (sequence_number, type) points
        points = []
        for index, row in server_df.iterrows():
            start_seq = row['tcp_seq_rel']
            end_seq = start_seq + row['data_len']
            points.append((start_seq, 1))
            points.append((end_seq, -1))

        # Sort points
        points.sort()

        # Sweep-line algorithm
        received_bytes = 0
        count = 0
        
        if not points:
            return 0.0

        last_seq = points[0][0]

        for seq, type in points:
            if count > 0:
                received_bytes += seq - last_seq
            
            count += type
            last_seq = seq
            
        # Calculate total expected bytes
        min_seq = server_df['tcp_seq_rel'].min()
        max_seq = (server_df['tcp_seq_rel'] + server_df['data_len']).max()
        total_expected_bytes = max_seq - min_seq

        if total_expected_bytes == 0:
            return 0.0
            
        lost_bytes = total_expected_bytes - received_bytes
        
        loss_rate = lost_bytes / total_expected_bytes
        
        print(f"Total Bytes Received: {received_bytes}")
        print(f"Total Bytes Expected: {total_expected_bytes}")
        print(f"Total Bytes Lost: {lost_bytes}")

        return received_bytes, lost_bytes

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return 0.1,0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0.1,0


def get_tshark_df(dirc, in_file):
    tshark_file = in_file.replace('curl_squid', 'tcpdump').replace('.txt', '.pcap.tshark')
    columns = ['time_epoch','ip_id','src_ip','srcport','dstport','data_len','tcp_seq_rel','tcp_ack_rel','rwnd']
    with open(os.path.join(dirc, tshark_file), 'r') as inf:
        lines = inf.read().splitlines()
        fields = lines[0].split(',')
        if len(fields) == 10:
            columns += ['ooo']            
    df = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', header = None, names = columns, on_bad_lines='skip',low_memory=False) #'dstport','rwnd'

    # --- Data Cleaning ---
    # for col in ['time_epoch', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel']:
    #     df[col] = pd.to_numeric(df[col], errors='coerce')
    # df.dropna(inplace=True)

    return df


def get_lossrate(df_tshark, ports):
    received_bytes_sum, lost_bytes_sum = 0,0
    for port in ports:
        #print(df_tshark[df_tshark.dstport == port])
        received_bytes, lost_bytes = calculate_loss_rate_from_file(df_tshark[df_tshark.dstport == port])
        received_bytes_sum += received_bytes
        lost_bytes_sum += lost_bytes
    return received_bytes_sum, lost_bytes_sum/(lost_bytes_sum+received_bytes_sum)


def get_rtt(df):
    # --- Identify Client and Server ---
    # Find the two unique IPs involved in the conversation from the src_ip column.
    unique_ips = df['src_ip'].unique()
    if len(unique_ips) < 2:
        print("Could not identify two distinct IPs in the conversation.")
        return
        
    # The client is the source of the first packet in the capture.
    client_ip = df.iloc[0]['src_ip']
    # The server is the other IP.
    server_ip = [ip for ip in unique_ips if ip != client_ip][0]

    print(f"Identified Client IP: {client_ip}")
    print(f"Identified Server IP: {server_ip}")

    # --- Separate Data and ACK packets ---
    # Data packets are sent *from* the client and have a data length > 0
    data_packets = df[(df['src_ip'] == client_ip) & (df['data_len'] > 0)].copy()
    
    # ACK packets are sent *from* the server in response
    ack_packets = df[df['src_ip'] == server_ip].copy()

    # --- Match Data to ACKs and Calculate RTT ---
    # Dictionary to store the time a data segment was sent.
    # Key: The sequence number the server should ACK (seq + len)
    # Value: The time the data packet was sent.
    sent_times = {}
    for _, row in data_packets.iterrows():
        expected_ack = row['tcp_seq_rel'] + row['data_len']
        # Only store the first time this sequence was sent to handle retransmissions
        if expected_ack not in sent_times:
            sent_times[expected_ack] = row['time_epoch']

    rtt_samples = []
    for _, ack in ack_packets.iterrows():
        ack_num = ack['tcp_ack_rel']
        # If this ACK corresponds to a data packet we've recorded
        if ack_num in sent_times:
            sent_time = sent_times[ack_num]
            rtt = (ack['time_epoch'] - sent_time) * 1000  # Convert to milliseconds
            if rtt > 0: # RTT must be a positive value
                rtt_samples.append(rtt)
            # Remove the entry to ensure we match an ACK only once
            del sent_times[ack_num]

    # --- Display Results ---
    if not rtt_samples:
        print("\nCould not find any matching Data/ACK pairs to calculate RTT.")
        return

    min_rtt = min(rtt_samples)
    max_rtt = max(rtt_samples)
    avg_rtt = sum(rtt_samples) / len(rtt_samples)

    print("\n--- TCP RTT Calculation Results ---")
    print(f"Number of RTT samples calculated: {len(rtt_samples)}")
    print(f"Minimum RTT: {min_rtt:.2f} ms")
    print(f"Maximum RTT: {max_rtt:.2f} ms")
    print(f"Average RTT: {avg_rtt:.2f} ms")

    return min_rtt, max_rtt, avg_rtt



def get_total_recvbytes(dirc, in_file, goodbytes, ports):
    tshark_file = in_file.replace('curl_squid', 'tcpdump').replace('.txt', '.pcap.tshark')
    with open(os.path.join(dirc, tshark_file), 'r') as inf:
        lines = inf.read().splitlines()
        fields = lines[0].split(',')
        if len(fields) == 8:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', header =  None, names = ['time','ipid','src_ip','srcport','tcplen','seq','ack','ooo']) #'dstport','rwnd'
    #df_tshark = df_tshark[df_tshark.srcport == 80]
            return df_tshark[df_tshark.seq <= goodbytes]['tcplen'].sum(), 0
        elif len(fields) == 10:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', header = None, names = ['time','ipid','src_ip','srcport','dstport','data_len','tcp_seq_rel','ack_sel','rwnd','ooo'], on_bad_lines='skip',low_memory=False) #'dstport','rwnd'
            #df_tshark = df_tshark[df_tshark.srcport == 80]
            #df_tshark = df_tshark[df_tshark.tcp_seq_rel <= goodbytes]
            received_bytes_sum, lost_bytes_sum = 0,0
            for port in ports:
                #print(df_tshark[df_tshark.dstport == port])
                received_bytes, lost_bytes = calculate_loss_rate_from_file(df_tshark[df_tshark.dstport == port])
                received_bytes_sum += received_bytes
                lost_bytes_sum += lost_bytes
            return received_bytes_sum, lost_bytes_sum/(lost_bytes_sum+received_bytes_sum)


in_dir = os.path.expanduser(sys.argv[1])
date_string = os.path.basename(os.path.abspath(in_dir))
out_file = in_dir + '/' + sys.argv[2] + "_" + date_string + "_group_throughput.csv"
lossrate = sys.argv[2].split("loss")[0]
tag_fields = sys.argv[2].split('_')
optim_num, fix_num, rtt = 0,0,0
fix_kw, test_kw = '',''
kw_dict = {'group':1, 'thread':2}
for field in tag_fields:
    if 'optim' in field:
        subfields = field.split('optim')
        optim_num = int(subfields[0])
        if 'thread' in subfields[1]:
            fix_kw = 'thread'
            test_kw = 'group'
        elif 'group' in subfields[1]:
            fix_kw = 'group'
            test_kw = 'thread'
        if fix_kw:
            fix_num = int(subfields[1].split(fix_kw)[0])
    elif 'ms' in field:
        rtt = int(field.strip('ms'))
    elif 'wholeset' in field or 'pareto' in field:
        fix_kw = 'wholeset'
print(optim_num, fix_kw, fix_num)
optim_num, fix_num = 1,3

cols = ['optim_num', 'group_num', 'thread_num', 'range','range_sum','optim','curl','goodbytes','recvedbytes', 'effi', 'lossrate', 'rtt_min', 'rtt_max', 'rtt_avg', 'filename']
df_output = pd.DataFrame(columns = cols)

count = 0
with open(out_file, 'w') as outf:
    for root, dirs, files in os.walk(in_dir):
        for in_file in files:
            # print("Process: " + in_file)
            if(in_file.startswith('curl_squid') and in_file.endswith('.txt')) and sys.argv[2] in in_file:
                configs = get_configs_filename(in_file)
                # print(configs, optim_num, configs[kw_dict[fix_kw]], fix_num, configs[0] == optim_num, configs[kw_dict[fix_kw]] == fix_num)
                if True: #configs[0] == optim_num and configs[kw_dict[fix_kw]] == fix_num: #fix_kw == '' or fix_kw == 'wholeset' or (configs[0] == optim_num configs[kw_dict[fix_kw]] == fix_num): #and (configs[1] < 12)
                    print("Process: " + in_file)
                    process_file = find_process_file(in_dir, in_file)
                    total_goodbytes = 87548090
                    if process_file:
                        with open(os.path.join(root, in_file), 'r') as inf:
                            lines = list(filter(None, inf.read().splitlines()))
                            for line in lines[::-1]: 
                                #print(line)                                   
                                if 'curl: (18)' in line or 'curl: (52)' in line or 'curl: (28) Operation too slow' in line:
                                    if 'curl: (18)' in line and '83.4M' in lines[::-2]:
                                        fields = list(filter(None,line.replace('d ','d').split(' ')))
                                        if int(fields[0]) >= 98:
                                            lr = re.findall(r'\d+', line)
                                            total_bytes -= int(lr[1])
                                            break
                                    total_goodbytes = 0
                                    print("\033[31m%s\n\033[0m" % line)
                                    break
                                elif 'curl: (28)' in line:
                                    lr = re.findall(r'\d+', line)
                                    total_goodbytes = int(lr[2])
                                    break

                        if not total_goodbytes:
                            continue

                        # print(total_recvbytes)
                        df = load_dataframe(os.path.join(root, process_file))
                        df_tshark = get_tshark_df(root, in_file)
                        df_tshark = df_tshark[df_tshark.tcp_seq_rel <= total_goodbytes]
                        
                        optim_ports = df[df.is_range=='optim_recv']['port'].unique()
                        range_ports = df[df.is_range=='range_recv']['port'].unique()

                        total_recvbytes, lossrate = get_lossrate(df_tshark, optim_ports)
                        rtt_mins, rtt_maxs, rtt_avgs = [], [], []
                        for range_port in range_ports:
                            print(range_port)
                            rtt_min, rtt_max, rtt_avg = get_rtt(df_tshark[(df_tshark['srcport'] == range_port) | (df_tshark['dstport'] == range_port)])
                            rtt_mins += [rtt_min]
                            rtt_maxs += [rtt_max]
                            rtt_avgs += [rtt_avg]
            
                        # total_recvbytes,lossrate = get_total_recvbytes(root, in_file, total_goodbytes, df[df.is_range=='optim_recv']['port'].unique())
                        
                        df = df[ df['seq_start'] <= total_goodbytes ]
                        # 1. check if duration is larger than 59
                        duration = df['time'].iloc[-1] - df['time'].iloc[0]
                        #print(duration_real)
                        #duration = 60

                        df_optim = df[ df.is_range == 'optim_recv']
                        df_optim['byte'] = (df_optim['seq_end'] - df_optim['seq_start'])
                        optim_bytes = df_optim['byte'].sum()
                        optim_thrpt = optim_bytes*8/1024.0/duration

                        df_range = df[ df.is_range == 'range_recv' ]
                        df_range['bytes'] = (df_range['seq_end'] - df_range['seq_start'])

                        df_range_sum = df_range.groupby(by=['conn'], as_index=False).sum()
                        range_thrpt = df_range_sum['bytes'].sum()*8/1024.0/duration

                        if rtt_mins:
                            df_range_sum['rtt_min'] = statistics.mean(rtt_mins)
                            df_range_sum['rtt_max'] = statistics.mean(rtt_maxs)
                            df_range_sum['rtt_avg'] = statistics.mean(rtt_avgs)
                        else:
                            df_range_sum['rtt_min'] = 0
                            df_range_sum['rtt_max'] = 0
                            df_range_sum['rtt_avg'] = 0

                        df_range_sum['range'] = df_range_sum['bytes']*8/1024.0/duration
                        df_range_sum['optim_num'] = configs[0]
                        df_range_sum['group_num'] = configs[1]
                        df_range_sum['thread_num'] = configs[2]

                        df_range_sum['optim'] = optim_thrpt
                        df_range_sum['range_sum'] = range_thrpt
                        df_range_sum['curl'] = (optim_thrpt+range_thrpt)/1000.0
                        df_range_sum['goodbytes'] = total_goodbytes
                        df_range_sum['recvedbytes'] = total_recvbytes
                        df_range_sum['effi'] = total_goodbytes*100.0/total_recvbytes
                        df_range_sum['lossrate'] = lossrate
                        df_range_sum['filename'] = in_file
                        df_output = pd.concat([df_output, df_range_sum[cols]])

                        print(optim_thrpt, range_thrpt, optim_thrpt+range_thrpt, duration)
                        print()
                        count += 1
                        #if count == 10:
                        #    break
        break


print(df_output)
df_output = df_output[ df_output.range > 0 ]
#df_output = df_output[ df_output.thread_num % 2 == 0]
df_output.to_csv(out_file, encoding='utf-8',index=False)


# df_output_5 = df_output[df_output['lossrate'] <= 0.051]
# df_output_5_above = df_output[df_output['lossrate'] > 0.051]
# df_output_10 = df_output_5_above[df_output_5_above['lossrate'] <= 0.10]
# df_output_10_above = df_output_5_above[df_output_5_above['lossrate'] > 0.10]


# #if  fix_kw == '' or fix_kw != 'wholeset':
# fix_kw = 'thread'
# test_kw = 'group'
# for df in [df_output_5, df_output_10, df_output_10_above]:
#     for optinum in [1, 2]:
#         fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(9.5,5.5))
#     #for cl in ['range_sum''curl']:
#         df = df[df.optim_num == optinum]
#         for i in range(4):
#             df = df[df[fix_kw+'_num'] == i+3]
#             axes1 = df.boxplot(ax=axes[i], column='curl', by='%s_num' % test_kw, showmeans=True)
#             axes1.set_ylim(0, 11)
#             axes1.set_xlabel('')
#             axes1.set_ylabel('Goodput(Mpbs)')
#             axes1.set_title(f"{fix_kw} = {i+3}")

#     #axes2 = df_output.boxplot(ax=axes[1], column='range_sum', by='%s_num' % test_kw, showmeans=True)
#     #axes2.set_ylim(0, 1100)
#     #axes2.set_xlabel('')
#     #axes2.set_ylabel('Goodput(Kpbs)')
#     #axes2.set_title("Overall Recovery Bandwidth of All Groups")

#     # axes3 = df_output.boxplot(ax=axes[2], column='effi', by='thread_num', showmeans=True)
#     # axes3.set_ylim(0, 1000)
#     # axes3.set_xlabel('')
#     # axes3.set_ylabel('Efficiency(%)')
#     # axes3.set_title("Efficiency")
#     # axes2.text(0.98, 0.98, date_string, ha='right', va='bottom', transform=axes2.transAxes)

#         xlabels = {'group':'Number of Threads Inside Each Group', 'thread': 'Number of Group'}

#         fig.add_subplot(111, frameon=False)
#         plt.figtext(0.98, 0.08, date_string, ha='right', va='bottom', transform=fig.transFigure)
#         plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
#         plt.grid(False)
#         plt.xlabel(xlabels[fix_kw]) #Groups, 
#         fig.suptitle("Optim = %d, %s = %f, China-Shenzhen" % (optim_num, 'Loss rate', df.lossrate.mean())) # lossrate, rtt)
#         plt.savefig(out_file.replace('.csv', 'curl_range_sum_%doptim_%d%s.png' % (optim_num, 'lossrate', df.lossrate.mean()*100)), bbox_inches="tight")

