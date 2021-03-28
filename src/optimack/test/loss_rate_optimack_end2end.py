import os, sys, shlex, time, datetime, traceback, pandas as pd, subprocess as sp, pipes

def pcap2df(input_file):
    tshark_out= input_file.replace('.pcap','.tshark')
    if not os.path.exists(tshark_out):
        tshark_cmd = 'tshark -o tcp.calculate_timestamps:TRUE -r %s -T fields -e frame.time_epoch -e ip.id -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y "tcp.srcport eq 80 and tcp.len > 0" > %s' % (pipes.quote(input_file), pipes.quote(tshark_out))
        p = sp.Popen(tshark_cmd, stdout=sp.PIPE, shell=True)
        out, err = p.communicate()
        print(out, err)
        print("tshark done")
    df = pd.read_csv(tshark_out, names=['time_epoch', 'ip_id', 'dstport', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel', 'out_of_order'])#col
    print(df)
    return df

def correct_ofo_timestamp2(df_all):
    df_all['orig_index'] = df_all.index
    # df_ports = [pd.DataFrame(y) for x, y in df_all.groupby('dstport', as_index=False)]
    ports = df_all.dstport.unique()
    print(sorted(ports))
    for port in ports:
        df_port = df_all[df_all.dstport == port].sort_values('tcp_seq_rel').reset_index(drop=True)
        row_len, col_len = df_port.shape
        i = row_len - 2
        while i >= 0:
            if df_port.at[i, 'out_of_order'] != 1.0:
                bottom_in_order_i, bottom_in_order_time = i, df_port.at[i, 'time_epoch']
                i -= 1
                continue
            if not bottom_in_order_time: #case: last two lines are out_of_order
                i -= 1
                continue
            while i >= 0 and df_port.at[i, 'out_of_order'] == 1.0:
                i -= 1
            if i < 0: # case: first lines are out_of_order
                top_in_order_i, top_in_order_time = -1, bottom_in_order_time
            else:
                top_in_order_i, top_in_order_time = i, df_port.at[i, 'time_epoch']
            j = top_in_order_i + 1
            offset = (bottom_in_order_time - top_in_order_time)/(bottom_in_order_i - top_in_order_i + 1)
            while j < bottom_in_order_i:
                orig_index = df_port.at[j, 'orig_index']
                print(j, df_all.at[orig_index, 'time_epoch'], top_in_order_time + offset)
                df_all.at[orig_index, 'time_epoch'] = top_in_order_time + offset
                print(j, df_all.at[orig_index, 'time_epoch'], top_in_order_time + offset)
                df_all.at[orig_index, 'out_of_order'] += 1
                offset += offset
                j += 1	

ports = [55624, 55626, 55628, 55630, 55632, 55634, 55636, 55638, 55640, 55642, 55644, 55646, 55648, 55650, 55652, 55654]
client_file, server_file = sys.argv[1], sys.argv[2]
df_client, df_server = pcap2df(client_file), pcap2df(server_file)
df_client = df_client[df_client['dstport'].isin(ports)]
df_server = df_server[df_server['dstport'].isin(ports)]
# print(df_client.dstport.unique(), df_client[df_client.dstport is in []])
# print(df_client.data_len.unique(), df_server.data_len.unique())
correct_ofo_timestamp2(df_client)
# print(df_client)
df_client_no_ofo = df_client[['time_epoch', 'ip_id', 'dstport', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel']]
df_server_patched = df_server.merge(df_client_no_ofo, how='left', on=['ip_id', 'dstport', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel'])
print(df_server_patched)
df_server_patched['time_epoch_x'] = df_server_patched['time_epoch_x'].apply(lambda x: int(x))
print(df_server_patched)
df_per_second = [pd.DataFrame(y) for x, y in df_server_patched.groupby('time_epoch_x', as_index=False)]
bytes_per_sec = pd.DataFrame(columns=['lost', 'all'])
for df_sec in df_per_second:
    print(df_sec)
    sec = df_sec['time_epoch_x'].unique()[0]
    all_cnt = df_sec.data_len.sum()
    lost_cnt = df_sec[df_sec.time_epoch_y.isna()].data_len.sum()
    bytes_per_sec.loc[sec] = [lost_cnt, all_cnt]

bytes_per_sec.sort_index(inplace=True)
bytes_per_sec['loss_rate'] = bytes_per_sec['lost']*1.0/(bytes_per_sec['all'])
print(bytes_per_sec)
print(bytes_per_sec['lost'].sum(), bytes_per_sec['all'].sum())
bytes_per_sec.to_csv('bytes_per_sec.csv', encoding='utf-8',index=True)
# local_ports = map(int, filter(None, sys.argv[2].split(',')))


