import os, sys, shlex, time, datetime, traceback, pandas as pd, subprocess as sp, pipes

input_file = sys.argv[1]
local_ports = map(int, filter(None, sys.argv[2].split(',')))
# local_ports = [33246, 33248, 33252, 33254, 33256, 33258, 33260, 33262, 33264, 33266, 33268, 33270, 33272, 33274, 33276, 33278]
# local_ports = [38000,38002,38004]
# input_file = "/Users/pxzhu/Google Drive/workspace/2020_optimack/bursty_loss/2021-03-06/raw_data/tcpdump_2021-03-06T15:18:54.pcap"

tshark_out = input_file.replace('.pcap','.tshark')
if not os.path.exists(tshark_out):
	tshark_cmd = 'tshark -o tcp.calculate_timestamps:TRUE -r %s -T fields -e frame.time_epoch -e ip.id -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y "tcp.srcport eq 80 and tcp.len > 0" > %s' % (pipes.quote(input_file), pipes.quote(tshark_out))
	p = sp.Popen(tshark_cmd, stdout=sp.PIPE, shell=True)
	out, err = p.communicate()
	print(out, err)
	print("tshark done")

bytes_per_sec = pd.DataFrame(columns=['lost', 'received'])
df_all = pd.read_csv(tshark_out, names=['time_epoch', 'ip_id', 'dstport', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel', 'out_of_order'])#col
print(df_all)

for port in local_ports:
	df_port = df_all[df_all.dstport == port].sort_values('tcp_seq_rel').reset_index(drop=True)
	row_len, col_len = df_port.shape
	i = row_len - 2
	bottom_in_order_i, bottom_in_order_time = 0, 0
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
			# print(j, df_port.at[j, 'time_epoch'], top_in_order_time + offset)
			df_port.at[j, 'time_epoch'] = top_in_order_time + offset
			offset += offset
			j += 1	

	df_port['time_epoch'] = df_port['time_epoch'].apply(lambda x: int(x))
	next_seq_rel = 1
	for i, row in df_port.iterrows():
		sec, seq, data_len = row['time_epoch'], row['tcp_seq_rel'], row['data_len']
		if not sec in bytes_per_sec.index:
			bytes_per_sec.loc[sec] = [0, 0]
		if seq <= next_seq_rel:
			bytes_per_sec.loc[sec] += [0, data_len]
		else:
			bytes_per_sec.loc[sec] += [seq - next_seq_rel, 0]
		next_seq_rel = seq + data_len
	print(port," done")

bytes_per_sec.sort_index(inplace=True)
bytes_per_sec['loss_rate'] = bytes_per_sec['lost']*1.0/(bytes_per_sec['lost']+bytes_per_sec['received'])
print(bytes_per_sec)
print(bytes_per_sec['lost'].sum(), bytes_per_sec['lost'].sum()+bytes_per_sec['received'].sum())
print(df_all[df_all['dstport'].isin(local_ports)].data_len.sum())
bytes_per_sec.to_csv(tshark_out.replace('.tshark',"_loss.csv"), encoding='utf-8',index=True)
# p = sp.Popen('rm %s' % tshark_out, shell=True)
# p.communicate()


# (19196080, 184476840)
# (19181480, 167827000)



# i_time_epoch, i_stream_id, i_ip_src, i_dstport, i_len, i_tcp_seq_rel, i_tcp_ack_rel = 0,1,2,3,4,5,6
