import os, sys, random, pandas as pd, time, json, multiprocessing, traceback, subprocess as sp, pipes
from datetime import datetime, timedelta
from interval import remove_interval, intersect_intervals, total_bytes
from loss_rate_optimack_end2end import pcap2df
from loss_rate_optimack_client import loss_rate_optimack_client
# from parse_info_files import find_info_file

def remove_received_intervals(intervals, df_port):
    # print(df_port['tcp_seq_rel'].max())
    next_seq = 1
    for i, row in df_port.iterrows():
        sec, seq, data_len = row['time_epoch'], row['tcp_seq_rel'], row['data_len']
        # print(seq, seq+data_len)
        remove_interval(intervals, [seq, seq+data_len])
        # if next_seq != seq:
        #     print(next_seq, seq, data_len)
        next_seq = seq + data_len
        # print(intervals)
    # return intervals

def remove_received_intervals_apply(row, intervals):
    remove_interval(intervals, [row['tcp_seq_rel'], row['tcp_seq_rel']+row['data_len']])
    # return remove_interval()

def pcap2tshark(input_file, tshark_out, port):
    if not os.path.exists(tshark_out):
        tshark_cmd = 'tshark -o tcp.calculate_timestamps:TRUE -r %s -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y "tcp.srcport eq %s and tcp.len > 0" > %s' % (pipes.quote(input_file), port, pipes.quote(tshark_out))
        p = sp.Popen(tshark_cmd, stdout=sp.PIPE, shell=True)
        out, err = p.communicate()
        print(out, err)
        print("Convert %s to %s" % (input_file, tshark_out))

def tshark2df(tshark_out):
    df = pd.read_csv(tshark_out, names=['time_epoch', 'ip_id', 'ip_src', 'dstport', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel', 'out_of_order'])#col
    # print(df)
    return df

def get_info_per_conn(df, ports, out_file):

    if os.path.exists(out_file):
        print('File exists: ' + out_file)
        with open(out_file, 'r') as inf:
            return json.load(inf)

    print("Missing gaps per conn:\nI, Port,  Max len, Bytes Lost")
    gaps_left_per_conn, max_lens, loss_rates, all_bytes = [], [], [], sys.maxint
    for i, port in enumerate(ports):
        df_port = df[df.dstport == port ].sort_values('tcp_seq_rel')
        max_len = df_port['tcp_seq_rel'].max()
        max_lens.append(max_len)
        all_bytes = min(all_bytes, max_len)
        gaps_left_per_conn.append([[1, max_len]])
        remove_received_intervals(gaps_left_per_conn[i], df_port)
        loss_rates.append(total_bytes(gaps_left_per_conn[i])*1.0/max_len)
        print('%2d' % i, port, max_len, total_bytes(gaps_left_per_conn[i]), total_bytes(gaps_left_per_conn[i])*1.0/max_len)
        # print(gaps_left_per_conn[i])
    print("Max byte:"+str(all_bytes))
    # print(df['data_len'])

    info_per_conn = {
        'ports': ports,
        'gaps': gaps_left_per_conn,
        'max_lens': max_lens,
        'min_max_len': all_bytes,
        'data_len': df['data_len'].mode()[0]
    }

    print("Write gap infos to: " + out_file)
    with open(out_file, 'w') as outf:
        json.dump(info_per_conn, outf)

    return info_per_conn

def get_seq_lost_count(info_per_conn, out_file):

    if os.path.exists(out_file):
        print('File exists: ' + out_file)
        return

    all_bytes = int(info_per_conn['min_max_len'])
    data_len = int(info_per_conn['data_len'])
    gaps_left_per_conn = info_per_conn['gaps']
    num = len(gaps_left_per_conn)

    counts = []
    for i in range(1, all_bytes, data_len):
        counts.append(0)
    for i in range(num):
        # gaps_left_intersect = intersect_intervals([[1, all_bytes]], gaps_left_per_conn[i])
        for gap in gaps_left_per_conn[i]:
            right = gap[1]
            if gap[0] >= all_bytes:
                break
            elif gap[1] > all_bytes:
                right = all_bytes
            for j in range(int(gap[0]), int(right), data_len):
                # print(gap[0], gap[1], j, j/data_len)
                counts[j//data_len] += 1
            if right - gap[0] < data_len:
                print(right, gap[0], right - gap[0], "< %d" % data_len)

    max_gap = 0
    print("Write seq lost count to: " + out_file)
    with open(out_file, 'w') as outf:
        for i in range(1, all_bytes, data_len):
            max_gap = max(max_gap, counts[i/data_len])
            outf.writelines("%d, %d\n" % (i, counts[i/data_len]))
    print(max_gap)
    return max_gap

def get_overall_lossbyte_and_mean_loss_rate(info_per_conn, out_file):
    # if os.path.exists(out_file):
    #     print('File exists: '+out_file)
    #     return []

    max_lens = info_per_conn['max_lens']
    all_bytes = max(max_lens)
    ports = info_per_conn['ports']
    gaps_left_per_conn = info_per_conn['gaps']
    num = len(ports)

    print("Missing packet rate adding one(intersect gaps):")
    gaps_left = [[1, all_bytes]]
    loss_byte_sum, all_byte_sum = 0,0
    for i in range(num):
        loss_byte_sum += total_bytes(gaps_left_per_conn[i])
        all_byte_sum += max_lens[i]
        if gaps_left:
            gaps_left[:] = intersect_intervals(gaps_left, gaps_left_per_conn[i])
    avg_lossrate = loss_byte_sum*1.0/all_byte_sum
    print("bytes lost %d, avg_lossrate %f" % (total_bytes(gaps_left), avg_lossrate))

    print("Write possibility result to: " + out_file)
    with open(out_file, 'a') as outf:
        outf.writelines("Overall lost bytes: %d\nAvg loss rate: %f\n" % (total_bytes(gaps_left), avg_lossrate))

    return

def get_possibility(info_per_conn, out_file):

    if os.path.exists(out_file):
        print('File exists: '+out_file)
        return []

    all_bytes = info_per_conn['min_max_len']
    ports = info_per_conn['ports']
    gaps_left_per_conn = info_per_conn['gaps']
    num = len(ports)
    
    loss_rates = []
    indexes = range(num)
    random.shuffle(indexes)
    print(indexes)

    print("Missing packet rate adding one(intersect gaps):")
    gaps_left = [[1, all_bytes]]
    for i in range(num):
        index = indexes[i]
        if gaps_left:
            gaps_left[:] = intersect_intervals(gaps_left, gaps_left_per_conn[index])
            loss_rate = total_bytes(gaps_left)*1.0/(all_bytes-1)
        else:
            loss_rate = 0
        # loss_rates.append(loss_rate)
        print(i, ports[index], loss_rate)
    # print("bytes lost %d" % total_bytes(gaps_left))
    print(loss_rates)

    # print("Missing packet rate adding one:")
    # loss_rates = []
    # intervals = [[1, all_bytes]]
    # is_zero = False
    # for i in range(num):
    #     index = indexes[i]
    #     if not is_zero:
    #         remove_received_intervals(intervals, df[df.dstport == ports[index]])
    #         loss_rate = total_bytes(intervals)*1.0/(all_bytes-1)
    #         if not loss_rate:
    #             is_zero = True
    #     else:
    #         loss_rate = 0
    #     loss_rates.append(loss_rate)
    #     print(i, ports[index], loss_rate)

    print("Write possibility result to: " + out_file)
    with open(out_file, 'w') as outf:
        outf.writelines("bytes lost on all: %d\n" % total_bytes(gaps_left))
        for loss in loss_rates:
            outf.writelines(str(loss)+'\n')

    return loss_rates

# def parse_info_file(info_file):
#     ip, ports = '',[]
#     if not os.path.exists(info_file):
#         print(info_file+' Not exists!')
#     else:
#         with open(info_file, 'r') as inf:
#             for line in inf.read().splitlines():
#                 if line.startswith('IP:'):
#                     ip = line.split('IP: ')[1]
#                 elif line.startswith('Ports:'):
#                     ports = map(int, filter(None, line.split('Ports: ')[1].split(', ')))
#     return ip, ports

def parse_pcap(root, f):
    global extension
    print('Parse: '+f)
    tshark_file = f.replace(extension,'.pcap.tshark')
    pcap2tshark(root+'/'+f, root+"/"+tshark_file)
    extension = '.pcap.tshark'
    parse_tshark(root, tshark_file)
    os.remove(root+'/'+f)
    print('Removed: '+f)


def parse_tshark(root, f, info_file, info_dict):
    # root, f = packed_list[0], packed_list[1]
    if not os.path.exists(root+'/'+f):
        print(f+' Not exists!')
        return

    print('Parse: '+f)

    # info_file, info_dict = find_info_file(sys.argv[1], f, extension, "avg loss rate")
    # if not info_file:
    #     print("No info file found for %s\n" % f)
    #     return

    extension = '.pcap.tshark'
    prob_file = root+'/'+f.replace(extension,'_prob.csv')
    avg_file = root+'/'+f.replace(extension,'_avg.csv')
    gap_info_file = root+'/'+f.replace(extension, '.infos')
    gaps_count_file = root+'/'+f.replace(extension, '_gaps_count.csv')
    loss_file = root+'/'+f.replace(extension,"_loss.csv")
    # if os.path.exists(out_file):
    #     print('Skip: '+out_file+' exists')
        # os.remove(root+'/'+f)
        # print('Removed: '+f)
        # continue
    df = tshark2df(root+'/'+f)
    ip, ports = info_dict['IP'], map(int, filter(None,info_dict['Ports'].split(', ')[:int(float(info_dict['Num of Conn']))]))
    print(ip, ports)
    if ip and ports:
        df = df[df.ip_src == ip]
        df = df[df['dstport'].isin(ports)]
        info_per_conn = get_info_per_conn(df, ports, gap_info_file)
        # info_per_conn = get_info_per_conn(pd.DataFrame(), [], gap_info_file)
        # get_seq_lost_count(info_per_conn, gaps_count_file)
        # get_possibility(info_per_conn, prob_file)
        get_overall_lossbyte_and_mean_loss_rate(info_per_conn, info_file)
        # loss_rate_optimack_client(df, ports, loss_file)
    else:
        print("Info file not exists.")
    # os.remove(root+'/'+f)
    # print('Removed: '+f)
    print
    print

def parse_info(root, f):
    gaps_count_file = root+'/'+f.replace(extension, '_gaps_count.csv')
    info_per_conn = get_info_per_conn(pd.DataFrame(), [], root+'/'+f)
    get_seq_lost_count(info_per_conn, gaps_count_file)
    

def get_total_loss(root, f):
    time_str = f.split(extension)[0].split('_')[1]
    gaps_count_file = root+'/'+f.replace(extension, '_gaps_count.csv')
    info_per_conn = get_info_per_conn(pd.DataFrame(), [], root+'/'+f)
    max_lens = info_per_conn['max_lens']
    gaps_left_per_conn = info_per_conn['gaps']
    num = len(max_lens)
    gaps_sum, total_sum = 0, 0
    for i in range(num):
        gaps_sum += total_bytes(gaps_left_per_conn[i])
        total_sum += max_lens[i]
    print(time_str, gaps_sum*1.0/total_sum)
    print
    with open(root+'/'+'total_loss_rate.csv', 'a') as outf:
        outf.writelines("%s, %f\n" % (time_str, gaps_sum*1.0/total_sum))


if __name__ == '__main__':
    # extension = '.infos'
    # parse_tshark(os.path.expanduser(sys.argv[1]), sys.argv[2])
    # sys.exit(0)

    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        for f in sorted(files):
                # parse_info(root, f)
            try:
                if f.endswith('.pcap.tshark'):
                    # get_total_loss(root, f)
                    extension = '.pcap.tshark'
                    # parse_tshark(root, f)
                    # args_list.append([root, f])
                # elif f.endswith('.pcap'):
                #     extension = '.pcap'
                #     parse_pcap(root, f)
                # elif f.endswith('.tshark'):
                #     # get_total_loss(root, f)
                #     extension = '.tshark'
                #     parse_tshark(root, f)

            except KeyboardInterrupt:
                os._exit(-1)
            except:
                print '%s' % traceback.format_exc()
        break
    
    # pool = multiprocessing.Pool(processes=4)
    # pool.map(parse_tshark, args_list)










#/nonexistent/rs/large_file_succ_rate/2021-03-29/




    # ports = sorted(df.dstport.unique())
    # print(ports)
    # ports = [60940,60942,60948,60950,60952,60954, 60958,60960,60962,60964,60968,60970,60972]
    # ports = [57404,57406,57408,57410,57412,57414,57416,57418,57420,57422,57424,57426,57428,57430,57432,57434]
    # ports = [44246, 44248, 44250, 44254, 44256, 44258, 44260, 44262, 44264, 44266, 44268, 44270, 44272, 44274]
    # ports = [43002, 43004, 43006, 43008, 43010, 43012, 43014, 43016, 43018, 43020, 43022, 43024, 43026, 43028, 43030, 43032]
    # ports = [ 60562, 60564, 60568, 60570, 60572, 60574, 60576, 60578, 60580, 60582, 60584, 60586, 60588, 60590]
    # ports = [52038, 52040, 52042, 52044, 52046, 52048, 52050, 52052, 52054, 52056, 52058, 52060, 52062, 52064, 52066, 52068]

    #     # start_time = time.time()
    #     # df[df.dstport == port].apply(add_one_conn_apply, axis=1, args=(intervals,))
    #     # print("add_one_conn_apply- %s seconds ---" % (time.time() - start_time))