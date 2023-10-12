import csv, os, pandas as pd, sys, numpy as np, socket
from possibility import parse_tshark, pcap2tshark
from datetime import datetime, timedelta

def find_info_file(search_dir, input_file, extension, key):
    fname_fields = input_file.split(extension)[0].split('_')
    tshark_time = datetime.strptime(fname_fields[-1], '%Y%m%d%H%M%S')
    extract_dict = {}
    for fname_field in fname_fields:
        for k in ['optim', 'ackpace']:
            if k in fname_field:
                sub_fields = fname_field.split('+')
                for sub_field in sub_fields:
                    if k in sub_field:
                        extract_dict[k] = sub_field.strip(k)
    con_num, ackpace = extract_dict['optim'], extract_dict['ackpace']
    print(con_num, ackpace)

    print("time_str: %s" % tshark_time)
    info_file, info_dict = '', {}
    for root, dirs, files in os.walk(os.path.expanduser(search_dir)): 
        for finfo in sorted(files):
            if finfo.startswith("info_") and finfo.endswith(".txt"):
                info_file_time = datetime.strptime(finfo.split(".txt")[0].split('_')[-1], '%Y-%m-%dT%H:%M:%S')#.strftime("%Y%m%d%H%M")
                # print(info_file_time, tshark_time)
                if info_file_time >= tshark_time and info_file_time - tshark_time < timedelta(0,30):
                    print("Found: %s, validating..." % finfo)
                    info_file = root+'/'+finfo
                    info_dict = read_info_file(info_file)
                    if 'Num of Conn' not in info_dict or 'ACK Pacing' not in info_dict:
                        print("Empty file")
                        info_file, info_dict = '',{}
                    else:
                        print(con_num, ackpace, info_dict['Num of Conn'], info_dict['ACK Pacing'])
                        if info_dict['ACK Pacing'] != ackpace: #info_dict['Num of Conn'] == con_num and
                            print("ACK Pace doesn't match")
                            info_file, info_dict = '',{}
                        elif info_dict.has_key(key):
                            print("Already written with key: %s" % key)
                            info_file, info_dict = '',{}
                        else:
                            print("found %s" % info_file)
                            break
                    
    print
    return info_file, info_dict

def append_to_info_file(info_file, str):
    print("Append result to: " + info_file)
    with open(info_file, 'a') as outf:
            outf.writelines(str)


def read_info_file(infile):
    dict_ = {}
    with open(infile, 'r') as inf:
        lines = inf.read().replace("\r\n",", ").splitlines()
        for line in lines:
            cells = line.split(': ')
            if len(cells) >= 2:
                dict_[cells[0]] = cells[1]
    return dict_

def remove_line_from_info_file(infile, key, value):
    dict_ = read_info_file(infile)
    # if 'Ack pacing' in dict_:
    #     dict_['ACK Pacing'] = dict_.pop('Ack pacing')
    # if 'Num of conn' in dict_:
    #     dict_['Num of Conn'] = dict_.pop('Num of conn')
    # if 'Ip' in dict_:
    #     dict_['IP'] = dict_.pop('Ip')
    if key in dict_ and dict_[key] == value:
        del dict_[key]
        with open(infile, 'w') as outf:
            for k in sorted(dict_):
                outf.writelines(k + ': ' + dict_[k] + '\n')

def duration_str_to_sec(str):
    cells = str.split(':')
    if len(cells) != 3:
        print("Wrong duration str: %s" % str)
        return -1
    cells = map(int, cells)
    return cells[0]*3600+cells[1]*60+cells[2]

def parse_curl_squid_file(dir, filename):
    fcells = filename.split('.txt')[0].split('_')
    hostname = fcells[2]

    write_key = 'Curl squid duration'
    info_file, info_dict = find_info_file(dir, filename, '.txt', write_key)
    if not info_file:
        print("No info file found for %s\n" % f)
        return

    dict_ = {}
    with open(dir+'/'+filename, 'r') as inf:
        lines = inf.read().splitlines()
        if len(lines) == 0:
            return
        if lines[0].startswith("Start: "):
                time_str = lines[0][7:23]
        else:
            print("First line not starts with Start time")
        if lines[-1].startswith("100 "):
            duration_str = filter(None,lines[-1].replace('d ','d').split(' '))[-3]
            duration = duration_str_to_sec(duration_str)
        elif 'left intact' in lines[-1]:
            if(lines[-2].startswith("100 ")):
                duration_str = filter(None,lines[-2].replace('d ','d').split(' '))[-3]
                duration = duration_str_to_sec(duration_str)
            else:
                print("Left intact previous line doesn't start with '100 '")
        elif 'curl: (18) transfer closed with' in lines[-1] or 'curl: (28)' in lines[-1]:
            duration = -1
        else:
            duration = -1
            print("Unexpected last line: %s" % lines[-1])
    
        if duration != -1:
            append_to_info_file(info_file, "\n%s: %f\n" % (write_key, duration))


def parse_curl_normal_file(dir, filename):
    fcells = filename.split('.txt')[0].split('_')
    hostname = fcells[2]

    write_key = 'Normal speed'
    info_file, info_dict = find_info_file(dir, filename, '.txt', write_key)
    if not info_file:
        print("No info file found for %s\n" % f)
        return


    dict_ = {}
    with open(dir+'/'+filename, 'r') as inf:
        lines = inf.read().splitlines()
        if len(lines) == 0:
            return
        if lines[0].startswith("Start: "):
                time_str = lines[0][7:23]
        else:
            print("First line not starts with Start time")
        for line in lines[::-1]:
            if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or 'Spent' in line or 'curl' in line:
                continue
            speed = 0
            fields = filter(None,line.replace('d ','d').split(' '))
            avg_speed = fields[6]
            # print avg_speed
            last_letter = avg_speed[-1]
            if last_letter.isdigit():
                speed = int(avg_speed)/1024.0
            elif last_letter == 'k':
                speed = int(avg_speed.replace('k',''))
            elif last_letter == 'M':
                speed = float(avg_speed.replace('M',''))*1024

            if speed <= 128:
                append_to_info_file(info_file, "\n%s: %f\nIn slowdown: True\n" % (write_key, speed))
            else: 
                append_to_info_file(info_file, "\n%s: %f\nIn slowdown: False\n" % (write_key, speed))
            
            break              

# print(parse_seq_file(sys.argv[1]))
if __name__ == '__main__':

    # remove_line_from_info_file('info_BJ-OPTACK_2022-05-15T00:06:12_test.txt', 'Curl squid duration', '-1.000000')
    # sys.exit(0)

    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        for f in sorted(files):
            # print(f)
            if f.startswith('curl_normal') and f.endswith('.txt'):
                print("Parse: %s" % f)
                parse_curl_normal_file(root, f)
            elif f.startswith('curl_squid') and f.endswith('.txt'):
                print("Parse: %s" % f)
                parse_curl_squid_file(root, f)
            elif f.startswith('tcpdump_'):
                print("Parse: %s" % f)
                if f.endswith(".pcap"):
                    pcap2tshark(root+'/'+f, root+'/'+f+'.tshark', sys.argv[3])
                    f = f+'.tshark'

                if f.endswith(".pcap.tshark"):
                    info_file, info_dict = find_info_file(root, f, ".pcap.tshark", "Avg loss rate")
                    if not info_file:
                        print("No info file found for %s\n" % f)
                        continue
                    parse_tshark(root, f, info_file, info_dict)

        # with open(root+'/info_files_result_%s_%s.csv' % (socket.gethostname(), sys.argv[2]), 'w') as outf:
        df = pd.DataFrame()
        # outf.writelines('timestamp,hostname,conn_num,ack_pace(us),ip,duration(s),duration_curl,normal_speed,overrun_count,overrun_penalty(s),we2squid_loss_count,we2squid_loss_penalty,range_timeout_count,range_timeout_penalty,mode,all_lost_bytes,range_requested(byte),all_lost_bytes(true),avg_loss_rate\n')# we2squid_loss_bytes,
        for f in sorted(files):
            extension = '.txt'
            if f.startswith('info') and f.endswith(extension):
                # remove_line_from_info_file(root+'/'+f, 'Curl squid duration', '-1.000000')
                fcells = f.split(extension)[0].split('_')
                dict_ = read_info_file(root+'/'+f)
                if dict_ and 'Request' in dict_:
                    dict_['Timestamp'] = fcells[-1]
                    dict_['Hostname'] = fcells[-2]
                    dict_['Duration'] = dict_['Duration'].strip('s')

                    df_dict = pd.DataFrame([dict_])                        
                    df = pd.concat([df, df_dict], sort=True, ignore_index=True)
                # if dict_ and 'Request' in dict_: #and dict_['IP'] in ['142.93.117.107', '138.68.49.206', '67.205.159.15'] '/pub/ubuntu/indices/md5sums.gz' in 
                #     print(time_str+', '+hostname)
                #     outf.writelines(','.join([time_str, hostname, dict_['Num of Conn'], dict_['ACK Pacing'], dict_['IP'], dict_['Duration'].strip('s'), dict_['Overrun count'], dict_['Overrun penalty'], dict_['We2Squid loss count'], dict_['We2Squid loss penalty'], dict_['Range timeout count'], dict_['Range timeout penalty'], ])) #dict_['Packet lost between us and squid'], 
                #     if not dict_.has_key('Mode'):
                #         if dict_.has_key('Packet lost on all'):
                #             dict_['Mode'] = 'range'
                #         else:
                #             dict_['Mode'] = ''
                #     outf.writelines(',' + dict_['Mode'] + ',')
                #     if dict_['Mode'] == 'range':
                #         outf.writelines(','.join([dict_['Packet lost on all'], dict_['Range requested'],]))
                #     else:
                #         outf.writelines(',,')
                #     if "avg loss rate" in dict_:
                #         outf.writelines(','+dict_['avg loss rate'])
                #     outf.writelines('\n')

        print(df)
        input_file = 'info_files_result_%s_%s.csv' % (socket.gethostname(), sys.argv[2])
        df.to_csv(root+input_file, index=False)

        df = df.apply(pd.to_numeric, errors='ignore')
        df['Preindex'] = df['Timestamp'] + df['Hostname']
        df = df.set_index('Preindex')
        # df['ACK Speed'] = 10000000.0/df['ACK Pacing']
        df.to_csv(root+'/'+input_file.replace('.csv','_validated_raw.csv'), encoding='utf-8', index=False)
        print(df['In slowdown'])
        df = df[df['In slowdown'] == 'True']
        df = df[df['Curl squid duration'].notnull()]
        df = df[df['Avg loss rate'] > 0.002]
        print("After validation")
        print df
        df.to_csv(root+'/'+input_file.replace('.csv','_validated.csv'), encoding='utf-8', index=False)
        df_mean = df.groupby(['Hostname','Num of Conn','ACK Pacing','Mode']).mean().reset_index()
        df_std = df.groupby(['Hostname','Num of Conn','ACK Pacing','Mode']).std().reset_index()
        df_min = df.groupby(['Hostname','Num of Conn','ACK Pacing','Mode']).min().reset_index()
        df_mean['duration_std'] = df_std['Duration']
        df_mean['normal_speed_std'] = df_std['Normal speed']
        df_mean['loss_std'] = df_std['Avg loss rate']
        df_mean['overall_lost_byte_std'] = df_std['Overall lost bytes']
        print df_min
        df_mean['duration_min'] = df_min['Duration']
        print df_mean['Duration'], df_std['Duration']
        df_mean.to_csv(root+'/'+input_file.replace('.csv','_validated_mean.csv'), encoding='utf-8', index=False)

        break

