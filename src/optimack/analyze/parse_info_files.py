import csv, os, pandas as pd, sys, numpy as np, socket
# from possibility import parse_tshark
from datetime import datetime, timedelta

def find_info_file(search_dir, input_file, extension, key):
    fname_fields = input_file.split(extension)[0].split('_')
    tshark_time = datetime.strptime(fname_fields[-1], '%Y%m%d%H%M%S')
    con_num, ackpace = 0,0
    for fname_field in fname_fields:
        if 'optim' in fname_field:
            con_num = fname_field.split('+')[0].strip('optim')
            ackpace = fname_field.split('+')[1].strip('ackpace')
    # print(con_num, ackpace)

    # print("time_str: %s" % time_str)
    info_file, info_dict = '', {}
    for root, dirs, files in os.walk(os.path.expanduser(search_dir)): 
        for finfo in sorted(files):
            if finfo.startswith("info_") and finfo.endswith(".txt"):
                info_file_time = datetime.strptime(finfo.split(".txt")[0].split('_')[-1], '%Y-%m-%dT%H:%M:%S')#.strftime("%Y%m%d%H%M")
                # print(info_file_time, tshark_time, )
                if info_file_time >= tshark_time and info_file_time - tshark_time < timedelta(0,10):
                    print("Found: %s, validating..." % finfo)
                    info_file = root+'/'+finfo
                    info_dict = read_info_file(info_file)
                    print(con_num, ackpace, info_dict['Num of Conn'], info_dict['ACK Pacing'])
                    if info_dict['ACK Pacing'] != ackpace: #info_dict['Num of Conn'] == con_num and
                        print("ACK Pace doesn't match")
                        info_file, info_dict = '',{}
                    elif info_dict.has_key(key):
                        print("Already written with key %s" % key)
                        info_file, info_dict = '',{}
                    else:
                        print("found %s" % info_file)
                        break

    return info_file, info_dict

def append_to_info_file(info_file, str):
    print("Append result to: " + info_file)
    with open(info_file, 'a') as outf:
            outf.writelines(str)


def read_info_file(infile):
    dict_ = {}
    with open(infile, 'r') as inf:
        for line in inf.read().splitlines():
            cells = line.split(': ')
            if len(cells) == 2:
                dict_[cells[0]] = cells[1]
    return dict_

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
        if 'left intact' in lines[-1]:
            duration_str = filter(None,lines[-2].replace('d ','d').split(' '))[-3]
            duration = duration_str_to_sec(duration_str)
        elif 'curl: (18) transfer closed with' in lines[-1] or 'curl: (28)' in lines[-1]:
            duration = -1
        else:
            duration = -1
            print("Unexpected last line: %s" % lines[-1])
    
        append_to_info_file(info_file, "\n%s: %f\n" % (write_key, duration))


def parse_curl_normal_file(dir, filename, df):
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
    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
        for f in sorted(files):
            print(f)
            if f.startswith('cur_normal') and f.endswith('.txt'):
                print("Parse: %s" % f)
                parse_curl_normal_file(root, f)
            elif f.startswith('curl_squid') and f.endswith('.txt'):
                print("Parse: %s" % f)
                parse_curl_squid_file(root, f)
            elif f.startswith('tcpdump_') and f.endswith(".pcap.tshark"):
                print("Parse: %s" % f)
                info_file, info_dict = find_info_file(root, f, ".pcap.tshark", "avg loss rate")
                if not info_file:
                    print("No info file found for %s\n" % f)
                    continue
                parse_tshark(root, f, info_file, info_dict)

        with open(root+'/info_files_result_%s_%s.csv' % (socket.gethostname(), sys.argv[2]), 'w') as outf:
            outf.writelines('timestamp,hostname,conn_num,ack_pace(us),ip,duration(s),duration_curl,normal_speed,overrun_count,overrun_penalty(s),we2squid_loss_count,we2squid_loss_penalty,range_timeout_count,range_timeout_penalty,mode,all_lost_bytes,range_requested(byte),all_lost_bytes(true),avg_loss_rate\n')# we2squid_loss_bytes,
            for f in sorted(files):
                extension = '.txt'
                if f.startswith('info') and f.endswith(extension):
                    fcells = f.split(extension)[0].split('_')
                    time_str = fcells[-1]
                    hostname = fcells[-2]
                    dict_ = parse_info_file(root+'/'+f)
                    if dict_ and dict_['Request']: #and dict_['IP'] in ['142.93.117.107', '138.68.49.206', '67.205.159.15'] '/pub/ubuntu/indices/md5sums.gz' in 
                        print(time_str+', '+hostname)
                        outf.writelines(','.join([time_str, hostname, dict_['Num of Conn'], dict_['ACK Pacing'], dict_['IP'], dict_['Duration'].strip('s'), dict_['Overrun count'], dict_['Overrun penalty'], dict_['We2Squid loss count'], dict_['We2Squid loss penalty'], dict_['Range timeout count'], dict_['Range timeout penalty'], ])) #dict_['Packet lost between us and squid'], 
                        if not dict_.has_key('Mode'):
                            if dict_.has_key('Packet lost on all'):
                                dict_['Mode'] = 'range'
                            else:
                                dict_['Mode'] = ''
                        outf.writelines(',' + dict_['Mode'] + ',')
                        if dict_['Mode'] == 'range':
                            outf.writelines(','.join([dict_['Packet lost on all'], dict_['Range requested'],]))
                        else:
                            outf.writelines(',,')
                        if dict_.has_key("avg loss rate"):
                            
                        outf.writelines('\n')
            break
