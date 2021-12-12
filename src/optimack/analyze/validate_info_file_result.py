import csv, os, pandas as pd, sys, numpy as np, socket
from datetime import datetime

def duration_str_to_sec(str):
    cells = str.split(':')
    if len(cells) != 3:
        print("Wrong duration str: %s" % str)
        return -1
    cells = map(int, cells)
    return cells[0]*3600+cells[1]*60+cells[2]

def parse_curl_squid_file(dir, filename, df):
    fcells = filename.split(extension)[0].split('_')
    hostname = fcells[2]
    mode = fcells[-2]
    # if mode not in ['backup', 'range']:
    #     mode = ''
    dict_ = {}
    with open(dir+'/'+filename, 'r') as inf:
        lines = inf.read().splitlines()
        if len(lines) == 0:
            return
        if lines[0].startswith("Start: "):
                time_str = lines[0][7:23]
        else:
            print("First line not starts with Start time")
        index = time_str+hostname
        if 'left intact' in lines[-1]:
            duration_str = filter(None,lines[-2].replace('d ','d').split(' '))[-3]
            duration = duration_str_to_sec(duration_str)
            if index in df.index:
                df.at[index, "duration_curl"] = int(duration)
                # df.at[index, "mode"] = mode
            else:
                print("Error: %s not in index" % index)
        elif 'curl: (18) transfer closed with' in lines[-1] or 'curl: (28)' in lines[-1]:
            if index in df.index :
                print("Error: %s failed!" % time_str)
        else:
            print("Unexpected last line: %s" % lines[-1])

def parse_curl_normal_file(dir, filename, df):
    fcells = filename.split(extension)[0].split('_')
    hostname = fcells[2]
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
            index = time_str+hostname
            if index in df.index:
                df.at[index, "normal_speed"] = speed
                if speed <= 128:
                    df.at[index, "in_slowdown"] = True
                else: 
                    df.at[index, "in_slowdown"] = False
            else:
                print("Error: %s not in index" % index)  
            break              

def parse_loss_file(dir, filename, df):
    fcells = filename.split('_avg.csv')[0].split('_')
    hostname = fcells[1]
    time_str = fcells[-1]
    time_str = datetime.strptime(time_str, "%Y%m%d%H%M").strftime('%Y-%m-%dT%H:%M')
    index=time_str+hostname
    if index not in df.index:
        print("Error: %s not in index" % index)

    with open(dir+'/'+filename, 'r') as inf:
        for line in inf.read().splitlines():
            cells = line.split(': ')
            if len(cells) == 2:
                if 'overall lost byte' in cells[0]:
                    df.at[index, "all_lost_bytes(true)"] = float(cells[1])
                elif 'avg loss rate' in cells[0]:
                    df.at[index, "avg_loss_rate"] = float(cells[1])


# print(parse_seq_file(sys.argv[1]))
if __name__ == '__main__':
    for root, dirs, files in os.walk(os.path.expanduser(sys.argv[1])): 
            input_file = 'info_files_result_%s_%s.csv' % (socket.gethostname(), sys.argv[2])
            df = pd.read_csv(root+'/'+input_file, sep=',')
            df['preindex'] = df['timestamp'] + df['hostname']
            df = df.set_index('preindex')
            print df
            df["duration_curl"] = np.nan
            df["normal_speed"] = np.nan
            df["in_slowdown"] = ""
            df["all_lost_bytes(true)"] = np.nan
            df["avg_loss_rate"] = np.nan
            # df["mode"] = ""
            for f in sorted(files):
                extension = '.txt'
                if f.startswith('curl_squid') and f.endswith(extension):
                    print("Parse: %s" % f)
                    parse_curl_squid_file(root, f, df)
                elif f.startswith('curl_normal') and f.endswith(extension):
                    print("Parse: %s" % f)
                    parse_curl_normal_file(root, f, df)
                elif f.startswith('tcpdump_') and f.endswith("_avg.csv"):
                    print("Parse: %s" % f)
                    parse_loss_file(root, f, df)
            print df
            df['ackspeed'] = 10000000.0/df['ack_pace(us)']
            df.to_csv(root+'/'+input_file.replace('.csv','_validated_raw.csv'), encoding='utf-8', index=False)
            df = df[df.in_slowdown == True]
            df = df[df.duration_curl.notnull()]
            print df
            df.to_csv(root+'/'+input_file.replace('.csv','_validated.csv'), encoding='utf-8', index=False)
            df_mean = df.groupby(['hostname','conn_num','ack_pace(us)','mode']).mean().reset_index()
            df_std = df.groupby(['hostname','conn_num','ack_pace(us)','mode']).std().reset_index()
            df_min = df.groupby(['hostname','conn_num','ack_pace(us)','mode']).min().reset_index()
            df_mean['duration_std'] = df_std['duration(s)']
            df_mean['normal_speed_std'] = df_std['normal_speed']
            # df_mean['loss_std'] = df_std['overall_lost_rate']
            # df_mean['overall_lost_byte_std'] = df_std['overall_lost_byte']
            df_mean['duration_min'] = df_min['duration(s)']
            print df_mean['duration(s)'], df_std['duration(s)']
            df_mean.to_csv(root+'/'+input_file.replace('.csv','_validated_mean.csv'), encoding='utf-8', index=False)
            break
