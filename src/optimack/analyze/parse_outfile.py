import time, os, sys,traceback,threading,dateutil,re,json,multiprocessing
import numpy as np
import pandas as pd
from os.path import expanduser
from datetime import datetime,timedelta
from dateutil import tz, parser
from collections import OrderedDict

def files(path):  
    for file in os.listdir(path):
        filepath_abs = os.path.join(path, file)
        if os.path.isfile(filepath_abs):
            yield filepath_abs

def parse_ss(input_path, output_path):
    with open(input_path,'r') as inf, open(output_path, 'w') as outf:
        outf.writelines('time, sk_alloc_mem\n')
        lines = filter(None,inf.read().splitlines())
        for line_num,line in enumerate(lines):
            if '+08:00' in line:
                time = parser.parse(line)
                if line_num+1 >= len(lines) or 'skmem' not in lines[line_num+1]: 
                    continue
                rmem_allocated = re.findall('r\d+', lines[line_num+1])[0][1:]
                outf.write(time.strftime('%Y-%m-%d %H:%M:%S.%f,') + rmem_allocated + '\n')


def parse_traceroute_outfile(input_path,output_path):
    path_dict = {}#all
    cur_path = {}
    tm = None
    output = []
    with open(input_path,'r') as inf:
        for line_num,line in enumerate(filter(None,inf.read().splitlines())):  
            try:
                if re.match('^2019-.* UTC$',line):
                    if tm:
                        cur_path_str = str(cur_path)
                        if path_dict.has_key(cur_path_str):
                            pi = path_dict[cur_path_str]
                        else:
                            pi = len(path_dict)
                            path_dict[cur_path_str] = pi
                        output.append('%s,%d'%(tm,pi))          
                    tm = dateutil.parser.parse(line).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    line_list = filter(None, line.replace(')','(').split('('))
                    if len(line_list) == 3:
                        hopnum = int(line[:2])
                        cur_path[hopnum] = line_list[1]
            except:
                print('###\n%s' % traceback.format_exc())
    
    path_list = [None] * len(path_dict)
    for k,v in path_dict.items():
        path_list[v] = k
#    cur_path = pa

    with open(output_path,'w') as outf,open(output_path.replace('.csv','.path_info'),'w') as pf:
        outf.writelines('time,path_index\n%s' % '\n'.join(output))
        pf.writelines('\n'.join(path_list))


# def parse_tr_path_outfile(input_path,output_path):
#     with open(input_path,'r') as inf:
#         for line_num,line in enumerate(filter(None,inf.read().splitlines())):
#             line_list = line.split(':')

def parse_hping3_stdout_outfile(input_path,output_path):

    tm,lr = None,'0'
    rxn,tot,flag = 0,60.0,0
    tots = {}
    rslt = []
    out_lines,err_lines = [],[]
    # if os.path.basename(input_path).split('_')[5] == 'SA':
    #     tot = 120.0
    with open(input_path,'r') as inf:
        out_lines = filter(None,inf.read().splitlines())
    with open(input_path.replace('stdout','stderr'),'r') as inf:
        err_lines = filter(None,inf.read().splitlines())
    print err_lines
    try:
        for line in err_lines:
            if re.match('^2019-.* UTC$',line):
                tm = dateutil.parser.parse(line).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
            elif re.search('\d+ packets transmitted, \d+ packets received',line):
                tot = re.findall('[-]?\d+',line)[0]
                if tm:
                    tots[tm] = int(tot)
                    print('add %d' %  int(tot))
        tm = None
        for line_num,line in enumerate(out_lines):       
            if re.match('^2019-.* UTC$',line):
                if tm:
                    if tots.has_key(tm):
                        tot = tots[tm]
                        lsn = tot-rxn
                        if rxn:
                            flag += 1
                        if lsn < 0:
                            print('rxn > tot!')
                            print(rxn,tot)
                        else:
                            rslt.append(tm+','+str(lsn/tot*100))                                  
                        rxn = 0
                tm = dateutil.parser.parse(line).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
            if re.search('len=\w+ ip=[\w,.]+ ttl=\d+ id=\d+ sport=\d+ flags=R\w* seq=\d+ win=\d+ rtt=',line):
                rxn += 1

        if flag > 9:
            with open(output_path,'w') as outf:
                outf.write('time,loss_rate\n')
                outf.write('\n'.join(rslt)) 
    except:
        print '###\n%s' % traceback.format_exc()

def parse_opthrput_outfile(input_path,output_path):
    lines,out_str = [],'time,throughput\n'
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    try:
        for line in lines:
            if 'KB/s' in line and 'UTC' in line:
                cells = line.split(',')
                cells[0] = dateutil.parser.parse(cells[0]).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
                cells[1] = cells[1].replace(' KB/s','')
                out_str += ','.join(cells) + '\n'
        with open(output_path,'w') as outf:
            outf.write(out_str)
    
    except:
        print '###\n%s' % traceback.format_exc()

def parse_hping3_outfile(input_path,output_path):
    hcnt,cnt = 0,0
    tm,lr,rtt = None,'0','0'
    lines,out_str = [],'time,loss_rate,latency_average\n'
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    
    try:
        for line_num,line in enumerate(lines):   
            if re.match('^2019-.* UTC$',line):
                tm = dateutil.parser.parse(line).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
            elif re.match('^\d+ packets transmitted, \d+ packets received, \d+% packet loss$',line):
                lr = re.findall('[-]?\d+',line)[2]
                rtt = re.findall('\d+\.\d',lines[line_num+1])[1]
                cnt += 1
                if int(lr) > 80:
                    hcnt += 1                
                if tm:
                    out_str +=','.join([tm,lr,rtt])+'\n'
                    # if '-' in lr:
                        # lr = '0'
                # elif re.match('^\d+ packets transmitted, \d+ packets received, -\d+% packet loss$',line):
                #     return
                # elif re.match('^round-trip min/avg/max = \d+\.\d/\d+\.\d/\d+\.\d ms',line):
        if cnt != 0 and hcnt/float(cnt) > 0.8:
            print('Too high!')
            return

        print('Write to %s' % output_path)
        with open(output_path,'w') as outf:
            outf.write(out_str)
 
    except:
        print '###\n%s' % traceback.format_exc()


def parse_curl_outfile_avg(input_path,output_path):
    line_num = 0
    start_time = 0
    lines = []
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    with open(output_path,'w') as outf:
        outf.write('time,speed\n')
        for line_num,line in enumerate(lines[:len(lines)-1]):
            try:
                if re.match('^< Date: .* GMT$',line):
                    start_time = datetime.strptime(line,'< Date: %a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
                if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or '* Closing connection' not in lines[line_num+1]:
                    continue                                          
                intvl = time.strptime(line[55:63].strip(), '%H:%M:%S')
                
                speed,index = 0,34
                fields = filter(None,line.replace('d ','d').split(' '))
                # print fields
                speed_str = fields[-6]
                last_letter = speed_str[-1]
                if last_letter.isdigit():
                    speed = int(speed_str)/1024.0
                elif last_letter == 'k':
                    speed = int(speed_str.replace('k',''))
                elif last_letter == 'M':
                    speed = float(speed_str.replace('M',''))*1024
                else:
                    raise ValueError('inner level')
                if speed == 0:
                    print(fields)
                    print(fields[-6],speed)
                outf.write((start_time + timedelta(hours=intvl.tm_hour,minutes=intvl.tm_min,seconds=intvl.tm_sec)).strftime('%Y-%m-%d %H:%M:%S,') + str(speed) + '\n')
            except ValueError as e:
                print(e)
                print('parse speed error: %d: %s' % (line_num, line))
                print(fields[-6])
            except:
                print('###\n%s' % traceback.format_exc())
                print('%d: %s' % (line_num, line))


def parse_curl_outfile_no_time(input_path,output_path):
    line_num = 0
    start_time = 0
    lines = []
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    start_time = datetime.strptime('2019'+os.path.basename(input_path).split('_')[-1],'%Y%m%d%H%Mutc.txt').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai')) - timedelta(seconds=40)
    with open(output_path,'w') as outf:
        outf.write('time,speed\n')
        for line_num,line in enumerate(lines):
            # print line
            try:
                if re.match('^< Date: .* GMT$',line):
                # if ' Task :' in line :
                #     index = line.find('2018-')
                #     start_time = dateutil.parser.parse(line[index:index+25])
                #     if start_time.tzinfo:
                #         start_time = start_time.astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                #     else:
                #         print 'no tzinfo'
                # start_time = datetime.strptime(line[index:index+18],'%Y-%m-%d %H:%M:%S')
                    # start_time = datetime.strptime(line,'< Date: %a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
                    start_time += timedelta(seconds=40)
                if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or 'Spent' in line or 'curl' in line:
                    continue
                intvl = time.strptime(line[55:63].strip(), '%H:%M:%S')
                
                speed = 0
                if line[77].isdigit():
                    speed = int(line[72:78])/1024
                elif line[77] == 'k':
                    speed = int(line[72:77])
                elif line[77] == 'M':
                    speed = float(line[72:77])*1024
                else:
                    raise ValueError('inner level')
                # print speed
                outf.write((start_time + timedelta(hours=intvl.tm_hour,minutes=intvl.tm_min,seconds=intvl.tm_sec)).strftime('%Y-%m-%d %H:%M:%S,') + str(speed) + '\n')
                # start_time += timedelta(seconds=1)
            except ValueError as e:
                prin(e)
                print 'parse speed error: %d: %s' % (line_num, line)
                print line[72:78]
                print line[77]
            except:
                print '###\n%s' % traceback.format_exc()
                print '%d: %s' % (line_num, line)


def parse_curl_outfile_with_ip(input_path,output_path):
    line_num = 0
    start_time = 0
    ips = {}
    lines = []
    output_path = output_path.replace('curl','curl-ip')
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    # file_time = datetime.strptime(os.path.basename(input_path).split('_')[-1],'%Y%m%d%H%M.txt').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
    file_time = datetime.strptime('2019'+os.path.basename(input_path).split('_')[-1],'%Y%m%d%H%Mutc.txt').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
    with open(output_path,'w') as outf:
        outf.write('time,speed,ip\n')
        for line_num,line in enumerate(lines):
            # print line
            try:
                if line.startswith('2019-'):
                # if re.match('^< [Dd]ate: .* GMT$',line):
                # if ' Task :' in line :
                #     index = line.find('2018-')
                #     start_time = dateutil.parser.parse(line[index:index+25])
                #     if start_time.tzinfo:
                #         start_time = start_time.astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                #     else:
                #         print 'no tzinfo'
                # start_time = datetime.strptime(line[index:index+18],'%Y-%m-%d %H:%M:%S')
                    start_time = datetime.strptime(line,'%Y-%m-%d %H:%M:%S').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
                    # if start_time >= file_time + timedelta(days=2):
                    #     break
                if '* Connected to' in line:
                    ip_raw = re.findall('\(\d+\.\d+\.\d+\.\d+\)',line)
                    if len(ip_raw) != 1:
                        print 'parse_curl_outfile_with_ip: more than one ip in "Connected to"'
                    ip = re.findall('\d+\.\d+\.\d+\.\d+', ip_raw[0])[0]
                    if not ips.has_key(ip):
                        ips[ip] = str(len(ips))
                if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or 'Spent' in line or 'curl' in line:
                    continue
                intvl = time.strptime(line[55:63].strip(), '%H:%M:%S')
                
                speed = 0
                if line[77].isdigit():
                    speed = int(line[72:78])/1024
                elif line[77] == 'k':
                    speed = int(line[72:77])
                elif line[77] == 'M':
                    speed = float(line[72:77])*1024
                else:
                    raise ValueError('inner level')
                # print speed

                outf.write(','.join([(start_time + timedelta(hours=intvl.tm_hour,minutes=intvl.tm_min,seconds=intvl.tm_sec)).strftime('%Y-%m-%d %H:%M:%S'),str(speed),ips[ip]]) + '\n')
            except ValueError as e:
                print e
                print 'parse speed error: %d: %s' % (line_num, line)
                print line[72:78]
                print line[77]
            except:
                print '###\n%s' % traceback.format_exc()
                print '%d: %s' % (line_num, line)
    with open(output_path.replace('.csv','_dns_ip.txt'),'w') as outf:
        outf.writelines(json.dumps(ips))



def parse_aria2_outfile(input_path,output_path):
    line_num = 0
    start_time = parser.parse('2020-12-20 14:30:22+08:00')
    lines = []
    second = 0
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())

    with open(output_path,'w') as outf:
        outf.write('time,speed\n')
        for line_num,line in enumerate(lines):
            try:
                time_match = re.match('Start: (.*)$',line)
                if time_match:
                    start_time = parser.parse(time_match.group(1))
                    # start_time = datetime.strptime(line,'Start: %Y-%m-%d %H:%M:%S').replace(tzinfo=tz.tzutc())#.astimezone(tz.gettz('Asia/Shanghai'))
                    second = 0
                m = re.match(r"\[#\w+ \w+/\w+\(\d+%\) CN:\d+ DL:(\w+) ETA:\w+\]", line)
                if m:
                    speed_str = m.group(1)
                    speed = 0
                    if 'KiB' in speed_str:
                        speed = int(speed_str.strip("KiB"))
                    elif 'MiB' in speed_str:
                        speed = int(speed_str.strip("MiB")) * 1024
                    outf.writelines((start_time+timedelta(seconds=second)).strftime('%Y-%m-%d %H:%M:%S,') + str(speed) + '\n')
                    second += 1
            except:
                print '###\n%s' % traceback.format_exc()
                print '%d: %s' % (line_num, line)



cn_ips = ['221.194.155.186','122.224.45.229','218.58.101.229','27.148.139.136','210.192.117.229','222.138.3.126','221.230.146.237','60.221.218.191','119.145.144.223','118.123.102.227','182.247.227.19']

def parse_curl_outfile(input_path,output_path):
    line_num = 0
    start_time = parser.parse('2020-12-20 14:30:22+08:00')
    start_epochtime = (start_time.replace(tzinfo=None) - datetime(1970, 1, 1)).total_seconds()
    lines = []
    with open(input_path,'r') as inf:
        lines = filter(None,inf.read().splitlines())
    try:
        file_time = datetime.strptime(os.path.basename(input_path).split('_')[-1],'%Y%m%d%H%M%S.txt').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
    except ValueError:
        file_time = datetime.strptime('2020'+os.path.basename(input_path).split('_')[-1],'%Y%m%d%H%M.txt').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
    
    apple_pattern = re.compile('.*\* Connected to www\.apple\.com \(([\d]+\.[\d]+\.[\d]+\.[\d]+)\) port 443 \(#\d\)')
    skip_flag = False

    with open(output_path,'w') as outf:
        outf.write('time,epoch_time,relav_time,speed\n')
        for line_num,line in enumerate(lines):
            # print line
            try:
                if 'apple' in os.path.basename(output_path):
                    # print line
                    apple_match = apple_pattern.match(line)
                    if apple_match:
                        # print apple_match.group(1),type(apple_match.group(1)),apple_match.group(1) in cn_ips
                        if apple_match.group(1) in cn_ips:
                            skip_flag = True
                        else:
                            skip_flag = False
                        # if skip_flag:
                        #     print apple_match.group
                if re.match('^< [Dd]ate: .* GMT$',line):
                    start_time = datetime.strptime(line,'< Date: %a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
                # if re.match('Start: .*$',line):
                #     start_time = datetime.strptime(line,'Start: %Y-%m-%d %H:%M:%S').replace(tzinfo=tz.tzutc())#.astimezone(tz.gettz('Asia/Shanghai'))
                time_match = re.match('Start: (.*)$',line)
                if time_match:
                    start_time = parser.parse(time_match.group(1))
                    start_epochtime = (start_time.replace(tzinfo=None) - datetime(1970, 1, 1)).total_seconds()

                # if ' Task :' in line :
                #     index = line.find('2018-')
                #     start_time = dateutil.parser.parse(line[index:index+25])
                #     if start_time.tzinfo:
                #         start_time = start_time.astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                #     else:
                #         print 'no tzinfo'
                # start_time = datetime.strptime(line[index:index+18],'%Y-%m-%d %H:%M:%S')
                    # if start_time >= file_time + timedelta(days=2):
                    #     break
                if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or 'Spent' in line or 'curl' in line:
                    continue
                intvl = time.strptime(line[55:63].strip(), '%H:%M:%S')
                intvl_sec = (intvl.tm_hour * 60 + intvl.tm_min) * 60 + intvl.tm_sec
                
                speed = 0
                if line[77].isdigit():
                    speed = int(line[72:78])/1024
                elif line[77] == 'k':
                    speed = int(line[72:77])
                elif line[77] == 'M':
                    speed = float(line[72:77])*1024
                else:
                    raise ValueError('inner level')
                # print speed
                if not skip_flag:
                    if not start_time:
                        print "Null start time"
                    cur_time = start_time + timedelta(hours=intvl.tm_hour,minutes=intvl.tm_min,seconds=intvl.tm_sec)
                    outf.write(','.join([cur_time.strftime('%Y-%m-%d %H:%M:%S'), str(start_epochtime+intvl_sec), str(intvl_sec), str(speed)])+'\n')
                    # for i in range(7):
                    #         outf.write(',,\n')
            except ValueError as e:
                print e
                print 'parse speed error: %d: %s' % (line_num, line)
                print line[72:78]
                # print line[77]
            except:
                print '###\n%s' % traceback.format_exc()
                print '%d: %s' % (line_num, line)


def parse_old_outfile(input_path,output_path):
    with open(input_path,'r') as inf,open(output_path,'w') as outf:
        outf.write('time,speed\n')
        for line_num, line in enumerate(inf.read().splitlines()):
            if 'k/s' not in line:
                continue
            try:
                outf.write(line[:19]+','+str(float(line[23:32]))+'\n')
            except:
                print '###\n%s' %traceback.format_exc()
                print '%d: %s' % (line_num, line)
                print line[:19]
                print line[23:32]
 

def parse_iperf3(input_path,output_path):
    with open(input_path,'r') as inf,open(output_path,'w') as outf:
        outf.write('time,speed\n')
        for line_num, line in enumerate(inf.read().splitlines()):
            if 'Time' in line:
                time = datetime.strptime(line,'Time: %a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=tz.tzutc()).astimezone(tz.gettz('Asia/Shanghai'))
            elif 'receiver' not in line and 'sender' not in line and 'KBytes/sec' in line:
                try:
                    fields = filter(None,line.split('  '))
                    if len(fields) > 5:
                        speed = float(fields[5].split('KBytes/sec')[0].replace(' ',''))
                        offset = float(fields[2].split('-')[0].replace(' ',''))
                        outf.write((time+timedelta(seconds=offset)).strftime('%Y-%m-%d %H:%M:%S,') + str(speed)+'\n')
                except:
                    print '###\n%s' %traceback.format_exc()
                    print '%d: %s' % (line_num, line)
                    print fields[5]
                    print fields[2]

def parse_scp(input_path,output_path):
    with open(input_path,'r') as inf, open(output_path,'w') as outf:
        outf.write('time,speed\n')    
        interval = 0
        for line_num, line in enumerate(inf.read().splitlines()):
            try:
                if ' Task :' in line :
                    interval = 0
                    index = line.find('2018-')
                    start_time = dateutil.parser.parse(line[index:index+25])
                    if start_time.tzinfo:
                        start_time = start_time.astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                    else:
                        print 'no tzinfo'
                if line.startswith('my.pcap'):
                    line_list = filter(None, line.split(' '))
                    if len(line_list) < 4:
                        continue
                    interval += 1
                    speed_str = line_list[3].strip('/s')
                    if 'KB' in speed_str:
                        speed = float(speed_str.strip('KB'))
                    elif 'MB' in speed_str:
                        speed = float(speed_str.strip('MB'))*1024
                    else:
                        raise ValueError('not KB or MB')
                    outf.write((start_time + timedelta(seconds=interval)).strftime('%Y-%m-%d %H:%M:%S,')+str(speed)+'\n')
            except ValueError as e:
                print e
                print 'parse speed error: %d: %s' % (line_num, line)


            except:
                print '###\n%s' % traceback.format_exc()
                print '%d: %s' % (line_num, line)


def parse_nethogs(input_path,output_path):
    try:
        interval = 0
        start_time = dateutil.parser.parse(('2018'+os.path.basename(input_path).split('_')[2].split('.')[0].replace('utc','UTC'))).astimezone(dateutil.tz.gettz('Asia/Shanghai'))
        pid = 0
        pids = {}
        filename_list = []
        outstr_list = []
        # valid_file_num = 0
        for filepath_abs in files(out_dir+'/raw_data/'):
            filename = os.path.basename(filepath_abs)
            if filename.startswith('pid') and filename.endswith('txt') and os.path.basename(input_path).split('_')[1] == filename.split('_')[1]:
                outfile_absp = out_dir + '/csv/' + filename.replace('pid_','nethogs_').replace('.txt','.csv')
                if os.path.exists(outfile_absp):
                    print 'parse_outfile: File exist %s\n' % os.path.basename(output_path)
                    continue
                filename_list.append(outfile_absp)
                outstr_list.append('time,throughput\n')
                print 'add: %s,%d' % (outfile_absp,len(filename_list))
                with open(filepath_abs,'r') as f:
                    for pid in filter(None,f.read().splitlines()):
                        pids[int(pid)] = len(filename_list)-1
                    # pids[outfile_absp] = {'pids':map(int,filter(None,f.read().splitlines())),'output':None}
                    # print pids[outfile_absp]
        if not filename_list:
            return

        with open(input_path,'r') as inf:#,open(output_path.replace('nethogs','nethogs_http'),'w') as fhttp, open(output_path.replace('nethogs','nethogs_shadowsocks'),'w') as fss:
            for line_num,line in enumerate(filter(None,inf.read().splitlines())):    

                    if line == 'Refreshing:':
                        interval += 1
                        continue
                    split_tabs = line.split('\t')
                    split_slash = split_tabs[0].split('/')
                    # print split_tabs
                    # print split_slash
                    if len(split_tabs) == 3 and len(split_slash) > 2:
                        if '/usr/bin/python/' in split_tabs[0]:
                            pid = int(split_slash[4])
                            # print (start_time + timedelta(seconds=interval)).strftime('%Y-%m-%d %H:%M:%S,')+split_tabs[2]+'\n'
                            # fss.write((start_time + timedelta(seconds=interval)).strftime('%Y-%m-%d %H:%M:%S,')+split_tabs[2]+'\n')
                        elif split_slash[0] == 'curl' and split_tabs[1] != '0' and split_tabs[2] != '0':
                            pid = int(split_slash[1])
                        else:
                            continue
                        s = (start_time + timedelta(seconds=interval)).strftime('%Y-%m-%d %H:%M:%S,')+split_tabs[2]+'\n'
                        if pids.has_key(pid):
                            outstr_list[pids[pid]] += s
                        else:
                            print 'no key:%d' % pid
                        # print s

        for i,file in enumerate(filename_list):
            print 'write: %s' % file
            with open(file,'w') as f:
                f.writelines('%s' % outstr_list[i])
                    
    except ValueError as e:
        print e
        print 'parse speed error: %d: %s' % (line_num, line)
        print '###\n%s' % traceback.format_exc()

    except KeyError:
        print '###\n%s' % traceback.format_exc()

    except:
        print '###\n%s' % traceback.format_exc()
        print '%d: %s' % (line_num, line)
        print pids[pid]
        # print di


def parse_mtr_each_hop_lazy(input_path,output_path):
    try:
        ign_as_list = []
        i_row_df = -1
        ip_group_dict = get_ip_groups(input_path)
        if not ip_group_dict:
            print ip_group_dict.keys()
        df_loss = pd.DataFrame(columns=['time'].append(ip_group_dict.keys()))
        df_rtt = pd.DataFrame(columns=['time'].append(ip_group_dict.keys()))
        df_bestrtt = pd.DataFrame(columns=['time'].append(ip_group_dict.keys()))
        with open(input_path,'r') as inf:
            for line_num,line in enumerate(filter(None,inf.read().splitlines())):
                try:
                    if len(line) < 13:
                        continue
                    if line[:6] == 'Start:':
                        i_row_df += 1
                        time_tmp = dateutil.parser.parse(line[7:]).astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                        # if time_tmp < parser.parse("2021-02-23T07:13:35+0800") or time_tmp > parser.parse("2021-02-23T07:30:58+0800"):
                        #     continue
                        # if time_tmp.tzinfo:
                        #     time_tmp = time_tmp.astimezone(dateutil.tz.gettz('Asia/Shanghai'))
                        #     # time_tmp = time_tmp.astimezone(dateutil.tz.gettz('America/Los_Angeles'))
                        # else:
                        #     time_tmp += timedelta(hours=8)
                            # time_tmp -= timedelta(hours=7)
                        time_str = time_tmp.strftime('%Y-%m-%d %H:%M:%S')
                        df_loss.loc[i_row_df,'time'] = time_str
                        df_rtt.loc[i_row_df,'time'] = time_str
                        df_bestrtt.loc[i_row_df,'time'] = time_str
                    elif line[3] == '.' and line[7:12].strip() not in ign_as_list:
                        # if time_tmp < parser.parse("2021-02-23T07:13:35+0800") or time_tmp > parser.parse("2021-02-23T07:30:58+0800"):
                        #     continue
                        line_list = filter(None, line.split(' '))
                        # if sys.argv[2] == 'loss':
                        #     target_value = float(line_list[3].strip('%'))
                        # elif sys.argv[2] == 'latency':
                        #     target_value = float(line_list[6].strip())
                        # else:
                        #     print 'please enter: loss/latecy'
                        if '.' not in line_list[0]:
                            print '. not in line_list[0]'
                            print '%d:%s'%(line_num, line)
                        rt_list = [cname for cname,ip_set in ip_group_dict.iteritems() if line_list[2] in ip_set]
                        if len(rt_list) > 1:
                            print 'ip:%s\n rt:%s\n' % (line_list[2],str(rt_list))
                        # hop_num = line_list[0].strip('.')
                        # if not hopname_dict.has_key(hop_num):
                        #     hopname_dict[hop_num] = hop_num + '_' + line_list[1]
                        elif rt_list:
                            df_loss.loc[i_row_df, rt_list[0]] = float(line_list[3].strip('%'))
                            df_rtt.loc[i_row_df, rt_list[0]] = float(line_list[6].strip())
                            df_bestrtt.loc[i_row_df, rt_list[0]] = float(line_list[7].strip())
                except KeyboardInterrupt:
                    os._exit(-1)
                except:
                    print '###\n%s' %traceback.format_exc()
                    print '%d:%s' % (line_num, line)
                    print 'target value: %s' % line[29:35]
                    print ip_group_dict
        df_loss.to_csv(output_path,encoding='utf-8', index=False)#[['time']+ip_group_dict.keys()],[['time']+ip_group_dict.keys()],[['time']+ip_group_dict.keys()]
        df_rtt.to_csv(os.path.dirname(output_path)+'/'+os.path.basename(output_path).replace('_loss_','_latency_'),encoding='utf-8', index=False)
        df_rtt.to_csv(os.path.dirname(output_path)+'/'+os.path.basename(output_path).replace('_loss_avg','_latency_best'),encoding='utf-8', index=False)
    except:
        print '###\n%s' % traceback.format_exc()


def get_ip_groups(input_path):
    try: 
        output_path = csv_dir + '/' + os.path.basename(input_path.replace('.txt','_ip_count.txt'))
        if os.path.exists(output_path):
            lines = []
            with open(output_path,'r') as f:
               lines = filter(None,f.read().splitlines())
            if lines:
                # print('From existing branch')
                return json.loads(lines[0],object_pairs_hook=OrderedDict)
        
        ip_hop_dict = {}
        with open(input_path,'r') as inf:
            lines = filter(None,inf.read().splitlines())
            i = 0
            # time_tmp = parser.parse("2021-02-21T07:13:35+0800")
            while(i < len(lines)):
                # if lines[i][:6] == 'Start:':
                #     time_tmp = dateutil.parser.parse(lines[i][7:])
                # if time_tmp < parser.parse("2021-02-23T07:13:35+0800") or time_tmp > parser.parse("2021-02-23T07:30:58+0800"):
                #     continue
                if len(lines[i]) >= 13 and lines[i][3] == '.':
                    line_list = filter(None, lines[i].split(' '))
                    hop_num = int(line_list[0].strip('.'))
                    ips = [line_list[2]]
                    as_num = line_list[1]
                    i += 1
                    while(i < len(lines) and len(lines[i]) >= 13 and lines[i][3] != '.'):
                        line_list = filter(None, lines[i].split(' '))
                        if line_list[0].startswith('AS'):
                            if line_list[0] != 'AS???' and line_list[0] != as_num: #two ASs in one hop
                                as_num = 'AS incons'
                            try:
                                ips.append(line_list[1])
                            except:
                                print '###\n%s' %traceback.format_exc()
                        i += 1
                    for ip in ips:
                        if ip == '???':
                            continue
                        if not ip_hop_dict.has_key(ip):
                            ip_hop_dict[ip] = {'hops':{hop_num:1},'AS':{as_num:1}}
                        else:
                            if not ip_hop_dict[ip]['hops'].has_key(hop_num):
                                ip_hop_dict[ip]['hops'].update({hop_num:1})
                            else:
                                ip_hop_dict[ip]['hops'][hop_num] += 1
                            if not ip_hop_dict[ip]['hops'].has_key(as_num):
                                ip_hop_dict[ip]['AS'].update({as_num:1})
                            else:
                                ip_hop_dict[ip]['AS'][as_num] += 1
                    i -= 1
                i += 1
        # print 'Here'
        #sort
        for key,val in ip_hop_dict.items():
            val['AS'].pop('AS???',None)
            for hop_index,cnt in val['hops'].items():#denoise
                if cnt < 1:
                    val['hops'].pop(hop_index)
            if not val['hops']:
                ip_hop_dict.pop(key)
            else:
                ip_hop_dict[key]['hops'] = sorted(val['hops'].items())
        ip_hop_sorted_list = sorted(ip_hop_dict.items(),key=lambda x:x[1]['hops'][0])

        #group
        ip_set_dict = {}
        for ip,hops_as in ip_hop_sorted_list:
            hop_indexs = '_'.join([str(key) for key,val in hops_as['hops']] + hops_as['AS'].keys())
            if not ip_set_dict.has_key(hop_indexs):
                ip_set_dict[hop_indexs] = []
            if ip not in ip_set_dict[hop_indexs]:
                ip_set_dict[hop_indexs].append(ip)
            # # [str(hop) for hop,cnt in hops_cnt])
            # found_keys = [key for key,val in ip_set_dict.items() if hop_indexs in key]
            # if not found_keys:
            #     new_key = hop_indexs + '_' + '_'.join(hops_as['AS'])
            #     ip_set_dict[new_key] = set([ip])
            # elif len(found_keys) == 1:
            #     ip_set_dict[found_keys[0]].update([ip])
            #     new_as = [v for v in hops_as['AS'] if v not in found_keys[0]]
            #     if new_as:
            #         new_key = found_keys[0] + '_' + '_'.join(new_as)
            #     if new_key != found_keys:
            #         ip_set_dict[new_key] = ip_set_dict.pop(found_keys[0])
        for key,ip_set in ip_set_dict.items():
            if len(ip_set) == 1:
                ip = list(ip_set)[0]
                hop_dict = ip_hop_dict[ip]['hops']
                new_key = '_'.join(['{}({})'.format(str(k),str(v)) for k,v in hop_dict]) + '_' + '_'.join(ip_hop_dict[ip]['AS']) + '_' + ip 
            else:
                # print key
                # print key.split('_')[0]
                # print ip_hop_dict[list(ip_set)[0]]
                slist = []
                for ip in ip_set:
                    for hop_num,cnt in ip_hop_dict[ip]['hops']:
                        if str(hop_num) == key.split('_')[0]:
                            slist += ['%s(%d)'%(ip,cnt)]
                new_key = '_'.join([key] + slist)
                print new_key
            ip_set_dict[new_key] = ip_set_dict.pop(key)
        ip_set_orderdict = OrderedDict(sorted(ip_set_dict.items(),key=lambda x:int(x[0].split('_')[0].split('(')[0])))
        # print ip_set_orderdict

        if ip_set_orderdict:
            with open(output_path,'w') as outf:
                # print str(ip_set_dict)
                outf.writelines(json.dumps(ip_set_orderdict))
                outf.write('\n')
                for ip,hops_cnt in ip_hop_sorted_list:
                    outf.write(ip + ':{%s},{%s}\n'%(','.join([str(hop)+': '+str(cnt) for hop,cnt in hops_cnt['hops']]),','.join(hops_cnt['AS'])))
                # for hop_indexs,vset in ip_set_orderdict.items():
                #     outf.write('%s: %s\n'%(hop_indexs,','.join(vset)))
        
        return ip_set_orderdict
    except KeyboardInterrupt:
        sys.exit(-1)
    except:
        print '###\n%s' %traceback.format_exc()


'''
--- 202.97.6.69 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 1502ms
rtt min/avg/max/mdev = 36.989/38.737/40.191/1.216 ms
'''

abbr_to_fullname_dict = {'BJ':'China/Beijing',
                         'CD':'China/Chengdu',
                         'CQ':'China/Chongqing',
                         'Harbin':'China/Harbin',
                         'HHHT':'China/Hohht',
                         'HK':'Hong Kong',
                         'HZ':'China/Hangzhou',
                         'QD':'China/Qingdao',
                         'SH':'China/Shanghai',
                         'SZ':'China/Shenzhen',
                         'SJZ':'China/Shijiazhuang',
                         'Tianjin':'China/Tianjin',
                         'Xiamen':'China/Fujian',
                         'ZJK':'China/Zhangjiakou',

                         'AUS':'Australia',
                         'BRA':'Brazil',
                         'CAN':'Canada',
                         'DEU':'Germany',
                         'GBR':'United Kingdom',
                         'IND':'India',
                         'JPN':'Japan',
                         'KOR':'Korea',
                         'NY':'United States/New York',
                         'OH':'United States/Ohio',
                         'OR':'United States/Oregon',
                         'RUS':'Russia',
                         'SF':'United States/California',
                         'SGP':'Singapore',
                         'SWE':'Sweden',
                         'VG':'United States/Virginia',
                         'CKG':'United States/Chicago',
                         'LA':'United States/Los Angeles',
                         'SEA':'United States/Seattle',
                         'SV':'United States/Silicon Valley',
                         'PAR':'France/Paris',
                         'AMS':'Netherland',
                         'CA':'United States/California',
                         'GZ':'China/Guangzhou',
                         'IRE':'Ireland'
                         }


def parse_shortestPing(input_path, out_path):
    try:
        ip_pattern = re.compile('^--- ([\d]+\.[\d]+\.[\d]+\.[\d]+) ping statistics ---$')
        rtt_pattern = re.compile('^rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms$')

        with open(input_path,'r') as inf, open(out_path, 'w') as outf:
            # col_name = '_'.join(os.path.basename(input_path).split('.')[0].split('_')[1:])
            col_name = abbr_to_fullname_dict[os.path.basename(input_path).split('.')[0].split('_')[1].split('-')[0]]
            outf.writelines('ip,%s\n'%(col_name))
            lines = filter(None,inf.read().splitlines())
            for i in range(len(lines)):
                ip_match = ip_pattern.match(lines[i])
                if ip_match:
                    ip = ip_match.group(1)
                    rtt_min = 'NA'
                    if i+2 < len(lines):
                        rtt_match = rtt_pattern.match(lines[i+2])
                        if rtt_match:
                            rtt_min = rtt_match.group(1)
                    outf.writelines(','.join([ip,rtt_min])+'\n')
                
    except:
        print '###\n%s' %traceback.format_exc()



def unpack_args(l):
    print "Parse file:%s" % l[2]
    l[0](l[1],l[2])
    if os.path.exists(l[2]) and os.stat(l[2]).st_size <= 1024:
        os.remove(l[2])

csv_dir = ''


if __name__ == '__main__':

    out_dir = os.path.abspath(os.path.expanduser(sys.argv[1]))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    csv_dir = os.path.join(out_dir, 'csv')
    if not os.path.exists(csv_dir):
        os.makedirs(csv_dir)

    thread_count = 0
    old_kw = ['regular','socks','iperf']

    task_list = []
    for filepath_abs in files(os.path.join(out_dir,'raw_data')):
        filename = os.path.basename(filepath_abs)
        if not filename.endswith("txt") or os.stat(filepath_abs).st_size < 5 or '_check_' in filename or (len(sys.argv) > 3 and sys.argv[3] not in filename):# or 'mtr' in filename or :
            continue

        postfix = '_speed.csv'
        if filename.startswith('iperf3'):
            func = parse_iperf3
        elif filename.startswith('aria2'):
            func = parse_aria2_outfile
            postfix = '.csv'
        elif filename.startswith('ss_'):
            postfix = '.csv'
            func = parse_ss
        elif filename.startswith('mtr'):
            # get_ip_groups(filepath_abs)
            postfix = '_loss_avg_each_hop.csv'
            func = parse_mtr_each_hop_lazy
        elif filename.startswith('scp'):
            func = parse_scp
        #elif any(x in filename for x in old_kw):
        #    func = parse_old_outfile
        elif filename.startswith('nethogs'):
            func = parse_nethogs
        elif filename.startswith('ptraceroute_'):
            postfix = '.csv'
            func = parse_traceroute_outfile
        elif filename.startswith('hping3') and 'stderr' in filename:
            postfix = '.csv'
            func = parse_hping3_outfile
        # elif filename.startswith('hping3') and 'stdout' in filename:
        #     postfix = '.csv'
        #     func = parse_hping3_stdout_outfile
        elif filename.startswith('curl'):
            postfix = '.csv'
            # os.system('dos2unix -c mac %s' % filepath_abs)
            func = parse_curl_outfile
            if '__https' in filename or 'twich' in filename:
                func = parse_curl_outfile_no_time
        elif filename.startswith('opthrput'):
            func = parse_opthrput_outfile
        elif filename.startswith('shortestPing_'):
            postfix = '.csv'
            func = parse_shortestPing
        else:
            continue

        output_path = os.path.join(csv_dir, filename.replace('.txt',postfix))
        print 'parse: %s' % os.path.basename(output_path)
        if (sys.argv[2] != '1' and os.path.exists(output_path)) or postfix == '':
            print 'parse_outfile: File exist or invalid postfix %s' % os.path.basename(output_path)
        else:
            func(filepath_abs,output_path)
            # task_list.append([func,filepath_abs,output_path])

    # pool = multiprocessing.Pool(processes=4)
    # pool.map(unpack_args, task_list)




    # input_path = '/home/pzhu011/Dropbox/GFW_Data/dataset/mtr_zjk1-aliyun_mit_07241511.txt'
    # parse_lossrate_each_AS(input_path)

    # if any(x for x in hopname_list if str(hop_num) in x): #(hop_num-first_hopnum) > len(hopname_list):
    #     cname = str(hop_num) + '_' + line_list[1]
    #     if not hopname_list:
    #         first_hopnum = hop_num
    #     hopname_list.append(cname)
    #     df[cname] = np.nan                      
    # hopname_list_index = hop_num - first_hopnum   
    # if hop_num != int(hopname_list[hopname_list_index].split('_')[0]):
    #     print '\nerror: hop_num %d, hop_list %d,hoplist_index %d' % (hop_num,int(hopname_list[hopname_list_index].split('_')[0]),hopname_list_index)   
    #     print '%d:%s'%(line_num, line)
    #     print hopname_list            
    # df.loc[i_row_df, hopname_list[hopname_list_index]] = target_value
        # all_files = [ files for root, dirs, files in os.walk(out_dir+'/raw_data/')]#expanduser("~/GoogleDrive/dataset/raw_")  

    # output_path = csv_dir + os.path.basename(input_path).replace('.txt','') +             
    # output_path = csv_dir + os.path.basename(input_path).replace('.txt','') + '_speed.csv'
    # output_path = csv_dir + os.path.basename(input_path.replace('.txt','_')) + sys.argv[2] + '_avg_each_hop.csv'
    # output_path = csv_dir + os.path.basename(input_path.replace('.txt','_ip_count.txt'))        
    # output_path = csv_dir + os.path.basename(input_path).replace('.txt','') + '_speed.csv'

                        # outfile = None
                        # for k,v in pids.iteritems():
                        #     if pid in v['pids']:
                        #         outfile = k
                        #         v['output'] += (start_time + timedelta(seconds=interval)).strftime('%Y-%m-%d %H:%M:%S,')+split_tabs[2]+'\n'
                        #         break
                        # if not outfile:
                        #     print pid
                        #     raise ValueError

    # parse_nethogs(out_dir+'/raw_data/nethogs_hhht1-aliyun_1128003121utc.txt',out_dir)
    # sys.exit(0)

    # threads = []

    # exist_fig = [ x.split('_09')[0] for x in os.listdir(csv_dir) ]