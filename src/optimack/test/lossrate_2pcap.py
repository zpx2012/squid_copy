import os, sys, shlex, time, datetime, traceback, dateutil, inspect, numpy as np, multiprocessing
import subprocess as sp
from dateutil import tz, parser
from datetime import datetime, timedelta

def is_valid_file(path, filename):
  return filename.startswith('tcpdump') and filename.endswith('wtime') and os.stat(os.path.join(path, filename)).st_size > 0


#-e frame.time_relative -e ip.id -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr
def seg_packet(line, seglen):
    ret = []
    fields = line.split('\t')
    if len(fields) < 7:
        return ''
    data_len = int(fields[6])
    # fields[1] = str(int(fields[1], 16))
    if data_len <= seglen:
        return line

    ipid = int(fields[1], 16)
    seq_num = int(fields[4])
    while data_len > 0:
        fields[1] = "0x{:08x}".format(ipid, 16)
        fields[4] = str(seq_num)
        fields[6] = str(seglen)
        ret.append('\t'.join(fields))
        seq_num += seglen
        data_len -= seglen
        ipid += 1
    return '\n'.join(ret)


def get_seglen(fp):
    lens = {}
    with open(fp, 'r') as f:
        i = 0
        for line in f:
            line = line.strip()
            if i > 20:
                break
            fields = line.split('\t')
            if len(fields) > 7:
                pktlen = int(fields[6])
                if pktlen:
                    if pktlen >= 1000:
                        i += 1
                        if pktlen < 1500:
                            if pktlen not in lens.keys():
                                lens[pktlen] = 0
                            else:
                                lens[pktlen] += 1
                        else:
                            if lens:
                                for k, v in lens.items():
                                    if k and pktlen % k == 0:
                                        lens[k] += 1
                            else:
                                for j in range(2, 5):
                                    if pktlen % j == 0:
                                        lens[pktlen/j] = 0
                                        break
                    else:
                        if pktlen not in lens.keys():
                            lens[pktlen] = 0
                        else:
                            lens[pktlen] += 1
    print lens
    # return max(lens, key=lens.get)
    return 1460


def seg_file(dir, fil, seglen):
    if not dir.endswith('/'):
        dir += '/'
    out, fout = '', fil+'_seged'
    if os.path.exists(dir+fout):
        # print 'seg_file: File exists %s' % fil
        return fout
    print 'seg_file:'+fil
    try:

        with open(dir+fil, 'r') as f:
            for line in f:
                line = line.strip()
                out += seg_packet(line, seglen)+'\n'
        with open(dir+fout, 'w+') as f:
            f.write(out)
        return fout
    except:
        print '###\n%s' % traceback.format_exc()


def find_time_offset(dir, fc_wtime, fs_wtime, port):
    if not dir.endswith('/'):
        dir += '/'
    stimes, souts, offsets = [], [], []
    try:
        with open(dir+fs_wtime, 'r') as inf:
            cnt = 0
            for i, line in enumerate(inf):
                fields = line.strip().split('\t')
                if i%1000 < 100 and fields[2] == port: #keep away
                    stimes.append(float(fields[0]))
                    souts.append('\t'.join(fields[1:]))
                    cnt += 1
                    if cnt == 400:
                        break
        with open(dir+fc_wtime, 'r') as inf:
            for i, line in enumerate(inf):
                if i > 10000:
                    break
                fields = line.strip().split('\t')
                out_str= '\t'.join(fields[1:])
                rt = [i for i, x in enumerate(souts) if x == out_str]
                if rt:
                    ctime = float(fields[0])
                    stime = stimes[rt[0]]
                    if ctime < stime:
                        print 'ctime:%f stime:%f'%(ctime, stime)
                    offsets.append(ctime - stime)
        avg = 100
        if offsets:
            avg = np.mean(offsets)
        # print souts
        # print avg
        return avg

    except:
        print '###\n%s' % traceback.format_exc()


def split_by_port_minute(dir, in_file, port):
    # if not in_file or not in_file.endswith('.wtime_seged'):
    #     print '%s: Invalid filename' % inspect.stack()[0][3]
    #     return
    if not dir.endswith('/'):
        dir += '/'
    print inspect.stack()[0][3]+':'+os.path.basename(in_file)
    start = None
    sout, slines = dir+in_file.split('.')[0].split('_')[-1]+'.src%s_'%port, []
    dout, dlines = dir+in_file.split('.')[0].split('_')[-1]+'.dst%s_'%port, []
    # rtts, time_rtt_dict = [], {}
    # first_tmrel, first_tsval = None, None
    intvl = 1
    with open(dir+in_file, 'r') as inf:
        for line in inf:
            try:
                # print line.strip()
                fields = line.strip().split('\t')
                if len(fields) > 3:
                    cur = float(fields[0])
                    if not start:
                        start = int(cur) / intvl * intvl
                    select_fields = [fields[1]] + fields[4:]
                    if cur <= start + intvl:
                        if   fields[2] == port:
                            slines.append('\t'.join(select_fields))
                        elif fields[3] == port:
                            dlines.append('\t'.join(select_fields))
                        else:
                            print inspect.stack()[0][3]+":no port found - "+fields[2]+" "+fields[3]
                    else:
                        time_str = datetime.utcfromtimestamp(start).replace(tzinfo=dateutil.tz.tzutc()).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y%m%d%H%M%S')
                        if slines:
                            with open(sout + time_str, 'w') as outf:
                                outf.writelines('\n'.join(slines)+'\n')
                        if dlines:
                            with open(dout + time_str, 'w') as outf:
                                outf.writelines('\n'.join(dlines)+'\n')
                        slines, dlines, rtts = [], [], []
                        start += intvl
            except:
                print '###\n%s' % traceback.format_exc()

        time_str = datetime.utcfromtimestamp(start).replace(tzinfo=dateutil.tz.tzutc()).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y%m%d%H%M%S')
        if slines:
            with open(sout + time_str, 'w') as outf:
                outf.writelines('\n'.join(slines)+'\n')
        if dlines:
            with open(dout + time_str, 'w') as outf:
                outf.writelines('\n'.join(dlines)+'\n')


def cat_mfiles(dir, kw):
    print inspect.stack()[0][3]+':'+dir
    files = [x for x in sorted(os.listdir(dir)) if kw in x and not x.endswith('_cat')]
    for i in range(len(files)):
        # print files[i]
        file_cat_name = files[i] + '_cat'
        if os.path.exists(dir+file_cat_name):
            continue
        subfiles = files[i - 5 if i - 5 >= 0 else 0:i + 10]
        p = sp.Popen(shlex.split('bash -c "cd {0};cat {1} > {2}"'.format(dir, ' '.join(subfiles), file_cat_name)))
        p.communicate()
        with open(dir+files[i]+'_cat_subfiles.log', 'w') as outf:
            outf.writelines('\n'.join(subfiles))
    # for f in files:
    #     os.remove(dir+'/'+f)

#  0. .pcap -> client.wtime/server.wtime
#  1. Include all wtime in one dir
#     find client/server using fields[1:3]+fields[4][:4](e.g. VG-AWS-O2C_ZJK-ALI-O2C_0402)
#     mkdir VG-AWS-O2C_ZJK-ALI-O2C_0402
#     cp _client/server*.wtime
#  2. .wtime -> .wtime_seged
#  3. .wtime_seged -> .src80_201903151544/.dst80_201903151544
#  5. cat min file to 15min:
#     client.src80_201903151544 > client.src80_201903151544_cat
#     server.dst80_201903151544 > server.dst80_201903151544_cat  
#  6. find:
#     server.scr80_%time in client.src80_%time_cat  
#     client.dst80_%time in server.dst80_%time_cat


def tshark(in_file, out_file, port, typ):
    # tshark_cmd = 'tshark -r {0} -Tfields -o tcp.relative_sequence_numbers:FALSE -e frame.time_epoch -e ip.id -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -Y "ip.ttl > 10 and (tcp.srcport eq {1} or tcp.dstport eq {1}) and tcp.data == 0" > {2}'.format(in_file, port, out_file) and tcp.len > tcp.hdr_len
    if typ == 'normal':
        tshark_cmd = 'tshark -r {0} -Tfields -o tcp.relative_sequence_numbers:FALSE -e frame.time_epoch -e ip.id -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -Y "ip.ttl > 10 and (tcp.srcport eq {1} or tcp.dstport eq {1})" > {2}'.format(in_file, port, out_file)
    elif typ == 'data':
        tshark_cmd = 'tshark -r {0} -Tfields -o tcp.relative_sequence_numbers:FALSE -e frame.time_epoch -e ip.id -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -Y "ip.ttl > 10 and (tcp.srcport eq {1} or tcp.dstport eq {1}) and tcp.len > tcp.hdr_len" > {2}'.format(in_file, port, out_file)
    elif typ == 'ack':
        tshark_cmd = 'tshark -r {0} -Tfields -o tcp.relative_sequence_numbers:FALSE -e frame.time_epoch -e ip.id -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -Y "ip.ttl > 10 and (tcp.srcport eq {1} or tcp.dstport eq {1}) and tcp.len < tcp.hdr_len" > {2}'.format(in_file, port, out_file)
    else:
        print 'Invalid type'
        return

    p = sp.Popen(tshark_cmd, stdout=sp.PIPE, shell=True)
    # p = sp.Popen(shlex.split(tshark_cmd), stdout=sp.PIPE)#'/'.join(in_dir, file) stderr=open(os.devnull, 'w')
    out, err = p.communicate()
    # print out
    # print err

def loss_only(dir, fsender, frecver):
    print("loss_only: sender:%s recver:%s" % (fsender, frecver))
    if not frecver.endswith("_cat"):
        print("loss_only: Invalid recver!")
    loss_rate = None
    p = sp.Popen(shlex.split('wc -l ' + dir + fsender), stdout=sp.PIPE)
    out, err = p.communicate()
    print out
    all_num = int(out.split(' ')[0])
    if all_num > 100:
        p = sp.Popen(
            shlex.split('bash -c \'comm -23 <(sort {0}) <(sort {1}) | wc -l\''.format(dir + fsender, dir + frecver)),
            stdout=sp.PIPE)
        out, err = p.communicate()
        print out
        lines = out.splitlines()
        loss_num = float(lines[0])

        if loss_num > all_num:
            print 'Error: loss_num %d > all_num %d: %s' % (loss_num, all_num, fsender)
        if all_num:
            loss_rate = loss_num/all_num
    return loss_rate


def loss_rtt(dir, fsnd, frcv):
    loss_num, all_num, rtts = 0, 0, []
    with open(dir+fsnd, 'r') as fsnd_, open(dir+frcv, 'r') as frcv_:
        for line in fsnd_:
            all_num += 1
            try:
                fields = line.strip().split('\t')
                stime, sline = float(fields[0]), '\t'.join(fields[1:])
                res = [x for x in frcv_ if sline in x]
                if res:
                    if len(res) > 1:
                        print 'loss_rtt: More than one match found', res
                    rtime = float(res[0].split('\t')[0])
                    if stime > rtime:
                        print 'sendtime > rcvtime: %f %f %s', stime, rtime, sline
                    rtts.append(rtime - stime)
                    loss_num += 1
            except:
                print '###\n%s' % traceback.format_exc()

    loss_rate, rtt = 1.0, 1000.0
    if all_num:
        loss_rate = float(loss_num)/all_num
    if rtts:
        rtt = sum(rtts)/len(rtts)
    return loss_rate, rtt


def lossrate_2pcap_client_side(packed_list):
    dir, fc_wtime, fs_wtime, port = packed_list[0], packed_list[1], packed_list[2], packed_list[3]
    if not fc_wtime or not fs_wtime or fc_wtime == '' or fs_wtime == '' or 'client' not in fc_wtime or 'server' not in fs_wtime:
        print 'Bad argument'
        return
    if not dir.endswith('/'):
        dir += '/'
    if packed_list[4] == '1':
        fc_seglen = get_seglen(dir+fc_wtime)
        fs_seglen = get_seglen(dir+fs_wtime)
        seglen = min(fc_seglen, fs_seglen)
        print fc_seglen, fs_seglen, seglen
        fc_wtime_seg, fs_wtime_seg = seg_file(dir, fc_wtime, seglen), seg_file(dir, fs_wtime, seglen)
    else:
        fc_wtime_seg, fs_wtime_seg = fc_wtime, fs_wtime
    print dir, find_time_offset(dir, fc_wtime_seg, fs_wtime_seg, port)

    kws = ['server.src', 'client.dst']
    outfs = [os.path.basename(fs_wtime).replace('.wtime', '')+'_src%s_%s.csv' % (port, packed_list[5]), os.path.basename(fc_wtime).replace('.wtime', '')+'_dst%s_%s.csv' % (port, packed_list[5])]
    fc_per_sec = split_by_port_minute(dir, fc_wtime_seg, port)

    out_str = ''
    for fc in fc_per_sec:
        loss = loss_only(dir, fs_wtime_seg, fc)
        if loss > 0.5:
            print("loss = %d: %s" % (loss, fc))
            # sys.exit(-1)
        # loss, rtt = loss_rtt(dir, f, fs)
        if loss != None:
            time_str = fc.split('.')[1].split('_')[1]
            out_str += ', '.join([dateutil.parser.parse(time_str).strftime('%Y-%m-%d %H:%M:%S'), str(loss)]) + '\n'
    
    if out_str:
        print 'write to:', dir+outfs[1]
        with open(dir+outfs[1], 'w') as out_sender:
            out_sender.writelines('time, loss_rate, rtt\n'+out_str)




def lossrate_2pcap(packed_list):
    dir, fc_wtime, fs_wtime, port = packed_list[0], packed_list[1], packed_list[2], packed_list[3]
    if not fc_wtime or not fs_wtime or fc_wtime == '' or fs_wtime == '' or 'client' not in fc_wtime or 'server' not in fs_wtime:
        print 'Bad argument'
        return
    if not dir.endswith('/'):
        dir += '/'
    if packed_list[4] == '1':
        fc_seglen = get_seglen(dir+fc_wtime)
        fs_seglen = get_seglen(dir+fs_wtime)
        seglen = min(fc_seglen, fs_seglen)
        print fc_seglen, fs_seglen, seglen
        fc_wtime_seg, fs_wtime_seg = seg_file(dir, fc_wtime, seglen), seg_file(dir, fs_wtime, seglen)
    else:
        fc_wtime_seg, fs_wtime_seg = fc_wtime, fs_wtime
    print dir, find_time_offset(dir, fc_wtime_seg, fs_wtime_seg, port)

    kws = ['server.src', 'client.dst']
    outfs = [os.path.basename(fs_wtime).replace('.wtime', '')+'_src%s_%s.csv' % (port, packed_list[5]), os.path.basename(fc_wtime).replace('.wtime', '')+'_dst%s_%s.csv' % (port, packed_list[5])]
    time_rtts = [split_by_port_minute(dir, fs_wtime_seg, port), split_by_port_minute(dir, fc_wtime_seg, port)]

    cat_mfiles(dir, 'server.dst')
    cat_mfiles(dir, 'client.src')

    for i, kw in enumerate(kws):    
        try:
            out_str = ''
            sender_files = [x for x in sorted(os.listdir(dir)) if kw in x and not x.endswith('_cat')]
            print sender_files
            for fsender in sender_files:
                frecver = fsender.replace(kw.split('.')[0], kws[(i+1)%2].split('.')[0])+'_cat'
                if os.path.exists(dir+frecver):
                    loss = loss_only(dir, fsender, frecver)
                    # if loss:
                    if loss > 0.5:
                        print("loss = %d: %s" % (loss, fsender))
                        # sys.exit(-1)
                    # loss, rtt = loss_rtt(dir, f, fs)
                    if loss != None:
                        time_str = fsender.split('.')[1].split('_')[1]
                        out_str += ', '.join([dateutil.parser.parse(time_str).strftime('%Y-%m-%d %H:%M:%S'), str(loss)]) + '\n'
            if out_str:
                print 'write to:', dir+outfs[i]
                with open(dir+outfs[i], 'w') as out_sender:
                    out_sender.writelines('time, loss_rate, rtt\n'+out_str)
        except:
            print '###\n%s' % traceback.format_exc()
    
    #clean the mess
    # p = sp.Popen(shlex.split('bash -c "cd %s;rm *.src* *.dst*"'%dir))
    # out, err = p.communicate()


# def unpack(args):
#     return lossrate_2pcap(*args)

def get_mark(filename):
    fields = filename.split('_')
    if len(fields) > 3:
        return fields[1]+'_'+fields[2]+'_'+fields[3][:4]
    else:
        return None
# lossrate_2pcap('/data/pzhu/seged/BRA-AWS-O2C_BJ-CU-HM1_0325', 'tcpdump_BRA-AWS-O2C_BJ-CU-HM1_03261941_client.wtime', 'tcpdump_BRA-AWS-O2C_BJ-CU-HM1_03261947_server.wtime', 80)
# lossrate_2pcap(['/data/pzhu/all-wtime/AUS-AWS-O2C_BJ-CU-HM2_0327', 'tcpdump_AUS-AWS-O2C_BJ-CU-HM2_03271942_client.wtime', 'tcpdump_AUS-AWS-O2C_BJ-CU-HM2_03271946_server.wtime', '80'])
# sys.exit(-1)

in_dir = sys.argv[1]
port = sys.argv[2]
tshark_port = sys.argv[3]
segflag = sys.argv[4]
typ = sys.argv[5]
# for root, dirs, files in os.walk(in_dir):
#     files = sorted(files)
#     for i, f in enumerate(files):
#         try:
#             if is_valid_file(root, f):
#                 mark = get_mark(f)
#                 new_dir = root + '/' + mark
#                 if not os.path.exists(new_dir):
#                     p = sp.Popen(shlex.split('bash -c "cd {0};mkdir {1};mv *{1}* {1}/"'.format(root, mark)))
#                     p.communicate()
#         except:
#             print '###\n%s' % traceback.format_exc()
#     break
args_list = []
for root, dirs, files in os.walk(in_dir):
    cwtimes, swtimes, finished = [], [], 0
    for f in reversed(sorted(files)):
        print f
        # if is_valid_file(root, f):
        if f.endswith('_client.wtime') and os.stat(root+'/'+f).st_size > 0:
            cwtimes.append(f)
        elif f.endswith('_server.wtime') and os.stat(root+'/'+f).st_size > 0:
            swtimes.append(f)
        elif f.endswith('src%s_endhost.csv'%port) or f.endswith('dst%s_endhost.csv'%port):
            finished += 1
        elif len(cwtimes) == 0 and f.endswith('_client.pcap0000') and os.stat(root+'/'+f).st_size > 0:
            outfile = f.replace('_client.pcap0000','_client.wtime')
            tshark(root+'/'+f,root+'/'+outfile,tshark_port,typ)
            cwtimes.append(outfile)
        elif len(swtimes) == 0 and f.endswith('_server.pcap0000') and os.stat(root+'/'+f).st_size > 0:
            outfile = f.replace('_server.pcap0000','_server.wtime')
            tshark(root+'/'+f,root+'/'+outfile,tshark_port,typ)
            swtimes.append(outfile)

    if finished == 2:
        print root+": has two endhost.csv files"
        continue
    if len(cwtimes) == len(swtimes) and len(cwtimes) == 1:
        args_list.append([root, cwtimes[0], swtimes[0], port, segflag,typ])
        # if len(args_list) > 0:
        #     break
        # lossrate_2pcap(root, cwtimes[0], swtimes[0], port)
    elif len(cwtimes) > 1 or len(swtimes) > 1:
        print 'More than one cfile/sfile'
        print 'cwtimes:', cwtimes
        print 'swtimes:', swtimes

print 'cwtimes:', cwtimes
print 'swtimes:', swtimes
print args_list
lossrate_2pcap_client_side(args_list[0])
# pool = multiprocessing.Pool(processes=20)
# pool.map(lossrate_2pcap, args_list)

#lossrate_2pcap('ACKTest_SWE-AWS_CHN-ALI', 'tcpdump_SWE-AWS_CHN-ALI_03120847_ACKTest_p3389_client.wtime', 'tcpdump_SWE-AWS_CHN-ALI_03120849_ACKTest_p3389_server.wtime', '3389')
# fc_wtime = fc.replace('.pcap0000', '.wtime')
# fs_wtime = fs.replace('.pcap0000', '.wtime')

#  = fc_wtime.replace('.wtime_', '.')
# tshark_and_seg(fc, fc_wtime, tshark_cmd.format(fc, port))
# tshark_and_seg(fs, fs_wtime, tshark_cmd.format(fs, port))

# def tshark_and_seg(in_file, out_file, tshark_cmd):
#     out_seged = []
#     p = sp.Popen(shlex.split(tshark_cmd), stdout=sp.PIPE)#'/'.join(in_dir, file) stderr=open(os.devnull, 'w')
#     out, err = p.communicate()

#     for line in filter(None, out.splitlines()):
#         out_seged += [seg_packet(line)]
#     print len(out_seged)
#     with open(out_file, 'w') as f:#'/'.join(out_dir, file.replace('.pcap', '.tshark'))
#         f.writelines('\n'.join(out_seged)+'\n')
            
# def strip_rtime_field_and_sort(in_file):
#     if '.wtime_' not in os.path.basename(in_file):
#         print 'strip_rtime_field_and_sort: Invalid filename'
#         return None
#     try:
#         ftmp = in_file.replace('wtime_', 'tmp_')
#         fout = ftmp.replace('tmp_', '')
#         if os.path.exists(fout):
#             print 'strip_rtime_field_and_sort: File exists %s' % os.path.basename(fout)
#             return fout
#         print 'strip_rtime_field_and_sort:'+os.path.basename(in_file)                
#         lines = read_file(in_file)
#         with open(ftmp, 'w') as f:
#             f.writelines('\n'.join([ '\t'.join(x.split('\t')[1:]) for x in lines ]))
#         p = sp.Popen(shlex.split('sort -o {0} {1};rm {1}'.format(fout, ftmp)))
#         p.communicate()
#         return fout
#     except:
#         print '###\n%s' % traceback.format_exc()
    # if os.path.exists(outfs[0]) and os.path.exists(outfs[1]):
    #     print '%s: exists' % outfs[0]
    #     print '%s: exists' % outfs[1]
    #     return
    # for f in [fc_src, fc_dst, fs_src, fs_dst]:
    #     split_by_minute(dir, os.path.basename(f))






# def split_and_calc(fp_a, fp_b, port, fp_out):
#     fa = os.path.basename(fp_a)
#     fb = os.path.basename(fp_b)
#     # if '.wtime_' not in fa or '.wtime_' not in fb:
#     #     print 'split_file_per_minute: Invalid filename'
#     #     return
#     try:
#         lines, result = None, ''
#         start = dateutil.parser.parse('2019'+fa.split('_')[3].split('.')[0].replace('utc', 'UTC')+'+0000')
#         with open(fp_a, 'r') as f:
#             lines = filter(None, f.read().splitlines())
#         cur_min = 60
#         cur_lines = []
#         print len(lines)
#         for i, line in enumerate(lines):
#             fields = line.split('\t')
#             if float(fields[0]) <= cur_min:
#                 cur_lines += ['\t'.join(fields[1:])]
#             else:
#                 if cur_lines or i+1 == len(lines):
#                     #calculate loss rate
#                     comm_cmd = 'bash -c \'comm -12 <(sort %s) %s\''
#                     with open('tmp', 'w') as f:
#                         f.writelines('\n'.join(cur_lines))
#                     p = sp.Popen(shlex.split(comm_cmd%('tmp', fp_b)), stdout=sp.PIPE)#, port
#                     out, err = p.communicate()
#                     arrvnum = len(cur_lines)
#                     if arrvnum:
#                         lossnum = arrvnum - len(filter(None, out.splitlines()))
#                         result += (start + timedelta(seconds=cur_min)).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')+', '+str(float(lossnum)/arrvnum)+'\n'
#                     else:
#                         result += (start + timedelta(seconds=cur_min)).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')+', 0.0\n'
#                 cur_min += 60
#                 cur_lines = []
#                 # print out
#                 # print lossnum
#
#         with open(fp_out, 'w') as f:
#             f.writelines(result)
#     except:
#         print '###\n%s' % traceback.format_exc()
#
# #split the file by 1minute
# def split_by_minute(dir, in_file):
#     if '.wtime_src' not in in_file and '.wtime_dst' not in in_file:
#         print 'split_file_per_minute: Invalid filename'
#         return
#     if not dir.endswith('/'):
#         dir += '/'
#     try:
#         # start_str = in_file.split('.')[0].split('_')[3]
#         # start = dateutil.parser.parse('2019'+start_str.replace('utc', 'UTC')+'+0000')
#         with open(dir+in_file, 'r') as f:
#             start = int(f[0].split('\t')[0])/10*10
#             for line in f:
#                 cur_lines = []
#                 fields = line.split('\t')
#                 cur = float(fields[0])
#                 if cur <= start + 60:
#                     cur_lines += ['\t'.join(fields[1:])]
#                 else:
#                     if cur_lines:
#                         with open(dir+in_file.replace('.wtime_', '.').split('_')[-1] + '_'+ datetime.utcfromtimestamp(start).replace(tzinfo=dateutil.tz.tzutc()).astimezone(dateutil.tz.gettz('Asia/Shanghai')).strftime('%Y%m%d%H%M'), 'w') as outf:
#                             outf.writelines('\n'.join(cur_lines))
#                         cur_lines = []
#                         start += 60
#
#     except:
#         print '###\n%s' % traceback.format_exc()
