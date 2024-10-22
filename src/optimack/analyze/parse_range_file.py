import os, sys, re, traceback

def str_to_kbyte(st):
    num = 0
    last_letter = st[-1]
    if last_letter.isdigit():
        num = int(st)/1024.0
    elif last_letter == 'k':
        num = int(st.replace('k',''))
    elif last_letter == 'M':
        num = float(st.replace('M',''))*1024
    return num

def parse_range_file(dir_name, file_name):
    try:
        numbers_str = file_name.split('_')[5]
        output = tuple(map(int, re.findall("\d+", numbers_str)))
        with open(os.path.join(dir_name, file_name), 'r') as inf:
            lines = list(filter(None, inf.read().splitlines()))
            if len(lines) > 2:
                avg_speed, last_speed, duration, recv_bytes, total_bytes,error_cnt = 0,0,0,0,1,0
                if 'Total is' in lines[-1]:
                    total_bytes = int(lines[-1].split(': ')[1])/1024.0
                for line in lines[::-1]:
                    if 'curl: (18)' in line:
                        error_cnt += 1
                    if '83.4M' in line:
                        fields = list(filter(None,line.replace('d ','d').split(' ')))
                        if len(fields) < 7:
                            continue
                        recv_bytes = str_to_kbyte(fields[3])
                        avg_speed = str_to_kbyte(fields[6])
                        duration = sum(x * int(t) for x, t in zip([3600, 60, 1], fields[9].split(":"))) 
                        last_speed = str_to_kbyte(fields[11])
                        break
                output += avg_speed, last_speed, duration, recv_bytes/total_bytes, recv_bytes, total_bytes, error_cnt
                print(output)
                return output
    except:
        print(file_name)
        print('%s' % traceback.format_exc())
    return None

if __name__ == '__main__':
    in_dir = os.path.expanduser(sys.argv[1])
    keyword = sys.argv[2]
    outfile_path = in_dir+'/range_output_'+os.path.basename(in_dir)+'_'+keyword+'.csv'
    with open(outfile_path, 'w') as out_file:
        if not os.path.getsize(outfile_path):
            out_file.writelines(','.join(['optim_num','range_group_num','range_duplica_num','speed','last_speed', 'duration', 'efficiency','recved_bytes','total_bytes', 'error_cnt'])+'\n')
        for root, dirs, files in os.walk(in_dir):
            for f in files:
                if f.startswith('curl_squid_') and keyword in f and 'delete' not in f and f.endswith('.txt'):
                    # print('Parse: ' + f)
                    output = parse_range_file(root, f)
                    if output:
                        output = map(str, output)
                        out_file.writelines(','.join(output)+'\n')


# curl_file = os.path.expanduser(sys.argv[1])
# outfile_path = curl_file+'.csv'
# with open(outfile_path, 'a') as out_file:
#     if os.path.getsize(outfile_path):
#         out_file.writelines(','.join(['optim_num','range_group_num','range_duplica_num','speed','efficiency','recved_bytes','total_bytes'])+'\n')    
    # with open(curl_file, 'r') as inf:
    #     blocks = filter(None,inf.read().split('\n\n'))
    #     for block in blocks:
    #         lines = filter(None, block.splitlines())
    #         numbers = re.findall("\d+", lines[0])
    #         out_file.writelines(','.join(numbers))
    #         parse_range_file(lines, out_file)