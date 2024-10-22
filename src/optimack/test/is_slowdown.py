import os, sys


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

curl_file = os.path.expanduser(sys.argv[1])
with open(curl_file, 'r') as inf:
    lines = filter(None,inf.read().splitlines())
    for line in lines[::-1]:
        if len(line) != 78 or line[55:63] == '--:--:--' or '  0     0    0     0    0     0      0      0' in line or 'Spent' in line or 'curl' in line:
            continue
        speed = 0
        fields = filter(None,line.replace('d ','d').split(' '))
        speed = str_to_kbyte(fields[6])
        if speed < 128:
            print("True")
        else:
            print("False")
        break