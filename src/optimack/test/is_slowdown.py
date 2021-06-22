import os, sys

curl_file = os.path.expanduser(sys.argv[1])
with open(curl_file, 'r') as inf:
    lines = filter(None,inf.read().splitlines())
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
        if speed < 128:
            print("True")
        break