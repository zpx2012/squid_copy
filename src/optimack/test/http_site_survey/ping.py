import os, sys, subprocess as sp, re, shlex
from urllib.parse import urlparse

def parse_ping_result(output):
    output_lines = output.split('\n')
    rtt_pattern = re.compile('^rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms')

    for output_line in output_lines:
        rtt_match = rtt_pattern.match(output_line)
        if rtt_match:
            return rtt_match.group(2)
    return ""


with open(os.path.expanduser(sys.argv[1]),'r') as inf, open(os.path.expanduser(sys.argv[1].replace(".txt", "_cn_filtered.txt")), 'w') as outf:
    lines = filter(None,inf.read().splitlines())
    for line in lines:
        domain = urlparse(line.strip()).netloc
        cmd = "ping -c 20 -i 0.2 " + domain
        p = sp.Popen(shlex.split(cmd), stdout=sp.PIPE, encoding='utf8')
        out, err = p.communicate()
        # print(out, err)
        rtt_avg = parse_ping_result(out)
        if rtt_avg:
            print("%s, %s" % (domain, rtt_avg))
            if float(rtt_avg) > 100:
                outf.writelines(domain + "," + rtt_avg + "\n")