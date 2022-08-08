import pandas as pd, csv, sys

def parse_csv(infile):
    output_dict = {}
    # output_dict = {'tag' :['Port', 'Domain', 'URI', 'Request_Time', 'Response_Time', 'Content_Length']}
    # df = pd.DataFrame(columns = ['Port', 'Domain', 'URI', 'Request_Time', 'Response_Time', 'Content_Length'])
    with open(infile, 'r') as inf:
        for i, line in enumerate(inf.read().splitlines()):
            if line.startswith("csv,"):
                cells = line.split(', ')
                if cells[4] == 'request':
                    tag = '_'.join([cells[1], cells[2], cells[3]])
                    output_dict[tag] = [cells[1], cells[2], cells[3], cells[5], '', '']
                else:
                    tag = '_'.join([cells[1], cells[2], cells[3]])
                    output_dict[tag][4] = cells[5]
                    output_dict[tag][5] = cells[6]
    print(output_dict)
    df = pd.DataFrame.from_dict(output_dict, orient='index', columns=['Port', 'Domain', 'URI', 'Request_Time', 'Response_Time', 'Content_Length'])
    df = df.apply(pd.to_numeric, errors='ignore')
    df['Wait_Time'] = df['Response_Time'] - df['Request_Time']
    print(df)
    df.to_csv(infile+'_pd.csv', index=False)

parse_csv(sys.argv[1])