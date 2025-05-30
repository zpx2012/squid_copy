import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np

def plot_speed(infile, X, Ys, legendlabels):
    plt.figure(figsize=(8,5))
    # Ys.plot(x='seq',ms=200,figsize=(16,10))
    # plt.plot(X, Ys)
    for i in range(len(Ys)):
    	# print Ys
        if legendlabels is not None:
            plt.plot(X,Ys[i],label=legendlabels[i])
            plt.axhline(y=np.nanmean(Ys[i]), color='tab:orange')
        else:
            plt.plot(X,Ys[i])

    plt.xlabel("Seconds", fontsize=16)
    plt.ylabel("Goodput (Mbps)", fontsize=16)
    plt.yticks(fontsize=12)
    plt.xticks(fontsize=12)
    plt.ylim(0,12)
    plt.title("")
    plt.tight_layout()
    if legendlabels is not None:
        plt.legend(prop={'size': 14})
    plt.savefig(infile+".png",transparent=True)

in_dir = os.path.expanduser(sys.argv[1])
for root, dirs, files in os.walk(in_dir):
    for fn in files:
        if fn.startswith('curl_squid') and fn.endswith('.csv'):
            in_file = root+'/'+fn
            tag = fn.split('_')[5]
            conn_num = int(tag.split('optim')[0])
            df = pd.read_csv(in_file, sep=',') #, names=['time', 'speed']
            rlen, clen = df.shape
            print(rlen, clen)
            df['speed'] = df['speed'] * 8/ 1000
            if rlen >= 59:
                plot_speed(in_file, range(rlen), [list(df.speed)], [tag])