import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np

def scatter_plot(infile, domain, X, Ys, legendlabels):
    print(Ys)
    plt.figure(figsize=(8,5))
    #print(type(list(X)[0]))
    cols = Ys.columns
    # for col in cols[1:]:
    # Ys.plot(x='timestamp', y = cols[1:], ms=200, figsize=(16,10)) #kind='scatter')
    #plt.plot(X, Ys)
    # for i in range(len(Ys)):
    for col in cols[1:]:
    # 	# print Ys
        plt.scatter(X,Ys[col],label=col)

    plt.xlabel("Time")
    plt.ylabel("Duration(s)")
    ax = plt.gca()
    ax.set_xticks(ax.get_xticks()[::80])
    # plt.locator_params(axis='x', nbins=10)
    #plt.ylim(0,15)
    plt.title("ShenZhen-8G_4thread_8connections_"+domain)
    plt.tight_layout()
    if legendlabels is not None:
        plt.legend()	
    plt.savefig(infile+".png")#,transparent=True)

def boxplot(infile, domain, X, Ys, legendlabels):
    ax1 = Ys.plot(kind='box',showmeans=True,meanprops=dict(marker='.', markersize=10),rot=5, showfliers=False,sort_columns=True,grid=False,legend=True)
    ax1.xaxis.grid(visible=True,linestyle='-')
    # plt.tight_layout()
    plt.title("ShenZhen-8G_4thread_8connections_"+domain)
    plt.savefig(infile+".png")#,transparent=True)

    


in_file = os.path.expanduser(sys.argv[1])
df = pd.read_csv(in_file, sep=',')
df.columns = ['domain', 'mode', 'timestamp', 'ErrorCode', 'connectEnd', 'connectStart', 'domComplete', 'domContentLoadedEventEnd', 'domContentLoadedEventStart', 'domInteractive', 'domLoading', 'domainLookupEnd', 'domainLookupStart', 'fetchStart', 'loadEventEnd', 'loadEventStart', 'navigationStart', 'redirectEnd', 'redirectStart', 'requestStart', 'responseEnd', 'responseStart', 'secureConnectionStart', 'unloadEventEnd', 'unloadEventStart', 'backendTime', 'domContentLoadedTime', 'onLoadTime']
df = df[df['ErrorCode'] == 'Success']
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df[df.timestamp >= pd.to_datetime('2023-03-02T4:0:0')]
df = df[df['timestamp'] < pd.to_datetime('2023-03-03T4:0:0') ]
modes = ['Normal', 'Squid', 'Proxy']
durations = ['backendTime', 'domContentLoadedTime', 'onLoadTime']
for dur in durations:
    for mode in modes:
        if mode == 'Squid':
            df[dur+'_'+mode] = df[dur][df['mode'] == mode] / 1000
        elif mode == 'Proxy':
            df[dur+'_'+mode] = df[dur][df['mode'] == mode] / 1000
        else:
            df[dur+'_'+mode] = df[dur][df['mode'] == mode] / 1000


#domains = ['nginx.org', 'go.com', 'www.videolan.org']
domains = ['nginx.org', 'go.com', 'www.videolan.org', 'www.ebay.com', 'www.sciencedirect.com', 'www.springer.com', 'www.yandex.ru', 'www.ted.com', 'www.github.com', 'www.gnu.org']
for domain in domains:
    print(domain)
    df_sub = df[df['domain'] == domain]
    if not df_sub.empty: 
        for dur in durations:
            scatter_plot(in_file+domain+dur, domain, df_sub['timestamp'], df_sub[['timestamp', dur+'_Normal', dur+'_Squid', dur+'_Proxy']], ['Normal', 'Squid', 'Proxy'])
            boxplot(in_file+'_boxplot_cleaned_'+domain+dur, domain, df_sub['timestamp'], df_sub[['timestamp', dur+'_Normal', dur+'_Squid', dur+'_Proxy']], ['Normal', 'Squid', 'Proxy'])
    #plot(in_file+domain+'onLoadTime', df_sub['timestamp'], df_sub[['timestamp', 'onLoadTime_Normal', 'onLoadTime_Squid', 'onLoadTime_Proxy']], ['Normal', 'Squid', 'Proxy'])
