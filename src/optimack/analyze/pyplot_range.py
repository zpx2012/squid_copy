import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np


def load_csv(in_file):
    df = pd.read_csv(in_file, sep=',')
    df.columns = ['optim_num','range_group_num','range_duplica_num','speed','last_speed','duration','efficiency','recved_bytes','total_bytes','error_cnt']
    df = df[ df.last_speed > 0 ]
    df = df[ df.duration >= 59 ]
    df = df[ df.total_bytes > 1 ]
    return df

def reform_df(df, keyword, out_file, group):
    union_df = 0
    first = 0
    if group:
        df = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).mean()
        df.to_csv(in_file.replace('.csv',"_union.csv"), encoding='utf-8',index=False)
    print(df)
    for i in range(1,4):
        for j in range(1,8):
            df_sub = df[ df.optim_num == i ]
            df_sub = df_sub[ df_sub.range_duplica_num == j ]
            df_sub = df_sub[ ['range_group_num', keyword] ]
            df_sub.columns = ['range_group_num', str(i)+'optim+'+str(j)+'duplica']
            if not first:
                union_df = df_sub
                first = 1
            else:
                union_df = pd.merge(union_df,df_sub,on=['range_group_num'],how='outer')
    union_df.sort_values(by=['range_group_num'],inplace=True)
    union_df.to_csv(out_file, encoding='utf-8',index=False)
    return union_df

def plot(df, out_file, lim):
    fig = df.plot(x='range_group_num')
    for i, line in enumerate(fig.get_lines()):
        line.set_marker(markers[i%(len(markers))])
    fig.legend(bbox_to_anchor=(0, -0.4, 1, 0.2), loc="lower center", mode="expand", ncol=3, fancybox=True)
    plt.ylim(0, lim)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_file) #transparent=True

def boxplot(df, keyword, out_file, lim):
    fig = df.boxplot(column=[keyword], by=['optim_num', 'range_group_num', 'range_duplica_num'])
    fig.legend(bbox_to_anchor=(0, -0.4, 1, 0.2), loc="lower center", mode="expand", ncol=3, fancybox=True)
    plt.ylim(0, lim)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_file) #transparent=True

in_file = os.path.expanduser(sys.argv[1])
title = sys.argv[2]
markers = ['H', '^', 'v', 's', '3', '.', '1', '_', 'x', ',', '*', '+']
ylims = {'speed':1200, 'efficiency':1}
for keyword in ['speed','efficiency']:
    union_file = in_file.replace('.csv',"_"+keyword+"_union.csv")
    fig_file = union_file+'.png'
    df = load_csv(in_file)
    # union_df = reform_df(df, keyword, union_file, False)
    # plot(union_df, fig_file, ylims[keyword])
    boxplot(df, keyword, union_file+'_boxplot.png', ylims[keyword])

#Confidence Interval figure
#p value