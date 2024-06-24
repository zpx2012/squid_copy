import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np


def load_csv(in_file):
    df = pd.read_csv(in_file, sep=',')
    df.columns = ['optim_num','range_group_num','range_duplica_num','speed','efficiency','recved_bytes','total_bytes']
    return df

def reform_df(df, keyword, out_file):
    union_df = 0
    first = 0
    df = df[ df.speed > 50 ]
    df = df[ df.total_bytes > 1 ]
    df = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).mean()
    print(df)
    for i in range(1,3):
        for j in range(1,3):
            df_sub = df[ df.optim_num == i ][ df.range_duplica_num == j ][ ['range_group_num', keyword] ]
            df_sub.columns = ['range_group_num', str(i)+'optim+'+str(j)+'duplica']
            if not first:
                union_df = df_sub
                first = 1
            else:
                union_df = pd.merge(union_df,df_sub,on=['range_group_num'],how='outer')
    union_df.sort_values(by=['range_group_num'],inplace=True)
    union_df.to_csv(out_file, encoding='utf-8',index=False)
    return union_df

def plot(df, out_file):
    fig = df.plot(x='range_group_num')
    for i, line in enumerate(fig.get_lines()):
        line.set_marker(markers[i])
    fig.legend(bbox_to_anchor=(0, 1.02, 1, 0.2), loc="lower left", mode="expand", ncol=2, fancybox=True)
    plt.tight_layout()
    plt.savefig(out_file) #transparent=True

in_file = os.path.expanduser(sys.argv[1])
markers = ['H', '^', 'v', 's', '3', '.', '1', '_', 'x', ',', '*', '+']
for keyword in ['speed','efficiency']:
    union_file = in_file.replace('.csv',"_"+keyword+"_union.csv")
    fig_file = union_file+'.png'
    df = load_csv(in_file)
    union_df = reform_df(df, keyword, union_file)
    plot(union_df, fig_file)


#Confidence Interval figure
#p value