import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np


def load_csv(in_file):
    df = pd.read_csv(in_file, sep=',')
    df.columns = ['optim_num','range_group_num','range_duplica_num','speed','last_speed','duration','efficiency','recved_bytes','total_bytes','error_cnt']
    df = df[ df.last_speed > 0 ]
    df = df[ df.duration >= 59 ]
    df = df[ df.total_bytes > 1 ]
    return df

def group_df(df):
    df_mean = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).mean()
    df_mean['count'] = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).size()[['size']]
    print(df_mean)
    # df_mean.to_csv(in_file.replace('.csv',"_union.csv"), encoding='utf-8',index=False)
    return df_mean

def reform_df(df, keyword, out_file):
    union_df = 0
    first = 0
    for i in range(1,4):
        for j in range(1,6):
            df_sub = df[ df.optim_num == i ]
            df_sub = df_sub[ df_sub.range_group_num == j ]
            df_sub = df_sub[ ['range_duplica_num', keyword] ]
            df_sub.columns = ['range_duplica_num', str(i)+'optim+'+str(j)+'group']
            if not first:
                union_df = df_sub
                first = 1
            else:
                union_df = pd.merge(union_df,df_sub,on=['range_duplica_num'],how='outer')
    union_df.sort_values(by=['range_duplica_num'],inplace=True)
    union_df.to_csv(out_file, encoding='utf-8',index=False)
    print(union_df)
    return union_df

def plot(df, out_file, lim):
    fig = df.plot(x='range_duplica_num', figsize=(8,5), title=title)
    for i, line in enumerate(fig.get_lines()):
        line.set_marker(markers[i%(len(markers))])
    fig.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    # fig.legend(loc=7)
    # fig.legend(loc="center right", bbox_to_anchor=(1.8, 0.5)) #bbox_to_anchor=(0, -0.6, 1, 0.2), ncol=3,
    plt.ylim(0, lim)
    # plt.title(title)
    plt.tight_layout() #rect=[0, 0, 0.75, 1]
    # plt.suplots_adjust(right=0.75)
    plt.savefig(out_file, bbox_inches="tight") #transparent=True

def boxplot(df, keyword, out_file, lim):
    ax = 0
    for i in range(1,4):
        for j in range(1,7):
            col_name = str(i)+'optim+'+str(j)+'duplica'
            df_sub = df[ df.optim_num == i ]
            df_sub = df_sub[ df_sub.range_duplica_num == j ]
            df_sub = df_sub[ ['range_group_num', keyword] ]
            df_sub.columns = ['range_group_num', col_name]
            # if not ax:
                # ax = df_sub.boxplot(column=str(i)+'optim+'+str(j)+'duplica', by='range_group_num')
            # else:
            df_sub.boxplot(column=col_name, by='range_group_num', showmeans=True)
            plt.savefig(out_file+'_'+col_name+'.png')
            # plt.boxplot(list(df_sub[[str(i)+'optim+'+str(j)+'duplica']]), positions=list(df_sub[['range_group_num']]))
    # fig = df.boxplot(column=[keyword], by=['optim_num', 'range_group_num', 'range_duplica_num'], )
    # ax.legend(bbox_to_anchor=(0, -0.4, 1, 0.2), loc="lower center", mode="expand", ncol=3, fancybox=True)
    # plt.ylim(0, lim)
    # # plt.title(title)
    # plt.tight_layout()
    # plt.savefig(out_file) #transparent=True

in_file = os.path.expanduser(sys.argv[1])
title = sys.argv[2]
markers = ['H', '^', 'v', 's', '3', '.', '1', '_', 'x', ',', '*', '+']
ylims = {'speed':1200, 'efficiency':1, 'count':10}

df = load_csv(in_file)
df_mean = group_df(df)
for keyword in ['speed',]: #,'count''efficiency'
    union_file = in_file.replace('.csv',"_"+keyword+"_union.csv")
    fig_file = union_file+'.png'
    union_df = reform_df(df_mean, keyword, union_file)
    plot(union_df, fig_file, ylims[keyword])
    # boxplot(df, keyword, in_file.strip('.csv'), ylims[keyword])

#Confidence Interval figure
#p value