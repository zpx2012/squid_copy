import csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np
from datetime import datetime


def load_csv(in_file):
    df = pd.read_csv(in_file, sep=',')
    # df.columns = ['optim_num','range_group_num','range_duplica_num','speed','last_speed','duration','efficiency','recved_bytes','total_bytes','error_cnt']
    df = df[ df.last_speed > 0 ]
    df.speed = df.speed * 8 / 1000.0
    df.efficiency = df.efficiency * 100
    df = df[ df.duration >= 59 ]
    df = df[ df.total_bytes > 1 ]
    return df

def group_df(df):
    df_mean = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).mean()
    df_mean['count'] = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).size()[['size']]
    df_mean['err_cnt'] = df.groupby(by=['optim_num','range_group_num','range_duplica_num'], as_index=False).agg({'error_cnt':sum})['error_cnt']
    print(df_mean)
    df_mean.to_csv(in_file.replace('.csv',"_union.csv"), encoding='utf-8',index=False)
    return df_mean

def reform_df(df, by_tag, legend_tag, legend_lim, keywords):
    union_df = 0
    first = 0
    by_col = 'range_%s_num' % by_tag
    y_col = 'range_%s_num' % legend_tag
    for i in range(1,4):#3, 4
        for j in range(1,legend_lim):
            # df_sub = df[ df.optim_num == i ]
            df_sub = df[ df[y_col] == j ]
            df_sub = df_sub[ df_sub.optim_num == i ]
            df_sub = df_sub[ [by_col] + keywords ]
            keywords_tag = [ kw + '_' + str(i)+'optim+'+str(j)+legend_tag for kw in keywords]
            df_sub.columns = [by_col, str(i)+'optim+'+str(j)+legend_tag]
            if not first:
                union_df = df_sub
                first = 1
            else:
                union_df = pd.merge(union_df,df_sub,on=[by_col],how='outer')
    union_df.sort_values(by=[by_col],inplace=True)
    # union_df.to_csv(out_file, encoding='utf-8',index=False)
    print(union_df)
    return union_df


def reform_df_per_optim(df, i, by_tag, legend_tag, legend_lim, keywords):
    union_df = 0
    first = 0
    by_col = 'range_%s_num' % by_tag
    y_col = 'range_%s_num' % legend_tag
    # for i in range(1,4):#3, 4
    for j in range(1,legend_lim):
        df_sub = df[ df[y_col] == j ]
        df_sub = df_sub[ df_sub.optim_num == i ]
        df_sub = df_sub[ [by_col] + keywords ]
        keywords_tag = [ kw + '_' + str(i)+'optim+'+str(j)+legend_tag for kw in keywords]
        df_sub.columns = [by_col, str(i)+'optim+'+str(j)+legend_tag]
        if not first:
            union_df = df_sub
            first = 1
        else:
            union_df = pd.merge(union_df,df_sub,on=[by_col],how='outer')
    union_df.sort_values(by=[by_col],inplace=True)
    # union_df.to_csv(out_file, encoding='utf-8',index=False)
    print(union_df)
    return union_df


# def reform_df_duplica(df, keyword, out_file):
#     union_df = 0
#     first = 0
#     for i in range(1,4):
#         for j in range(1,7):
#             df_sub = df[ df.optim_num == i ]
#             df_sub = df_sub[ df_sub.range_duplica_num == j ]
#             df_sub = df_sub[ ['range_group_num', keyword] ]
#             df_sub.columns = ['range_group_num', str(i)+'optim+'+str(j)+'duplica']
#             if not first:
#                 union_df = df_sub
#                 first = 1
#             else:
#                 union_df = pd.merge(union_df,df_sub,on=['range_group_num'],how='outer')
#     union_df.sort_values(by=['range_group_num'],inplace=True)
#     union_df.to_csv(out_file, encoding='utf-8',index=False)
#     print(union_df)
#     return union_df


def plot(df1, df2, out_file):
    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(9, 4))
    axes1 = df1.plot(ax=axes[0], x='range_duplica_num', ylim=(0, 10), legend=False) #figsize=(6.4,4.2)
    for i, line in enumerate(axes1.get_lines()):
        line.set_marker(markers[i%(len(markers))])
    axes1.set_xlabel('Number of Duplicate Range Request Connection(s)')
    axes1.set_ylabel('Goodput (Mbps)')

    axes2 = df2.plot(ax=axes[1], x='range_duplica_num', ylim=(0, 100), legend=False)
    for i, line in enumerate(axes2.get_lines()):
        line.set_marker(markers[i%(len(markers))])    
    axes2.set_xlabel('Number of Duplicate Range Request Connection(s)')
    axes2.set_ylabel('Efficiency (%)')

    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5)) #
    fig.suptitle(title)
    # fig.legend(loc=7)
    # fig.legend(loc="center right", bbox_to_anchor=(1.8, 0.5)) #bbox_to_anchor=(0, -0.6, 1, 0.2), ncol=3,

    # plt.tight_layout() #rect=[0, 0, 0.75, 1]
    # plt.suplots_adjust(right=0.75)
    plt.savefig(out_file, bbox_inches="tight") #transparent=True

def single_plot(axe, df, xcol, xlabel, ylabel, ylim, with_title):
    axes1 = df.plot(ax=axe, x=xcol, legend=False)
    for i, line in enumerate(axes1.get_lines()):
        line.set_marker(markers[i%(len(markers))])
    if with_title:
        axes1.set_ylabel(ylabel)
        # axes1.set_title(ylabel)
    axes1.set_xlabel(xlabel)

    if ylim:
        axes1.set_ylim(0, ylim)


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
ylims = {'speed':10, 'efficiency':100, 'count':10, 'request_delay_avg':1, 'resp_delay_avg':3, 'detect_delay_avg':15, 'timeout_delay_sum':300}
labels = {'speed': 'Goodput (Mbps)', 'efficiency': 'Efficiency (%)', 'count':'Count', 'request_delay_avg':'Request Delay(s)', 'resp_delay_avg':'Response Delay(s)', 'detect_delay_avg':"Detect Delay(s)", 'timeout_delay_sum':'Timeout Delay'}


df = load_csv(in_file)
df_mean = group_df(df)

keywords = ['speed', 'efficiency']
# keywords = ['speed','request_delay_avg','resp_delay_avg'] #'request_delay_max', ,'resp_delay_max'  'efficiency'
# keywords = ['speed','detect_delay_avg','request_delay_avg',] #'request_delay_max', ,'resp_delay_max'  'efficiency'
#keywords = ['speed','timeout_delay_sum','resp_delay_avg']
ncol = len(keywords)
nrow = 1
fig, axes = plt.subplots(nrows=1, ncols=ncol, figsize=(9, 4))
for i in range(ncol):
    keyword = keywords[i]
    if nrow == 1:
        df_reform = reform_df(df_mean, 'duplica', 'group', 7, [keyword]) #[ df_mean.optim_num == j]
        single_plot(axes[i], df_reform, 'range_duplica_num', '', labels[keyword], ylims[keyword], True)
    else:
        for j in range(1,nrow+1):
            df_reform = reform_df_per_optim(df_mean, j, 'group', 'duplica', 7, [keyword]) #[ df_mean.optim_num == j]
            # print(type(df_reform))
            if j == 1:
                single_plot(axes[i][j-1], df_reform, 'range_group_num', '', labels[keyword], ylims[keyword], True)
            else:
                single_plot(axes[i][j-1], df_reform, 'range_group_num', '', labels[keyword], ylims[keyword], False)
        # df_reform = reform_df(df_mean, 'duplica', 'group', 7, [keyword])
        # single_plot(axes[i], df_reform, 'range_duplica_num', 'Number of Duplicate Range Request Connection(s)', labels[keyword], ylims[keyword])

plt.legend(loc='center left', bbox_to_anchor=(1,0.5))

fig.add_subplot(111, frameon=False)
# hide tick and tick label of the big axes
plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
plt.grid(False)
plt.xlabel('Number of Standard TCP Connection(s)')

#handles, labels = axes[0][0].get_legend_handles_labels()
#fig.legend(handles, ['1 TCP', '2 TCPs', '3 TCPs', '4 TCPs', '5 TCPs', '6 TCPs'], ncol=6, loc='upper center', bbox_to_anchor=(0.5, 0.95))
fig.suptitle(title)
fig_file = in_file.replace('.csv',"_group_%s.png" % datetime.now().strftime("%Y%m%dT%H%M%S"))
plt.savefig(fig_file, bbox_inches="tight") #transparent=True

# plot(df_speed, df_effi, fig_file)
    # boxplot(df, keyword, in_file.strip('.csv'), ylims[keyword])

#Confidence Interval figure
#p value
