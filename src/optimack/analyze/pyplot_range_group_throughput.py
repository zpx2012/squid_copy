import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np, re
from datetime import datetime, timedelta
from matplotlib.offsetbox import AnchoredText

date_string = os.path.basename(os.path.dirname(os.path.abspath(sys.argv[1])))
df_output = pd.read_csv(sys.argv[1], sep=',').dropna(how='any')
for col in ['range', 'lossrate', 'optim_num','thread_num','group_num','curl','range','range_sum']:
    df_output[col] = pd.to_numeric(df_output[col], errors='coerce')
df_output = df_output[ df_output.range > 0 ]
df_output['range'] = df_output['range']
df_output['range_sum'] = df_output['range_sum'] / 1000.0

#df_output = df_output[ df_output.thread_num % 2 == 0]
#df_output.to_csv(out_file, encoding='utf-8',index=False)
#df_output_5 = df_output[df_output['lossrate'] <= 0.051]
#df_output_5_above = df_output[df_output['lossrate'] > 0.051]
#df_output_10 = df_output_5_above[df_output_5_above['lossrate'] <= 0.10]
#df_output_10_above = df_output_5_above[df_output_5_above['lossrate'] > 0.10]

df_bigger = df_output
dfs = []
for loss in np.arange(0.025, 0.2, 0.025):
     df_lower = df_bigger[df_bigger['lossrate'] <= loss]
     df_bigger = df_bigger[df_bigger['lossrate'] > loss]
     dfs += [df_lower]

#if  fix_kw == '' or fix_kw != 'wholeset':
fix_kw = 'thread'
test_kw = 'group'
for df in dfs:
    for optim_num in [1,2]:
        fig, axes = plt.subplots(nrows=2, ncols=3, figsize=(9.5,6))
    #for cl in ['range_sum''curl']:
        #print(df)
        df_sub = df[df.optim_num == optim_num]
        #print(df)
        cols = ['curl', 'rtt_avg'] #'range','range_sum']
        ylabels = ['Overall Goodput(Mbps)', 'Avg RTT(ms)'] #'Range Goodput(Kpbs)', 'Range Sum Goodput(Mbps)']
        ylims = [11, 400] #, 1.6]
        for j in range(2):
            for i in range(3):
                #print(df)
                df_i = df_sub[df_sub[fix_kw+'_num'] == i+3]
                #print(df_i)
                if df_i.empty:
                    continue
                axes1 = df_i.boxplot(ax=axes[j][i], column=cols[j], by='%s_num' % test_kw, showmeans=True)
                axes1.set_ylim(0, ylims[j])
                axes1.set_xlabel('')
                if i == 0:
                     axes1.set_ylabel(ylabels[j])
                else:
                     axes1.set_ylabel('')
                if j == 0:
                     axes1.set_title(f"{fix_kw} = {i+3}")
                else:
                     axes1.set_title('')
    #axes2 = df_output.boxplot(ax=axes[1], column='range_sum', by='%s_num' % test_kw, showmeans=True)
    #axes2.set_ylim(0, 1100)
    #axes2.set_xlabel('')
    #axes2.set_ylabel('Goodput(Kpbs)')
    #axes2.set_title("Overall Recovery Bandwidth of All Groups")

    # axes3 = df_output.boxplot(ax=axes[2], column='effi', by='thread_num', showmeans=True)
    # axes3.set_ylim(0, 1000)
    # axes3.set_xlabel('')
    # axes3.set_ylabel('Efficiency(%)')
    # axes3.set_title("Efficiency")
    # axes2.text(0.98, 0.98, date_string, ha='right', va='bottom', transform=axes2.transAxes)

        xlabels = {'group':'Number of Threads Inside Each Group', 'thread': 'Number of Group'}

        fig.add_subplot(111, frameon=False)
        plt.figtext(0.9, 0.08, date_string, ha='right', va='bottom', transform=fig.transFigure)
        plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
        plt.grid(False)
        plt.xlabel(xlabels[fix_kw]) #Groups, 
        fig.suptitle(f"Optim = {optim_num}, Loss Rate ={df.lossrate.mean(): .2%}, China-Shenzhen, Range Goodput") # lossrate, rtt)
        outfile = sys.argv[1].replace('.csv', 'curl_range_sum_%doptim_%s%s_25step_rtti.png' % (optim_num, 'lossrate', "{:02d}".format(int(df.lossrate.mean()*100))))
        plt.savefig(outfile, bbox_inches="tight")
        print("write to " + outfile)
