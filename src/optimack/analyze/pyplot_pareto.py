import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np, re
from datetime import datetime, timedelta

pd.options.mode.chained_assignment = None

in_file = os.path.expanduser(sys.argv[1])
lossrate, rtt = 0,0
for field in os.path.basename(in_file).split('_'):
    if 'loss' in field:
        lossrate = int(field.strip('loss'))
    elif 'ms' in field:    
        rtt = int(field.strip('ms'))

df = pd.read_csv(in_file, sep=',',error_bad_lines=False).dropna(how='any')#.drop_duplicates(subset=['is_range','conn','seq_start','seq_end'], keep='first')
df_unique = df.drop_duplicates(subset = ['curl','effi'])

tab10 = plt.cm.tab10.colors
paired = plt.cm.Paired.colors

n = 3
fig, axes = plt.subplots(nrows=1, ncols=n, figsize=(4.5*n,4))

for i in [1, 2]:
    df_optim = df[df['optim_num'] == i]
    df_optim.plot.scatter(ax=axes[0], x='effi', y='curl', color=tab10[i], label='Optim = %d' % i)

# Add title and labels
axes[0].legend(loc='best')
axes[0].set_title('')
axes[0].set_xlabel('')
axes[0].set_ylabel('Goodput(Mpbs)')
axes[0].set_ylim(0, 11)
axes[0].set_xlim(50,100)

kw = 'group'
for i in [1, 2]:
    optim_num = i % 2 + 1
    df_optim = df[df['optim_num'] == optim_num]
    for j, kw_num in enumerate(sorted(df_optim['%s_num' % kw].unique())):
        df_thread = df_optim[df_optim['%s_num' % kw] == kw_num]
        df_thread.plot.scatter(ax=axes[i], x='effi', y='curl', color=plt.cm.Paired.colors[j], label='%s = %d' %(kw.capitalize(), kw_num))

    axes[i].set_title('Optim = %d' % optim_num)
    axes[i].set_xlabel('')
    axes[i].set_ylabel('')
    axes[i].set_ylim(0, 11)
    # axes[i].set_xlim(50,100)

axes[2].get_legend().set_visible(False)
handles, labels = axes[1].get_legend_handles_labels()
axes[1].legend(reversed(handles), reversed(labels))

fig.add_subplot(111, frameon=False)
# plt.figtext(0.98, 0.08, date_string, ha='right', va='bottom', transform=fig.transFigure)
plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
plt.grid(False)
plt.xlabel('Efficiency') #Groups, 
fig.suptitle("Loss Rate = %s%%, RTT = %dms" % (lossrate, rtt))
plt.savefig(in_file.replace('.csv', '_%s_pareto.png' % kw), bbox_inches="tight")
