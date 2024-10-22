import os, sys, re, traceback, csv, os, matplotlib.pyplot as plt, pandas as pd, sys, numpy as np
from itertools import cycle

def parse_delay_file(in_file):
    df = pd.read_csv(in_file, sep=',')
    df['epoch_time'] = df.time - df.loc[0, 'time']
    df.sort_values(by=['seq_start','epoch_time'], inplace=True)
    df['seq_end_shift'] = df['seq_end'].shift(1, fill_value=1)
    df = df[['time', 'epoch_time','is_range','conn','seq_start','seq_end_shift','seq_end']]
    df = df[:-1]
    df['bytes'] = df['seq_end'] - df['seq_start']
    df_check = df[ df.seq_start != df.seq_end_shift ]
    print(df_check)
    
    df_distri = df[['conn', 'bytes']].groupby(by=['conn'], as_index=False).sum()
    df_distri['percent'] = df_distri['bytes'] / df.seq_end.iloc[-1] * 100
    print(df_distri)
    fig = df_distri.plot(x='conn', y='percent', kind='bar')
    plt.xlabel("Connection")
    plt.ylabel("Byte Percentage(%)")
    plt.tight_layout()
    plt.savefig(in_file+'_percent.png') #transparent=True

    df_request = df
    df_request['is_range_shift'] = df_request['is_range'].shift(-1, fill_value=0)
    df_request = df_request[ df_request.is_range != df_request.is_range_shift]
    df_request['epoch_time_shift'] = df_request['epoch_time'].shift(-1, fill_value=0)
    df_request.to_csv(in_file.replace('.csv',"_request.csv"), encoding='utf-8',index=False)



    # df_delay = df[ df.is_range != df.is_range_shift ]
    # df_delay['epoch_time_shift'] = df_delay['epoch_time'].shift(-1, fill_value=0)
    # # df_delay = df_delay[df_delay.is_range == 0]
    # groups = cycle([0, -1, 1])
    # df_delay['is_range_shift_by_3'] = df_delay['is_range'].rolling(3, min_periods=3).sum().shift(-2, fill_value=-2)
    # print(df_delay)
    # # df_delay = df_delay[df_delay.is_range == df_delay.is_range_shift_by_3]
    # df_delay['delay'] = df_delay['epoch_time_shift'] - df_delay['epoch_time']
    # print(df_delay)
    # print(df_delay['delay'].mean(), df_delay['delay'].median())
    # df_delay.to_csv(in_file.replace('.csv',"_delay.csv"), encoding='utf-8',index=False)

    # fig = df_delay.plot(x='epoch_time', y='delay')
    # plt.axhline(y = df_delay['delay'].mean(), color = 'tab:orange', linestyle = '-') 
    # plt.xlabel("Time")
    # plt.ylabel("Delay(s)")
    # plt.tight_layout()
    # plt.savefig(in_file+'_delay.png') #transparent=True


in_file = os.path.expanduser(sys.argv[1])
parse_delay_file(in_file)