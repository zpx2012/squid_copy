import csv, os, pandas as pd, sys, numpy as np, socket, matplotlib.pyplot as plt
from datetime import datetime
from parse_range_file import parse_range_file
#1. df_speedf, filename, epoch_time
#2. df_delayf, filename, epoch_time

def get_epochtime(row, index, match_str, fn_end): 
    fname_fields = row['filename'].split(fn_end)[0].split('_')
    fn_time = datetime.strptime(fname_fields[index], match_str)
    return (fn_time - datetime(1970, 1, 1)).total_seconds()


def get_fn_df(dir, fn_start, fn_end, match_str):
    files = []
    for f in os.listdir(dir):
        if f.startswith(fn_start) and f.endswith(fn_end) and not f.endswith('_union.csv'):
            files.append(f)
    df = pd.DataFrame(files, columns=['filename'])
    df['epoch_time'] = df.apply(get_epochtime, index=-1, match_str=match_str, fn_end=fn_end, axis=1)
    return df.sort_values(by=['epoch_time'])


def pair_delay_file(row, df_delayf):
    df_tmp = df_delayf[ df_delayf.epoch_time > row['epoch_time']]
    df_tmp = df_tmp[ df_tmp.epoch_time < row['epoch_time']+15]
    rn, cn = df_tmp.shape
    if rn > 1 :
        print('Error: two matching files')
        print(df_tmp)
        return None
        # return None,None,None,None,None,None,None,None,None,None,None,None,None,None,None
    elif rn == 1:
        speed_tuple = parse_range_file(dir1, row['filename'])

        delay_filename = list(df_tmp['filename'])[0]
        df_delay = pd.read_csv(os.path.join(dir2, delay_filename), sep=',')
        if not df_delay.empty:
            detect_delay_avg = df_delay['detect_delay'].mean()
            request_delay_avg = df_delay['request_delay'].mean()
            request_delay_max = df_delay['request_delay'].max()
            timeout_delay_sum = df_delay['timeout_delay'].sum()
            resp_delay_avg = df_delay['resp_delay'].mean()
            resp_delay_max = df_delay['resp_delay'].max()
            return speed_tuple + (delay_filename, request_delay_avg, request_delay_max, resp_delay_avg, resp_delay_max, detect_delay_avg, timeout_delay_sum)
    
    return None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None
    

def plot_per_run(df_union, infile):
    fig, ax1 = plt.subplots(figsize=(8,5))
    color1 = 'tab:blue'
    ax1.plot(df_union['epoch_time'],df_union['speed'],label='throughput',color=color1)
    ax1.axhline(y=np.nanmean(df_union['speed']), color='b')
    ax1.set_xlabel("Seconds", fontsize=16)
    ax1.set_ylabel("Goodput (Mbps)", fontsize=16, color=color1)
    # ax1.set_yticks(fontsize=12)
    # ax1.set_xticks(fontsize=12)
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_ylim(0,12)

    ax2 = ax1.twinx()
    ax2.plot(df_union['epoch_time'],df_union['request_delay'],label='request delay',color='tab:green')
    ax2.plot(df_union['epoch_time'],df_union['resp_delay'],label='response delay',color='tab:orange')
    ax2.set_ylabel("Delay(s)")

    plt.title("")
    plt.tight_layout()
    plt.savefig(os.path.join(dir1,'union_per_run_'+infile+".png"),transparent=True)



def get_union_df(row):
    df_speed = pd.read_csv(os.path.join(dir1, row['filename']), sep=',')
    df_speed = df_speed[['epoch_time', 'speed']]
    df_speed['speed'] = df_speed['speed'] * 8 / 1000

    df_delay = pd.read_csv(os.path.join(dir2, row['delay_filename']), sep=',')
    df_delay = df_delay[['time_primary', 'request_delay', 'resp_delay']]
    df_delay.columns = ['epoch_time', 'request_delay', 'resp_delay']

    if not df_speed.empty and not df_delay.empty:
        df_union = pd.merge(df_speed, df_delay, on=['epoch_time'], how='outer')
        df_union = df_union.sort_values(by='epoch_time').reset_index(drop=True)
        print(df_union)
        df_union['epoch_time'] = df_union['epoch_time'] - df_union.loc[0, 'epoch_time']
        df_union.to_csv(os.path.join(dir1,'union_delay_'+row['filename']), encoding='utf-8', index=False)

        plot_per_run(df_union, row['filename'])

if len(sys.argv) < 5:
    print('Usage: python pair_speed_delay.py dir1 fn_start1 dir2 fn_start2')

dir1 = os.path.expanduser(sys.argv[1])
fn_start1 = sys.argv[2]
fn_end1 = sys.argv[3]

dir2 = os.path.expanduser(sys.argv[4])
fn_start2 = sys.argv[5]
fn_end2 = sys.argv[6]

df_speedf = get_fn_df(dir1, fn_start1, fn_end1, '%Y%m%d%H%M%S')
df_delayf = get_fn_df(dir2, fn_start2, fn_end2, '%Y-%m-%dT%H:%M:%S')
print(df_speedf)

if not df_speedf.empty and not df_delayf.empty:
    df_speedf[ ['optim_num','range_group_num','range_duplica_num','speed','last_speed','duration','efficiency','recved_bytes','total_bytes','error_cnt','delay_filename','request_delay_avg','request_delay_max','resp_delay_avg','resp_delay_max','detect_delay_avg','timeout_delay_sum'] ] = df_speedf.apply(pair_delay_file, df_delayf=df_delayf, axis=1, result_type='expand')
    df_speedf = df_speedf.dropna(how='any')
    print(df_speedf)
    df_speedf.to_csv(os.path.join(dir1,'union_range_'+os.path.basename(dir1)+'.csv'), encoding='utf-8', index=False)


# df_speedf.apply(get_union_df, axis=1)


