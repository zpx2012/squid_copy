import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np
from matplotlib import colors
from matplotlib.colors import LinearSegmentedColormap

def compress_range(df_local):
    index_p, row_p = 0, 0
    for index, row in df_local.iterrows():
        if index_p and row_p['seq_end'] == row['seq_start']:
            row_p['seq_end'] = row['seq_end']
            df_local.loc[index_p, 'seq_end'] = row['seq_end']
            df_local.drop(index, inplace=True)
            continue
        index_p = index
        row_p = row
    # return df_local

def load_dataframe(in_file):
    df = pd.read_csv(in_file, sep=',',error_bad_lines=False).dropna(how='any').drop_duplicates(subset=['is_range','seq_start','seq_end'], keep='first')
    df['seq_start'] = pd.to_numeric(df['seq_start'],errors='ignore')
    return df

def get_df_gap(df_primary):
    df_primary['seq_start_shift'] = df_primary['seq_start'].shift(-1, fill_value=1)
    df_primary = df_primary[['time', 'is_range','conn','seq_end','seq_start_shift']]
    df_primary.columns = ['time', 'is_range','conn','seq_start','seq_end']
    return df_primary

def get_df_union(df_gap, df_detect, df_request, df_timeout, df_resp):
    # df_request = df_request[['time', 'conn', 'seq_start', 'seq_end']]
    # df_timeout = pd.merge(df_request, df_request, on=['seq_start','seq_end'], how='inner')
    # df_timeout = df_timeout[ df_timeout.conn_x != df_timeout.conn_y ]
    # df_timeout['timeout_delay'] = df_timeout['time_y'] - df_timeout['time_x']
    # print(df_timeout)
    # return df_timeout

    df_gap = df_gap[['time', 'seq_start', 'seq_end']]
    df_gap.columns = ['time_primary','seq_start', 'seq_end']
    print(df_gap)

    df_detect = df_detect[['time', 'seq_start', 'seq_end']]
    df_detect['seq_end'] = df_detect['seq_end'] + 1
    df_detect.columns = ['time_detect','seq_start', 'seq_end']
    print(df_detect)

    df_request = df_request[['time', 'seq_start', 'seq_end']]
    df_request.columns = ['time_request','seq_start', 'seq_end']
    print(df_request)

    df_timeout = df_timeout[['time', 'seq_start', 'seq_end']]
    df_timeout.columns = ['time_timeout', 'seq_start', 'seq_end']
    print(df_timeout)

    df_resp = df_resp[['time', 'seq_start', 'seq_end']]
    df_resp.columns = ['time_resp','seq_start', 'seq_end']
    print(df_resp)

    df_union = pd.merge(df_gap, df_detect, on=['seq_start', 'seq_end'], how='inner')
    # df_union = pd.merge(df_union, df_request, on=['seq_start', 'seq_end'], how='inner')
    df_union = pd.merge(df_union, df_resp, on=['seq_start', 'seq_end'], how='inner')
    df_union = pd.merge(df_union, df_timeout, on=['seq_start', 'seq_end'], how='left')
    if df_union.empty:
        print("df_union is empty")
        return df_union

    df_union_timeout_null = df_union[df_union.time_timeout.isnull()]
    df_union_timeout_null['time_timeout'] = df_union_timeout_null['time_request']
    df_union_timeout_notnull = df_union[df_union.time_timeout.notnull()]
    df_union = pd.concat([df_union_timeout_null, df_union_timeout_notnull]).sort_index()
    # print(df_union)

    df_union['detect_delay'] = df_union['time_detect'] - df_union['time_primary']
    df_union['request_delay'] = df_union['time_request'] - df_union['time_detect']
    df_union['timeout_delay'] = df_union['time_timeout'] - df_union['time_request']
    df_union['resp_delay'] = df_union['time_resp'] - df_union['time_timeout']
    df_union.to_csv('union_'+in_file, encoding='utf-8',index=False)
    print(df_union)
    return df_union

def chop_cmap_frac(cmap: LinearSegmentedColormap, frac: float) -> LinearSegmentedColormap:
    """Chops off the beginning `frac` fraction of a colormap."""
    cmap_as_array = cmap(np.arange(256))
    cmap_as_array = cmap_as_array[int(frac * len(cmap_as_array)):]
    return LinearSegmentedColormap.from_list(cmap.name + f"_frac{frac}", cmap_as_array)

def plot_single_hist(ax, Y, xlabel, cmap):
    N, bins, patches = ax.hist(Y) #, range=[0.01,5]
    fracs = N / N.max()
    # we need to normalize the data to 0..1 for the full range of the colormap
    norm = colors.Normalize(fracs.min(), fracs.max())

    # Now, we'll loop through our objects and set the color of each accordingly
    for thisfrac, thispatch in zip(fracs, patches):
        color = cmap(norm(thisfrac))
        thispatch.set_facecolor(color)
    ax.set(xlabel=xlabel)

def plot_hist(df_union):
    cmap1 = chop_cmap_frac(plt.get_cmap('GnBu'), 0.3)
    fig, axs = plt.subplots(1, 4, sharey=True, tight_layout=True)
    plot_single_hist(axs[0], df_union['detect_delay'], "Detect Delay(s)", cmap1)
    plot_single_hist(axs[1], df_union['request_delay'], "Request Delay(s)", cmap1)
    plot_single_hist(axs[2], df_union['timeout_delay'], "Timeout Delay(s)", cmap1)
    plot_single_hist(axs[3], df_union['resp_delay'], "Respond Delay(s)", cmap1)
    plt.show()
    plt.savefig(in_file.replace('.csv','_delay_hist.png'), transparent=True)


in_file = os.path.expanduser(sys.argv[1])
if(in_file.startswith('processed_seq') and in_file.endswith('.csv')):
    print("Process: " + in_file)
    df = load_dataframe(in_file)
    df_primary = df[ df.is_range == '0' ].sort_values(by=['seq_start'])
    df_detect = df[ df.is_range == 'detect'].sort_values(by=['seq_start'])
    df_request = df[ df.is_range == 'request'].sort_values(by=['seq_start'])
    df_timeout = df[ df.is_range == 'request timeout'].sort_values(by=['seq_start'])
    df_resp = df[ df.is_range == '1']

    compress_range(df_primary)
    compress_range(df_resp)
    df_gap = get_df_gap(df_primary)
    df_union = get_df_union(df_gap, df_detect, df_request, df_timeout, df_resp)
    # if not df_union.empty:
    #     plot_hist(df_union)

    #print(df_gap)
    #print(df_request)
    #print(df_resp) 
    #print(df_union)
elif(in_file.startswith('union_processed_seq') and in_file.endswith('.csv')):
    df = pd.read_csv(in_file, sep=',')
    if not df.empty:
        plot_hist(df)
