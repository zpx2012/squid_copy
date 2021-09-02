import os, sys, pandas as pd
df1, df2 = pd.read_csv(os.path.expanduser(sys.argv[1])), pd.read_csv(os.path.expanduser(sys.argv[2]))
# df1.time = df1.time - df1['time'][0]
# df2.time = df2.time - df2['time'][0]
# df1 = df1[df1.srcport == 80]
# df1 = df1.rename(columns={'time':'server_time'})
# df2 = df2.rename(columns={'time':'recv_time'})

# df1.columns = ['time','http']
# df1.columns = ['time','HTTP']
# df2.columns = ['time','VPN']
# df2 = df2.groupby('time', as_index=False).mean()
union = pd.merge(df1,df2,on=['dstport','seq'],how='inner')
# union['time_offset'] = union.recv_time - union.Recv_time
# union.sort_values(by=['port','seq'],inplace=True)
# union.sort_values('time',inplace=True)
union.to_csv(sys.argv[2].replace('.csv',"_union.csv"), encoding='utf-8',index=False)
