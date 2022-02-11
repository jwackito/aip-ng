import pandas as pd
import datetime as dt

firstday = '2021-08-01'
fulldays = pd.date_range(start=firstday, end='2021-12-09')

df = pd.read_csv(f'../../data/processed/attacks.{firstday}.csv')
for date1, date2 in [(x.strftime('%Y-%m-%d'), (x+dt.timedelta(days=1)).strftime('%Y-%m-%d')) for x in fulldays]:
    df1 = pd.read_csv(f'../../data/processed/attacks.{date1}.csv')
    df2 = pd.read_csv(f'../../data/processed/attacks.{date2}.csv')
    oldips = len(df2.merge(df1,on='orig'))
    print(f'The percentage of new IPs for {date2} with respect to {date1} is {1 - oldips/len(df2):0.2f}')
    oldips = len(df2.merge(df,on='orig'))
    print(f'The percentage of new IPs for {date2} with respect to {firstday} is {1 - oldips/len(df2):0.2f}')

ips_hist = dict()
for date1 in [(x.strftime('%Y-%m-%d')) for x in fulldays]:
    df = pd.read_csv(f'../../data/processed/attacks.{date1}.csv')
    for ip in df.itertuples():
        if ip.orig not in df.keys():
            ips_hist.setdefault(ip.orig, [])
        ips_hist[ip.orig].append([dt.date.fromisoformat(date1), ip.count])

recurrent = []  # seen every day
sporadic = []  # seen just one day
periodic = []  # seen more than one day and less than everyday
for k in ips_hist:
    if len(ips_hist[k]) == len(fulldays):
        recurrent.append(k)
    elif len(ips_hist[k]) == 1:
        sporadic.append(k)
    else:
        periodic.append(k)

stats = []
date = '2021-08-01'
df = pd.read_csv(f'../../data/processed/attacks.{date}.csv')
for date1, date2 in [(x.strftime('%Y-%m-%d'), (x+dt.timedelta(days=1)).strftime('%Y-%m-%d')) for x in pd.date_range(start=firstday, end='2021-12-09')]:
    df1 = pd.read_csv(f'../../data/processed/attacks.{date1}.csv')
    df2 = pd.read_csv(f'../../data/processed/attacks.{date2}.csv')
    oldips1 = len(df2.merge(df1,on='orig'))
    print(f'The percentage of new IPs for {date2} with respect to {date1} is {1 - oldips1/len(df2):0.2f}')
    oldips2 = len(df2.merge(df,on='orig'))
    print(f'The percentage of new IPs for {date2} with respect to {firstday} is {1 - oldips2/len(df2):0.2f}')
    stats.append([1 - oldips1/len(df2), 1 - oldips2/len(df2)])
stats = np.array(stats)

plt.plot(pd.date_range(start=firstday, end='2021-12-10'), stats[:,0]*100, label='New IP vs previous day')
plt.plot(pd.date_range(start=firstday, end='2021-12-10'), stats[:,1]*100, label=f'New IP vs {date}')
plt.title('Comparison of new attackers by day')
plt.xlabel('Date')
plt.ylabel('New attackers (in %)')
plt.legend()
plt.grid()

def minus(a, b):
    return (b - a).days

def calculate_periods(ip):
    return list(map(minus,np.array(ips_hist[ip])[:-1,0],np.array(ips_hist[ip])[1:,0]))

means = []
for ip in ips_hist:
    l = calculate_periods(ip)
    if len(l) >= 5 and len(l) < 10:
        s = '+'
    elif len(l) >= 10 and len(l) < 15:
        s = '#'
    elif len(l) >= 15:
        s = '*'
    else:
        s = '-'
    means.append([s, ip, mean(l), std(l)])
