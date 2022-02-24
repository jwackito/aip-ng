import pandas as pd
import datetime as dt

def MCC(TP, TN, FP, FN):
    """
    Calculates the Mathew's Correlation Coeficient
    """
    if (TP+FP)*(TP+FN)*(TN+FP)*(TN+FN) == 0:
        return 0
    else:
        return ((TP*TN)-(FP*FN))/np.sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN))

def calculate_TPTNFPFN(attacklist, blocklist):
    TP = 0.
    TN = 0.
    FP = 0.
    FN = 0.
    for ip in blocklist:
        if ip in attacklist:
            TP += 1
        if ip not in attacklist:
            FP += 1
    for ip in attacklist:
        if ip not in blocklist:
            FN += 1
    TN = 2**32 - FP
    return TP, TN, FP, FN

def compute_MCC(attacklist, blocklist):
    TP, TN, FP, FN = calculate_TPTNFPFN(attacklist, blocklist)
    return MCC(TP, TN, FP, FN)

def create_random_ip():
    ip = '.'.join([str(random.randint(0,256)) for x in range(4)])
    if ip.startswith('10.'):
        return create_random_ip()
    elif ip.startswith('172.') and ip[4:7] in [str(x)+'.' for x in range(16,33)]:
        return create_random_ip()
    elif ip.startswith('192.168.'):
        return create_random_ip()
    else:
        return ip
     
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

marks = {'-': 0, '+':0, '#':0, '*':0}
for x in means:
    marks[x[0]] += 1

for k in marks:
    print(f'{k}: {marks[k]*100/432033:3.2f}%')

firstday = '2021-08-01'
lastday = '2021-08-30'
fulldays = pd.date_range(start=firstday, end=lastday)
days = {str(k.date()):[] for k in fulldays}
for date in [str(x.date()) for x in fulldays]:
    df = pd.read_csv(f'../../data/processed/attacks.{date}.csv')
    print(date,end='\r')
    for date1 in [str(x.date()) for x in fulldays]:
        df1 = pd.read_csv(f'../../data/processed/attacks.{date1}.csv')
        oldips = len(df1.merge(df,on='orig'))
        days[date].append(1 - oldips/len(df))
        #print(f'The percentage of new IPs for {date2} with respect to {date1} is {1 - oldips/len(df2):0.2f}')

keys = []
values = []
for d in days:
    keys.append(d)
    values.append(np.array(list(map(float,days[d]))))
values = np.array(values)
plt.imshow(values, norm=matplotlib.colors.LogNorm())
plt.yticks(range(0,len(fulldays),5),[str(x.date()) for x in pd.date_range(start=firstday, end=lastday,freq='5D')])
plt.xticks(range(0,len(fulldays),5),[str(x.date()) for x in pd.date_range(start=firstday, end=lastday,freq='5D')], rotation=90)


def check_segment_24(ip):
    return '.'.join(ip.split('.')[:-1])

def check_segment_16(ip):
    return '.'.join(ip.split('.')[:-2])

#### This sniplet takes a looooot of time.
####  MCC for 100k and 200k can be commented and readed from the dataset mccs.csv
random.seed(42)
ips_100k = [create_random_ip() for x in range(100000)]
ips_200k = [create_random_ip() for x in range(200000)]
days = []
stats = []
firstday = '2021-08-01'
lastday = '2021-11-30'
fulldays = pd.date_range(start=firstday, end=lastday)
for date1, date2 in [(str(x.date()), str((x+dt.timedelta(days=1)).date())) for x in fulldays]:
    df1 = pd.read_csv(f'../../data/processed/attacks.{date1}.csv')
    df2 = pd.read_csv(f'../../data/processed/attacks.{date2}.csv')
    days.append(date1)
    IPsday1 = len(df1)
    IPsday2 = len(df2)
    IPsboth = len(df2.merge(df1,on='orig'))
    IPsbothperc = (IPsboth/len(df1))*100
    mcc = compute_MCC(df2.orig.values, df1.orig.values)
    mcc_100k = compute_MCC(df2.orig.values, ips_100k)
    mcc_200k = compute_MCC(df2.orig.values, ips_200k)
    stats.append([IPsday1, IPsbothperc, IPsboth, mcc, mcc_100k, mcc_200k])
stats = np.array(stats)

dff = pd.DataFrame(stats, columns=['ips', 'ips_both_percent', 'ips_both', 'mcc', 'mcc_100k', 'mcc_200k'], index=days)
dff['date'] = days
dff.to_csv('mccs.csv', index=False)

# plot 1 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
plt.plot(days, stats[:,0], label='Attackers per day')
plt.xticks(range(0, len(pd.date_range(start=firstday, end=lastday)),5), [str(x.date()) for x in pd.date_range(start=firstday, end=lastday, freq='5D')], rotation=90)
plt.legend()
plt.grid()
plt.title('Number of different attackers per day')
plt.xlabel('Date')
plt.ylabel('Number of different attackers')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/attackers_per_day.png')

# plot 2 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
plt.plot(days, stats[:,1], label='Overlapping attackers (percent)')
plt.xticks(range(0, len(pd.date_range(start=firstday, end=lastday)),5), [str(x.date()) for x in pd.date_range(start=firstday, end=lastday, freq='5D')], rotation=90)
plt.legend()
plt.grid()
plt.title('Percentage of overlapping attackers with respect to the next day')
plt.xlabel('Date')
plt.ylabel('Percentage of overlapping w.r.t. the following day')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/overlapping_next_day.png')

# plot 3 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
plt.plot(days, stats[:,3], label='MCC')
plt.xticks(range(1, len(pd.date_range(start=firstday, end=lastday))+1, 5), [str(x.date()) for x in pd.date_range(start=firstday, end=lastday, freq='5D')], rotation=90)
plt.legend()
plt.grid()
plt.title('MCC for the blocklist of date x')
plt.xlabel('Date')
plt.ylabel('Matthews correlation coefficient')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/mcc_model_alpha.png')

# plot 4 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
plt.plot(days, stats[:,4], label='MCC for ips_100k list')
plt.plot(days, stats[:,5], label='MCC for ips_200k list')
plt.xticks(range(1, len(pd.date_range(start=firstday, end=lastday))+1, 5), [str(x.date()) for x in pd.date_range(start=firstday, end=lastday, freq='5D')], rotation=90)
plt.legend()
plt.grid()
plt.title('MCC for the blocklist of date x')
plt.xlabel('Date')
plt.ylabel('Matthews correlation coefficient')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/mcc_random_lists.png')


#### This segment runs in < 30 seconds in joaquin's localhost
####    If MCC calculation is added (needed for plot 5), then it tooks 4.5 hours :¬/
stime = time.time()
days = []
stats = []
firstday = '2021-08-01'
lastday = '2021-11-30'
fulldays = pd.date_range(start=firstday, end=lastday)
maxinterval = 10
nipsbothstats = []
#mccstats = []
blsizes = []
for i in range(len(fulldays) - maxinterval):
    print(f'{i}/{len(fulldays)-10}', end='\r')
    prevdays = [pd.read_csv(f'../../data/processed/attacks.{str(date.date())}.csv', usecols=['orig']) for date in fulldays[i:i+maxinterval]]
    target = pd.read_csv(f'../../data/processed/attacks.{str(fulldays[i+maxinterval].date())}.csv', usecols=['orig'])
    days.append(str(fulldays[i+maxinterval].date()))
    df = prevdays[-1]
    xs1 = []
    #xs2 = []
    xs3 = []
    jidx = []
    for j in range(maxinterval-1, -1, -1):
        jidx.append(j)
        df = df.merge(prevdays[j],on='orig', how='outer')
        xs1.append(len(target.merge(df,on='orig')))
        #xs2.append(compute_MCC(target.orig.values, df.orig.values))
        xs3.append(len(df))
    nipsbothstats.append(xs1)
    #mccstats.append(xs2)
    blsizes.append(xs3)
nipsbothstats = np.array(nipsbothstats)
mccstats = np.array(mccstats)
blsizes = np.array(blsizes)
print(f'run in {(time.time() - stime)/60} minutes.')


# plot 5 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
for i in range(mccstats.shape[1]):
    plt.plot(days, mccstats[:,i], label=f'BL{i+1}')
#plt.plot(days, nipsbothstats[:,-1], label='MCC for ips_200k list')
plt.xticks(range(0, len(pd.date_range(start=days[0], end=days[-1])), 5), [str(x.date()) for x in pd.date_range(start=days[0], end=days[-1], freq='5D')], rotation=90)
plt.legend(loc='upper left')
plt.grid()
plt.title('MCC for the BL created using the IPs of the previous days')
plt.xlabel('Date')
plt.ylabel('Matthews correlation coefficient')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/mcc_alpha_x.png')

# plot 6 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
for i in range(nipsbothstats.shape[1]):
    plt.plot(days, nipsbothstats[:,i], label=f'BL{i+1}')
plt.xticks(range(0, len(pd.date_range(start=days[0], end=days[-1])), 5), [str(x.date()) for x in pd.date_range(start=days[0], end=days[-1], freq='5D')], rotation=90)
plt.legend(loc='upper left')
plt.grid()
plt.title('Number of IPs in the BL that have attacked on date')
plt.xlabel('Date')
plt.ylabel('Number of IPs in BL that have attacked')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/number_of_ips_in_target.png')


# plot 7 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
for i in range(blsizes.shape[1]):
    plt.plot(days, blsizes[:,i], label=f'BL{i+1}')
plt.xticks(range(0, len(pd.date_range(start=days[0], end=days[-1])), 5), [str(x.date()) for x in pd.date_range(start=days[0], end=days[-1], freq='5D')], rotation=90)
plt.legend(loc='lower right')
plt.grid()
plt.title('Number of IPs in the BL')
plt.xlabel('Date')
plt.ylabel('Number of IPs in BL')
plt.subplots_adjust(top=.95, left=.075, bottom=.2, right=.95)
plt.savefig('images/number_of_ips_bl.png')



# runs in 8 minutes
stime = time.time()
firstday = '2021-08-01'
lastday = '2021-11-30'
fulldays = pd.date_range(start=firstday, end=lastday)
stats = []
blday = []
for i in range(30):
    print(i,end='\r')
    bl = pd.read_csv(f'../../data/processed/attacks.{str(fulldays[i].date())}.csv', usecols=['orig'])
    blday.append(str(fulldays[i].date()))
    ministats = []
    for date1 in [str(x.date()) for x in fulldays[i:]]:
        target = pd.read_csv(f'../../data/processed/attacks.{date1}.csv', usecols=['orig'])
        ipsboth = len(target.merge(bl,on='orig'))
        mcc = compute_MCC(target.orig.values, bl.orig.values)
        ministats.append([date1, ipsboth, mcc])
    stats.append(ministats)
stats = np.array(stats)
print(f'run in {(time.time() - stime)/60} minutes.')

z = zeros_like(np.array(stats[0])[:,1].astype(float)) 
for i in range(len(stats)): 
    print(i) 
    z += np.resize(np.array(stats[i])[:,2].astype(float), 122) 
z /= len(stats)

# plot 7 in the AIP data exploration report
plt.rcParams['figure.figsize'] = [12,6]
plt.plot(range(1,len(z)-len(stats)), z[1:-len(stats)], '-.', label='Average BL1 MCC')
plt.legend()
plt.grid()
plt.title('Average MCC for a blocklist used several days after its creation')
plt.xlabel('Days after the attacks used to create the BL')
plt.ylabel('MCC')
plt.subplots_adjust(top=.95, left=.075, bottom=.1, right=.95)
plt.savefig('images/mcc_decay.png')


