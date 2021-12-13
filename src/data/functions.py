import gzip
import datetime as dt
import pandas as pd

class NotAZeekFile(Exception):
    pass

def read_zeek_header(path):
    header = dict()
    try:
        f = gzip.open(path, 'rt')
        line = f.readline()
    except gzip.BadGzipFile:
        f = open(path, 'rt')
        line = f.readline()
    if '#separator' not in line:
        raise NotAZeekFile
    header['separator'] = line.rstrip().split()[-1].encode().decode('unicode_escape')
    line = f.readline()
    header['set_separator'] = line.rstrip().split()[-1]
    line = f.readline()
    header['empty_field'] = line.rstrip().split()[-1]
    line = f.readline()
    header['unset_field'] = line.rstrip().split()[-1]
    line = f.readline()
    header['path'] = line.rstrip().split()[-1]
    line = f.readline()
    header['open'] = dt.datetime.strptime(str(line.rstrip().split()[-1]),"%Y-%m-%d-%H-%M-%S")
    line = f.readline()
    header['fields'] = line.rstrip().split()[1:]
    line = f.readline()
    header['types'] = line.rstrip().split()[1:]
    return header



def read_zeek(path, **kwargs):
    header = read_zeek_header(path)
    df = pd.read_csv(path, skiprows=8, names=header['fields'], sep=header['separator'], comment='#', **kwargs)
    if 'ts' in df.keys():
        df['ts'] = pd.to_datetime(df.ts, unit='s')
    return df
