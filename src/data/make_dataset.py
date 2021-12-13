import click
import datetime as dt
import logging
import pandas as pd

from pathlib import Path
from os import scandir, path
from functions import read_zeek

#from dotenv import find_dotenv, load_dotenv

def _make_dataset(date):
    '''
    Create a dataset for the date string date in the data/interim folder
    THIS FUNCTION IS DESTRUCTIVE and will overwrite the datasets for the processed date if exists.
    '''
    logger = logging.getLogger(__name__)
    honeypots = pd.read_csv(path.join(project_dir, 'data', 'external', 'honeypots_public_ips.csv'))
    ips = honeypots.public_ip.values
    try:
        zeek_files = (x for x in  scandir(path.join(project_dir,'data','raw', date)) if x.name.startswith('conn.'))
    except FileNotFoundError:
        logger.warning(f'Skipping {path.join(project_dir,"data","raw", date)}. Directory not exist.')
        return

    daily = pd.DataFrame()
    for z in zeek_files:
        #df = read_zeek(z, usecols=['id.orig_h', 'id.resp_h'])
        hourly = pd.DataFrame()
        zeekdata = read_zeek(z)
        for ip in ips:
            hourly = hourly.append(zeekdata[zeekdata['id.resp_h'] == ip])
        hourly.to_csv(path.join(project_dir,'data','interim', f'hourly.conn.{date}-{z.name[5:10]}.csv'), index=False)
        logger.debug('Writting file: ' + path.join(project_dir,'data','interim', f'hourly.conn.{date}-{z.name[5:10]}.csv'))
        daily = daily.append(hourly)
    daily.to_csv(path.join(project_dir,'data','interim', f'daily.conn.{date}.csv'), index=False)
    logger.debug('Writting file: ' + path.join(project_dir,'data','interim', f'daily.conn.{date}.csv'))







@click.command()
@click.argument('dates' , type=click.DateTime(formats=['%Y-%m-%d']), nargs=-1)
def main(dates):
    """ 
    Creates the dataset or part of it
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'Making  dataset from raw data for dates {dates}')
    if dates:
        dates = [x.strftime('%Y-%m-%d') for x in dates]
    else:
        dates = []
        for x in scandir(path.join(project_dir, 'data', 'raw')):
            try:
                dt.datetime.strptime(x.name, '%Y-%m-%d')
                dates.append(x.name)
            except ValueError:
                pass
    for date in dates:
        _make_dataset(date)



if __name__ == '__main__':
    log_fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    #logging.basicConfig(level=logging.INFO, format=log_fmt)
    logging.basicConfig(level=logging.DEBUG, format=log_fmt)

    # not used in this stub but often useful for finding various files
    project_dir = Path(__file__).resolve().parents[2]
    
    # find .env automagically by walking up directories until it's found, then
    # load up the .env entries as environment variables
    #load_dotenv(find_dotenv())

    main()
