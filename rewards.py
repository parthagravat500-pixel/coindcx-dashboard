"""Compare published ceilings using cached ECB reference rates; never infer payouts."""
import datetime
import json
import math
import time
import urllib.request
import xml.etree.ElementTree as ET

SOURCE = 'https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml'


def init(c):
    c.execute('CREATE TABLE IF NOT EXISTS reward_fx (id INTEGER PRIMARY KEY CHECK(id=1), day TEXT, rates TEXT, due INTEGER)')
    c.execute("INSERT OR IGNORE INTO reward_fx VALUES(1,'','{}',0)")


def parse(raw):
    root = ET.fromstring(raw)
    day = next((x.attrib['time'] for x in root.iter() if 'time' in x.attrib), '')
    datetime.date.fromisoformat(day)
    rates = {'EUR': 1.0}
    for node in root.iter():
        if 'currency' in node.attrib and 'rate' in node.attrib:
            rate = float(node.attrib['rate'])
            if not math.isfinite(rate) or rate <= 0: raise ValueError('Invalid exchange rate')
            rates[node.attrib['currency']] = rate
    if 'USD' not in rates: raise ValueError('USD rate missing')
    return day, rates


def refresh(db, opener):
    now = int(time.time())
    with db() as c:
        row = c.execute('SELECT due FROM reward_fx WHERE id=1').fetchone()
        if row[0] > now: return
        c.execute('UPDATE reward_fx SET due=? WHERE id=1', (now+3600,))
    try:
        with opener.open(urllib.request.Request(SOURCE, headers={'User-Agent':'ScopeGuard-Rewards/1.0'}), timeout=15) as response:
            raw = response.read(65537)
        if len(raw) > 65536: raise ValueError('Rate feed too large')
        day, rates = parse(raw)
        with db() as c:
            c.execute('UPDATE reward_fx SET day=?,rates=?,due=? WHERE id=1', (day,json.dumps(rates),now+86400))
    except Exception:
        pass  # Preserve last successful rates; UI shows their date, retry in one hour.


def rank(c, programs):
    row = c.execute('SELECT day,rates FROM reward_fx WHERE id=1').fetchone()
    rates = json.loads(row['rates'])
    for p in programs:
        maximum = p['maximum']
        currency = p['currency']
        p['reward_usd'] = (maximum if currency == 'USD' else maximum * rates['USD'] / rates[currency] if currency in rates and 'USD' in rates else None) if maximum is not None else None
        p['reward_group'] = 'Unavailable programs' if not p['available'] else 'Highest listed rewards' if p['reward_usd'] is not None else 'Exchange rate unavailable' if maximum is not None else 'Reward not published'
    groups = {'Highest listed rewards':0,'Exchange rate unavailable':1,'Reward not published':2,'Unavailable programs':3}
    programs.sort(key=lambda p:(groups[p['reward_group']], -(p['reward_usd'] or 0), p['currency'], -(p['maximum'] or 0), p['name'].casefold()))
    return {'date':row['day'], 'source':SOURCE}
