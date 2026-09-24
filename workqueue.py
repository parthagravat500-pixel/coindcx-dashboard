"""Persistent local review queue. No network requests or target authorization."""
import hashlib
import json
import time
import casework
import supervisor
import workflow


def init(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS background_reviews (
      kind TEXT, item TEXT, fingerprint TEXT, result TEXT, updated INTEGER,
      PRIMARY KEY(kind,item));
    CREATE TABLE IF NOT EXISTS background_status (
      id INTEGER PRIMARY KEY, heartbeat INTEGER, status TEXT, completed INTEGER, last_task TEXT);
    INSERT OR IGNORE INTO background_status VALUES (1,0,'Starting',0,'None yet');
    CREATE TABLE IF NOT EXISTS queue_migrations (name TEXT PRIMARY KEY);
    ''')
    if not c.execute("SELECT 1 FROM queue_migrations WHERE name='directory-15-minutes'").fetchone():
        c.execute('UPDATE discovery_sources SET due=MIN(due,last_attempt+?) WHERE failures=0', (workflow.INTERVAL,))
        c.execute("INSERT INTO queue_migrations VALUES ('directory-15-minutes')")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def jobs(c):
    w = workflow.snapshot(c)
    if w['enabled']:
        for p in w['programs']:
            if p['stage'] == 'dismissed': continue
            payload = {k:p[k] for k in ('name','url','maximum','minimum','currency','available','stale','details','policy_review')}
            yield 'program', p['id'], fingerprint(payload), p['name'], p['local_review']
    for row in c.execute('SELECT * FROM findings ORDER BY last_seen DESC'):
        f = dict(row)
        t = dict(c.execute('SELECT * FROM targets WHERE id=?',(f['target'],)).fetchone())
        r = supervisor.review(c,f,t)
        case = casework.assess(c,f,r)
        yield 'finding', f['id'], fingerprint([f,r,case]), f['title'], {'supervisor':r,'casework':case}


def pending(c):
    saved = {(r['kind'],r['item']):r['fingerprint'] for r in c.execute('SELECT kind,item,fingerprint FROM background_reviews')}
    return [job for job in jobs(c) if saved.get((job[0],job[1])) != job[2]]


def tick(db, log):
    now = int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:
            c.execute("UPDATE background_status SET heartbeat=?,status='Paused' WHERE id=1",(now,))
            return
        queue = pending(c)
        batch = queue[:100]
        for kind,key,fp,name,result in batch:
            c.execute('INSERT INTO background_reviews VALUES (?,?,?,?,?) ON CONFLICT(kind,item) DO UPDATE SET fingerprint=excluded.fingerprint,result=excluded.result,updated=excluded.updated',
                      (kind,key,fp,json.dumps(result),now))
        status = 'Reviewing queued changes' if len(queue)>len(batch) else 'Waiting for new or changed data'
        c.execute('UPDATE background_status SET heartbeat=?,status=?,completed=completed+? WHERE id=1',(now,status,len(batch)))
        if batch:
            label = batch[-1][3]
            c.execute('UPDATE background_status SET last_task=? WHERE id=1',(label,))
            log(c, 'Local review completed for '+str(len(batch))+' new or changed items; '+str(len(queue)-len(batch))+' remaining. No website requests made.')


def snapshot(c):
    s=dict(c.execute('SELECT * FROM background_status WHERE id=1').fetchone())
    now=int(time.time())
    s['healthy']=bool(s['heartbeat'] and now-s['heartbeat']<60)
    if c.execute('SELECT paused FROM settings').fetchone()[0]:s['status']='Paused'
    elif not s['healthy']:s['status']='Worker status unavailable'
    s['pending']=len(pending(c))
    s['next_website_check']=c.execute('SELECT MIN(due) FROM targets WHERE enabled=1 AND expires>?',(now,)).fetchone()[0]
    s['next_directory_update']=c.execute('SELECT MIN(due) FROM discovery_sources').fetchone()[0]
    s['directory_enabled']=bool(c.execute('SELECT enabled FROM discovery_settings').fetchone()[0])
    s['poll_seconds']=10
    return s
