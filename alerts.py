"""Local alert lifecycle; no network, notifications, CLI calls, or HTTP writes."""
import html
import json
import math
import os
import re

DAY = 86400000
RANK = {'info':0, 'warn':1, 'alarm':2, 'critical':3}
RULES = {'limit_window','credits','failed_sessions','gateway_unreachable','gateway_pressure','new_agent','collector_stale'}
DEFAULTS = {'thresholds':{'warn':70,'alarm':80,'critical':90}, 'credits_warn':100,
            'credits_critical':25, 'agent_stale_minutes':None}


def safe(value, fallback='Subject'):
    from collector import task_label, string
    if not isinstance(value,str):
        return fallback
    # Decode before privacy checks: HTML entities must not disguise emails/paths.
    value = html.unescape(value)
    value = re.sub(r'<[^>]*>', '', value)
    if string(value) is None:
        return fallback
    value = task_label(value)
    if not value or '[hidden]' in value:
        return fallback
    value = ''.join(c for c in value if c not in '<>"' and ord(c)>=32 and ord(c)!=127)
    return value.strip()[:80] or fallback


def agent_id(value):
    from collector import string, task_label
    return value if string(value,identifier=True) and task_label(value)==value else None


def config(path):
    raw=json.loads(path.read_text())
    cfg=dict(DEFAULTS, **{k:raw[k] for k in DEFAULTS if k in raw})
    t=cfg['thresholds']
    nums=[t[k] for k in ('warn','alarm','critical')]+[cfg['credits_critical'],cfg['credits_warn']]
    if any(type(v) not in (int,float) or not math.isfinite(v) for v in nums):
        raise ValueError('invalid alert config')
    if not 0<=t['warn']<t['alarm']<t['critical']<=100 or not 0<=cfg['credits_critical']<cfg['credits_warn']:
        raise ValueError('invalid alert config')
    return cfg


def state(db,key,default=None):
    row=db.execute('SELECT value FROM alert_state WHERE key=?',(key,)).fetchone()
    return json.loads(row[0]) if row else default


def put(db,key,value):
    db.execute('INSERT INTO alert_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               (key,json.dumps(value,separators=(',',':'))))


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY, rule TEXT NOT NULL, subject_key TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('info','warn','alarm','critical')),
      state TEXT NOT NULL CHECK(state IN ('active','resolved')),
      first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, resolved_at INTEGER,
      message TEXT NOT NULL, notified INTEGER NOT NULL DEFAULT 0)""")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS alerts_active ON alerts(rule,subject_key) WHERE state='active'")
    db.execute('CREATE TABLE IF NOT EXISTS alert_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS alert_agents (id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS alert_failure_seen (session_id TEXT PRIMARY KEY, seen_at INTEGER NOT NULL)')
    # Baseline before collection: installation never announces historical agents/failures.
    if state(db,'installed') is None:
        db.execute('INSERT OR IGNORE INTO alert_agents SELECT id,MIN(timestamp) FROM agents WHERE id IS NOT NULL GROUP BY id')
        db.execute("INSERT OR IGNORE INTO alert_failure_seen SELECT sessionId,timestamp FROM sessions WHERE status='failed'")
        put(db,'installed',True)


def active(db,rule,subject):
    cur=db.execute("SELECT * FROM alerts WHERE rule=? AND subject_key=? AND state='active'",(rule,subject))
    row=cur.fetchone()
    return dict(zip([d[0] for d in cur.description],row)) if row else None


def resolve(db,rule,subject,now):
    db.execute("UPDATE alerts SET state='resolved',resolved_at=?,notified=0 WHERE rule=? AND subject_key=? AND state='active'",(now,rule,subject))


def emit(db,rule,subject,level,message,now):
    row=active(db,rule,subject)
    message=message[:80]
    if row:
        db.execute('UPDATE alerts SET severity=?,last_seen=?,message=?,notified=0 WHERE id=?',
                   (level,now,message,row['id']))
    else:
        db.execute("INSERT INTO alerts(rule,subject_key,severity,state,first_seen,last_seen,message) VALUES (?,?,?,'active',?,?,?)",
                   (rule,subject,level,now,now,message))


def evaluate(db,now,cfg):
    # Local import keeps HTTP helpers independent of collection or migration.
    from collector import number
    thresholds=cfg['thresholds']
    status_now=db.execute('SELECT 1 FROM gateway_health WHERE timestamp=?',(now,)).fetchone() is not None
    # Reset elapsed windows even if the current status command failed.
    for key,value in db.execute("SELECT key,value FROM alert_state WHERE key LIKE 'window:%'").fetchall():
        previous=json.loads(value)
        if previous is not None and previous<=now:
            resolve(db,'limit_window',key[7:],now)
    if status_now:
        windows=db.execute('SELECT provider,windowLabel,usedPercent,resetAt FROM usage_windows WHERE timestamp=?',(now,)).fetchall()
        for provider,label,percent,reset in windows:
            if not agent_id(provider) or not isinstance(label,str): continue
            # JSON encoding avoids ambiguity between arbitrary provider/window pairs.
            subject=json.dumps([provider,safe(label,'Window')],separators=(',',':'))
            key='window:'+subject
            previous=state(db,key)
            if previous is not None and reset!=previous:
                resolve(db,'limit_window',subject,now)
            put(db,key,reset)
            if number(percent) is None or (reset is not None and reset<=now): continue
            row=active(db,'limit_window',subject)
            level=next((s for s in ('critical','alarm','warn') if percent>=thresholds[s]),None)
            if row and percent <= thresholds[row['severity']]-5:
                resolve(db,'limit_window',subject,now)
                row=None
            if row and (level is None or RANK[level]<RANK[row['severity']]):
                level=row['severity']
            if level:
                emit(db,'limit_window',subject,level,f'Limit {safe(label,"Window")}: {level}',now)
        amounts=[r[0] for r in db.execute('SELECT amount FROM credits WHERE timestamp=?',(now,)) if number(r[0]) is not None]
        level='critical' if amounts and min(amounts)<=cfg['credits_critical'] else 'warn' if amounts and min(amounts)<=cfg['credits_warn'] else None
        if level: emit(db,'credits','credits',level,f'Credits balance: {level}',now)
        else: resolve(db,'credits','credits',now)
    # Count fresh failed session identities, never repeated terminal snapshots.
    names={aid:safe(name,'Agent') for aid,name in db.execute('SELECT id,name FROM agents WHERE timestamp=(SELECT MAX(timestamp) FROM agents)') if agent_id(aid)}
    counts={}
    for sid,aid in db.execute("SELECT sessionId,agentId FROM sessions WHERE timestamp=? AND status='failed'",(now,)):
        if not agent_id(aid): continue
        if db.execute('INSERT OR IGNORE INTO alert_failure_seen VALUES (?,?)',(sid,now)).rowcount:
            counts[aid]=counts.get(aid,0)+1
    for aid in set(counts)|{r[0] for r in db.execute("SELECT subject_key FROM alerts WHERE rule='failed_sessions' AND state='active'")}:
        key='failure:'+aid
        memo=state(db,key,{'count':0,'last':0,'emitted':0})
        if counts.get(aid):
            if now-memo['last']>=3600000:
                resolve(db,'failed_sessions',aid,now)
                memo={'count':0,'last':0,'emitted':0}
            memo['count']+=counts[aid]; memo['last']=now
            row=active(db,'failed_sessions',aid)
            if row: db.execute('UPDATE alerts SET last_seen=? WHERE id=?',(now,row['id']))
        if memo['count'] and now-memo['last']>=3600000:
            resolve(db,'failed_sessions',aid,now)
        elif memo['count'] and (not active(db,'failed_sessions',aid) or now-memo['emitted']>=1800000):
            # Name budget preserves the count even for long display names.
            emit(db,'failed_sessions',aid,'warn',f'Failed sessions: {memo["count"]} ({names.get(aid,"Agent")[:48]})',now)
            memo['emitted']=now
        put(db,key,memo)
    # Unknown/missed status polls break a consecutive-poll sequence.
    g=db.execute('SELECT reachable,connectLatencyMs,rssBytes,hostUtilization FROM gateway_health WHERE timestamp=?',(now,)).fetchone()
    counters=state(db,'gateway',{'down':0,'pressure':0})
    try: capacity=os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')
    except (ValueError,OSError): capacity=0
    down=bool(g and g[0]==0)
    pressure=bool(g and ((number(g[1]) is not None and g[1]>1000) or
                       (number(g[3]) is not None and g[3]>.9) or
                       (capacity and number(g[2]) is not None and g[2]/capacity>.9)))
    for key,condition,minimum,rule,level,message in (
        ('down',down,2,'gateway_unreachable','critical','Gateway unreachable'),
        ('pressure',pressure,5,'gateway_pressure','warn','Gateway resource pressure')):
        counters[key]=counters[key]+1 if condition else 0
        if counters[key]>=minimum: emit(db,rule,'gateway',level,message,now)
        elif g and not condition: resolve(db,rule,'gateway',now)
    put(db,'gateway',counters)
    for aid,name in names.items():
        if db.execute('INSERT OR IGNORE INTO alert_agents VALUES (?,?)',(aid,now)).rowcount:
            emit(db,'new_agent',aid,'info',f'New agent: {name}',now)
    db.execute("UPDATE alerts SET state='resolved',resolved_at=?,notified=0 WHERE rule='new_agent' AND state='active' AND first_seen<=?",(now,now-DAY))
    db.execute("DELETE FROM alerts WHERE COALESCE(resolved_at,last_seen)<?",(now-90*DAY,))
    # Seen identities remain while their session survives so old failures cannot refire.
    db.execute('DELETE FROM alert_failure_seen WHERE seen_at<? AND session_id NOT IN (SELECT sessionId FROM sessions)',(now-90*DAY,))


def isolated_evaluate(db,now,path):
    db.execute('SAVEPOINT alert_evaluation')
    try:
        evaluate(db,now,config(path))
        db.execute('RELEASE alert_evaluation')
    except Exception:
        db.execute('ROLLBACK TO alert_evaluation');db.execute('RELEASE alert_evaluation')
        db.execute('INSERT INTO errors VALUES (?,?,?,?)',(now,'alerts','evaluation_error',None))


def public_alerts(db,now,state_filter='active'):
    # Rebuild messages from approved templates; never trust persisted free text.
    result=[]
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts'").fetchone()
    rows=db.execute('SELECT * FROM alerts'+(" WHERE state='active'" if state_filter=='active' else '')) if exists else []
    names={r['id']:safe(r['name'],'Agent') for r in db.execute('SELECT id,name FROM agents WHERE timestamp=(SELECT MAX(timestamp) FROM agents)')}
    for r in rows:
        rule=r['rule'];level=r['severity'];subject=r['subject_key']
        if rule not in RULES or rule=='collector_stale' or level not in RANK or r['state'] not in ('active','resolved'): continue
        aid=label=None
        if rule in ('new_agent','failed_sessions'):
            aid=agent_id(subject)
            if not aid: continue
            if rule=='new_agent': message=f'New agent: {names.get(aid,"Agent")}'
            else:
                match=re.match(r'^Failed sessions: ([0-9]{1,12}) ',r['message'])
                count=match[1] if match else '0'
                message=f'Failed sessions: {count} ({names.get(aid,"Agent")[:48]})'
        elif rule=='limit_window':
            try:
                provider,window=json.loads(subject)
                if not agent_id(provider): continue
                label=safe(window,'Window'); message=f'Limit {label}: {level}'
            except (ValueError,TypeError): continue
        else:
            message={'credits':f'Credits balance: {level}','gateway_unreachable':'Gateway unreachable','gateway_pressure':'Gateway resource pressure'}[rule]
            label='credits' if rule=='credits' else 'gateway'
        result.append({'id':r['id'],'rule':rule,'severity':level,'state':r['state'],
                       'firstSeen':r['first_seen'],'lastSeen':r['last_seen'],'resolvedAt':r['resolved_at'],
                       'message':message[:80],'agentId':aid,'windowLabel':label})
    # A completed partial/failed run does not mask the last fully successful run.
    last=db.execute('SELECT MAX(timestamp) FROM collection_runs WHERE successfulCommands>0 AND failedCommands=0').fetchone()[0]
    if last is None or now-last>300000:
        level='critical' if last is None or now-last>900000 else 'warn'
        result.append({'id':'collector-stale','rule':'collector_stale','severity':level,'state':'active',
                       'firstSeen':last+300000 if last is not None else None,'lastSeen':now,'resolvedAt':None,
                       'message':'Collector stale','agentId':None,'windowLabel':'collector'})
    return sorted(result,key=lambda r:(r['state']=='active',RANK[r['severity']],r['lastSeen']),reverse=True)
