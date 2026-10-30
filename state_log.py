"""Private additive diagnostics. No labels or session identifiers are persisted."""
import sqlite3

def diagnostics_from_rows(rows):
    return {'total':len(rows), 'complete':None, 'rows':[row[:11] for row in rows]}

def updated(row):
    return row['updatedAt'] if row['updatedAt'] is not None else row['timestamp']-row['ageMs'] if row['ageMs'] is not None else -1

def write_state_log(db, now, meta, duration, roots, agent_states, session_states, activity_ms):
    # State comes from the unchanged production classifier, not a replacement.
    states=agent_states(db,now)
    classified=list(session_states(db,now).values())
    names=['sessionId','agentId','kind','status','model','modelProvider','totalTokens','lastInteractionAt','sessionStartedAt','ageMs','updatedAt']
    rows=[dict(zip(names,row),timestamp=now) for row in meta['rows']]
    for agent,state in states.items():
        owned=[r for r in rows if r['agentId']==agent]
        newest=max(owned,key=updated,default={})
        rule='none'
        if state=='recent':
            rule='recent-finished'
        elif state=='working':
            rule='null-status-fresh'
            for row,session_state in classified:
                if row['agentId']!=agent or session_state!='working':
                    continue
                previous=db.execute('SELECT totalTokens FROM session_history WHERE sessionId=? AND agentId=? AND timestamp=(SELECT MAX(timestamp) FROM session_polls WHERE timestamp<?)',(row['sessionId'],agent,row['timestamp'])).fetchone()
                if previous is not None and previous[0] is not None and row['totalTokens'] is not None and row['totalTokens']>previous[0] and 0<=now-row['timestamp']<activity_ms:
                    rule='token advance'
                    break
        # Only known enums survive diagnostic text fields; arbitrary text cannot leak.
        kind=newest.get('kind')
        kind=kind if kind in ('direct','cron','spawn','spawn-child','subagent') or kind is None else 'other'
        status=newest.get('status')
        status=status if status in ('done','failed','running','active','idle','aborted','completed','error','cancelled') or status is None else 'other'
        counts=[sum(r['status']==value for r in owned) for value in (None,'done','failed')]
        values=[now,agent,state,rule,len(owned),*counts,len(owned)-sum(counts),sum(r['status'] is None and r['kind']!='cron' for r in owned),kind,status,newest.get('updatedAt'),newest.get('ageMs'),newest.get('totalTokens'),meta['total'],meta['complete'],duration,roots]
        db.execute('INSERT INTO agent_state_log VALUES ('+','.join('?' for _ in values)+')',values)

def isolated_state_log(db, now, meta, duration, roots, agent_states, session_states, activity_ms):
    db.execute('SAVEPOINT state_diagnostics')
    try:
        if meta is not None:
            write_state_log(db,now,meta,duration,roots,agent_states,session_states,activity_ms)
        db.execute('DELETE FROM agent_state_log WHERE timestamp < ?',(now-14*86400000,))
    except Exception:
        # Never record exception text, CLI payloads, identifiers or partial rows.
        db.execute('ROLLBACK TO state_diagnostics')
        db.execute('RELEASE state_diagnostics')
        db.execute('INSERT INTO errors VALUES (?,?,?,?)',(now,'agent_state_log','diagnostic_failure',None))
    else:
        db.execute('RELEASE state_diagnostics')
