#!/usr/bin/env python3
"""Read-only OpenClaw telemetry. Raw CLI output never leaves process memory."""
import argparse
import concurrent.futures
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from state_log import diagnostics_from_rows, isolated_state_log
from alerts import initialize as initialize_alerts, isolated_evaluate

ROOT = Path(__file__).resolve().parent
COMMANDS = {
    'status': ('status', '--usage', '--json'),
    'sessions': ('sessions', '--all-agents', '--limit', 'all', '--json'),
    'agents': ('agents', 'list', '--json'),
    'cron': ('cron', 'list', '--all', '--json'),
}
TABLES = {
 'agent_state_log': 'timestamp INTEGER, agentId TEXT, state TEXT, rule TEXT, sessionCount INTEGER, nullCount INTEGER, doneCount INTEGER, failedCount INTEGER, otherCount INTEGER, nullNonCronCount INTEGER, newestKind TEXT, newestStatus TEXT, newestUpdatedAt INTEGER, newestAgeMs INTEGER, newestTotalTokens INTEGER, pollSessionCount INTEGER, responseComplete INTEGER, cliDurationMs INTEGER, rootRequests INTEGER',
 'collection_runs': 'timestamp INTEGER PRIMARY KEY, successfulCommands INTEGER, failedCommands INTEGER',
 'usage_providers': 'timestamp INTEGER, provider TEXT, plan TEXT, windowCount INTEGER',
 'session_polls': 'timestamp INTEGER PRIMARY KEY',
 'agents': 'timestamp INTEGER, id TEXT, name TEXT, model TEXT',
 'usage_windows': 'timestamp INTEGER, provider TEXT, plan TEXT, windowLabel TEXT, usedPercent REAL, resetAt INTEGER',
 'credits': 'timestamp INTEGER, amount REAL, unit TEXT',
 'gateway_health': 'timestamp INTEGER, reachable INTEGER, connectLatencyMs REAL, runtimeState TEXT, rssBytes INTEGER, hostUtilization REAL',
 'sessions': 'timestamp INTEGER, sessionId TEXT PRIMARY KEY, agentId TEXT, kind TEXT, status TEXT, model TEXT, modelProvider TEXT, totalTokens INTEGER, lastInteractionAt INTEGER, sessionStartedAt INTEGER, ageMs INTEGER, updatedAt INTEGER',
 'session_history': 'timestamp INTEGER, sessionId TEXT, agentId TEXT, kind TEXT, status TEXT, model TEXT, modelProvider TEXT, totalTokens INTEGER, lastInteractionAt INTEGER, sessionStartedAt INTEGER, ageMs INTEGER, updatedAt INTEGER',
 'cron_jobs': 'timestamp INTEGER, name TEXT, schedule TEXT, lastRun INTEGER, lastStatus TEXT, nextRun INTEGER',
 'errors': 'timestamp INTEGER, command TEXT, category TEXT, returnCode INTEGER',
}

def string(v, identifier=False, model=False):
    if not isinstance(v, str) or not v or len(v) > 160:
        return None
    # Do not retain paths, emails, session routing keys or credential-like strings,
    # even if unexpectedly delivered inside an otherwise allowed field.
    if re.search(r'[@\\\n\r]|(?:^|[ :])(?:/|~)|(?:agent:|session:|bearer |sk-|token=|secret=)', v, re.I):
        return None
    if '/' in v and not (model and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.:-]+', v)):
        return None
    if identifier and not re.fullmatch(r'[A-Za-z0-9_.-]+', v):
        return None
    return v

# Reject routing/participant identifiers entirely, rather than retaining context.
LABEL_IDS = re.compile(r'(?:\b(?:agent|session):|\b(?:chat|user|participant|channel|account)(?:[_ -]?id)?\s*[:=#-]\s*\S+|\b(?:discord|telegram|whatsapp|slack|signal):|<@!?[0-9]+>)', re.I)
LABEL_PATTERNS = [
    r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
    r'(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s]+',
    r'(?<!\w)(?:~?/|\.{1,2}/|[A-Za-z]:[\\/]|\\\\)[^\s]+',
    r'(?<!\w)(?:[\w.-]+/)+[\w.-]+',
    r'(?<!\w)\+?\d(?:[ () .-]*\d){6,}(?!\w)',
    r'(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|authorization|bearer)\s*[:= ]\s*[^\s]+',
    r'(?i)\b(?:sk-|pk-|gh[pousr]_|github_pat_|xox[baprs]-|AKIA)[A-Za-z0-9_-]+',
    r'\beyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}\b',
    r'\b[A-Za-z0-9_+/=-]{24,}\b',
    r'[^\s]*\d{6,}[^\s]*',
]

def task_label(value, enabled=True):
    if not enabled or not isinstance(value, str) or LABEL_IDS.search(value):
        return None
    value = value.strip()
    for pattern in LABEL_PATTERNS:
        value = re.sub(pattern, '[hidden]', value)
    value = re.sub(r'[\x00-\x1f\x7f]', ' ', value).strip()
    return value[:80] or None

def load_config(path=None):
    path = ROOT/'config.json' if path is None else Path(path)
    if not path.exists():
        return True
    try:
        config = json.loads(path.read_text())
        enabled = config.get('STORE_TASK_LABELS', True)
        return enabled if type(enabled) is bool else False
    except (OSError, ValueError, AttributeError):
        return False  # Invalid configuration fails closed, with no raw error logging.

def schedule_string(v, key):
    if not isinstance(v, str) or len(v) > 160:
        return None
    patterns = {'expr': r'[A-Za-z0-9*?,/# L-]+', 'tz': r'[A-Za-z_+-]+(?:/[A-Za-z_+-]+)*',
                'at': r'[0-9TtZz:.+-]+', 'kind': r'[A-Za-z]+'}
    return v if re.fullmatch(patterns[key], v) else None

def number(v):
    return v if type(v) in (int, float) and math.isfinite(v) else None

def fields(s, spec):
    return [number(s.get(k)) if typ == 'n' else string(s.get(k), identifier=typ == 'i', model=typ == 'm') for k, typ in spec]

SESSION_FIELDS = [('sessionId','i'), ('agentId','i'), ('kind','s'), ('status','s'), ('model','m'), ('modelProvider','i'), ('totalTokens','n'), ('lastInteractionAt','n'), ('sessionStartedAt','n'), ('ageMs','n'), ('updatedAt','n')]

def project(command, data, store_task_labels=True):
    """Explicit allowlist, also used to create safe real-output fixtures."""
    out = {}
    if command == 'agents':
        agents = data if isinstance(data, list) else data.get('agents', [])
        out['agents'] = [fields(a, [('id','i'),('name','s'),('model','m')]) for a in agents]
    elif command == 'status':
        out['usage_windows'], out['credits'], out['usage_providers'] = [], [], []
        for p in data.get('usage', {}).get('providers', []):
            out['usage_providers'].append(fields(p, [('provider','i'),('plan','s')]) + [len(p.get('windows', []))])
            for w in p.get('windows', []):
                out['usage_windows'].append(fields(p, [('provider','i'),('plan','s')]) + fields(w, [('label','s'),('usedPercent','n'),('resetAt','n')]))
            for b in p.get('billing', []):
                if b.get('type') == 'balance':
                    out['credits'].append(fields(b, [('amount','n'),('unit','s')]))
        budget = data.get('shutdownBudget', {})
        active = budget.get('activeWork', {}) if isinstance(budget, dict) else {}
        out['_root_requests'] = number(active.get('rootRequests')) if isinstance(active, dict) else None
        g = data.get('gateway', {})
        runtime = data.get('gatewayService', {}).get('runtime', {})
        out['gateway_health'] = [[g.get('reachable') if type(g.get('reachable')) is bool else None,
            number(g.get('connectLatencyMs')), string(runtime.get('state') or runtime.get('status')),
            number(data.get('processMemory', {}).get('rssBytes')),
            number(data.get('eventLoop', {}).get('cpuBreakdown', {}).get('hostUtilization'))]]
    elif command == 'sessions':
        if data.get('hasMore'):
            raise ValueError('incomplete')
        out['sessions'] = [fields(s, SESSION_FIELDS) + [task_label(s.get('label'), store_task_labels)] for s in data.get('sessions', [])]
        diagnostic_rows = [row[:11] for row in out['sessions']]
        for row, source in zip(diagnostic_rows, data.get('sessions', [])):
            # Count raw missing/null vs other status without retaining arbitrary text.
            status = source.get('status')
            row[3] = status if status in ('done','failed','running','active','idle','aborted','completed','error','cancelled') or status is None else 'other'
            kind = source.get('kind')
            row[2] = kind if kind in ('direct','cron','spawn','spawn-child','subagent') or kind is None else 'other'
        out['_session_diagnostics'] = {'total':len(diagnostic_rows), 'complete':int(data['hasMore'] is False) if type(data.get('hasMore')) is bool else None, 'rows':diagnostic_rows}
        out['sessions'] = [s for s in out['sessions'] if s[0] is not None]
    elif command == 'cron':
        if data.get('hasMore'):
            raise ValueError('incomplete')
        out['cron_jobs'] = []
        for j in data.get('jobs', []):
            state = j.get('state', {})
            sched = j.get('schedule', {})
            safe = {k: (number(sched[k]) if k in ('everyMs','anchorMs') else schedule_string(sched[k], k))
                    for k in ('kind','everyMs','anchorMs','expr','tz','at') if k in sched}
            out['cron_jobs'].append([string(j.get('name')), json.dumps(safe, sort_keys=True),
                number(state.get('lastRunAtMs', j.get('lastRunAtMs'))),
                string(state.get('lastRunStatus') or state.get('lastStatus') or j.get('lastRunStatus')),
                number(state.get('nextRunAtMs', j.get('nextRunAtMs')))])
    return out

def connect(path):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute('PRAGMA secure_delete=ON')
    for table, schema in TABLES.items():
        db.execute('CREATE TABLE IF NOT EXISTS ' + table + ' (' + schema + ')')
        if table != 'agent_state_log':
            db.execute('CREATE INDEX IF NOT EXISTS idx_' + table + '_timestamp ON ' + table + '(timestamp)')
    # Additive migration: legacy samples retain unknown age/update time.
    for table in ('sessions', 'session_history'):
        columns = {r[1] for r in db.execute('PRAGMA table_info('+table+')')}
        for column in ('ageMs', 'updatedAt'):
            if column not in columns:
                db.execute('ALTER TABLE '+table+' ADD COLUMN '+column+' INTEGER')
    for table in ('sessions', 'session_history'):
        if 'task_label' not in {r[1] for r in db.execute('PRAGMA table_info('+table+')')}:
            db.execute('ALTER TABLE '+table+' ADD COLUMN task_label TEXT')
    db.execute('CREATE INDEX IF NOT EXISTS idx_history_session_poll ON session_history(sessionId, timestamp)')
    db.execute('INSERT OR IGNORE INTO session_polls SELECT DISTINCT timestamp FROM session_history')
    initialize_alerts(db)
    return db

def save(db, rows, now):
    if 'sessions' in rows:
        db.execute('INSERT OR IGNORE INTO session_polls VALUES (?)', (now,))
    for table, values in rows.items():
        if table.startswith('_'):
            continue  # In-memory diagnostic metadata is never passed to SQL.
        for row in values:
            vals = [now] + row
            marks = ','.join('?' for _ in vals)
            if table == 'sessions':
                cols = [x[1] for x in db.execute('PRAGMA table_info(sessions)')]
                updates = ','.join(c+'=excluded.'+c for c in cols if c != 'sessionId')
                db.execute('INSERT INTO sessions VALUES ('+marks+') ON CONFLICT(sessionId) DO UPDATE SET '+updates, vals)
                db.execute('INSERT INTO session_history VALUES ('+marks+')', vals)
            else:
                db.execute('INSERT INTO '+table+' VALUES ('+marks+')', vals)

def fetch(command, executable, store_task_labels=True):
    try:
        started = time.monotonic_ns()
        result = subprocess.run([executable, *COMMANDS[command]], capture_output=True, text=True, timeout=20)
        duration = max(0, (time.monotonic_ns()-started)//1000000)
        if result.returncode:
            return None, ('exit', result.returncode)
        try:
            rows = project(command, json.loads(result.stdout), store_task_labels)
            if command == 'sessions':
                rows['_cli_duration_ms'] = duration
            return rows, None
        except (ValueError, TypeError, KeyError, AttributeError):
            return None, ('invalid_or_incomplete_json', None)
    except subprocess.TimeoutExpired:
        return None, ('timeout', None)
    except OSError:
        return None, ('launch', None)

def collect(db, executable='openclaw', now=None, runner=fetch, store_task_labels=None):
    now = int(time.time()*1000) if now is None else now
    enabled = load_config() if store_task_labels is None else store_task_labels is True
    if not enabled:
        for table in ('sessions', 'session_history'):
            db.execute('UPDATE '+table+' SET task_label=NULL WHERE task_label IS NOT NULL')
    successes = failures = 0
    session_diagnostics = None
    cli_duration = root_requests = None
    # Parallel independent commands: each gets 20 seconds; a cycle fits one minute.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = {c: pool.submit(fetch, c, executable, enabled) if runner is fetch
                   else pool.submit(runner, c, executable) for c in COMMANDS}
        for command, future in pending.items():
            rows, error = future.result()
            if error:
                failures += 1
                db.execute('INSERT INTO errors VALUES (?,?,?,?)', (now, command, *error))
            else:
                successes += 1
                if not enabled and 'sessions' in rows:
                    rows = dict(rows, sessions=[row[:-1]+[None] for row in rows['sessions']])
                save(db, rows, now)
                if command == 'sessions' and 'sessions' in rows:
                    session_diagnostics = rows.get('_session_diagnostics', diagnostics_from_rows(rows['sessions']))
                    cli_duration = rows.get('_cli_duration_ms')
                if command == 'status':
                    root_requests = rows.get('_root_requests')
    isolated_state_log(db, now, session_diagnostics, cli_duration, root_requests, agent_states, session_states, ACTIVITY_MS)
    db.execute('INSERT OR REPLACE INTO collection_runs VALUES (?,?,?)', (now, successes, failures))
    for table in TABLES:
        if table == 'agent_state_log':
            continue  # Separate 14-day retention, isolated from collection failures.
        db.execute('DELETE FROM '+table+' WHERE timestamp < ?', (now - 90*86400000,))
    isolated_evaluate(db, now, ROOT/'config.json')
    db.commit()

ACTIVITY_MS = 10 * 60 * 1000

def session_states(db, now=None):
    """Classify latest successful session poll, never reuse older deltas."""
    now = int(time.time()*1000) if now is None else now
    cursor = db.execute('SELECT * FROM session_history WHERE timestamp=(SELECT MAX(timestamp) FROM session_polls)')
    names = [col[0] for col in cursor.description]
    rows = [dict(zip(names, row)) for row in cursor]
    states = {}
    for row in rows:
        age = row['ageMs']
        age = age + max(0, now-row['timestamp']) if age is not None else None
        fresh = age is not None and 0 <= age < ACTIVITY_MS
        previous = db.execute(
            'SELECT totalTokens FROM session_history WHERE sessionId=? AND agentId=? '
            'AND timestamp=(SELECT MAX(timestamp) FROM session_polls WHERE timestamp<?)',
            (row['sessionId'], row['agentId'], row['timestamp'])).fetchone()
        growing = (previous is not None and previous[0] is not None
                   and row['totalTokens'] is not None and row['totalTokens'] > previous[0]
                   and 0 <= now-row['timestamp'] < ACTIVITY_MS)
        if row['status'] is None and age is not None and age >= ACTIVITY_MS:
            state = 'stale'  # Explicit stale veto, including counter increases.
        elif growing or (row['status'] is None and fresh and row['kind'] != 'cron'):
            state = 'working'
        elif row['status'] in ('done', 'failed') and fresh:
            state = 'recent'
        else:
            state = 'idle'
        states[row['sessionId']] = (row, state)
    return states

def agent_states(db, now=None):
    """Activity heuristic: working > recent latest terminal session > idle."""
    sessions = list(session_states(db, now).values())
    agents = db.execute('SELECT DISTINCT id FROM agents WHERE timestamp=(SELECT MAX(timestamp) FROM agents)')
    out = {}
    for (agent,) in agents:
        owned = [(row, state) for row, state in sessions if row['agentId'] == agent]
        latest = max(owned, key=lambda x: x[0]['updatedAt'] if x[0]['updatedAt'] is not None else
                     x[0]['timestamp']-x[0]['ageMs'] if x[0]['ageMs'] is not None else -1, default=None)
        out[agent] = ('working' if any(state == 'working' for _, state in owned)
                      else 'recent' if latest and latest[1] == 'recent' else 'idle')
    return out

def agent_tasks(db, now=None):
    """Current task per agent, without exposing session IDs or routing metadata."""
    now = int(time.time()*1000) if now is None else now
    states = list(session_states(db, now).values())
    def updated(row):
        if row['updatedAt'] is not None:
            return row['updatedAt']
        return row['timestamp']-row['ageMs'] if row['ageMs'] is not None else -1
    out = {}
    agents = db.execute('SELECT DISTINCT id FROM agents WHERE timestamp=(SELECT MAX(timestamp) FROM agents)')
    for (agent,) in agents:
        working = [r for r, state in states if r['agentId'] == agent and state == 'working']
        if working:
            row = max(working, key=updated)
            state = 'working'
        else:
            cur = db.execute("SELECT * FROM sessions WHERE agentId=? AND status IN ('done','failed')", (agent,))
            names = [c[0] for c in cur.description]
            row = max((dict(zip(names, r)) for r in cur), key=updated, default=None)
            state = row['status'] if row else 'idle'
        age = max(0, now-updated(row)) if row and updated(row) >= 0 else None
        out[agent] = {'task_label': row['task_label'] if row else None,
                      'kind': row['kind'] if row else None, 'status': state, 'ageMs': age}
    return out

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', type=Path, default=ROOT/'data'/'monitor.db')
    parser.add_argument('--openclaw', default='openclaw')
    args = parser.parse_args()
    args.db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(args.db.parent/'collector.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        with connect(args.db) as db:
            collect(db, args.openclaw)

if __name__ == '__main__':
    main()
