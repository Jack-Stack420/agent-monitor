#!/usr/bin/env python3
"""Restricted-address read-only monitor API; no CLI calls or persistent writes."""
import hashlib
import auth
from auth_http import Boundary
import secrets
import errno
import ipaddress
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import re
import sqlite3
import time
import threading
from urllib.parse import parse_qs, urlsplit

from alerts import public_alerts, RANK
from collector import agent_states, agent_tasks, string, task_label

ROOT = Path(__file__).resolve().parent
DASHBOARD_WORDING = {'title': 'AGENT MONITOR', 'subtitle': 'LOCAL AGENT STATUS', 'sampleTag': 'SAMPLE DATA', 'staleTag': 'COLLECTOR STALE', 'agents': 'AGENTS', 'working': 'WORKING', 'recent': 'RECENT', 'idle': 'IDLE', 'currentRite': 'CURRENT TASK', 'lastRite': 'LAST TASK', 'lastComm': 'LAST ACTIVE', 'ritesToday': 'TASKS TODAY', 'offences': 'ERRORS', 'mood': 'STATUS', 'moodOk': 'HEALTHY', 'moodBad': 'DEGRADED', 'limits': 'USAGE LIMITS', 'radar': 'LIMITS RADAR', 'credits': 'CREDITS', 'gateway': 'GATEWAY', 'tokens': 'TOKENS USED', 'log': 'TASK LOG', 'stOk': 'OK', 'stWarn': 'LOW', 'stCrit': 'CRITICAL', 'logRunning': 'RUNNING', 'logDone': 'DONE', 'logFailed': 'FAILED', 'footer': 'SELF-HOSTED AGENT MONITOR'}
DASHBOARD_WORDING.update({'alertsTitle': 'Alerts', 'alertsEmpty': 'All quiet. No active alerts.', 'alertInfo': 'Info', 'alertWarn': 'Warn', 'alertAlarm': 'Alarm', 'alertCritical': 'Critical', 'alertDismiss': 'Dismiss', 'alertSoundOn': 'Sound on', 'alertSoundOff': 'Sound off', 'alertsResolved': 'Resolved in the last 24 hours'})
ENDPOINTS = ('overview', 'agents', 'limits', 'credits', 'gateway', 'tokens', 'log', 'health')
PROXY_BIND_ERROR='Rejected tailscale-proxy listener: requires literal 127.0.0.1; listener disabled'
PROXY_START_ERROR='Tailscale-proxy listener startup failed; LAN listener unaffected'
DEFAULTS = {'listeners':None, 'proxy_allowed_hosts':None, 'bind_address':'127.0.0.1', 'allowed_hosts':['127.0.0.1:8787','localhost:8787'], 'port':8787, 'stale_after_seconds':180, 'thresholds':{'warn':70,'alarm':80,'critical':90}, 'credit_alert_level':5, 'agents':{}}


def read_json(path):
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError('invalid configuration')
    return data


def finite(value, default=None):
    return value if type(value) in (int, float) and math.isfinite(value) else default


def text(value):
    return task_label(value)


def identifier(value):
    return string(value, identifier=True) if text(value) == value else None


def model(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.:-]+)?',value):
        return None
    # Permit the model's structural provider/name slash, but independently scrub
    # every component so credential prefixes cannot masquerade as model names.
    if any(text(part)!=part for part in value.split('/')):
        return None
    return string(value,model=True)


def valid_proxy_host(host):
    if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}',host):return False
    return 1<=int(host.rsplit(':',1)[1])<=65535


def config_at(root):
    raw = read_json(root/'config.json')
    cfg = dict(DEFAULTS, **{k:raw[k] for k in DEFAULTS if k in raw})
    if type(cfg['port']) is not int or not 1 <= cfg['port'] <= 65535:
        raise ValueError('invalid configuration')
    if finite(cfg['stale_after_seconds'],0) <= 0 or finite(cfg['credit_alert_level']) is None:
        raise ValueError('invalid configuration')
    thresholds = cfg['thresholds']
    if not isinstance(thresholds,dict) or any(finite(thresholds.get(k)) is None for k in ('warn','alarm','critical')) or not 0 <= thresholds['warn'] < thresholds['alarm'] < thresholds['critical'] <= 100:
        raise ValueError('invalid configuration')
    if not isinstance(cfg['agents'], dict):
        raise ValueError('invalid configuration')
    if not isinstance(cfg['allowed_hosts'],list) or not cfg['allowed_hosts'] or any(not isinstance(h,str) or not h or h != h.strip() for h in cfg['allowed_hosts']):
        raise ValueError('invalid allowed_hosts: expected nonempty list of Host values')
    if cfg['listeners'] is not None and not isinstance(cfg['listeners'],list):
        raise ValueError('invalid listeners: expected list')
    cfg['labels'] = raw.get('STORE_TASK_LABELS',True) is True
    return cfg


def lexicon_at(root):
    raw=read_json(root/'lexicon.json')
    # Only approved display namespaces/keys; no arbitrary config data is echoed.
    allowed={'status':('working','recent','idle','done','failed','stale','unknown','ok','warn','alarm','critical','not_reported','reported'),
             'moods':('calm','watchful','urgent'),
             'sections':('overview','agents','limits','credits','gateway','tokens','log','health'), 'dashboard':tuple(DASHBOARD_WORDING)}
    defaults={'status':{'not_reported':'not reported','reported':'Reported'},
              'moods':{'calm':'Calm','watchful':'Watchful','urgent':'Urgent'},
              'sections':{k:k.title() for k in ENDPOINTS},'dashboard':DASHBOARD_WORDING}
    result={}
    for group,keys in allowed.items():
        values=raw.get(group,{})
        if not isinstance(values,dict): values={}
        result[group]={key:text(values.get(key)) or defaults.get(group,{}).get(key,key) for key in keys}
    return result


def latest(db, table):
    return [dict(r) for r in db.execute('SELECT * FROM '+table+' WHERE timestamp=(SELECT MAX(timestamp) FROM '+table+')')]


def severity(value,cfg):
    if value is None:
        return 'not_reported'
    for name in ('critical','alarm','warn'):
        if value >= cfg['thresholds'][name]: return name
    return 'ok'


def visible_ids(db,cfg):
    return {r['id'] for r in latest(db,'agents') if identifier(r['id']) and not (isinstance(cfg['agents'].get(r['id']),dict) and cfg['agents'][r['id']].get('hidden') is True)}


def session_kind_display(kind):
    return {'direct':'Direct session', 'spawn':'Spawn-child session',
            'spawn-child':'Spawn-child session', 'subagent':'Spawn-child session',
            'cron':'Scheduled job'}.get(kind, 'Session' if kind else None)


def agents_data(db,cfg,now):
    states=agent_states(db,now); tasks=agent_tasks(db,now); visible=visible_ids(db,cfg)
    out=[]
    for r in latest(db,'agents'):
        aid=r['id']
        if aid not in visible: continue
        override=cfg['agents'].get(aid,{})
        override=override if isinstance(override,dict) else {}
        color=override.get('accent_color')
        if not isinstance(color,str) or not re.fullmatch(r'#[0-9A-Fa-f]{6}',color):
            color=None  # Only explicit overrides; the dashboard owns fallback colors.
        start=now-now%86400000
        counts=db.execute('SELECT COUNT(*), SUM(CASE WHEN status=? THEN 1 ELSE 0 END) FROM sessions WHERE agentId=? AND COALESCE(updatedAt,timestamp)>=? AND COALESCE(updatedAt,timestamp)<=?',('failed',aid,start,now)).fetchone()
        task=tasks.get(aid,{})
        kind=text(task.get('kind')); label=text(task.get('task_label')) if cfg['labels'] else None
        out.append({'id':aid,'name':text(override.get('display_name')) or text(r['name']) or aid,
                    'accent_color':color,'rank':text(override.get('rank')),'model':model(r['model']),
                    'status':states.get(aid,'idle'), 'sessionsToday':counts[0], 'failedToday':counts[1] or 0, 'task':{'label':label,'display':label or session_kind_display(kind),'kind':kind,
                    'status':task.get('status','idle'),'ageMs':finite(task.get('ageMs'))}})
    return sorted(out,key=lambda r:r['id'])


def window_id(provider, label):
    return hashlib.sha256(json.dumps([provider,label],ensure_ascii=True).encode()).hexdigest()[:24]


def limits_history(db,now,hours):
    groups={}
    for r in db.execute('SELECT timestamp,provider,windowLabel,usedPercent FROM usage_windows WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp,rowid',(now-hours*3600000,now)):
        if not identifier(r['provider']) or text(r['windowLabel']) != r['windowLabel']:
            continue
        at=finite(r['timestamp']); percent=finite(r['usedPercent'])
        if at is None or percent is None: continue
        key=window_id(r['provider'],r['windowLabel'])
        groups.setdefault(key,[]).append({'timestamp':at,'usedPercent':percent})
    out=[]
    for key,points in sorted(groups.items()):
        if len(points)>200:
            points=[points[i*(len(points)-1)//199] for i in range(200)]
        out.append({'id':key,'points':points})
    return out


def limits_data(db,cfg):
    # gateway_health is emitted by every successful status poll, even an empty
    # provider census. Never revive windows/providers from an older status poll.
    sample=db.execute('SELECT MAX(timestamp) FROM gateway_health').fetchone()[0]
    providers=[dict(r) for r in db.execute('SELECT * FROM usage_providers WHERE timestamp=?',(sample,))]
    windows=[dict(r) for r in db.execute('SELECT * FROM usage_windows WHERE timestamp=?',(sample,))]
    if not providers and windows:
        providers=[{'provider':p,'plan':None,'timestamp':sample,'windowCount':1} for p in sorted({r['provider'] for r in windows if r['provider']})]
    out=[]
    for p in providers:
        pid=identifier(p['provider'])
        if not pid: continue
        rows=[r for r in windows if r['provider']==pid and r['timestamp']==p['timestamp']]
        out.append({'provider':pid,'plan':text(p['plan']),'status':'reported' if rows else 'not_reported',
                    'windows':[{'id':window_id(pid,r['windowLabel']),'label':text(r['windowLabel']),'usedPercent':finite(r['usedPercent']),
                    'resetAt':finite(r['resetAt']),'level':severity(finite(r['usedPercent']),cfg)} for r in rows]})
    return out


def credits_data(db,cfg):
    return {'alert_level':cfg['credit_alert_level'],'balances':[{'amount':finite(r['amount']), 'unit':text(r['unit']),
            'alert':r['amount'] is not None and r['amount'] <= cfg['credit_alert_level'],'timestamp':r['timestamp']} for r in latest(db,'credits')]}


def gateway_data(db):
    rows=latest(db,'gateway_health')
    if not rows: return None
    r=rows[0]
    return {'timestamp':r['timestamp'],'reachable':bool(r['reachable']) if r['reachable'] is not None else None,
            'connectLatencyMs':finite(r['connectLatencyMs']),'runtimeState':text(r['runtimeState']),
            'rssBytes':finite(r['rssBytes']),'hostUtilization':finite(r['hostUtilization'])}


def tokens_data(db,cfg,now,days):
    visible=visible_ids(db,cfg)
    # Latest session totals, counted once; UTC calendar days by stored activity.
    cutoff=now-now%86400000-(days-1)*86400000
    rows=db.execute('''SELECT agentId,totalTokens,
      COALESCE(updatedAt,lastInteractionAt,
        CASE WHEN ageMs>=0 THEN timestamp-ageMs END) AS activityAt
      FROM sessions''')
    daily={}; by_agent={}; daily_agents={}
    for r in rows:
        if r['agentId'] not in visible: continue
        activity=finite(r['activityAt'])
        if activity is None or not cutoff<=activity<=now: continue
        delta=max(0,finite(r['totalTokens'],0))
        day=time.strftime('%Y-%m-%d',time.gmtime(activity/1000))
        daily_agents.setdefault(day,{})[r['agentId']]=daily_agents.get(day,{}).get(r['agentId'],0)+delta
        daily[day]=daily.get(day,0)+delta; by_agent[r['agentId']]=by_agent.get(r['agentId'],0)+delta
    return {'days':days,'total':sum(daily.values()),'daily':[{'date':k,'tokens':v,'by_agent':daily_agents[k]} for k,v in sorted(daily.items())],
            'by_agent':[{'id':k,'tokens':v} for k,v in sorted(by_agent.items())]}


def log_data(db,cfg,limit):
    visible=visible_ids(db,cfg); events=[]
    for r in db.execute('SELECT * FROM errors ORDER BY timestamp DESC LIMIT ?', (limit,)):
        # Enumerations only; raw CLI/error messages are never exposed.
        events.append({'timestamp':r['timestamp'],'type':'collector_error',
                       'command':r['command'] if r['command'] in ('status','sessions','agents','cron','alerts') else None,
                       'category':r['category'] if r['category'] in ('timeout','launch','exit','invalid_or_incomplete_json','evaluation_error') else None,
                       'returnCode':finite(r['returnCode'])})
    for r in db.execute("SELECT agentId,status,updatedAt,kind,task_label,model,totalTokens,sessionStartedAt FROM sessions WHERE status IN ('done','failed') ORDER BY updatedAt DESC LIMIT ?",(limit,)):
        if r['agentId'] not in visible: continue
        events.append({'timestamp':r['updatedAt'],'type':'session_finished','agent':r['agentId'],
                       'status':r['status'],'kind':text(r['kind']),
                       'model':model(r['model']),'totalTokens':finite(r['totalTokens']),
                       'sessionStartedAt':finite(r['sessionStartedAt']),
                       'durationMs':max(0,r['updatedAt']-r['sessionStartedAt']) if finite(r['updatedAt']) is not None and finite(r['sessionStartedAt']) is not None else None,'label':text(r['task_label']) if cfg['labels'] else None})
    return sorted(events,key=lambda r:r['timestamp'] or 0,reverse=True)[:limit]


def health_data(db,cfg,now):
    rows=latest(db,'collection_runs')
    row=rows[0] if rows else None
    last=row['timestamp'] if row else None
    age=max(0,now-last) if last is not None else None
    return {'last_run':last,'ageMs':age,'stale':age is None or age>cfg['stale_after_seconds']*1000,
            'stale_after_seconds':cfg['stale_after_seconds'],
            'successfulCommands':row['successfulCommands'] if row else None,
            'failedCommands':row['failedCommands'] if row else None,
            'last_sessions':db.execute('SELECT MAX(timestamp) FROM session_polls').fetchone()[0]}


def integer_param(params,name,default,maximum):
    values=params.get(name,[str(default)])
    if len(values)!=1 or not re.fullmatch(r'[0-9]{1,3}',values[0]) or not 1<=int(values[0])<=maximum:
        raise ValueError('invalid query')
    return int(values[0])


def clamped_param(params,name,default,minimum,maximum,allowed=None):
    values=params.get(name,[str(default)])
    if len(values)!=1: raise ValueError('invalid query')
    value=values[0]
    if not re.fullmatch(r'-?[0-9]+',value): return default
    digits=value.lstrip('-').lstrip('0') or '0'
    # Compare magnitude before int(): arbitrarily long numeric queries stay bounded.
    if value.startswith('-'): value=minimum
    elif len(digits)>len(str(maximum)): value=maximum
    else: value=max(minimum,min(maximum,int(digits)))
    return min(allowed,key=lambda n:abs(n-value)) if allowed else value


def response(root,path,now=None):
    now=int(time.time()*1000) if now is None else now
    route=urlsplit(path); name=route.path.removeprefix('/api/')
    if not route.path.startswith('/api/') or name not in (*ENDPOINTS,'limits/history','alerts'): return 404,{'error':'not_found'}
    params=parse_qs(route.query,keep_blank_values=True)
    permitted={'tokens':{'days'},'log':{'limit'},'limits/history':{'hours'},'alerts':{'state','limit'}}.get(name,set())
    if set(params)-permitted: return 400,{'error':'invalid_query'}
    try:
        alert_state=params.get('state',['active'])
        if name=='alerts' and (len(alert_state)!=1 or alert_state[0] not in ('active','all')): raise ValueError('invalid query')
        alert_limit=clamped_param(params,'limit',50,1,200) if name=='alerts' else 50
        days=clamped_param(params,'days',7,7,30,(7,14,30)) if name=='tokens' else 7
        hours=clamped_param(params,'hours',72,1,720) if name=='limits/history' else 72
        limit=integer_param(params,'limit',20,100) if name=='log' else 20
    except ValueError:
        return 400,{'error':'invalid_query'}
    try:
        cfg=config_at(root); lexicon=lexicon_at(root)
        # mode=ro cannot create a DB. query_only prevents accidental writes too.
        with sqlite3.connect((root/'data/monitor.db').resolve().as_uri()+'?mode=ro',uri=True,timeout=2) as db:
            db.row_factory=sqlite3.Row
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            if name=='alerts':
                return 200,{'data':public_alerts(db,now,alert_state[0])[:alert_limit],'generatedAt':now}
            if name=='limits/history':
                return 200,{'data':limits_history(db,now,hours)}
            functions={'agents':lambda:agents_data(db,cfg,now),'limits':lambda:limits_data(db,cfg),
                       'credits':lambda:credits_data(db,cfg),'gateway':lambda:gateway_data(db),
                       'tokens':lambda:tokens_data(db,cfg,now,days),'log':lambda:log_data(db,cfg,limit),
                       'health':lambda:health_data(db,cfg,now)}
            if name=='overview':
                data={k:f() for k,f in functions.items()}
                alerts=public_alerts(db,now)
                data['alerts']={'active':len(alerts),'highest':max((a['severity'] for a in alerts),key=RANK.get,default=None)}
                levels=[w['level'] for p in data['limits'] for w in p['windows']]
                mood='urgent' if data['health']['stale'] or 'critical' in levels or 'alarm' in levels else 'watchful' if 'warn' in levels or any(b['alert'] for b in data['credits']['balances']) else 'calm'
                return 200,dict(data,generatedAt=now,lexicon=lexicon,thresholds=cfg['thresholds'],mood=mood)
            return 200,{'data':functions[name](),'generatedAt':now,'lexicon':lexicon}
    except (OSError, ValueError, TypeError, AttributeError, sqlite3.Error, KeyError):
        return 503,{'error':'unavailable'}


class Handler(Boundary, BaseHTTPRequestHandler):
    server_version='MonitorAPI'
    sys_version=''
    def log_message(self,*args):
        pass  # No URLs, headers, addresses, exceptions or request data in logs.
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','same-origin')
        super().end_headers()
    def send_json(self,status,data):
        if self.command=='POST' and urlsplit(self.path).path=='/login' and not getattr(self,'auth_attempted',False):
            self.auth_attempted=True
            try:self.server.auth.audit('rejected',self.client_address[0])
            except sqlite3.Error:status,data=503,{'error':'unavailable'}
        body=json.dumps(data,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('Connection','close')
        if status==405: self.send_header('Allow','GET, POST' if urlsplit(self.path).path=='/login' else 'POST' if urlsplit(self.path).path=='/logout' else 'GET')
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(body)
        self.close_connection=True
    def do_HEAD(self):
        if self.server.mode=='tailscale-proxy':self.do_GET()
        else:self.send_json(405,{'error':'method_not_allowed'})
    def do_GET(self):
        # No CORS; host validation also prevents browser DNS-rebinding attacks.
        if self.headers.get('Host') not in self.server.allowed_hosts:
            self.send_json(403,{'error':'forbidden'}); return
        try:
            if not self.authorize_get(): return
        except sqlite3.Error:
            self.send_json(503,{'error':'unavailable'});return
        route=urlsplit(self.path)
        if not route.path.startswith('/api/'):
            self.send_static(route); return
        status,data=response(self.server.root,self.path)
        self.send_json(status,data)
    def send_static(self,route):
        # Resolve below web only; reject traversal, symlinks, directories and queries.
        from urllib.parse import unquote
        name=unquote(route.path)
        base=(self.server.root/'web').resolve()
        target=base/('index.html' if name=='/' else name.lstrip('/'))
        if route.query or '..' in Path(name).parts or target.is_symlink():
            self.send_json(404,{'error':'not_found'}); return
        try:
            resolved=target.resolve()
            if not resolved.is_relative_to(base) or not resolved.is_file():
                self.send_json(404,{'error':'not_found'}); return
            is_font=resolved.suffix=='.woff2' and resolved.is_relative_to(base/'fonts')
            mime='font/woff2' if is_font else {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.ico':'image/x-icon'}.get(resolved.suffix)
            if mime is None:
                self.send_json(404,{'error':'not_found'}); return
            body=resolved.read_bytes()
            if resolved.name=='index.html':
                csrf=self.csrf(self.cookie('cp_session'))
                body=body.replace(b'<!-- AUTH_CSRF -->', ('<meta name="cp-csrf" content="'+csrf+'">').encode())
        except OSError:
            self.send_json(404,{'error':'not_found'}); return
        self.send_response(200)
        if resolved.suffix=='.html':
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        for key,value in [('Content-Type',mime),('Content-Length',str(len(body))),('Cache-Control','no-store'),('Connection','close')]:
            self.send_header(key,value)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(body)
        self.close_connection=True
    def __getattr__(self,name):
        if name.startswith('do_'):
            return lambda:self.send_json(405,{'error':'method_not_allowed'})
        raise AttributeError(name)
    def send_error(self,code,message=None,explain=None):
        self.send_json(code,{'error':'bad_request'})
    def setup(self):
        super().setup()
        self.connection.settimeout(5)


def validated_bind_address(value):
    """Only literal IPv4 LAN/loopback addresses; never wildcard or Tailscale."""
    try:
        address = ipaddress.ip_address(value) if isinstance(value,str) else None
    except ValueError:
        address = None
    if (isinstance(address,ipaddress.IPv4Address)
            and any(address in ipaddress.ip_network(net) for net in ('192.168.0.0/16','127.0.0.0/8'))):
        return str(address)
    # Never echo arbitrary configuration strings into logs.
    logging.warning('Rejected bind_address: requires literal IPv4 in 192.168.0.0/16 or 127.0.0.0/8; wildcard, empty, IPv6 and Tailscale forbidden; falling back to 127.0.0.1')
    return '127.0.0.1'


class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,root=ROOT,port=None,listener=None):
        self.root=Path(root)
        cfg=config_at(self.root)
        listener=listener if listener is not None else {'mode':'lan','address':cfg['bind_address'],'port':cfg['port']}
        if not isinstance(listener,dict):raise ValueError('invalid listener')
        self.mode=listener.get('mode','lan')
        if self.mode not in ('lan','tailscale-proxy'):raise ValueError('invalid listener mode')
        proxy=self.mode=='tailscale-proxy'
        address=listener.get('address','127.0.0.1' if proxy else cfg['bind_address'])
        if proxy:
            hosts=cfg['proxy_allowed_hosts']
            if not isinstance(hosts,list) or not hosts or any(not valid_proxy_host(h) for h in hosts):
                raise ValueError('invalid proxy_allowed_hosts')
            if not auth.tailscale_owner(self.root):
                raise ValueError('proxy owner unconfigured')
            if type(address) is not str or address!='127.0.0.1':
                logging.error(PROXY_BIND_ERROR)
                raise ValueError(PROXY_BIND_ERROR)
        else:address=validated_bind_address(address)
        selected_port=listener.get('port',8788 if proxy else cfg['port']) if port is None else port
        if type(selected_port) is not int or not 0<=selected_port<=65535:raise ValueError('invalid listener port')
        self.auth=auth.Store(self.root/'data/auth/auth.db',scope=self.mode)
        self.allowed_hosts=tuple(cfg['proxy_allowed_hosts'] if proxy else cfg['allowed_hosts'])
        super().__init__((address,selected_port),Handler,bind_and_activate=False)
        try:
            if self.mode=='tailscale-proxy':self.server_bind()
            else:self.bind_with_fallback()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise
    def bind_with_fallback(self,wait_seconds=60):
        deadline=time.monotonic()+wait_seconds
        waiting=False
        while True:
            try:
                self.server_bind()
                return
            except OSError as exc:
                if exc.errno != errno.EADDRNOTAVAIL:
                    raise
                remaining=deadline-time.monotonic()
                if remaining <= 0:
                    logging.warning('Configured bind_address unavailable after 60 seconds; falling back to 127.0.0.1')
                    self.server_address=('127.0.0.1',self.server_address[1])
                    self.server_bind()
                    return
                if not waiting:
                    logging.warning('Configured bind_address not assigned yet; waiting up to 60 seconds')
                    waiting=True
                time.sleep(min(1,remaining))
    def handle_error(self,request,client_address):
        pass


def configured_servers(root=ROOT):
    """Bind independently; a rejected/unavailable proxy cannot take down LAN."""
    cfg=config_at(Path(root))
    listeners=cfg['listeners']
    if listeners is None:listeners=[{'mode':'lan','address':cfg['bind_address'],'port':cfg['port']}]
    servers=[]
    for listener in listeners:
        try:servers.append(Server(root,listener=listener))
        except (OSError,ValueError,TypeError,KeyError):
            if isinstance(listener,dict) and listener.get('mode')=='tailscale-proxy':
                logging.error(PROXY_START_ERROR)
                continue
            for server in servers:server.server_close()
            raise
    if not servers:raise ValueError('no available listeners')
    return servers


def main():
    servers=[]
    try:
        servers=configured_servers()
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in servers]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
    except (OSError,ValueError,TypeError,KeyError):
        raise SystemExit('Monitor API startup failed')
    finally:
        for server in servers:server.server_close()


if __name__=='__main__': main()
