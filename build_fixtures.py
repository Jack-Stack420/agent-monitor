#!/usr/bin/env python3
"""Rebuild privacy-minimal real-output fixtures; raw inputs are never copied."""
import json
from pathlib import Path
import subprocess
import collector as c

PROBE = Path.home() / 'dash-probe'

def minimal(command, raw):
    if command == 'agents':
        return [{k: a.get(k) for k in ('id','name','model')} for a in raw]
    if command == 'sessions':
        return {'sessions': [{k:s.get(k) for k,t in c.SESSION_FIELDS} for s in raw['sessions']]}
    if command == 'status':
        return {'gateway': {k:raw.get('gateway',{}).get(k) for k in ('reachable','connectLatencyMs')},
          'gatewayService': {'runtime': {'state':raw.get('gatewayService',{}).get('runtime',{}).get('state')}},
          'processMemory': {'rssBytes':raw.get('processMemory',{}).get('rssBytes')},
          'eventLoop': {'cpuBreakdown': {'hostUtilization':raw.get('eventLoop',{}).get('cpuBreakdown',{}).get('hostUtilization')}},
          'usage': {'providers': [{
            'provider':p.get('provider'), 'plan':p.get('plan'),
            'windows':[{k:w.get(k) for k in ('label','usedPercent','resetAt')} for w in p.get('windows',[])],
            'billing':[{k:b.get(k) for k in ('type','amount','unit')} for b in p.get('billing',[]) if b.get('type')=='balance']
          } for p in raw.get('usage',{}).get('providers',[])]}}
    return {'jobs': [{
      'name':j.get('name'),
      'schedule':{k:v for k,v in j.get('schedule',{}).items() if k in ('kind','everyMs','anchorMs','expr','tz','at')},
      'state':{k:v for k,v in j.get('state',{}).items() if k in ('lastRunAtMs','lastRunStatus','lastStatus','nextRunAtMs')}
    } for j in raw.get('jobs',[])]}

def main():
    source = {'status':'status_--usage.json','sessions':'sessions.json','agents':'agents_list.json'}
    for command in c.COMMANDS:
        if command in source:
            raw=json.loads((PROBE/source[command]).read_text())
        else:
            result=subprocess.run(['openclaw',*c.COMMANDS[command]],capture_output=True,text=True,timeout=20,check=True)
            raw=json.loads(result.stdout)
        safe=minimal(command,raw)
        # Scrub strings in retained fields too, while allowing model provider/name.
        def scrub(x, key=''):
            if isinstance(x,dict):return {k:scrub(v,k) for k,v in x.items()}
            if isinstance(x,list):return [scrub(v,key) for v in x]
            return c.string(x,model=key=='model') if isinstance(x,str) else x
        safe=scrub(safe)
        (c.ROOT/'fixtures'/(command+'.json')).write_text(json.dumps(safe,indent=2)+chr(10))
        print(command,{t:len(rows) for t,rows in c.project(command,safe).items()})

if __name__=='__main__':main()
