#!/usr/bin/env python3
"""Local, read-only access checks; print statuses, never telemetry bodies."""
import http.client
import json
import socket
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parent
cfg=json.loads((ROOT/'config.json').read_text())
address=cfg['bind_address'];port=cfg['port']
listeners=subprocess.check_output(['ss','-H','-tlnp',f'sport = :{port}'],text=True)
rows=listeners.splitlines()
assert len(rows)==1, 'expected one listener'
assert rows[0].split()[3]==f'{address}:{port}', 'unexpected bind address'
print(listeners.strip())

def request(method,path,host=None):
    conn=http.client.HTTPConnection(address,port,timeout=3)
    conn.request(method,path,headers={} if host is None else {'Host':host})
    response=conn.getresponse();body=response.read()
    status=response.status
    assert response.getheader('Access-Control-Allow-Origin') is None
    assert response.getheader('Cache-Control')=='no-store'
    assert response.getheader('X-Content-Type-Options')=='nosniff'
    if method!='GET':assert response.getheader('Allow')=='GET'
    conn.close()
    return status

for path in ['/', '/api/overview','/api/agents','/api/limits','/api/credits','/api/gateway','/api/tokens','/api/log','/api/health']:
    status=request('GET',path);assert status==200,(path,status)
print('Dashboard and all 8 API GET endpoints: 200')
for host in cfg['allowed_hosts']:
    assert request('GET','/api/health',host)==200
for path in ['/','/api/health']:
    assert request('GET',path,'wrong.invalid:8787')==403
print('Configured Hosts accepted; wrong Host rejected on dashboard and API: 403')
for method in ['HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','CUSTOM']:
    assert request(method,'/')==405,method
print('All 9 non-GET methods rejected: 405')
for path in ['/api.py','/config.json','/lexicon.json','/data/monitor.db','/../config.json','/%2e%2e/config.json','/?x=1','/design/reference.html']:
    assert request('GET',path)==404,path
print('Static project/traversal/query paths rejected: 404')
interfaces=json.loads(subprocess.check_output(['ip','-j','addr','show'],text=True))
negative=['127.0.0.1','0.0.0.0','::1']
for interface in interfaces:
    if interface['ifname']=='tailscale0':
        negative += [entry['local'] for entry in interface['addr_info']]
for ip in negative:
    try:
        with socket.create_connection((ip,port),timeout=2):
            raise AssertionError('unexpected reachable listener: '+ip)
    except OSError:
        print(f'No TCP connection to {ip}:{port}')
print('PASS: listener and local negative network probes')
