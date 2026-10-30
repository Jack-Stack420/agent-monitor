#!/usr/bin/env python3
"""Owner-run atomic config merge. No service or Tailscale changes."""
import getpass
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


def configure(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('unsafe configuration path')
    before=path.read_bytes()
    cfg=json.loads(before)
    if not isinstance(cfg,dict):raise ValueError('invalid configuration')
    listeners=cfg.get('listeners')
    if listeners is None:
        listeners=[{'address':cfg.get('bind_address','127.0.0.1'),'port':cfg.get('port',8787),'mode':'lan'}]
    if not isinstance(listeners,list) or not listeners or any(not isinstance(x,dict) for x in listeners):
        raise ValueError('invalid listeners')
    expected={'address':'127.0.0.1','port':8788,'mode':'tailscale-proxy'}
    proxies=[x for x in listeners if x.get('mode')=='tailscale-proxy']
    if proxies and proxies != [expected]:raise ValueError('existing proxy listener differs; review manually')
    if not proxies:
        if any(x.get('port')==8788 and x.get('address')=='127.0.0.1' for x in listeners):
            raise ValueError('listener conflict; review manually')
        listeners.append(expected)
    cfg['listeners']=listeners
    if 'proxy_allowed_hosts' not in cfg:
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from api import valid_proxy_host
        host=getpass.getpass('Proxy hostname:port (hidden): ')
        if not valid_proxy_host(host):raise ValueError('invalid proxy host')
        cfg['proxy_allowed_hosts']=[host]
    payload=(json.dumps(cfg,indent=2,ensure_ascii=True)+chr(10)).encode()
    fd,name=tempfile.mkstemp(prefix='.config-proxy-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),stat.S_IMODE(path.stat().st_mode)&0o600 or 0o600)
            output.write(payload);output.flush();os.fsync(output.fileno())
        if path.is_symlink() or path.read_bytes()!=before:
            raise ValueError('configuration changed concurrently; unchanged')
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: python3 scripts/configure_proxy_listener.py config.json')
    try:configure(sys.argv[1])
    except (OSError,ValueError,TypeError):raise SystemExit('Config update refused; review configuration locally.')
    print('Proxy listener merged; unrelated configuration preserved. No service changes.')
