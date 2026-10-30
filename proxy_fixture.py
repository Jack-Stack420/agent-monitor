"""TEST-only fake Serve; loopback only, disposable data, no production state.
Used by MONITOR_TEST_PROXY=1 node browser_check.mjs. Never deploy this proxy.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import threading
from urllib.parse import urlsplit
import api
from auth_fixture import browser_server

TEST_HOST = 'monitor-test.invalid:8443'
TEST_OWNER = 'test-owner@example.invalid'

class FakeServe(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def forward(self):
        headers = {k:v for k,v in self.headers.items() if k.lower() not in
                   ('host','connection','tailscale-user-login','x-forwarded-proto','x-forwarded-host','x-forwarded-for')}
        headers.update({'Host':TEST_HOST, 'Tailscale-User-Login':TEST_OWNER, 'X-Forwarded-Proto':'https'})
        # Translate the fake browser origin to the emulated HTTPS Serve origin.
        # Foreign/null origins are deliberately NOT repaired.
        browser_host = '127.0.0.1:'+str(self.server.server_port)
        for name in ('Origin','Referer'):
            if name in headers:
                ref = urlsplit(headers[name])
                if ref.scheme == 'http' and ref.netloc == browser_host:
                    headers[name] = 'https://'+TEST_HOST+ref.path+('?' + ref.query if ref.query else '')
        size=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(size) if size else None
        conn=http.client.HTTPConnection('127.0.0.1',self.server.backend_port,timeout=10)
        try:
            conn.request(self.command,self.path,body,headers)
            response=conn.getresponse(); payload=response.read()
            self.send_response(response.status)
            for k,v in response.getheaders():
                if k.lower() not in ('server','date','connection','transfer-encoding'):
                    self.send_header(k,v)
            self.send_header('Connection','close');self.end_headers()
            if self.command != 'HEAD':self.wfile.write(payload)
        finally:
            conn.close();self.close_connection=True
    do_GET=do_POST=do_HEAD=do_OPTIONS=forward


def proxy_browser_server():
    tmp,lan=browser_server()
    root=lan.root
    lan.shutdown();lan.server_close()
    cfg=json.loads((root/'config.json').read_text());cfg['proxy_allowed_hosts']=[TEST_HOST]
    (root/'config.json').write_text(json.dumps(cfg))
    owner=root/'data/auth/tailscale_owner'
    owner.write_text(TEST_OWNER);owner.chmod(0o600)
    backend=api.Server(root,listener={'address':'127.0.0.1','port':0,'mode':'tailscale-proxy'})
    backend.allowed_hosts=(TEST_HOST,)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    proxy=ThreadingHTTPServer(('127.0.0.1',0),FakeServe)
    proxy.daemon_threads=True;proxy.backend_port=backend.server_port
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    return tmp,backend,proxy

if __name__=='__main__':
    os.umask(0o077)
    tmp,backend,proxy=proxy_browser_server()
    value='TEST-'+secrets.token_urlsafe(32);backend.auth.set_password(value)
    # Only private pipe to browser runner; never console or persistent artifacts.
    print(json.dumps({'base':f'http://127.0.0.1:{proxy.server_port}/','password':value}),flush=True)
    try:input()
    except EOFError:pass
    finally:
        proxy.shutdown();proxy.server_close()
        backend.shutdown();backend.server_close();tmp.cleanup()
