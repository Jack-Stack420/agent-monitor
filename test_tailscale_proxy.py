"""Task14: TEST-only loopback proxy boundary and independent LAN behavior."""
import contextlib
import http.client
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import api
import auth

HOST='monitor-test.invalid:8443'
OWNER='test-owner@example.invalid'
PASSWORD='TEST-only-unique-password-0395019'

class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.config={'proxy_allowed_hosts':[HOST]};self.save()
        (self.root/'web').mkdir()
        for name in ('index.html','login.css','app.js'):(self.root/'web'/name).write_text('TEST content <!-- AUTH_CSRF -->')
        self.servers=[]
        self.addCleanup(self.stop)
        auth.set_tailscale_owner(self.root,OWNER.upper())
        self.proxy=self.start('tailscale-proxy')
        self.proxy.auth.set_password(PASSWORD)
    def save(self):(self.root/'config.json').write_text(json.dumps(self.config))
    def start(self,mode):
        server=api.Server(self.root,listener={'mode':mode,'address':'127.0.0.1','port':0})
        if mode=='lan':server.allowed_hosts=(HOST,)
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        self.servers.append((server,t));return server
    def stop(self):
        for s,t in self.servers:s.shutdown();s.server_close();t.join()
    def request(self,method='GET',path='/login',headers=None,body=None,server=None):
        s=server or self.proxy
        h={'Host':HOST,'Tailscale-User-Login':OWNER,'X-Forwarded-Proto':'https'}
        if headers:
            for k,v in headers.items():
                if v is None:h.pop(k,None)
                else:h[k]=v
        c=http.client.HTTPConnection('127.0.0.1',s.server_port,timeout=5)
        c.request(method,path,body=body,headers=h)
        r=c.getresponse();result=(r.status,r.getheaders(),r.read());c.close();return result
    def dump(self):
        with self.proxy.auth.connect() as db:return '\n'.join(db.iterdump())
    def test_owner_file_private_normalized_and_unconfigured_fail_closed(self):
        p=self.root/'data/auth/tailscale_owner'
        self.assertEqual(p.read_text(),OWNER+'\n')
        self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertEqual(p.parent.stat().st_mode&0o777,0o700)
        p.chmod(0o644);self.assertEqual(self.request()[0],403)
        p.unlink();self.assertEqual(self.request()[0],403)
    def test_all_methods_paths_identity_gate_empty_generic_private_audit(self):
        for identity in (None,'TEST-stranger@example.invalid',OWNER+',TEST-spoof'):
            for method in ('GET','POST','HEAD','OPTIONS','PUT','PATCH','DELETE','TRACE','CONNECT','TEST'):
                for path in ('/','/login','/login.css','/fonts/test.woff2','/api/health','/logout','/missing'):
                    status,headers,body=self.request(method,path,{'Tailscale-User-Login':identity})
                    self.assertEqual((status,body),(403,b''),(identity,method,path))
                    self.assertFalse(any(k.lower()=='set-cookie' for k,v in headers))
        with self.proxy.auth.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM failures').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT DISTINCT result,ip FROM auth_log').fetchall(),[('proxy_rejected','')])
        dump=self.dump()
        for forbidden in (OWNER,'TEST-stranger','TEST-spoof',PASSWORD,'127.0.0.1'):self.assertNotIn(forbidden,dump)
    def test_exact_identity_case_insensitive_password_still_required(self):
        self.assertEqual(self.request(headers={'Tailscale-User-Login':OWNER.upper()})[0],200)
        for identity in (OWNER+'.extra','prefix'+OWNER,' '+OWNER,OWNER+' '):
            # HTTP parsers normalize leading OWS, but not suffixes.
            if identity.startswith(' '):continue
            self.assertEqual(self.request(headers={'Tailscale-User-Login':identity})[0],403)
        self.assertEqual(self.request(path='/api/health')[0],401)
    def test_all_paths_host_scheme_origin_referer_and_fetch(self):
        bad=[{'Host':v} for v in ('evil.test:8443',HOST.split(':')[0],HOST.replace('8443','443'),HOST.upper())]
        bad += [{'X-Forwarded-Proto':v} for v in (None,'http','https,http','HTTPS')]
        bad += [{name:v} for name in ('Origin','Referer') for v in ('null','http://'+HOST,'https://evil.test:8443','https://'+HOST.split(':')[0],'https://TEST@'+HOST)]
        bad += [{'Sec-Fetch-Site':v} for v in ('cross-site','same-site','null','none')]
        for path in ('/login','/login.css','/api/health','/'):
            for headers in bad:self.assertEqual(self.request(path=path,headers=headers)[0],403,(path,headers))
        self.assertEqual(self.request(headers={'Origin':'https://'+HOST,'Referer':'https://'+HOST+'/login','Sec-Fetch-Site':'same-origin'})[0],200)
        self.assertEqual(self.request(headers={'Sec-Fetch-Site':'none','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'})[0],200)
    def test_fetch_metadata_matrix(self):
        for method in ('GET','HEAD','POST'):
            for mode in (None,'navigate','cors','no-cors'):
                for site in (None,'none','same-origin','same-site','cross-site','null'):
                    headers={'Sec-Fetch-Mode':mode,'Sec-Fetch-Site':site}
                    accepted=site is None or site=='same-origin' or (method in ('GET','HEAD') and mode=='navigate' and site=='none')
                    status,_,_=self.request(method,headers=headers)
                    self.assertEqual(status!=403,accepted,(method,mode,site))
                    self.assertEqual(self.request(method,headers=dict(headers,Origin='null'))[0],403)
        for method in ('GET','HEAD'):
            for dest in (None,'document','iframe'):
                self.assertEqual(self.request(method,headers={'Sec-Fetch-Mode':'navigate','Sec-Fetch-Site':'none','Sec-Fetch-Dest':dest,'Referer':'https://'+HOST+'/login'})[0],200)

    def login(self,server=None):
        status,headers,body=self.request(server=server)
        self.assertEqual(status,200)
        cookie=next(v.split(';')[0] for k,v in headers if k.lower()=='set-cookie')
        csrf=re.search(b'name="csrf" value="([^"]+)"',body)[1].decode()
        return self.request('POST','/login',{'Cookie':cookie,'Origin':('http' if server else 'https')+'://'+HOST,'Content-Type':'application/x-www-form-urlencoded'},urlencode({'csrf':csrf,'password':PASSWORD}),server)
    def test_proxy_secure_host_cookies_login_logout_and_cookie_namespace(self):
        status,headers,_=self.request()
        csrf=next(v for k,v in headers if k.lower()=='set-cookie')
        self.assertTrue(csrf.startswith('__Host-cp_csrf='))
        status,headers,_=self.login();self.assertEqual(status,302)
        cookie=next(v for k,v in headers if k.lower()=='set-cookie')
        for value in (csrf,cookie):
            for flag in ('; Secure','; HttpOnly','; SameSite=Strict','; Path=/'):self.assertIn(flag,value)
            self.assertNotIn('Domain',value)
        pair=cookie.split(';')[0]
        self.assertEqual(self.request(path='/',headers={'Cookie':pair})[0],200)
        self.assertEqual(self.request(path='/',headers={'Cookie':pair.replace('__Host-',''),'Accept':'text/html'})[0],302)
        token=pair.split('=',1)[1];csrf=self.proxy.auth.csrf_token('/logout',token)
        status,headers,_=self.request('POST','/logout',{'Cookie':pair,'Content-Type':'application/x-www-form-urlencoded'},urlencode({'csrf':csrf}))
        self.assertEqual(status,302)
        self.assertIn('__Host-cp_session=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0',dict(headers)['Set-Cookie'])
        self.assertFalse(self.proxy.auth.session(token))
    def test_lan_completely_ignores_identity_and_forwarded_scheme(self):
        lan=self.start('lan')
        for headers in ({'Tailscale-User-Login':None,'X-Forwarded-Proto':None},{'Tailscale-User-Login':'TEST-spoof','X-Forwarded-Proto':'https'}):
            status,response,_=self.request(headers=headers,server=lan)
            self.assertEqual(status,200)
            cookie=next(v for k,v in response if k.lower()=='set-cookie')
            self.assertTrue(cookie.startswith('cp_csrf='));self.assertNotIn('Secure',cookie)
        status,headers,_=self.login(lan);self.assertEqual(status,302)
        self.assertTrue(dict(headers)['Set-Cookie'].startswith('cp_session='))
        status,_,_=self.request('POST','/login',{'Origin':'https://'+HOST,'Content-Type':'application/x-www-form-urlencoded'},'',lan)
        self.assertEqual(status,403)
        with lan.auth.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM auth_log WHERE result='proxy_rejected'").fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM failures').fetchone()[0],0)
    def test_scoped_lockouts_same_store_no_cross_listener_lock(self):
        lan=auth.Store(self.proxy.auth.path)
        now=1000
        for i in range(5):self.assertIsNone(self.proxy.auth.attempt('TEST-wrong','127.0.0.1',now=now))
        self.assertIsNone(self.proxy.auth.attempt(PASSWORD,'127.0.0.1',now=now))
        self.assertTrue(lan.attempt(PASSWORD,'127.0.0.1',now=now))
        with lan.connect() as db:
            self.assertEqual(dict(db.execute('SELECT subject,count FROM failures')),{'tailscale-proxy:global':5,'tailscale-proxy:ip:127.0.0.1':5})
        for i in range(5):self.assertIsNone(lan.attempt('TEST-wrong','127.0.0.1',now=now+2))
        self.assertTrue(self.proxy.auth.attempt(PASSWORD,'127.0.0.1',now=now+2))
    def test_duplicate_identity_host_and_forwarded_scheme_rejected(self):
        for name,value in [('Tailscale-User-Login',OWNER),('Host',HOST),('X-Forwarded-Proto','https'),('Origin','https://'+HOST)]:
            c=http.client.HTTPConnection('127.0.0.1',self.proxy.server_port,timeout=3)
            c.putrequest('GET','/login',skip_host=True)
            for k,v in [('Host',HOST),('Tailscale-User-Login',OWNER),('X-Forwarded-Proto','https'),(name,value),(name,value)]:c.putheader(k,v)
            c.endheaders();r=c.getresponse();self.assertEqual((r.status,r.read()),(403,b''));c.close()

class ListenerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.cfg={'proxy_allowed_hosts':[HOST]};self.save()
        auth.set_tailscale_owner(self.root,OWNER)
    def save(self):(self.root/'config.json').write_text(json.dumps(self.cfg))
    def test_backwards_compatible_and_defaults(self):
        cfg=api.config_at(self.root)
        self.assertEqual(cfg['proxy_allowed_hosts'],[HOST]);self.assertIsNone(cfg['listeners'])
        with api.Server(self.root,0) as s:self.assertEqual(s.mode,'lan')
        with patch.object(api.Server,'server_bind'),patch.object(api.Server,'server_activate'):
            with api.Server(self.root,listener={'mode':'tailscale-proxy'}) as s:self.assertEqual(s.server_address,('127.0.0.1',8788))
    def test_invalid_proxy_binds_fail_no_fallback_fixed_private_log(self):
        for address in ('0.0.0.0','::1','127.0.0.2','localhost','192.168.1.2','100.64.0.1','TEST-secret',None,42):
            with self.assertLogs(level='ERROR') as logs,self.assertRaisesRegex(ValueError,'literal 127.0.0.1'):
                api.Server(self.root,listener={'address':address,'port':0,'mode':'tailscale-proxy'})
            self.assertEqual(logs.output,['ERROR:root:'+api.PROXY_BIND_ERROR])
    def test_failed_proxy_does_not_stop_lan_invalid_or_occupied(self):
        for listener in ({'mode':'tailscale-proxy','address':'TEST-invalid','port':0},{'mode':'tailscale-proxy','address':'127.0.0.1','port':0}):
            self.cfg['listeners']=[listener,{'mode':'lan','address':'127.0.0.1','port':0}];self.save()
            real=api.Server.server_bind
            def bind(s):
                if s.mode=='tailscale-proxy':raise OSError('TEST-private-error')
                return real(s)
            with patch.object(api.Server,'server_bind',bind),self.assertLogs(level='ERROR') as logs:
                servers=api.configured_servers(self.root)
            try:self.assertEqual([s.mode for s in servers],['lan'])
            finally:
                for s in servers:s.server_close()
            self.assertNotIn('TEST-private-error',' '.join(logs.output))
    def test_two_listeners_same_process_and_default_scope(self):
        self.cfg['listeners']=[{'mode':m,'address':'127.0.0.1','port':0} for m in ('lan','tailscale-proxy')];self.save()
        servers=api.configured_servers(self.root)
        try:
            self.assertEqual([s.auth.scope for s in servers],['lan','tailscale-proxy'])
            self.assertEqual(servers[0].auth.path,servers[1].auth.path)
        finally:
            for s in servers:s.server_close()
    def test_proxy_failure_matrix_lan_remains_healthy(self):
        import socket
        for case in ('missing','empty','wrong_type','invalid_host','invalid_address','occupied','unconfigured_owner'):
            for proxy_first in (True,False):
                with self.subTest(case=case,proxy_first=proxy_first):
                    auth.set_tailscale_owner(self.root,OWNER)
                    proxy={'mode':'tailscale-proxy','address':'127.0.0.1','port':0}
                    lan={'mode':'lan','address':'127.0.0.1','port':0}
                    self.cfg={'proxy_allowed_hosts':[HOST],'listeners':[proxy,lan] if proxy_first else [lan,proxy]}
                    if case=='missing':self.cfg.pop('proxy_allowed_hosts')
                    if case=='empty':self.cfg['proxy_allowed_hosts']=[]
                    if case=='wrong_type':self.cfg['proxy_allowed_hosts']='TEST-private-value'
                    if case=='invalid_host':self.cfg['proxy_allowed_hosts']=['TEST-private-value']
                    if case=='invalid_address':proxy['address']='TEST-private-value'
                    if case=='unconfigured_owner':(self.root/'data/auth/tailscale_owner').unlink()
                    occupied=socket.socket()
                    try:
                        if case=='occupied':
                            occupied.bind(('127.0.0.1',0));occupied.listen();proxy['port']=occupied.getsockname()[1]
                        self.save()
                        with self.assertLogs(level='ERROR') as logs:servers=api.configured_servers(self.root)
                        self.assertNotIn('TEST-private-value',' '.join(logs.output))
                        self.assertEqual([s.mode for s in servers],['lan'])
                        server=servers[0];server.allowed_hosts=(HOST,)
                        thread=threading.Thread(target=server.serve_forever);thread.start()
                        try:
                            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                            c.request('GET','/login',headers={'Host':HOST});response=c.getresponse()
                            self.assertEqual(response.status,200);response.read();c.close()
                        finally:server.shutdown();server.server_close();thread.join()
                    finally:occupied.close()

    def test_proxy_hosts_require_explicit_port(self):
        for value in (None,[],['test.invalid'],['test.invalid:443/'],['test.invalid:0'],['test.invalid:65536'],['https://test.invalid:8443'],['test.invalid:8443 ']):
            self.cfg['proxy_allowed_hosts']=value;self.save()
            with self.assertRaisesRegex(ValueError,'proxy_allowed_hosts'):api.Server(self.root,listener={'mode':'tailscale-proxy','port':0})

if __name__=='__main__':unittest.main()
