import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import api
import auth
from auth_fixture import browser_server

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=auth.Store(Path(self.tmp.name)/'data/auth/auth.db')
        self.password=secrets.token_urlsafe(32)
    def test_policy_hash_parameters_permissions_and_status(self):
        self.assertFalse(self.store.configured())
        self.assertFalse(auth.policy(secrets.token_hex(6)))
        self.assertFalse(auth.policy(auth.COMMON[0]+str(14)))
        self.store.set_password(self.password)
        with self.store.connect() as db:
            salt,key,n,r,p,length=db.execute('SELECT salt,hash,n,r,p,length FROM owner').fetchone()
            self.assertEqual((len(salt),len(key),n,r,p,length),(16,32,32768,8,1,32))
            self.assertTrue(auth.hmac.compare_digest(key,auth.derive(self.password,salt)))
            self.assertNotIn(self.password,' '.join(db.iterdump()))
        self.assertEqual(self.store.path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.store.path.parent.stat().st_mode&0o777,0o700)
        self.assertTrue(self.store.status()['password_set'])
    def test_every_verification_hashes_even_unset_empty_wrong(self):
        for configured in [False,True]:
            if configured:self.store.set_password(self.password)
            for value in ['',secrets.token_urlsafe(24)]:
                with patch('auth.derive',wraps=auth.derive) as derive:
                    self.assertIsNone(self.store.attempt(value,'127.0.0.1'))
                    self.assertEqual(derive.call_count,1)
    def test_sessions_hash_only_rotation_idle_and_absolute(self):
        self.store.set_password(self.password)
        t=self.store.attempt(self.password,'127.0.0.1',now=100)
        t2=self.store.attempt(self.password,'127.0.0.1',now=101)
        self.assertTrue(t!=t2 and len(t)>=43)
        with self.store.connect() as db:
            dump=' '.join(db.iterdump());self.assertNotIn(t,dump);self.assertNotIn(self.password,dump)
            self.assertEqual(db.execute('SELECT hash FROM sessions WHERE hash=?',(auth.digest(t),)).fetchone()[0],auth.digest(t))
        self.assertTrue(self.store.session(t,now=102))
        self.assertFalse(self.store.session(t,now=102+auth.IDLE))
        t=self.store.attempt(self.password,'127.0.0.1',now=100)
        with self.store.connect() as db:db.execute('UPDATE sessions SET last_seen=?',(100+auth.ABSOLUTE-1,))
        self.assertFalse(self.store.session(t,now=100+auth.ABSOLUTE))
        t=self.store.attempt(self.password,'127.0.0.1')
        self.store.set_password(secrets.token_urlsafe(32))
        self.assertFalse(self.store.session(t))
        self.store.revoke();self.assertEqual(self.store.status()['active_sessions'],0)
    def test_persisted_global_ip_backoff_cap_and_correct_password_block(self):
        self.store.set_password(self.password);now=1000
        for count in range(1,17):
            self.assertIsNone(self.store.attempt('', '127.0.0.1',now=now))
            with self.store.connect() as db:
                states=dict((s,(c,u)) for s,c,u in db.execute('SELECT * FROM failures'))
            delay=min(900,2**max(0,count-5)) if count>=5 else 0
            self.assertEqual(states['global'][1],now+delay)
            self.assertEqual(states['ip:127.0.0.1'][0],count)
            if delay:
                other=auth.Store(self.store.path)
                self.assertIsNone(other.attempt(self.password,'127.0.0.2',now=now+.1))
            now+=delay+1
        self.assertTrue(self.store.attempt(self.password,'127.0.0.1',now=now))
    def test_log_retention_privacy_allowlist(self):
        self.store.set_password(self.password)
        with self.store.connect() as db:db.execute('INSERT INTO auth_log VALUES (?,?,?)',(1,'failure','127.0.0.1'))
        t=self.store.attempt(self.password,'127.0.0.1',now=10000000)
        self.store.attempt('', '127.0.0.1',now=10000001)
        with self.store.connect() as db:
            self.assertEqual([r[1] for r in db.execute('PRAGMA table_info(auth_log)')],['time','result','ip'])
            rows=db.execute('SELECT * FROM auth_log').fetchall()
        serialized=json.dumps(rows)
        self.assertEqual(len(rows),2);self.assertNotIn(t,serialized);self.assertNotIn(self.password,serialized)
        self.assertTrue(all(r[1] in ('success','failure','throttled') and r[2]=='127.0.0.1' for r in rows))

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp,self.server=browser_server();self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.cookies={};self.password=secrets.token_urlsafe(32)
    def req(self,path,method='GET',body=None,headers=None,track=True):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        hs={'Accept':'text/html','Cookie':'; '.join(k+'='+v for k,v in self.cookies.items())};hs.update(headers or {})
        conn.request(method,path,body=body,headers=hs)
        r=conn.getresponse();data=r.read();hh=r.getheaders();status=r.status;conn.close()
        for k,v in hh:
            if track and k.lower()=='set-cookie':
                c=SimpleCookie();c.load(v)
                for name,item in c.items():self.cookies[name]=item.value
        return status,dict(hh),data
    def csrf(self):
        self.server.auth.set_password(self.password) if not self.server.auth.configured() else None
        status,h,b=self.req('/login');self.assertEqual(status,200)
        return re.search(rb'name="csrf" value="([^"]+)"',b)[1].decode()
    def login(self):
        self.server.auth.set_password(self.password)
        csrf=self.csrf()
        return self.req('/login','POST',urlencode({'csrf':csrf,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded'})
    def test_unset_and_all_protected_boundaries(self):
        for path in ['/','/index.html','/app.js','/fonts/chakra-petch-700-latin.woff2','/data/auth/auth.db','/config.json']:
            status,h,b=self.req(path);self.assertEqual(status,302,path);self.assertEqual(h['Location'],'/login')
        for name in (*api.ENDPOINTS,'alerts','limits/history'):
            status,h,b=self.req('/api/'+name);self.assertEqual(status,401);self.assertEqual(json.loads(b),{'error':'unauthorized'})
        status,h,b=self.req('/login');self.assertIn(b'python3 scripts/set_password.py',b)
        for path in ['/login.css','/fonts/chakra-petch-500-latin.woff2']:
            self.assertEqual(self.req(path)[0],200)
        status,h,b=self.req('/login','POST',urlencode({'csrf':self.cookies['cp_csrf'],'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded'})
        self.assertEqual(status,401);self.assertNotIn('cp_session',self.cookies)
    def test_success_cookie_csrf_logout_and_headers(self):
        status,h,b=self.login();self.assertEqual(status,302)
        cookie=h['Set-Cookie']
        for flag in ['HttpOnly','SameSite=Strict','Path=/']:self.assertIn(flag,cookie)
        self.assertNotIn('Domain=',cookie);self.assertNotIn('Secure',cookie)
        token=self.cookies['cp_session']
        status,h,b=self.req('/');self.assertEqual(status,200)
        self.assertNotIn(token.encode(),b);self.assertNotIn(self.password.encode(),b)
        csrf=re.search(rb'name="cp-csrf" content="([^"]+)"',b)[1].decode()
        self.assertIn("form-action 'none'",h['Content-Security-Policy'])
        self.assertEqual(self.req('/logout','POST','csrf=',{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
        status,h,b=self.req('/logout','POST',urlencode({'csrf':csrf}),{'Content-Type':'application/x-www-form-urlencoded'})
        self.assertEqual(status,302);self.assertIn('Max-Age=0',h['Set-Cookie'])
        self.assertFalse(self.server.auth.session(token));self.assertEqual(self.req('/api/overview')[0],401)
        for path in ['/login','/app.js','/api/health','/login.css','/nope']:
            _,h,b=self.req(path)
            self.assertEqual(h['Cache-Control'],'no-store');self.assertEqual(h['Referrer-Policy'],'same-origin');self.assertEqual(h['X-Content-Type-Options'],'nosniff')
    def test_generic_failures_origin_csrf_size_parsing_methods_host(self):
        self.server.auth.set_password(self.password)
        bodies=[]
        for value in ['',secrets.token_urlsafe(32)]:
            csrf=self.csrf();status,h,b=self.req('/login','POST',urlencode({'csrf':csrf,'password':value}),{'Content-Type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,401);self.assertIn(b'Invalid credentials',b)
        csrf=self.csrf();form=urlencode({'csrf':csrf,'password':self.password})
        for headers in [{'Origin':'http://evil.invalid'},{'Referer':'http://evil.invalid'},{'Origin':'null'}]:
            self.assertEqual(self.req('/login','POST',form,{'Content-Type':'application/x-www-form-urlencoded',**headers})[0],403)
        self.assertEqual(self.req('/login','POST','csrf=bad',{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
        for body,expected in [('x'*2049,413),('csrf=%XX',400),('csrf=a&csrf=b',400),('noequals',400)]:
            self.assertEqual(self.req('/login','POST',body,{'Content-Type':'application/x-www-form-urlencoded'})[0],expected)
        for path in ['/','/app.js','/api/overview']:
            self.assertEqual(self.req(path,'POST')[0],405)
        for method in ['HEAD','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','CUSTOM']:
            for path in ['/login','/logout','/api/health']:
                self.assertEqual(self.req(path,method)[0],405)
        self.assertEqual(self.req('/login',headers={'Host':'evil.invalid'})[0],403)
        status,h,b=self.req('/login');self.assertIn("form-action 'self'",h['Content-Security-Policy'])
        # Proxy scheme headers cannot mark a plaintext connection Secure.
        csrf=self.csrf();status,h,b=self.req('/login','POST',urlencode({'csrf':csrf,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded','X-Forwarded-Proto':'https'})
        self.assertEqual(status,302);self.assertNotIn('Secure',h['Set-Cookie'])

    def test_login_pages_do_not_invalidate_other_tabs(self):
        self.server.auth.set_password(self.password)
        original=self.csrf();second=self.csrf()
        self.assertTrue(original==second)
        self.req('/favicon.ico');self.req('/login')
        status,h,b=self.req('/login','POST',urlencode({'csrf':original,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded'})
        self.assertEqual(status,302)
    def test_rejected_audit_unicode_csrf_and_actual_tls_cookie(self):
        from unittest.mock import create_autospec
        import ssl
        csrf=self.csrf()
        self.assertEqual(self.req('/login','POST',urlencode({'csrf':chr(233)}),{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
        with self.server.auth.connect() as db:
            rows=db.execute('SELECT * FROM auth_log').fetchall()
        self.assertEqual(rows[-1][1],'rejected')
        self.assertNotIn(csrf,json.dumps(rows));self.assertNotIn(self.password,json.dumps(rows))
        handler=object.__new__(api.Handler);handler.connection=create_autospec(ssl.SSLSocket,instance=True)
        headers=[];handler.send_header=lambda k,v:headers.append((k,v))
        handler.set_cookie('cp_session',secrets.token_urlsafe(32))
        self.assertIn('; Secure',headers[0][1])
    def test_parallel_first_token_and_independent_cookie(self):
        from concurrent.futures import ThreadPoolExecutor
        self.server.auth.set_password(self.password)
        first=self.csrf()
        with ThreadPoolExecutor(max_workers=4) as pool:
            replies=list(pool.map(lambda _:self.req('/login',headers={'Cookie':''},track=False),range(4)))
        for status,headers,body in replies:
            self.assertEqual(status,200)
        self.assertNotIn('Set-Cookie',self.req('/login')[1])
        self.cookies['cp_csrf']=self.server.auth.csrf_token('/login')
        for _ in range(3):self.req('/login')
        self.assertEqual(self.req('/login','POST',urlencode({'csrf':first,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded'})[0],302)
    def test_signed_token_expiry_purpose_forgery_and_fetch_site(self):
        self.server.auth.set_password(self.password);first=self.csrf()
        invalid=['',first[:-1]+('0' if first[-1]!='0' else '1'),self.server.auth.csrf_token('/login',now=time.time()-1801),self.server.auth.csrf_token('/logout')]
        for token in invalid:
            self.assertEqual(self.req('/login','POST',urlencode({'csrf':token,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
        for headers in [{'Origin':'http://evil.invalid'},{'Sec-Fetch-Site':'cross-site'},{'Sec-Fetch-Site':'same-site'}]:
            self.assertEqual(self.req('/login','POST',urlencode({'csrf':first,'password':self.password}),{'Content-Type':'application/x-www-form-urlencoded',**headers})[0],403)
        reopened=auth.Store(self.server.auth.path)
        self.assertTrue(reopened.valid_csrf(first,'/login'))
        self.assertFalse(reopened.valid_csrf(first,'/logout'))
    def test_browser_subresources_no_redirect_or_cookies(self):
        for path in ['/favicon.ico','/app.js','/unknown','/api/health']:
            for headers in [{'Accept':'*/*','Sec-Fetch-Dest':'image'},{'Accept':'application/json'},{'Accept':'text/html','Sec-Fetch-Dest':'script'}]:
                status,h,_=self.req(path,headers=headers)
                self.assertEqual(status,401 if path.startswith('/api/') else 404)
                self.assertNotIn('Set-Cookie',h);self.assertNotIn('Location',h)
        self.assertEqual(self.req('/',headers={'Accept':'text/html','Sec-Fetch-Dest':'document'})[0],302)
    def test_storage_and_unit_write_boundary(self):
        self.assertEqual(self.server.auth.path,Path(self.tmp.name)/'data/auth/auth.db')
        self.assertFalse((Path(self.tmp.name)/'data/auth.db').exists())
        unit=(api.ROOT/'agent-monitor-api.service').read_text()
        self.assertEqual([l for l in unit.splitlines() if l.startswith('ReadWritePaths=')],['ReadWritePaths=/home/youruser/agent-monitor/data/auth'])
        self.assertIn('ProtectHome=read-only',unit);self.assertIn('ProtectSystem=strict',unit)
    def test_referrer_policy_on_success_redirect_static_and_every_error(self):
        def check(path,method='GET',body=None,headers=None,status=None):
            result,h,b=self.req(path,method,body,headers)
            if status is not None:self.assertEqual(result,status)
            self.assertEqual(h['Referrer-Policy'],'same-origin')
            return result,h,b
        check('/login',status=200)
        check('/',status=302)
        check('/api/health',status=401)
        check('/favicon.ico',headers={'Accept':'*/*','Sec-Fetch-Dest':'image'},status=404)
        check('/login',headers={'Host':'foreign.invalid'},status=403)
        check('/login','HEAD',status=405)
        csrf=self.csrf()
        headers={'Content-Type':'application/x-www-form-urlencoded','Sec-Fetch-Site':'same-origin'}
        check('/login','POST','csrf=%XX',headers,status=400)
        check('/login','POST','x'*2049,headers,status=413)
        check('/login','POST',urlencode({'csrf':csrf,'password':''}),headers,status=401)
        check('/login','POST',urlencode({'csrf':csrf,'password':self.password}),headers,status=302)
        for path in ['/','/index.html','/app.js','/login.css']:
            check(path,status=200)
        for path in (Path(self.tmp.name)/'web/fonts').glob('*.woff2'):
            check('/fonts/'+path.name,status=200)
        check('/missing',status=404)
        with patch.object(self.server.auth,'session',side_effect=auth.sqlite3.OperationalError):
            check('/api/health',status=503)
        # BaseHTTPRequestHandler protocol errors also traverse end_headers.
        import socket
        with socket.create_connection(('127.0.0.1',self.server.server_port),timeout=5) as conn:
            conn.sendall(b'GET / HTTP/1.1\r\nHost: invalid\r\nX-Test: '+b'x'*65536+b'\r\n\r\n')
            response=b''
            while True:
                block=conn.recv(8192)
                if not block:break
                response+=block
        self.assertIn(b'Referrer-Policy: same-origin\r\n',response)

    def test_post_origin_referer_and_fetch_metadata_remain_fail_closed(self):
        csrf=self.csrf();form=urlencode({'csrf':csrf,'password':self.password})
        origin='http://127.0.0.1:'+str(self.server.server_port)
        headers={'Content-Type':'application/x-www-form-urlencoded','Origin':origin,'Referer':origin+'/login','Sec-Fetch-Site':'same-origin'}
        for override in [{'Origin':'null'},{'Origin':'http://foreign.invalid'},
                         {'Referer':'http://foreign.invalid/login'},
                         {'Sec-Fetch-Site':'cross-site'},{'Sec-Fetch-Site':'same-site'},
                         {'Sec-Fetch-Site':'none'},{'Sec-Fetch-Site':''},
                         {'Origin':origin+'@foreign.invalid'},{'Host':'foreign.invalid'}]:
            result,h,b=self.req('/login','POST',form,{**headers,**override})
            self.assertEqual(result,403)
            self.assertEqual(h['Referrer-Policy'],'same-origin')
            self.assertNotIn('cp_session',self.cookies)
        self.assertEqual(self.req('/login','POST',form,headers)[0],302)

    def test_html_has_no_referrer_override_or_network_favicon(self):
        for body in [self.req('/login')[2],(api.ROOT/'web/index.html').read_bytes()]:
            self.assertNotIn(b'no-referrer',body.lower())
            self.assertNotRegex(body.lower(),rb'referrerpolicy\s*=|name=["\']referrer["\']')
            self.assertIn(b'<link rel="icon" href="data:,">',body)

    def test_cli_helper_private_login_api_and_cleanup(self):
        import os
        import subprocess
        self.server.auth.set_password(self.password)
        env=dict(os.environ,MONITOR_URL=f'http://127.0.0.1:{self.server.server_port}')
        result=subprocess.run(['bash',str(api.ROOT/'scripts/api_get.sh'),'/api/health'],input=self.password+'\n',text=True,capture_output=True,env=env,timeout=10)
        self.assertEqual(result.returncode,0,'API helper must succeed without exposing subprocess output')
        self.assertIn('data',json.loads(result.stdout))
        self.assertNotIn(self.password,result.stdout+result.stderr)
        self.assertEqual(self.server.auth.status()['active_sessions'],0)

class ManagementTests(unittest.TestCase):
    setUp=StoreTests.setUp
    def test_hidden_prompt_confirmation_policy_and_rotation(self):
        import importlib.util
        import sys
        sys.path.insert(0,str(api.ROOT/'scripts'))
        spec=importlib.util.spec_from_file_location('set_password_local',api.ROOT/'scripts/set_password.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module,'store',return_value=self.store),patch.object(module.getpass,'getpass',side_effect=[self.password,self.password]),patch('builtins.print'):
            module.main()
        self.assertTrue(self.store.configured())
        with patch.object(module,'store',return_value=self.store),patch.object(module.getpass,'getpass',side_effect=[self.password,secrets.token_urlsafe(32)]):
            with self.assertRaises(SystemExit):module.main()
        self.assertTrue(self.store.attempt(self.password,'127.0.0.1'))
