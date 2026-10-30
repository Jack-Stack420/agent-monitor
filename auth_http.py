"""HTTP authentication boundary; proxy trust is confined to its loopback listener."""
import hashlib
import hmac
from http.cookies import SimpleCookie
import html
import secrets
import ssl
import sqlite3
import re
from urllib.parse import parse_qs, urlsplit

LOGIN_CSP="default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
PUBLIC_FONTS={'/fonts/chakra-petch-500-latin.woff2','/fonts/share-tech-mono-400-latin.woff2'}

class Boundary:
    def proxy_denied(self):
        # No IP/identity, no password counters, including denied POST /login.
        try:self.server.auth.audit('proxy_rejected','')
        except sqlite3.Error:pass
        self.send_response(403)
        self.send_header('Content-Length','0')
        self.send_header('Cache-Control','no-store')
        self.send_header('Connection','close')
        self.end_headers();self.close_connection=True

    def parse_request(self):
        if not super().parse_request():return False
        if self.server.mode!='tailscale-proxy':return True
        import auth
        owner=auth.tailscale_owner(self.server.root)
        logins=self.headers.get_all('Tailscale-User-Login',[])
        # This gate runs before dispatch for EVERY HTTP method and path.
        if not owner or len(logins)!=1 or logins[0].lower()!=owner:
            self.proxy_denied();return False
        hosts=self.headers.get_all('Host',[])
        schemes=self.headers.get_all('X-Forwarded-Proto',[])
        if len(hosts)!=1 or hosts[0] not in self.server.allowed_hosts or schemes!=['https']:
            self.proxy_denied();return False
        host=hosts[0]
        for name in ('Origin','Referer'):
            values=self.headers.get_all(name,[])
            if not values:continue
            try:
                ref=urlsplit(values[0])
                valid=len(values)==1 and ref.scheme=='https' and ref.netloc==host and ref.username is None and ref.password is None
                if name=='Origin':valid=valid and ref.path=='' and not ref.query and not ref.fragment
            except ValueError:valid=False
            if not valid:self.proxy_denied();return False
        sites=self.headers.get_all('Sec-Fetch-Site',[])
        # Only GET/HEAD navigate requests permit Fetch-Site none.
        navigation=self.command in ('GET','HEAD') and self.headers.get_all('Sec-Fetch-Mode',[])==['navigate']
        allowed=('same-origin','none') if navigation else ('same-origin',)
        if sites and (len(sites)!=1 or sites[0] not in allowed):
            self.proxy_denied();return False
        return True

    def cookie_name(self,name):
        return '__Host-'+name if getattr(getattr(self,'server',None),'mode','lan')=='tailscale-proxy' else name
    def cookie(self,name):
        try:
            values=SimpleCookie();values.load(self.headers.get('Cookie',''))
            return values[self.cookie_name(name)].value if self.cookie_name(name) in values else ''
        except Exception:return ''
    def csrf(self,token):
        return self.server.auth.csrf_token('/logout',token)
    def set_cookie(self,name,value,clear=False):
        flags='; Path=/; HttpOnly; SameSite=Strict'
        if getattr(getattr(self,'server',None),'mode','lan')=='tailscale-proxy' or isinstance(self.connection,ssl.SSLSocket):flags+='; Secure'
        if clear:flags+='; Max-Age=0'
        self.send_header('Set-Cookie',self.cookie_name(name)+'='+value+flags)
    def redirect(self,path,session=None,clear=False):
        self.send_response(302);self.send_header('Location',path)
        self.send_header('Content-Length','0');self.send_header('Cache-Control','no-store')
        if session is not None:self.set_cookie('cp_session',session)
        if clear:self.set_cookie('cp_session','',True)
        self.end_headers();self.close_connection=True
    def login_page(self,error=False):
        csrf=self.cookie('cp_csrf')
        issue_cookie=not self.server.auth.valid_csrf(csrf,'/login')
        if issue_cookie:csrf=self.server.auth.csrf_token('/login')
        configured=self.server.auth.configured()
        message='Invalid credentials' if error else ''
        if not configured:message='Password not set. Run: cd ~/agent-monitor && python3 scripts/set_password.py'
        content=('''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AGENT MONITOR - Sign in</title><link rel="icon" href="data:,"><link rel="stylesheet" href="/login.css"></head><body><main><h1>AGENT MONITOR</h1><p>OWNER AUTHENTICATION</p><p role="status">'''+html.escape(message)+'''</p><form method="post" action="/login"><input type="hidden" name="csrf" value="'''+csrf+'''"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="512" required><button type="submit">Sign in</button></form></main></body></html>''').encode()
        if not configured:content=re.sub(rb'<form.*?</form>',b'',content,flags=re.S)
        self.send_response(401 if error else 200)
        self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(content)))
        self.send_header('Content-Security-Policy',LOGIN_CSP);self.send_header('Cache-Control','no-store')
        if issue_cookie and not error:self.set_cookie('cp_csrf',csrf)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(content)
        self.close_connection=True
    def authorize_get(self):
        route=urlsplit(self.path)
        if route.path=='/login' and not route.query:self.login_page();return False
        if route.path=='/logout':self.send_json(405,{'error':'method_not_allowed'});return False
        if not route.query and (route.path=='/login.css' or route.path in PUBLIC_FONTS):return True
        token=self.cookie('cp_session')
        if self.server.auth.session(token):return True
        if route.path.startswith('/api/'):self.send_json(401,{'error':'unauthorized'})
        elif 'text/html' in self.headers.get('Accept','').lower() and self.headers.get('Sec-Fetch-Dest','document')=='document':self.redirect('/login')
        else:self.send_json(404,{'error':'not_found'})
        return False
    def do_POST(self):
        self.auth_attempted=False
        try:
            self.post_body()
        except (sqlite3.Error,ValueError):
            self.send_json(503,{'error':'unavailable'})
    def post_body(self):
        if self.headers.get('Host') not in self.server.allowed_hosts:
            self.send_json(403,{'error':'forbidden'});return
        route=urlsplit(self.path)
        if route.path not in ('/login','/logout') or route.query:
            self.send_json(405,{'error':'method_not_allowed'});return
        # Validate BOTH provided headers; never use forwarded scheme or address.
        scheme='https' if getattr(getattr(self,'server',None),'mode','lan')=='tailscale-proxy' or isinstance(self.connection,ssl.SSLSocket) else 'http'
        for name in ('Origin','Referer'):
            if name in self.headers:
                try:ref=urlsplit(self.headers[name])
                except ValueError:
                    self.send_json(403,{'error':'forbidden'});return
                if ref.scheme!=scheme or ref.netloc!=self.headers['Host'] or ref.username is not None or ref.password is not None:
                    self.send_json(403,{'error':'forbidden'});return
        # Non-browser CLI clients omit Fetch Metadata; any supplied value must be same-origin.
        if self.headers.get('Sec-Fetch-Site','same-origin')!='same-origin':
            self.send_json(403,{'error':'forbidden'});return
        try:
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or self.headers.get('Transfer-Encoding'):raise ValueError()
            size=int(lengths[0])
            if size<0 or size>2048:
                self.send_json(413,{'error':'invalid_request'});return
            if self.headers.get('Content-Type','').split(';')[0].strip().lower()!='application/x-www-form-urlencoded':raise ValueError()
            body=self.rfile.read(size)
            if len(body)!=size:raise ValueError()
            text=body.decode('utf-8',errors='strict')
            import re
            if re.search(r'%(?![0-9a-fA-F]{2})',text):raise ValueError()
            fields=parse_qs(text,keep_blank_values=True,strict_parsing=True,max_num_fields=3,encoding='utf-8',errors='strict')
            allowed={'csrf','password'} if route.path=='/login' else {'csrf'}
            if set(fields)-allowed or any(len(v)!=1 for v in fields.values()):raise ValueError()
        except (ValueError,UnicodeError,TimeoutError):
            self.send_json(400,{'error':'invalid_request'});return
        token=self.cookie('cp_session')
        supplied=fields.get('csrf',[''])[0]
        cookie_valid=route.path!='/login' or self.server.auth.valid_csrf(self.cookie('cp_csrf'),'/login')
        if not cookie_valid or not self.server.auth.valid_csrf(supplied,route.path,token if route.path=='/logout' else ''):
            self.send_json(403,{'error':'forbidden'});return
        if route.path=='/logout':
            if not self.server.auth.session(token):self.send_json(401,{'error':'unauthorized'});return
            self.server.auth.revoke(token);self.redirect('/login',clear=True);return
        password=fields.get('password',[''])[0]
        self.auth_attempted=True
        session=self.server.auth.attempt(password,self.client_address[0])
        if session:self.redirect('/',session=session)
        else:self.login_page(error=True)
