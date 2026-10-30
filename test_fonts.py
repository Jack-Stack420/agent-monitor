from auth_fixture import fixture_cookie
import hashlib
import http.client
import subprocess
import threading
import unittest
from pathlib import Path
import api
import test_api

CSP="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

class FontAssetTests(unittest.TestCase):
    @unittest.skip("needs private git history")
    def test_script_moved_unchanged(self):
        old=subprocess.check_output(['git','show','monitor-dashboard-v2.1.1:web/index.html'],text=True)
        self.assertEqual(old.split('<script>',1)[1].split('</script>',1)[0],subprocess.check_output(['git','show','monitor-dashboard-v2.2:web/app.js'],text=True))
        html=(api.ROOT/'web/index.html').read_text()
        self.assertNotIn('fonts.googleapis.com',html)
        self.assertNotIn('<script>',html)
        self.assertIn('<script src="/app.js"></script>',html)
        self.assertEqual(html.count('@font-face'),4)
        self.assertEqual(html.count('font-display:swap'),4)

    def test_provenance_and_non_ascii_glyphs(self):
        sources=(api.ROOT/'web/fonts/SOURCES.md').read_text()
        text=(api.ROOT/'web/index.html').read_text()+(api.ROOT/'web/app.js').read_text()+(api.ROOT/'lexicon.json').read_text()
        required={ord(c) for c in text if ord(c)>127}
        self.assertEqual(required,{0xb7,0x2026})
        for file in (api.ROOT/'web/fonts').glob('*.woff2'):
            self.assertEqual(file.read_bytes()[:4],b'wOF2')
            self.assertIn(hashlib.sha256(file.read_bytes()).hexdigest(),sources)
            charset=subprocess.check_output(['fc-query','--format','%{charset}',str(file)],text=True)
            ranges=[tuple(int(n,16) for n in item.split('-')) for item in charset.split()]
            self.assertTrue(all(any(r[0]<=c<=r[-1] for r in ranges) for c in required))
        for file in (api.ROOT/'web/fonts').glob('*OFL.txt'):
            self.assertIn('SIL OPEN FONT LICENSE',file.read_text())

class FontHTTPTests(unittest.TestCase):
    setUp = test_api.APITests.setUp
    tearDown = test_api.APITests.tearDown
    write_config = test_api.APITests.write_config
    def test_headers_font_allowlist_and_rejections(self):
        web=self.root/'web'; web.mkdir(); fonts=web/'fonts'; fonts.mkdir()
        (web/'index.html').write_text('synthetic page')
        (web/'app.js').write_text('/* synthetic */')
        for name in ['ok.woff2','bad.woff','bad.ttf','OFL.txt','SOURCES.md']:
            (fonts/name).write_bytes(b'wOF2synthetic')
        (web/'outside.woff2').write_bytes(b'wOF2synthetic')
        (fonts/'escape.woff2').symlink_to(self.root/'config.json')
        (fonts/'alias.woff2').symlink_to(fonts/'ok.woff2')
        (fonts/'escape-dir').symlink_to(self.root,target_is_directory=True)
        server=api.Server(self.root,0)
        cookie=fixture_cookie(server)
        server.allowed_hosts=(f'127.0.0.1:{server.server_port}',)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(path,method='GET',host=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
            conn.request(method,path,headers={'Cookie':cookie} if host is None else {'Host':host,'Cookie':cookie})
            r=conn.getresponse(); body=r.read(); result=(r.status,dict(r.getheaders()),body);conn.close()
            self.assertEqual(result[1].get('X-Content-Type-Options'),'nosniff')
            self.assertNotIn('Access-Control-Allow-Origin',result[1])
            return result
        try:
            for path in ['/','/index.html']:
                status,headers,_=request(path); self.assertEqual(status,200);self.assertEqual(headers['Content-Security-Policy'],CSP);self.assertEqual(headers['Cache-Control'],'no-store')
            status,headers,_=request('/fonts/ok.woff2');self.assertEqual(status,200);self.assertEqual(headers['Content-Type'],'font/woff2');self.assertEqual(headers['Cache-Control'],'no-store')
            for path in ['/fonts/','/fonts/bad.woff','/fonts/bad.ttf','/fonts/OFL.txt','/fonts/SOURCES.md','/outside.woff2','/fonts/escape.woff2','/fonts/alias.woff2','/fonts/escape-dir/config.json','/fonts/../config.json','/fonts/%2e%2e/config.json','/fonts/ok.woff2?x=1']:
                self.assertEqual(request(path)[0],404,path)
            for path in ['/app.js','/api/overview']:
                status,headers,_=request(path); self.assertEqual(status,200);self.assertEqual(headers['Cache-Control'],'no-store')
            self.assertEqual(request('/fonts/ok.woff2',host='wrong.invalid')[0],403)
            for method in ['HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','CUSTOM']:
                self.assertEqual(request('/fonts/ok.woff2',method)[0],405)
        finally:
            server.shutdown();server.server_close();thread.join()
