from auth_fixture import fixture_cookie
import unittest
import json
import http.client
import threading
import subprocess
from unittest.mock import patch
import hashlib
import api
import test_api

class HistoryTests(unittest.TestCase):
    setUp=test_api.APITests.setUp
    tearDown=test_api.APITests.tearDown
    write_config=test_api.APITests.write_config
    get=test_api.APITests.get
    session=test_api.APITests.session
    def test_history_bounded_projection_and_endpoints(self):
        self.db.execute('DELETE FROM usage_windows')
        rows=[(self.now-i*1000,'synthetic','ignored','Window',i%101,None) for i in range(1001)]
        self.db.executemany('INSERT INTO usage_windows VALUES (?,?,?,?,?,?)',rows)
        self.db.executemany('INSERT INTO usage_windows VALUES (?,?,?,?,?,?)',[(self.now-721*3600000,'synthetic',None,'Old',1,None),(self.now+1,'synthetic',None,'Future',2,None)])
        self.db.commit()
        payload=self.get('limits/history')
        self.assertEqual(set(payload),{'data'})
        series=payload['data'];self.assertEqual(len(series),1)
        self.assertEqual(set(series[0]),{'id','points'})
        points=series[0]['points'];self.assertEqual(len(points),200)
        self.assertEqual(points[0]['timestamp'],self.now-1000000)
        self.assertEqual(points[-1]['timestamp'],self.now)
        self.assertTrue(all(set(p)=={'timestamp','usedPercent'} for p in points))
        self.assertEqual(series[0]['id'],api.window_id('synthetic','Window'))
        self.assertEqual(points,sorted(points,key=lambda p:p['timestamp']))

    def test_ranges_clamps_queries(self):
        for value,expected in [('7',7),('14',14),('30',30),('0',7),('-9',7),('8',7),('13',14),('20',14),('99',30),('bad',7),('',7),('9'*5000,30),('-'+'9'*5000,7)]:
            self.assertEqual(self.get('tokens','?days='+value)['data']['days'],expected)
        for value,expected in [('0',1),('-5',1),('721',720),('bad',72),('72',72),('9'*5000,720),('-'+'9'*5000,1)]:
            self.assertEqual(api.clamped_param({'hours':[value]},'hours',72,1,720),expected)
            self.get('limits/history','?hours='+value)
        for suffix in ['?hours=1&hours=2','?other=1']:
            self.assertEqual(api.response(self.root,'/api/limits/history'+suffix,self.now)[0],400)

    def test_history_hours_actual_cutoffs_and_invalid_values(self):
        self.db.execute('DELETE FROM usage_windows')
        for hours in (0,1,2,719,720,721):
            self.db.execute('INSERT INTO usage_windows VALUES (?,?,?,?,?,?)',(self.now-hours*3600000,'synthetic',None,'Window',hours,None))
        self.db.execute('INSERT INTO usage_windows VALUES (?,?,?,?,?,?)',(self.now,'synthetic',None,'Window',None,None))
        self.db.commit()
        for query,expected in [('0',[1,0]),('72',[2,1,0]),('9999',[720,719,2,1,0])]:
            points=self.get('limits/history','?hours='+query)['data'][0]['points']
            self.assertEqual([p['usedPercent'] for p in points],expected)

    def test_history_readonly_no_cli(self):
        path=self.root/'data/monitor.db';before=hashlib.sha256(path.read_bytes()).digest()
        with patch.object(api.sqlite3,'connect',wraps=api.sqlite3.connect),patch('collector.subprocess.run',side_effect=AssertionError('forbidden')):
            self.get('limits/history')
        self.assertEqual(before,hashlib.sha256(path.read_bytes()).digest())

    def test_history_http_security(self):
        server=api.Server(self.root,0);cookie=fixture_cookie(server);server.allowed_hosts=(f'127.0.0.1:{server.server_port}',)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for method in ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','CUSTOM']:
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
                conn.request(method,'/api/limits/history?hours=72',headers={'Cookie':cookie});r=conn.getresponse();r.read()
                self.assertEqual(r.status,200 if method=='GET' else 405)
                self.assertEqual(r.getheader('Cache-Control'),'no-store');self.assertIsNone(r.getheader('Access-Control-Allow-Origin'))
                conn.close()
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
            conn.request('GET','/api/limits/history',headers={'Host':'invalid.example'})
            r=conn.getresponse();r.read();self.assertEqual(r.status,403);conn.close()
        finally:server.shutdown();server.server_close();thread.join()

    def test_log_details_allowlisted_stored_values(self):
        self.session(self.now,42,'done')
        self.db.execute('UPDATE sessions SET model=?,sessionStartedAt=?',('p/m',self.now-5000));self.db.commit()
        row=next(r for r in self.get('log')['data'] if r['type']=='session_finished')
        self.assertEqual((row['model'],row['totalTokens'],row['sessionStartedAt'],row['durationMs']),('p/m',42,self.now-5000,5000))
        self.assertNotIn('sessionId',row)
        self.db.execute('UPDATE sessions SET sessionStartedAt=NULL');self.db.commit()
        row=next(r for r in self.get('log')['data'] if r['type']=='session_finished')
        self.assertIsNone(row['durationMs'])

    def test_history_hash_allowlist(self):
        script=(api.ROOT/'web/app.js').read_text()
        script=script[:script.index("matchMedia('(min-width:1000px)').addEventListener")]
        check=r"""
const assert=require('node:assert/strict');
global.location={pathname:'/',search:'',hash:''};
global.history={replaceState:(_a,_b,url)=>{location.hash=url.includes('#')?url.slice(url.indexOf('#')):'';}};
const limits=[{id:'synthetic-window'}];
for(const hash of ['#range=8&window=unknown','#range=14&range=30&window=synthetic-window&window=other','#range=constructor&window=__proto__']){
 location.hash=hash;readHash([],limits);assert.equal(state.range,7);assert.equal(state.expanded,'');assert.equal(location.hash,'');
}
location.hash='#range=30&window=synthetic-window';readHash([],limits);assert.equal(state.range,30);assert.equal(state.expanded,'synthetic-window');
validateState([],[]);assert.equal(state.expanded,'');
console.log('ok');
"""
        r=subprocess.run(['node','-e',script+check],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,'synthetic hash validation');self.assertEqual(r.stdout.strip(),'ok')
