from auth_fixture import fixture_cookie
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import api
import collector as c
from privacy_fixtures import FORBIDDEN_VALUES


class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.now=1800000000000
        self.cfg=dict(api.DEFAULTS, STORE_TASK_LABELS=True, agents={})
        self.write_config()
        (self.root/'lexicon.json').write_text((api.ROOT/'lexicon.json').read_text())
        self.db=c.connect(self.root/'data/monitor.db')
        self.raw={k:json.loads((api.ROOT/'fixtures'/(k+'.json')).read_text()) for k in c.COMMANDS}
        c.collect(self.db,now=self.now,runner=lambda k,e:(c.project(k,self.raw[k]),None))
        self.db.execute('DELETE FROM agents')
        c.save(self.db,{'agents':[['a','Alpha','p/m']]},self.now)
        self.db.commit()
    def tearDown(self):
        self.db.close();self.tmp.cleanup()
    def write_config(self):
        (self.root/'config.json').write_text(json.dumps(self.cfg))
    def get(self,name,params=''):
        status,data=api.response(self.root,'/api/'+name+params,self.now)
        self.assertEqual(status,200,(name,data))
        return data
    def session(self,at,tokens,status=None):
        c.save(self.db,c.project('sessions',{'sessions':[dict(sessionId='fake',agentId='a',kind='direct',status=status,ageMs=0,updatedAt=at,totalTokens=tokens,label='Synthetic task')]}),at)
        self.db.commit()
    def test_all_endpoints_and_overview(self):
        self.session(self.now,10)
        overview=self.get('overview')
        for name in api.ENDPOINTS:
            with self.subTest(endpoint=name):
                data=self.get(name)
                if name!='overview':self.assertEqual(data['data'],overview[name])
        self.assertEqual(overview['agents'][0]['task']['display'],'Synthetic task')
        self.assertEqual(overview['health']['last_run'],self.now)
    def test_dynamic_agents_overrides_stable_palette_hidden(self):
        first=self.get('agents')['data'][0]['accent_color']
        self.assertIsNone(first)  # Unset overrides must reach the frontend as unset.
        c.save(self.db,{'agents':[['z','Zulu','p/z'],['a','Alpha','p/m']]},self.now+1);self.db.commit()
        agents=self.get('agents')['data']
        self.assertEqual([a['id'] for a in agents],['a','z'])
        self.assertEqual(agents[0]['accent_color'],first)
        self.cfg['agents']={'a':{'display_name':'The Scout','accent_color':'#123abc','rank':'Captain'},'z':{'hidden':True},'not-collected':{'display_name':'Must not appear'}}
        self.write_config();agents=self.get('agents')['data']
        self.assertEqual(len(agents),1)
        self.assertEqual((agents[0]['name'],agents[0]['accent_color'],agents[0]['rank']),('The Scout','#123abc','Captain'))
        self.cfg['agents']['a']['accent_color']='invalid';self.write_config()
        self.assertEqual(self.get('agents')['data'][0]['accent_color'],first)
    def test_limits_missing_windows_thresholds_and_empty_census(self):
        status={'usage':{'providers':[{'provider':'first','windows':[{'label':'A','usedPercent':70},{'label':'B','usedPercent':80},{'label':'C','usedPercent':90}]},{'provider':'second','windows':[]}]}}
        c.save(self.db,c.project('status',status),self.now+1);self.db.commit()
        data=self.get('limits')['data']
        self.assertEqual([w['level'] for w in data[0]['windows']],['warn','alarm','critical'])
        self.assertEqual(data[1]['status'],'not_reported')
        self.assertEqual(data[1]['windows'],[])
        c.save(self.db,c.project('status',{'usage':{'providers':[]}}),self.now+2);self.db.commit()
        self.assertEqual(self.get('limits')['data'],[])
    def test_credit_alerts_and_config_validation(self):
        self.db.execute('DELETE FROM credits');c.save(self.db,{'credits':[[5,'USD']]},self.now);self.db.commit()
        self.assertTrue(self.get('credits')['data']['balances'][0]['alert'])
        self.cfg['credit_alert_level']=4;self.write_config()
        self.assertFalse(self.get('credits')['data']['balances'][0]['alert'])
        for key,value in [('port',0),('thresholds',{'warn':90,'alarm':80,'critical':70}),('stale_after_seconds',-1),('credit_alert_level','x')]:
            orig=self.cfg[key];self.cfg[key]=value;self.write_config()
            self.assertEqual(api.response(self.root,'/api/overview',self.now)[0],503)
            self.cfg[key]=orig
    def test_health_staleness_and_no_samples(self):
        self.assertFalse(self.get('health')['data']['stale'])
        self.assertTrue(api.response(self.root,'/api/health',self.now+180001)[1]['data']['stale'])
        self.db.execute('DELETE FROM collection_runs');self.db.commit()
        self.assertTrue(self.get('health')['data']['stale'])
        self.assertIsNone(self.get('health')['data']['last_run'])
    def test_tokens_latest_session_totals_days_and_hidden(self):
        for offset,tokens in [(-8*86400000,10),(-6*86400000,30),(-5*86400000,40),(-4*86400000,5),(-3*86400000,8)]:
            self.session(self.now+offset,tokens,'running')
        result=self.get('tokens')['data']
        self.assertEqual(result['total'],8)
        self.assertEqual(result['by_agent'],[{'id':'a','tokens':8}])
        self.assertEqual(self.get('tokens','?days=1')['data']['total'],8)
        self.cfg['agents']['a']={'hidden':True};self.write_config()
        self.assertEqual(self.get('tokens')['data']['total'],0)
    def test_log_limit_and_terminal_events(self):
        self.session(self.now,30,'done')
        self.db.execute('INSERT INTO errors VALUES (?,?,?,?)',(self.now+1,'status','timeout',None));self.db.commit()
        data=self.get('log','?limit=1')['data']
        self.assertEqual(len(data),1);self.assertEqual(data[0]['type'],'collector_error')
        self.assertTrue(any(r['type']=='session_finished' for r in self.get('log')['data']))
    def test_retheme_and_disable_task_labels(self):
        lex=json.loads((self.root/'lexicon.json').read_text());lex['status']['working']='On mission';lex['sections']['agents']='Crew';lex['moods']['calm']='Serene'
        (self.root/'lexicon.json').write_text(json.dumps(lex))
        self.session(self.now,20)
        self.assertEqual(self.get('overview')['lexicon']['sections']['agents'],'Crew')
        self.cfg['STORE_TASK_LABELS']=False;self.write_config()
        self.assertIsNone(self.get('agents')['data'][0]['task']['label'])
        self.assertEqual(self.get('agents')['data'][0]['task']['display'],'Direct session')
    def test_query_errors_and_unavailable_have_no_raw_data(self):
        for url in ['/api/tokens?days=7&days=8','/api/log?limit=101','/api/log?limit=-1','/api/log?limit=','/api/agents?secret=/private/file']:
            status,data=api.response(self.root,url,self.now)
            self.assertEqual(status,400);self.assertEqual(data,{'error':'invalid_query'})
        self.assertEqual(api.response(self.root,'/private/file')[0],404)
        (self.root/'config.json').write_text('/private/file')
        self.assertEqual(api.response(self.root,'/api/agents'),(503,{'error':'unavailable'}))
    def test_readonly_and_no_external_calls(self):
        self.session(self.now,20)
        self.db.commit();path=self.root/'data/monitor.db';before=hashlib.sha256(path.read_bytes()).digest()
        with patch.object(c.subprocess,'run',side_effect=AssertionError('CLI forbidden')):
            for endpoint in (*api.ENDPOINTS,'limits/history','alerts'):self.get(endpoint)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),before)
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True) as db:
            with self.assertRaises(sqlite3.OperationalError):db.execute('DELETE FROM agents')
        path.unlink()
        self.assertEqual(api.response(self.root,'/api/agents')[0],503)
        self.assertFalse(path.exists())
    def test_every_endpoint_shared_forbidden_values(self):
        # Deliberately bypass the collector scrubber to test the API boundary.
        self.session(self.now,20,'done')
        for forbidden in FORBIDDEN_VALUES:
            for table in ('agents','usage_windows','usage_providers','credits','gateway_health','sessions','session_history','errors','alerts'):
                columns=[r[1] for r in self.db.execute('PRAGMA table_info('+table+')') if r[2]=='TEXT' and r[1] not in ('sessionId','agentId','id','status','provider')]
                if table=='alerts': columns=['message']  # Rule/state/severity are constrained enums; subjects have a unique key.
                for column in columns:self.db.execute('UPDATE '+table+' SET '+column+'=?',(forbidden,))
            self.db.commit()
            self.cfg['agents']={'a':{'display_name':forbidden,'rank':forbidden,'accent_color':forbidden}};self.write_config()
            lex=json.loads((api.ROOT/'lexicon.json').read_text())
            for group in lex:
                for k in lex[group]:lex[group][k]=forbidden
            (self.root/'lexicon.json').write_text(json.dumps(lex))
            for endpoint in (*api.ENDPOINTS,'limits/history','alerts'):
                with self.subTest(endpoint=endpoint,pattern=FORBIDDEN_VALUES.index(forbidden)):
                    body=json.dumps(self.get(endpoint))
                    for value in FORBIDDEN_VALUES:self.assertNotIn(value,body)
    def test_http_get_only_host_headers_and_errors(self):
        server=api.Server(self.root,0);cookie=fixture_cookie(server);server.allowed_hosts=(f'127.0.0.1:{server.server_port}',f'localhost:{server.server_port}');thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for method in ('GET','HEAD','POST','PUT','DELETE','PATCH','OPTIONS','TRACE','CONNECT','CUSTOM'):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                conn.request(method,'/api/health',headers={'Cookie':cookie});r=conn.getresponse();body=r.read()
                self.assertEqual(r.status,200 if method=='GET' else 405,method)
                self.assertEqual(r.getheader('Content-Type'),'application/json; charset=utf-8')
                self.assertEqual(r.getheader('Cache-Control'),'no-store')
                if method!='GET':self.assertEqual(r.getheader('Allow'),'GET')
                self.assertIsNone(r.getheader('Access-Control-Allow-Origin'));conn.close()
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            conn.request('GET','/api/health',headers={'Host':'untrusted.invalid'});r=conn.getresponse();r.read();self.assertEqual(r.status,403);conn.close()
            self.assertEqual(server.server_address[0],'127.0.0.1')
        finally:server.shutdown();server.server_close();thread.join()
    def test_model_credentials_and_configured_port(self):
        import socket
        for value in ['ghp_syntheticcredential','github_pat_syntheticcredential','xoxb-syntheticcredential','AKIAsyntheticcredential','provider/sk-syntheticcredential']:
            self.db.execute('UPDATE agents SET model=?',(value,));self.db.commit()
            self.assertIsNone(self.get('agents')['data'][0]['model'])
        for value in ['p/m','openai/gpt-6.1-sol']:
            self.assertEqual(api.model(value),value)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        self.cfg['port']=port;self.write_config()
        server=api.Server(self.root)
        try:self.assertEqual(server.server_address,('127.0.0.1',port))
        finally:server.server_close()

    def test_service_is_loopback_readonly_restartable(self):
        unit=(api.ROOT/'agent-monitor-api.service').read_text()
        for setting in ('Restart=on-failure','NoNewPrivileges=true','ProtectSystem=strict','ProtectHome=read-only','ReadOnlyPaths=/home/youruser/agent-monitor'):
            self.assertIn(setting,unit)


if __name__=='__main__':unittest.main()
