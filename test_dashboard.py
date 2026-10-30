from auth_fixture import fixture_cookie
import http.client
import json
import re
import subprocess
import threading
import test_api
import api
import collector as c
from privacy_fixtures import FORBIDDEN_VALUES


class DashboardTests(test_api.APITests):
    def adapter(self, raw):
        script=(api.ROOT/'web/app.js').read_text()
        script=script[:script.index("matchMedia('(min-width:1000px)').addEventListener")]
        result=subprocess.run(['node','-e',script+'\nconsole.log(JSON.stringify(adapt('+json.dumps(raw)+')));'],capture_output=True,text=True,check=True)
        return json.loads(result.stdout)

    def test_malformed_lexicon_groups_fall_back(self):
        for bad in (None,[],42,'wrong'):
            (self.root/'lexicon.json').write_text(json.dumps({'status':bad,'moods':bad,'sections':bad,'dashboard':bad}))
            data=self.get('overview')
            self.assertEqual(data['lexicon']['status']['working'],'working')
            self.assertEqual(data['lexicon']['dashboard']['title'],'AGENT MONITOR')
            self.assertEqual(data['lexicon']['sections']['agents'],'Agents')

    def test_fake_agent_window_and_daily_tokens_in_page_data(self):
        c.save(self.db,{'agents':[['new-agent','Synthetic Scout','p/new']]},self.now+1)
        c.save(self.db,c.project('status',{'usage':{'providers':[{'provider':'synthetic-provider','windows':[{'label':'Fortnight reserve','usedPercent':37}]}]}}),self.now+1)
        self.db.commit()
        data=self.adapter(self.get('overview'))
        self.assertEqual(data['agents'][0]['id'],'new-agent')
        self.assertEqual(data['limits'][0]['label'],'Fortnight reserve')
        self.assertEqual(data['limits'][0]['provider'],'synthetic-provider')
        self.assertFalse(data['stale'])
        raw=self.get('overview');raw['health']['stale']=True
        self.assertTrue(self.adapter(raw)['stale'])

    def test_page_requested_responses_privacy(self):
        self.test_every_endpoint_shared_forbidden_values()
        # Static content is also a page-requestable response, never project files.
        html=(api.ROOT/'web/index.html').read_text()+(api.ROOT/'web/app.js').read_text()
        self.assertIn('const USE_SAMPLE = false;',html)
        self.assertNotIn('innerHTML',html.replace('never innerHTML',''))
        self.assertIn('textContent',html)
        for value in FORBIDDEN_VALUES:self.assertNotIn(value,html)
        self.assertEqual(re.findall(r"const API_URL = '([^']+)'",html),['/api/overview'])
        self.assertNotIn('const SAMPLE =',html)
        data=self.adapter(self.get('overview'))
        for value in FORBIDDEN_VALUES:self.assertNotIn(value,json.dumps(data))

    def test_static_root_get_only_and_containment(self):
        web=self.root/'web';web.mkdir();(web/'index.html').write_text((api.ROOT/'web/index.html').read_text())
        (web/'outside.html').symlink_to(self.root/'config.json')
        (web/'folder').mkdir()
        server=api.Server(self.root,0);cookie=fixture_cookie(server);server.allowed_hosts=(f'127.0.0.1:{server.server_port}',f'localhost:{server.server_port}');thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for path,status in [('/',200),('/index.html',200),('/api.py',404),('/config.json',404),('/lexicon.json',404),('/folder/',404),('/outside.html',404),('/../config.json',404),('/%2e%2e/config.json',404),('/design/reference.html',404)]:
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
                conn.request('GET',path,headers={'Cookie':cookie});r=conn.getresponse();body=r.read().decode()
                self.assertEqual(r.status,status,path)
                for value in FORBIDDEN_VALUES:self.assertNotIn(value,body)
                conn.close()
            for method in ('HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','CUSTOM'):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port);conn.request(method,'/');r=conn.getresponse();r.read()
                self.assertEqual(r.status,405);conn.close()
        finally:server.shutdown();server.server_close();thread.join()

    def test_daily_breakdown_and_utc_activity_counts(self):
        self.session(self.now-1000,10,'running')
        self.session(self.now,30,'failed')
        raw=self.get('overview')
        data=self.adapter(raw)
        self.assertEqual(sum(sum(d['tokens'].values()) for d in data['days']),30)
        self.assertEqual(data['agents'][0]['sessionsToday'],1)
        self.assertEqual(data['agents'][0]['failedToday'],1)
        self.assertEqual(data['thresholds'],{'warn':70,'alarm':80,'crit':90})
        lex=json.loads((self.root/'lexicon.json').read_text());lex['dashboard']['title']='Synthetic title'
        (self.root/'lexicon.json').write_text(json.dumps(lex))
        self.assertEqual(self.adapter(self.get('overview'))['lexicon']['title'],'Synthetic title')

    def test_host_utilization_fraction_to_whole_percent(self):
        for ratio, expected in ((0.918,92),(0.953,95),(0,0),(1,100),(0.004,0),(None,None),(-1,None),(92,None),('0.918',None)):
            raw=self.get('overview')
            raw['gateway']={'hostUtilization':ratio}
            self.assertEqual(self.adapter(raw)['gateway']['hostLoadPct'],expected)

    def test_palette_order_override_and_invalid_accent(self):
        raw=self.get('overview'); template=raw['agents'][0]
        raw['agents']=[dict(template,id='synthetic-'+str(i),accent_color=None) for i in range(7)]
        expected=['#c9a24b','#e9dfc9','#e8863a','#8fb0ba','#b5654a','#9bbf8a','#c98fb0']
        self.assertEqual([a['accent'] for a in self.adapter(raw)['agents']],expected)
        raw['agents'][1]['accent_color']='#123abc'
        raw['agents'][2]['accent_color']='red;background:url(https://invalid.example)'
        expected[1]='#123abc'
        self.assertEqual([a['accent'] for a in self.adapter(raw)['agents']],expected)

    def test_tokens_backfill_activity_dates_once_and_utc_boundaries(self):
        self.db.execute('DELETE FROM sessions')
        self.db.execute('DELETE FROM session_history')
        start=self.now-self.now%86400000
        rows=[dict(sessionId='old',agentId='a',updatedAt=start-2*86400000,totalTokens=100),
              dict(sessionId='today',agentId='a',updatedAt=start,totalTokens=40),
              dict(sessionId='outside',agentId='a',updatedAt=start-7*86400000,totalTokens=900),
              dict(sessionId='future',agentId='a',updatedAt=self.now+1,totalTokens=900),
              dict(sessionId='missing',agentId='a',totalTokens=900),
              dict(sessionId='interaction',agentId='a',lastInteractionAt=start-86400000,totalTokens=20),
              dict(sessionId='age',agentId='a',ageMs=self.now-(start-3*86400000),totalTokens=10)]
        for at in (self.now-1,self.now):
            c.save(self.db,c.project('sessions',{'sessions':rows}),at)
        self.db.commit()
        result=self.get('tokens')['data']
        self.assertEqual(result['total'],170)
        self.assertEqual([d['tokens'] for d in result['daily']],[10,100,20,40])
        self.assertEqual(sum(sum(d['by_agent'].values()) for d in result['daily']),170)
        self.assertEqual(self.get('tokens','?days=1')['data']['total'],170)
        self.cfg['agents']['a']={'hidden':True};self.write_config()
        self.assertEqual(self.get('tokens')['data']['total'],0)

    def test_readable_kind_fallbacks_and_label_precedence(self):
        for kind,expected in [('direct','Direct session'),('spawn','Spawn-child session'),
                              ('spawn-child','Spawn-child session'),('subagent','Spawn-child session'),
                              ('cron','Scheduled job'),('unknown','Session')]:
            self.session(self.now,30,'done')
            self.db.execute('UPDATE sessions SET kind=?,task_label=NULL',(kind,))
            self.db.execute('UPDATE session_history SET kind=?,task_label=NULL',(kind,))
            self.db.commit()
            raw=self.get('overview')
            self.assertEqual(raw['agents'][0]['task']['display'],expected)
            self.assertEqual(self.adapter(raw)['log'][0]['what'],expected)
            raw['log'][0]['label']='Synthetic title'
            self.assertEqual(self.adapter(raw)['log'][0]['what'],'Synthetic title')


    def test_v2_client_only_layout_and_endpoint_contract(self):
        html=(api.ROOT/'web/index.html').read_text()+(api.ROOT/'web/app.js').read_text()
        self.assertIn('width:min(96vw, 2200px)',html)
        for boundary in (1000,1500,1800):self.assertIn('@media(min-width:'+str(boundary)+'px)',html)
        self.assertIn('repeat(auto-fit,minmax(380px,1fr))',html)
        self.assertIn("['Time','Agent','Task','Kind','Result']",html)
        # Execute the real request expressions; nested JS commas are not delimiters.
        self.assertEqual(len(re.findall(r"\bfetch\s*\(", (api.ROOT/'web/app.js').read_text())), 4)
        script=(api.ROOT/'web/app.js').read_text()
        script=script[:script.index("matchMedia('(min-width:1000px)').addEventListener")]
        check=r"""
const assert=require('node:assert/strict');
const calls=[];
global.fetch=async(url,options)=>{
  calls.push([url,options?.method||'GET',options?.cache]);
  return {ok:true,json:async()=>({agents:[],data:[]})};
};
// Isolate transport from DOM, timers and bookmarks, not from load/showMore.
adapt=raw=>raw;render=()=>{};schedulePoll=()=>{};
readHash=()=>{};writeHash=()=>{};renderError=error=>{throw error;};
(async()=>{
  assert.equal(LOG_MAX,100);assert.equal(LOG_STEP,20);
  state.search='Synthetic search &url=https://invalid.example';
  let hasTestSnapshot=false;
  for(const [limit,expected] of [[-1,null],[1,null],[20,null],[21,21],
      [40,40],[60,60],[80,80],[100,100],[101,100],[1000000,100]]){
    state.limit=limit;calls.length=0;await load();
    const expectedCalls=[['/api/overview','GET','no-store']];
    if(expected!==null)expectedCalls.push(['/api/log?limit='+expected,'GET','no-store']);
    if(!hasTestSnapshot)expectedCalls.push(['/api/alerts?state=all&limit=200','GET','no-store']);
    hasTestSnapshot=true;
    assert.deepEqual(calls,expectedCalls);
    assert.equal(loading,false);
  }
  calls.length=0;state.limit=20;
  for(let i=0;i<7;i++)await showMore();
  assert.deepEqual(calls,[40,60,80,100].flatMap(limit=>[
    ['/api/overview','GET','no-store'],['/api/log?limit='+limit,'GET','no-store']]));
  assert.equal(state.limit,100);
  console.log('ok');
})().catch(()=>{console.error('synthetic request contract failed');process.exitCode=1;});
"""
        result=subprocess.run(['node','-e',script+check],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,'synthetic request contract failed')
        self.assertEqual(result.stdout.strip(),'ok')
        self.assertNotRegex(html,r"\bon(?:click|keydown|load|error)\s*=")
        self.assertNotIn('setInterval(',html)

    def test_v2_hash_validates_api_roster_enum_duplicates_and_search(self):
        script=(api.ROOT/'web/app.js').read_text()
        script=script[:script.index("matchMedia('(min-width:1000px)').addEventListener")]
        check=r"""
const assert=require('node:assert/strict');
global.location={pathname:'/',search:'',hash:''};
global.history={replaceState:(_a,_b,url)=>{location.hash=url.includes('#')?url.slice(url.indexOf('#')):'';}};
const roster=[{id:'synthetic-new'}];
for(const hash of ['#agent=other&status=evil','#agent=__proto__&status=constructor','#agent=%3Cscript%3E&status=FAILED&q=%00','#agent=synthetic-new&agent=other&status=failed&status=done','#q=%3Cimg%3E','#q='+('x'.repeat(201))]){
 location.hash=hash;readHash(roster);assert.equal(state.agent,'');assert.equal(state.status,'all');assert.equal(state.search,'');assert.equal(location.hash,'');
}
location.hash='#agent=synthetic-new&status=failed&q=Synthetic+title&extra=ignore';readHash(roster);
assert.equal(state.agent,'synthetic-new');assert.equal(state.status,'failed');assert.equal(state.search,'Synthetic title');assert.ok(!location.hash.includes('extra'));
validateState([]);assert.equal(state.agent,'');
console.log('ok');
"""
        result=subprocess.run(['node','-e',script+check],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,'synthetic hash assertions failed')
        self.assertEqual(result.stdout.strip(),'ok')

    def test_v2_log_retains_agent_ids_and_kinds(self):
        raw=self.get('overview')
        raw['log']=[dict(timestamp=self.now,agent='a',status='failed',kind='direct',label='Synthetic title')]
        row=self.adapter(raw)['log'][0]
        self.assertEqual((row['agentId'],row['kind'],row['what'],row['status']),('a','direct','Synthetic title','failed'))
