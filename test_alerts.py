import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import alerts as a
import api
import collector as c
from privacy_fixtures import FORBIDDEN_VALUES


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.db=c.connect(self.root/'data/monitor.db');self.now=1800000000000
        self.cfg=json.loads(json.dumps(a.DEFAULTS))
        (self.root/'config.json').write_text(json.dumps(api.DEFAULTS))
        shutil.copy(api.ROOT/'lexicon.json',self.root/'lexicon.json')
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def tick(self,**status):
        self.now+=60000
        c.save(self.db,c.project('status',status),self.now)
        a.evaluate(self.db,self.now,self.cfg);self.db.commit()
    def window(self,percent,reset=None,provider='novel-provider',label='Novel window'):
        self.tick(usage={'providers':[{'provider':provider,'windows':[{'label':label,'usedPercent':percent,'resetAt':reset}]}]})
    def current(self,rule):
        cur=self.db.execute("SELECT * FROM alerts WHERE rule=? AND state='active'",(rule,))
        return [dict(zip([d[0] for d in cur.description],r)) for r in cur]
    def test_threshold_crossing_escalation_same_alert(self):
        self.window(69);self.assertFalse(self.current('limit_window'))
        self.window(70);row=self.current('limit_window')[0];self.assertEqual(row['severity'],'warn')
        for value,level in [(80,'alarm'),(90,'critical')]:
            self.window(value);new=self.current('limit_window')[0]
            self.assertEqual((new['id'],new['first_seen'],new['severity']),(row['id'],row['first_seen'],level))
    def test_hysteresis_and_recovery(self):
        for level,start,boundary in [('warn',70,65),('alarm',80,75),('critical',90,85)]:
            self.db.execute('DELETE FROM alerts');self.window(start)
            row=self.current('limit_window')[0];self.window(boundary+.1)
            self.assertEqual(self.current('limit_window')[0]['id'],row['id'])
            self.window(boundary)
            resolved=self.db.execute('SELECT state FROM alerts WHERE id=?',(row['id'],)).fetchone()[0]
            self.assertEqual(resolved,'resolved')
    def test_changed_and_elapsed_window_reset(self):
        reset=self.now+3600000;self.window(90,reset);old=self.current('limit_window')[0]['id']
        self.window(10,reset+3600000);self.assertFalse(self.current('limit_window'))
        self.assertEqual(self.db.execute('SELECT state FROM alerts WHERE id=?',(old,)).fetchone()[0],'resolved')
        self.window(90,self.now+120000);self.now+=180000
        a.evaluate(self.db,self.now,self.cfg);self.assertFalse(self.current('limit_window'))
    def test_custom_thresholds_and_dynamic_providers(self):
        self.cfg['thresholds']={'warn':30,'alarm':40,'critical':50}
        self.tick(usage={'providers':[{'provider':p,'windows':[{'label':w,'usedPercent':45} for w in ('Short','Long')]} for p in ('dynamic-one','dynamic-two')]})
        self.assertEqual(len(self.current('limit_window')),4)
        self.assertTrue(all(r['severity']=='alarm' for r in self.current('limit_window')))
    def test_credits_boundaries_disabled_and_recovery(self):
        for amount,level in [(101,None),(100,'warn'),(25,'critical'),(26,'warn'),(101,None),(10,'critical'),(None,None)]:
            billing=[] if amount is None else [{'type':'balance','amount':amount}]
            self.tick(usage={'providers':[{'provider':'new','billing':billing}]})
            rows=self.current('credits');self.assertEqual(rows[0]['severity'] if rows else None,level)
    def test_credit_config_tuning(self):
        self.cfg.update(credits_warn=10,credits_critical=2)
        self.tick(usage={'providers':[{'provider':'new','billing':[{'type':'balance','amount':9}]}]})
        self.assertEqual(self.current('credits')[0]['severity'],'warn')
    def fail(self,sid,aid='dynamic-agent'):
        c.save(self.db,c.project('sessions',{'sessions':[{'sessionId':sid,'agentId':aid,'status':'failed'}]}),self.now)
        a.evaluate(self.db,self.now,self.cfg)
    def test_failure_cooldown_aggregation_and_expiry(self):
        self.fail('synthetic-one');first=self.current('failed_sessions')[0]
        self.now+=60000;self.fail('synthetic-two')
        self.assertEqual(self.current('failed_sessions')[0]['message'],first['message'])
        self.now=first['first_seen']+1800000;a.evaluate(self.db,self.now,self.cfg)
        row=self.current('failed_sessions')[0];self.assertEqual(row['id'],first['id']);self.assertIn('2',row['message'])
        self.fail('synthetic-two');self.assertEqual(a.state(self.db,'failure:dynamic-agent')['count'],2)
        self.now=first['first_seen']+3660000;a.evaluate(self.db,self.now,self.cfg)
        self.assertFalse(self.current('failed_sessions'))
        self.now+=1;self.fail('synthetic-three');self.assertIn('1',self.current('failed_sessions')[0]['message'])
    def test_failures_separate_agents(self):
        self.fail('one','a');self.fail('two','b');self.assertEqual(len(self.current('failed_sessions')),2)
    def test_gateway_two_consecutive_and_recovery(self):
        self.tick(gateway={'reachable':False});self.assertFalse(self.current('gateway_unreachable'))
        self.tick(gateway={'reachable':True});self.tick(gateway={'reachable':False})
        self.assertFalse(self.current('gateway_unreachable'))
        self.tick(gateway={'reachable':False});self.assertEqual(self.current('gateway_unreachable')[0]['severity'],'critical')
        self.tick(gateway={'reachable':True});self.assertFalse(self.current('gateway_unreachable'))
    def test_gateway_pressure_each_metric_five_polls(self):
        for metric in ('latency','host','memory'):
            a.put(self.db,'gateway',{'down':0,'pressure':0})
            self.db.execute("DELETE FROM alerts WHERE rule='gateway_pressure'")
            for i in range(5):
                with patch.object(a.os,'sysconf',side_effect=lambda k:100 if k=='SC_PHYS_PAGES' else 1):
                    self.tick(gateway={'reachable':True,'connectLatencyMs':1001 if metric=='latency' else 1000},
                              processMemory={'rssBytes':91 if metric=='memory' else 90},
                              eventLoop={'cpuBreakdown':{'hostUtilization':.901 if metric=='host' else .9}})
                self.assertEqual(bool(self.current('gateway_pressure')),i==4)
            self.tick(gateway={'reachable':True,'connectLatencyMs':1000},eventLoop={'cpuBreakdown':{'hostUtilization':.9}})
            self.assertFalse(self.current('gateway_pressure'))
    def test_failed_poll_breaks_gateway_streak(self):
        self.tick(gateway={'reachable':False});self.now+=60000;a.evaluate(self.db,self.now,self.cfg)
        self.tick(gateway={'reachable':False});self.assertFalse(self.current('gateway_unreachable'))
    def test_new_agent_first_install_later_and_24h(self):
        # Simulate populated pre-feature schema, then reinstall additive schema.
        c.save(self.db,{'agents':[['existing','Existing','p/m']]},self.now)
        self.db.execute("DELETE FROM alert_state WHERE key='installed'");self.db.execute('DELETE FROM alert_agents')
        a.initialize(self.db);a.evaluate(self.db,self.now,self.cfg);self.assertFalse(self.current('new_agent'))
        self.now+=1;c.save(self.db,{'agents':[['existing','Existing','p/m'],['later','<b>Later</b>','p/m']]},self.now)
        a.evaluate(self.db,self.now,self.cfg);row=self.current('new_agent')[0]
        self.assertEqual(row['subject_key'],'later');self.assertEqual(row['message'],'New agent: Later')
        self.now+=a.DAY;a.evaluate(self.db,self.now,self.cfg);self.assertFalse(self.current('new_agent'))
        a.evaluate(self.db,self.now+1,self.cfg);self.assertFalse(self.current('new_agent'))
    def test_message_sanitization_and_length(self):
        self.assertEqual(a.safe('<b>Later</b>'),'Later')
        self.assertEqual(a.safe('private&#64;example.invalid'),'Subject')
        self.assertEqual(a.safe('&#47;private&#47;file'),'Subject')
        for bad in FORBIDDEN_VALUES:
            self.assertNotIn(bad,a.safe(bad))
        self.now+=1;c.save(self.db,{'agents':[['markup','<img onerror=oops>Safe</img>','p/m']]},self.now)
        a.evaluate(self.db,self.now,self.cfg)
        self.assertEqual(self.current('new_agent')[0]['message'],'New agent: Safe')
        self.window(90,label='X'*150)
        self.assertTrue(all(len(r[0])<=80 for r in self.db.execute('SELECT message FROM alerts')))
    def get(self,url='/api/alerts'):
        self.db.commit();status,body=api.response(self.root,url,self.now)
        self.assertEqual(status,200,body);return body
    def test_collector_stale_boundaries_and_successful_run(self):
        start=self.now
        self.db.execute('INSERT INTO collection_runs VALUES (?,?,?)',(start,4,0))
        for delta,level in [(300000,None),(300001,'warn'),(900000,'warn'),(900001,'critical')]:
            self.now=start+delta
            stale=[r for r in self.get()['data'] if r['rule']=='collector_stale']
            self.assertEqual(stale[0]['severity'] if stale else None,level)
        self.db.execute('INSERT INTO collection_runs VALUES (?,?,?)',(self.now,3,1))
        self.assertEqual(self.get()['data'][0]['severity'],'critical')
        self.db.execute('DELETE FROM collection_runs');self.assertEqual(self.get()['data'][0]['severity'],'critical')
    def test_api_limits_state_summary_and_readonly(self):
        self.window(90);self.window(0)
        self.db.execute('INSERT INTO collection_runs VALUES (?,?,?)',(self.now,4,0));self.db.commit()
        self.assertEqual(self.get()['data'],[])
        self.assertEqual(len(self.get('/api/alerts?state=all')['data']),1)
        summary=self.get('/api/overview')['alerts'];self.assertEqual(summary,{'active':0,'highest':None})
        for i in range(205):a.emit(self.db,'new_agent','agent-'+str(i),'info','New agent: Agent',self.now)
        self.db.commit();before=hashlib.sha256((self.root/'data/monitor.db').read_bytes()).digest()
        for value,count in [('0',1),('-1',1),('201',200),('9'*5000,200),('bad',50)]:
            self.assertEqual(len(self.get('/api/alerts?limit='+value)['data']),count)
        self.assertEqual(self.get('/api/overview')['alerts'],{'active':205,'highest':'info'})
        self.assertEqual(before,hashlib.sha256((self.root/'data/monitor.db').read_bytes()).digest())
        for query in ('state=no','state=active&state=all','limit=1&limit=2','unknown=1'):
            self.assertEqual(api.response(self.root,'/api/alerts?'+query,self.now)[0],400)
    def test_contaminated_alert_api_privacy(self):
        self.window(90)
        for bad in FORBIDDEN_VALUES:
            self.db.execute('UPDATE alerts SET message=?',(bad,))
            self.db.execute('UPDATE usage_windows SET windowLabel=?',(bad,))
            for url in ('/api/alerts','/api/alerts?state=all','/api/overview'):
                body=json.dumps(self.get(url))
                for forbidden in FORBIDDEN_VALUES:self.assertNotIn(forbidden,body)
    def test_evaluation_error_rollback_collection_continues(self):
        def broken(db,now,cfg):
            a.emit(db,'new_agent','partial','info','New agent: Synthetic',now)
            raise RuntimeError('private detail')
        with patch.object(a,'evaluate',side_effect=broken):
            c.collect(self.db,now=self.now,runner=lambda k,e:({},None))
        self.assertFalse(self.current('new_agent'))
        self.assertEqual(self.db.execute("SELECT command,category FROM errors").fetchall(),[('alerts','evaluation_error')])
        self.assertEqual(self.db.execute('SELECT successfulCommands FROM collection_runs').fetchone()[0],4)
    def test_retention_and_disabled_stuck_rule(self):
        a.emit(self.db,'new_agent','old','info','New agent: Synthetic',self.now-91*a.DAY)
        a.evaluate(self.db,self.now,self.cfg)
        self.assertFalse(self.current('new_agent'));self.assertIsNone(self.cfg['agent_stale_minutes'])
    @unittest.skip("needs a private database backup")
    def test_additive_idempotent_migration_on_populated_copy(self):
        backup=sorted(c.ROOT.glob('data/monitor.db.bak-*'))[-1]
        dest=self.root/'populated.db';shutil.copy2(backup,dest)
        db=sqlite3.connect(dest)
        schemas=db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
        hashes={name:hashlib.sha256(repr(db.execute('SELECT * FROM '+name).fetchall()).encode()).hexdigest() for name,_ in schemas}
        db.close()
        for _ in range(2):
            db=c.connect(dest);db.commit()
            for name,sql in schemas:
                self.assertEqual(db.execute('SELECT sql FROM sqlite_master WHERE name=?',(name,)).fetchone()[0],sql)
                self.assertEqual(hashlib.sha256(repr(db.execute('SELECT * FROM '+name).fetchall()).encode()).hexdigest(),hashes[name])
            self.assertFalse(db.execute('SELECT 1 FROM alerts').fetchone())
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok');db.close()


if __name__=='__main__':unittest.main()
