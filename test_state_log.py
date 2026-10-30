import ast
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import collector as c
import state_log
from privacy_fixtures import FORBIDDEN_VALUES

class StateLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'test.db'
        self.db=c.connect(self.path)
        self.now=1800000000000
        self.sessions=[]
        self.agents=[{'id':'a'},{'id':'b'}]
        self.status={}
        self.more=False
    def tearDown(self):
        self.db.close();self.tmp.cleanup()
    def runner(self,k,e):
        raw={'sessions':{'sessions':self.sessions,'hasMore':self.more},'agents':self.agents,'status':self.status,'cron':{'jobs':[]}}[k]
        rows=c.project(k,raw)
        if k=='sessions':rows['_cli_duration_ms']=37
        return rows,None
    def poll(self,at=None):c.collect(self.db,now=self.now if at is None else at,runner=self.runner)
    def logs(self):
        cur=self.db.execute('SELECT * FROM agent_state_log ORDER BY timestamp,agentId')
        return [dict(zip([d[0] for d in cur.description],row)) for row in cur]
    @unittest.skip("needs private git history")
    def test_schema_idempotent_and_classifier_unchanged(self):
        old=subprocess.check_output(['git','show','monitor-dashboard-v2.2:collector.py'],text=True)
        new=(c.ROOT/'collector.py').read_text()
        def functions(s):return {n.name:ast.get_source_segment(s,n) for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)}
        for name in ['session_states','agent_states','agent_tasks']:
            self.assertEqual(functions(old)[name],functions(new)[name])
        self.poll();before=self.logs()
        other=c.connect(self.path);other.close()
        self.assertEqual(self.logs(),before)
        self.assertEqual(len(self.logs()),2)
        self.assertNotIn('task_label',[r[1] for r in self.db.execute('PRAGMA table_info(agent_state_log)')])
    def test_all_states_rules_counts_and_newest(self):
        self.status={'shutdownBudget':{'activeWork':{'rootRequests':4}}}
        self.sessions=[dict(sessionId='s',agentId='a',kind='direct',ageMs=0,updatedAt=self.now,totalTokens=1),dict(sessionId='cron',agentId='a',kind='cron',ageMs=0),dict(sessionId='done',agentId='a',status='done',ageMs=1,updatedAt=self.now-1),dict(sessionId='failed',agentId='a',status='failed',ageMs=2),dict(sessionId='other',agentId='a',status='running',ageMs=3)]
        self.poll();a,b=self.logs()
        self.assertEqual((a['state'],a['rule']),('working','null-status-fresh'))
        self.assertEqual([a[k] for k in ['sessionCount','nullCount','doneCount','failedCount','otherCount','nullNonCronCount']],[5,2,1,1,1,1])
        self.assertEqual([a[k] for k in ['newestKind','newestStatus','newestUpdatedAt','newestAgeMs','newestTotalTokens']],['direct',None,self.now,0,1])
        self.assertEqual([a[k] for k in ['pollSessionCount','responseComplete','cliDurationMs','rootRequests']],[5,1,37,4])
        self.assertEqual((b['state'],b['rule'],b['sessionCount']),('idle','none',0))
        self.sessions[0]['totalTokens']=2;self.poll(self.now+1)
        self.assertEqual(self.logs()[-2]['rule'],'token advance')
        self.sessions=[dict(sessionId='done',agentId='a',status='done',ageMs=0,updatedAt=self.now+2)]
        self.poll(self.now+2);self.assertEqual((self.logs()[-2]['state'],self.logs()[-2]['rule']),('recent','recent-finished'))
        self.sessions=[];self.poll(self.now+3);self.assertEqual(self.logs()[-2]['rule'],'none')
    def test_activity_fixtures_log_exact_existing_state(self):
        for case in json.loads((c.ROOT/'fixtures/activity.json').read_text()):
            with self.subTest(case=case['name']):
                for table in ['session_history','session_polls','sessions','agent_state_log']:
                    self.db.execute('DELETE FROM '+table)
                if case['previous']:
                    self.sessions=[case['previous']];self.poll(self.now-60000)
                self.sessions=[case['current']];self.poll()
                self.assertEqual(self.logs()[-2]['state'],case['expected'])
                self.assertEqual(self.logs()[-2]['state'],c.agent_states(self.db,self.now)['a'])
    def test_retention_14_days_and_failed_poll_no_rows(self):
        self.poll(self.now-14*86400000-1);self.poll(self.now-14*86400000)
        self.poll()
        self.assertEqual(min(r['timestamp'] for r in self.logs()),self.now-14*86400000)
        def runner(k,e):return (None,('timeout',None)) if k=='sessions' else self.runner(k,e)
        c.collect(self.db,now=self.now+1,runner=runner)
        self.assertEqual(len(self.logs()),2)
        self.assertEqual(self.db.execute('SELECT category FROM errors ORDER BY timestamp DESC LIMIT 1').fetchone()[0],'timeout')
    def test_logging_failure_rolls_back_only_diagnostics_and_continues(self):
        original=state_log.write_state_log
        def broken(*args):
            original(*args)
            raise RuntimeError('private@example.invalid /private/path secret=synthetic')
        with patch.object(state_log,'write_state_log',side_effect=broken):self.poll()
        self.assertEqual(self.logs(),[])
        self.assertEqual(self.db.execute('SELECT command,category,returnCode FROM errors').fetchall(),[('agent_state_log','diagnostic_failure',None)])
        self.assertEqual(self.db.execute('SELECT successfulCommands,failedCommands FROM collection_runs').fetchone(),(4,0))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM agents').fetchone()[0],2)
        self.poll(self.now+1);self.assertEqual(len(self.logs()),2)
    def test_privacy_counts_unidentified_sessions_and_missing_completeness(self):
        source=dict(sessionId='s',agentId='a',kind='direct',ageMs=0)
        for key,value in zip(['label','key','path','participantId','accountEmail','token'],FORBIDDEN_VALUES):source[key]=value
        self.sessions=[source,dict(sessionId='/invalid/id',agentId='a',status='failed')]
        self.poll()
        self.assertEqual(self.logs()[0]['sessionCount'],2)
        self.assertEqual(self.logs()[0]['pollSessionCount'],2)
        dump=json.dumps(self.logs())
        for v in FORBIDDEN_VALUES:self.assertNotIn(v,dump)
        self.assertNotIn('sessionId',dump)
        rows=c.project('sessions',{'sessions':[]});self.assertIsNone(rows['_session_diagnostics']['complete'])
        with self.assertRaises(ValueError):c.project('sessions',{'hasMore':True})
    def test_cli_timing_and_root_requests_not_reused(self):
        payload={'sessions':[],'hasMore':False}
        with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')),patch.object(c.time,'monotonic_ns',side_effect=[1000000000,1042000000]):
            rows,error=c.fetch('sessions','synthetic')
        self.assertIsNone(error);self.assertEqual(rows['_cli_duration_ms'],42)
        self.status={'shutdownBudget':{'activeWork':{'rootRequests':2}}};self.poll()
        self.status={};self.poll(self.now+1)
        self.assertIsNone(self.logs()[-1]['rootRequests'])
    def test_audit_readonly_validation_and_interval(self):
        at=int(time.time()*1000);self.poll(at-121000);self.poll(at)
        self.db.commit();before=hashlib.sha256(self.path.read_bytes()).hexdigest()
        env=dict(os.environ,MONITOR_DB=str(self.path))
        result=subprocess.run([str(c.ROOT/'scripts/state_audit.sh'),'a','1'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0);self.assertIn('agentId',result.stdout)
        self.assertEqual(len(result.stdout.splitlines()),3)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(),before)
        for args in [['a', '0'],['a', '-1'],["a' OR 1=1",'5']]:
            self.assertNotEqual(subprocess.run([str(c.ROOT/'scripts/state_audit.sh'),*args],env=env,capture_output=True).returncode,0)
        missing=Path(self.tmp.name)/'missing.db';env['MONITOR_DB']=str(missing)
        self.assertNotEqual(subprocess.run([str(c.ROOT/'scripts/state_audit.sh'),'a','1'],env=env,capture_output=True).returncode,0)
        self.assertFalse(missing.exists())

    def test_sql_insert_failure_and_retention_failure_are_isolated(self):
        self.db.execute("CREATE TRIGGER reject_state BEFORE INSERT ON agent_state_log BEGIN SELECT RAISE(FAIL, 'private@example.invalid'); END")
        self.poll()
        self.assertEqual(self.logs(),[])
        self.assertEqual(self.db.execute('SELECT category FROM errors').fetchall(),[('diagnostic_failure',)])
        self.db.execute('DROP TRIGGER reject_state')
        self.poll(self.now-15*86400000)
        self.db.execute("CREATE TRIGGER reject_prune BEFORE DELETE ON agent_state_log BEGIN SELECT RAISE(FAIL, 'secret=synthetic'); END")
        self.poll(self.now+1)
        self.assertEqual(len(self.logs()),2)  # Current inserts rolled back with prune failure.
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM collection_runs').fetchone()[0],3)
        dump='\n'.join(self.db.iterdump())
        error_rows=str(self.db.execute('SELECT * FROM errors').fetchall())
        self.assertNotIn('private@example.invalid',error_rows)
        self.assertNotIn('secret=synthetic',error_rows)

    def test_diagnostic_text_allowlist_raw_status_counts_and_snapshot_fallback(self):
        self.sessions=[dict(sessionId='s',agentId='a',kind=FORBIDDEN_VALUES[2],status=FORBIDDEN_VALUES[0],ageMs=0)]
        self.poll()
        row=self.logs()[0]
        self.assertEqual((row['newestKind'],row['newestStatus'],row['otherCount'],row['nullCount']),('other','other',1,0))
        self.assertEqual(row['state'],c.agent_states(self.db,self.now)['a'])
        for v in FORBIDDEN_VALUES:self.assertNotIn(v,json.dumps(self.logs()))
        self.sessions=[]
        def runner(k,e):return (None,('timeout',None)) if k=='agents' else self.runner(k,e)
        c.collect(self.db,now=self.now+1,runner=runner)
        self.assertEqual(len(self.logs()),4)  # Latest available agent snapshot.

    def test_incomplete_response_adds_no_log_rows(self):
        self.poll()
        def runner(k,e):return (None,('invalid_or_incomplete_json',None)) if k=='sessions' else self.runner(k,e)
        c.collect(self.db,now=self.now+1,runner=runner)
        self.assertEqual(len(self.logs()),2)
