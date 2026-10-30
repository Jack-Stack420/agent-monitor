import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import collector as c
from privacy_fixtures import FORBIDDEN_VALUES

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=c.connect(Path(self.tmp.name)/'test.db')
        self.raw={k:json.loads((c.ROOT/'fixtures'/(k+'.json')).read_text()) for k in c.COMMANDS}
        self.now=1800000000000
    def tearDown(self):
        self.db.close(); self.tmp.cleanup()
    def runner(self,k,e):return c.project(k,self.raw[k]),None
    def count(self,t):return self.db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0]
    def test_all_data_tables_and_upsert(self):
        c.collect(self.db,now=self.now,runner=self.runner)
        for t in c.TABLES:
            if t!='errors':self.assertGreater(self.count(t),0,t)
        n=self.count('sessions')
        c.collect(self.db,now=self.now+1,runner=self.runner)
        self.assertEqual(self.count('sessions'),n)
        self.assertEqual(self.count('session_history'),n*2)
        self.assertIsNotNone(self.db.execute('SELECT model FROM agents WHERE model IS NOT NULL').fetchone())
    def test_failures_continue(self):
        def runner(k,e):return (None,('timeout',None)) if k=='status' else self.runner(k,e)
        c.collect(self.db,now=self.now,runner=runner)
        self.assertEqual(self.count('errors'),1)
        self.assertGreater(self.count('sessions'),0)
        self.assertGreater(self.count('agents'),0)
        self.assertGreater(self.count('cron_jobs'),0)
    def test_retention_all_tables(self):
        c.collect(self.db,now=self.now-91*86400000,runner=self.runner)
        self.db.execute('INSERT INTO errors VALUES (?,?,?,?)',(self.now-91*86400000,'status','timeout',None))
        c.collect(self.db,now=self.now,runner=lambda k,e: ({},None))
        for t in c.TABLES:self.assertEqual(self.count(t),1 if t=='collection_runs' else 0,t)
    def test_privacy_injection(self):
        sentinels=FORBIDDEN_VALUES
        for k,raw in self.raw.items():
            raw=copy.deepcopy(raw)
            entries=raw if isinstance(raw,list) else raw.get('sessions',raw.get('jobs',[raw]))
            for entry in entries:
                entry.update(dict(zip(['accountEmail','key','path','participantId','label','token'],sentinels)))
            c.save(self.db,c.project(k,raw),self.now)
        dump=chr(10).join(self.db.iterdump())
        for s in sentinels:self.assertNotIn(s,dump)
        for bad in [sentinels[0],sentinels[1],sentinels[2],sentinels[5]]:self.assertIsNone(c.string(bad))
    def test_subprocess_errors_and_timeout(self):
        cases=[(subprocess.TimeoutExpired('x',20),'timeout'),(OSError(),'launch')]
        for exc,kind in cases:
            with patch.object(c.subprocess,'run',side_effect=exc) as run:
                self.assertEqual(c.fetch('status','openclaw'),(None,(kind,None)))
                self.assertEqual(run.call_args.kwargs['timeout'],20)
        with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],4,'private@example.invalid','sk-private')):
            self.assertEqual(c.fetch('status','openclaw'),(None,('exit',4)))
        with patch.object(c.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'not json','')):
            self.assertEqual(c.fetch('status','openclaw'),(None,('invalid_or_incomplete_json',None)))
    def test_schedule_slashes(self):
        row=c.project('cron',{'jobs':[{'name':'Job','schedule':{'kind':'cron','expr':'*/5 * * * *','tz':'America/New_York'}}]})['cron_jobs'][0]
        self.assertEqual(json.loads(row[1])['expr'],'*/5 * * * *')
        self.assertEqual(json.loads(row[1])['tz'],'America/New_York')
    def test_partial_results_rejected(self):
        for k in ('sessions','cron'):
            with self.assertRaises(ValueError):c.project(k,{'hasMore':True})

if __name__=='__main__':unittest.main()
