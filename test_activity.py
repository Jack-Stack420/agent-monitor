import json
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
import collector as c

class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = c.connect(Path(self.tmp.name)/'test.db')
        self.now = 1800000000000
        c.save(self.db, {'agents': [['a','Synthetic','p/m']]}, self.now)
    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
    def poll(self, sessions, at):
        c.save(self.db,c.project('sessions',{'sessions':sessions}),at)
    def test_sanitized_activity_cases(self):
        cases=json.loads((c.ROOT/'fixtures/activity.json').read_text())
        for case in cases:
            with self.subTest(case=case['name']):
                self.db.execute('DELETE FROM session_history')
                self.db.execute('DELETE FROM session_polls')
                self.db.execute('DELETE FROM sessions')
                if case['previous']:
                    self.poll([case['previous']],self.now-60000)
                self.poll([case['current']],self.now)
                self.assertEqual(c.agent_states(self.db,self.now),{'a':case['expected']})
    def test_three_polls_delta_expires(self):
        s=dict(sessionId='s',agentId='a',status='running',totalTokens=1)
        self.poll([s],self.now-120000)
        s['totalTokens']=2
        self.poll([s],self.now-60000)
        self.assertEqual(c.agent_states(self.db,self.now-60000)['a'],'working')
        self.poll([s],self.now)
        self.assertEqual(c.agent_states(self.db,self.now)['a'],'idle')
    def test_multiple_sessions_precedence_and_latest(self):
        done=dict(sessionId='d',agentId='a',status='done',ageMs=100,updatedAt=self.now-100)
        active=dict(sessionId='s',agentId='a',ageMs=0,updatedAt=self.now)
        self.poll([done,active],self.now)
        self.assertEqual(c.agent_states(self.db,self.now)['a'],'working')
        active['ageMs']=600001
        self.poll([done,active],self.now+1)
        self.assertEqual(c.agent_states(self.db,self.now+1)['a'],'idle')
        done['updatedAt']=self.now+2
        self.poll([done,active],self.now+2)
        self.assertEqual(c.agent_states(self.db,self.now+2)['a'],'recent')
    def test_disappeared_session_not_running(self):
        self.poll([dict(sessionId='old',agentId='a',ageMs=0)],self.now-1)
        self.poll([dict(sessionId='new',agentId='a',status='done',ageMs=0)],self.now)
        self.assertEqual(c.agent_states(self.db,self.now)['a'],'recent')
    def test_sample_age_advances_and_delta_expires(self):
        self.poll([dict(sessionId='s',agentId='a',ageMs=599999)],self.now)
        self.assertEqual(c.agent_states(self.db,self.now+1)['a'],'idle')
    def test_empty_poll_clears_activity_and_breaks_delta(self):
        s=dict(sessionId='s',agentId='a',totalTokens=1,ageMs=0)
        self.poll([s],self.now-2)
        self.poll([],self.now-1)
        self.assertEqual(c.agent_states(self.db,self.now-1)['a'],'idle')
        s.update(totalTokens=2,status='running')
        self.poll([s],self.now)
        self.assertEqual(c.agent_states(self.db,self.now)['a'],'idle')
    def test_no_sessions(self):
        self.assertEqual(c.agent_states(self.db,self.now),{'a':'idle'})
    def test_v1_migration(self):
        path=Path(self.tmp.name)/'legacy.db'
        db=sqlite3.connect(path)
        for t in ('sessions','session_history'):
            schema=c.TABLES[t].split(', ageMs')[0]
            db.execute('CREATE TABLE '+t+' ('+schema+')')
            db.execute('INSERT INTO '+t+' VALUES (?,?,?,?,?,?,?,?,?,?)', (1,'s','a','direct',None,'m','p',1,1,1))
        db.commit();db.close()
        db=c.connect(path)
        self.assertEqual(db.execute('SELECT totalTokens,ageMs,updatedAt FROM sessions').fetchone(),(1,None,None))
        db.close()
    @unittest.skipUnless(shutil.which('flock'),'flock unavailable')
    def test_cron_nonblocking_overlap(self):
        lock=Path(self.tmp.name)/'cron.lock'
        with lock.open('w') as handle:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=subprocess.run(['/usr/bin/flock','-n',str(lock),'/usr/bin/true'],timeout=2)
            self.assertEqual(result.returncode,1)
        result=subprocess.run(['/usr/bin/flock','-n',str(lock),'/usr/bin/true'],timeout=2)
        self.assertEqual(result.returncode,0)
        entry=(c.ROOT/'cron-entry.txt').read_text()
        self.assertIn('/usr/bin/flock -n /home/youruser/agent-monitor/data/cron.lock',entry)

if __name__=='__main__':unittest.main()
