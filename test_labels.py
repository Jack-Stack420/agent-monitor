import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import collector as c

class LabelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = c.connect(Path(self.tmp.name)/'test.db')
        self.now = 1800000000000
        c.save(self.db, {'agents': [['a', 'Synthetic', 'p/m']]}, self.now)
    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
    def poll(self, rows, at=None, enabled=True):
        c.save(self.db, c.project('sessions', {'sessions': rows}, enabled), self.now if at is None else at)
    def session(self, sid='s', **extra):
        return dict(sessionId=sid, agentId='a', kind='direct', ageMs=0, updatedAt=self.now, **extra)
    def test_hidden_patterns(self):
        values = ['alice@example.invalid', '+1 (212) 555-0199', '212-555-0199',
                  'https://example.invalid/private', 'www.example.invalid',
                  '/home/fake/private.txt', '~/fake/private.txt', r'C:\fake\private.txt',
                  r'\\server\private\file', './private.txt', 'docs/private.txt',
                  '123456', 'order123456tail', 'sk-syntheticSecret',
                  'token=syntheticSecret', 'api_key: syntheticSecret',
                  'Bearer syntheticSecret', 'ghp_syntheticSecret',
                  'eyJsynthetic.eyJpayload.signature', 'AbCDef0123456789abcdef0123456789']
        for value in values:
            with self.subTest(pattern=values.index(value)):
                self.assertEqual(c.task_label('Review '+value), 'Review [hidden]')
                self.poll([self.session(label='Review '+value)])
                self.assertNotIn(value, '\n'.join(self.db.iterdump()))
    def test_identifier_labels_dropped(self):
        for value in ['agent:main:fake', 'session:fake', 'user:fake', 'user_id=12345',
                      'chat-id:fake', 'participant:fake', 'channel:fake',
                      'account:fake', 'discord:12345', '<@12345>']:
            self.assertIsNone(c.task_label('Review '+value))
    def test_trim_empty_and_scan_before_truncation(self):
        for value in [None, '', '  ', 42]:
            self.assertIsNone(c.task_label(value))
        self.assertEqual(c.task_label('  Task title  '), 'Task title')
        self.assertEqual(len(c.task_label(('word '*30))), 80)
        self.assertIsNone(c.task_label('word '*30+' user:fake'))
        value = 'word '*14+' synthetic@example.invalid'
        self.assertIn('[hidden]', c.task_label(value))
    def test_disabled_purges_existing_and_blocks_new(self):
        self.poll([self.session(label='Synthetic task')])
        def runner(command, executable):
            return (c.project('sessions', {'sessions':[self.session(label='Synthetic next')]}), None) if command=='sessions' else ({}, None)
        c.collect(self.db, now=self.now+1, runner=runner, store_task_labels=False)
        for table in ('sessions','session_history'):
            self.assertEqual(self.db.execute('SELECT COUNT(*) FROM '+table+' WHERE task_label IS NOT NULL').fetchone()[0], 0)
        self.assertNotIn('Synthetic task', '\n'.join(self.db.iterdump()))
        self.assertIsNone(c.project('sessions', {'sessions':[self.session(label='Task')]}, False)['sessions'][0][-1])
    def test_config(self):
        path=Path(self.tmp.name)/'config.json'
        self.assertTrue(c.load_config(path))
        for value, expected in [('{}',True), ('{"STORE_TASK_LABELS":false}',False), ('{"STORE_TASK_LABELS":true}',True), ('{"STORE_TASK_LABELS":"true"}',False), ('bad',False), ('[]',False)]:
            path.write_text(value)
            self.assertEqual(c.load_config(path), expected)
        with patch.object(c, 'load_config', return_value=False):
            c.collect(self.db, now=self.now, runner=lambda k,e: (c.project('sessions',{'sessions':[self.session(label='Task')]}),None) if k=='sessions' else ({},None))
        self.assertIsNone(self.db.execute('SELECT task_label FROM sessions').fetchone()[0])
    def test_current_working_precedence_and_most_recent(self):
        self.poll([self.session('a', label='Older task'), self.session('b', label='Newer task'), self.session('c',label='Finished',status='done')])
        self.db.execute("UPDATE session_history SET updatedAt=? WHERE sessionId='a'", (self.now-1,))
        result=c.agent_tasks(self.db,self.now)['a']
        self.assertEqual(result,dict(task_label='Newer task',kind='direct',status='working',ageMs=0))
        self.assertNotIn('sessionId',result)
    def test_finished_fallback_after_empty_poll_and_age(self):
        self.poll([self.session('a',label='Done task',status='done'), self.session('b',label='Failed task',status='failed')])
        self.db.execute("UPDATE sessions SET updatedAt=? WHERE sessionId='a'",(self.now-100,))
        self.poll([],self.now+1)
        self.assertEqual(c.agent_tasks(self.db,self.now+200)['a'],dict(task_label='Failed task',kind='direct',status='failed',ageMs=200))
    def test_no_label_and_no_session(self):
        self.assertEqual(c.agent_tasks(self.db,self.now)['a'],dict(task_label=None,kind=None,status='idle',ageMs=None))
        self.poll([self.session()])
        self.assertEqual(c.agent_tasks(self.db,self.now)['a']['kind'],'direct')
        self.assertIsNone(c.agent_tasks(self.db,self.now)['a']['task_label'])
    def test_existing_working_rule_used(self):
        self.poll([dict(sessionId='cron',agentId='a',kind='cron',ageMs=0,label='Scheduled')])
        self.assertEqual(c.agent_tasks(self.db,self.now)['a']['status'],'idle')
    def test_migration_keeps_legacy_label_null(self):
        path=Path(self.tmp.name)/'legacy.db'
        db=sqlite3.connect(path)
        for table in ('sessions','session_history'):
            db.execute('CREATE TABLE '+table+' ('+c.TABLES[table]+')')
        db.close()
        migrated=c.connect(path)
        for table in ('sessions','session_history'):
            self.assertIn('task_label',{r[1] for r in migrated.execute('PRAGMA table_info('+table+')')})
        migrated.close()

if __name__=='__main__': unittest.main()
