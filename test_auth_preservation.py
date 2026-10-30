"""Synthetic-only semantic authentication preservation regression tests."""
from pathlib import Path
import contextlib
import io
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from scripts.check_auth_preservation import snapshot, compare, main

SCHEMA = """
CREATE TABLE owner(id INTEGER PRIMARY KEY,salt BLOB,hash BLOB,n INTEGER,r INTEGER,p INTEGER,length INTEGER);
CREATE TABLE secrets(id INTEGER PRIMARY KEY,csrf BLOB);
CREATE TABLE sessions(hash TEXT PRIMARY KEY,created REAL,last_seen REAL,expiry REAL);
CREATE TABLE auth_log(time REAL,result TEXT,ip TEXT);
CREATE TABLE failures(subject TEXT PRIMARY KEY,count INTEGER,until REAL);
"""

class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.start = Path(self.tmp.name) / 'before.db'
        self.end = Path(self.tmp.name) / 'after.db'
        with sqlite3.connect(self.start) as db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO owner VALUES(1,?,?,32768,8,1,32)", (b'TEST-salt', b'TEST-hash'))
            db.execute("INSERT INTO secrets VALUES(1,?)", (b'TEST-secret',))
            db.execute("INSERT INTO sessions VALUES('TEST-token',100,900,2000)")
            db.execute("INSERT INTO auth_log VALUES(100,'TEST-success','TEST-ip')")
            db.execute("INSERT INTO failures VALUES('TEST-subject',1,200)")
        shutil.copyfile(self.start, self.end)
    def mutate(self, sql):
        with sqlite3.connect(self.end) as db:
            db.executescript(sql)
    def passes(self, **kwargs):
        return all(row[-1] for row in compare(snapshot(self.start), snapshot(self.end), now=1000, **kwargs))
    def test_identical(self):
        self.assertTrue(self.passes())
    def test_refreshed_last_seen_passes(self):
        self.mutate('UPDATE sessions SET last_seen=999')
        self.assertTrue(self.passes())
    def test_expiry_update_passes(self):
        self.mutate('UPDATE sessions SET expiry=3000')
        self.assertTrue(self.passes())
    def test_expired_session_deleted_passes(self):
        with sqlite3.connect(self.start) as db:
            db.execute('UPDATE sessions SET expiry=950')
        self.mutate('DELETE FROM sessions')
        self.assertTrue(self.passes())
    def test_idle_session_deleted_passes(self):
        with sqlite3.connect(self.start) as db:
            db.execute('UPDATE sessions SET last_seen=-50000')
        self.mutate('DELETE FROM sessions')
        self.assertTrue(self.passes())
    def test_active_session_deleted_fails(self):
        self.mutate('DELETE FROM sessions')
        self.assertFalse(self.passes())
    def test_changed_owner_hash_fails(self):
        self.mutate("UPDATE owner SET hash=x'00'")
        self.assertFalse(self.passes())
    def test_changed_secret_fails(self):
        self.mutate("UPDATE secrets SET csrf=x'00'")
        self.assertFalse(self.passes())
    def test_new_session_fails(self):
        self.mutate("INSERT INTO sessions VALUES('TEST-new',900,900,3000)")
        self.assertFalse(self.passes())
    def test_changed_session_creation_fails(self):
        self.mutate('UPDATE sessions SET created=101')
        self.assertFalse(self.passes())
    def test_deleted_auth_log_row_fails(self):
        self.mutate('DELETE FROM auth_log')
        self.assertFalse(self.passes())
    def test_altered_auth_log_row_fails(self):
        self.mutate("UPDATE auth_log SET result='TEST-other'")
        self.assertFalse(self.passes())
    def test_deleted_failure_fails(self):
        self.mutate('DELETE FROM failures')
        self.assertFalse(self.passes())
    def test_altered_failure_fails(self):
        self.mutate('UPDATE failures SET count=2')
        self.assertFalse(self.passes())
    def test_unexpected_additions_fail(self):
        for statement in ("INSERT INTO auth_log VALUES(200,'TEST-failure','TEST-ip')", "INSERT INTO failures VALUES('TEST-new',1,300)"):
            with self.subTest(statement=statement):
                shutil.copyfile(self.start, self.end)
                self.mutate(statement)
                self.assertFalse(self.passes())
    def test_exact_deliberate_additions_pass(self):
        self.mutate("INSERT INTO auth_log VALUES(200,'TEST-failure','TEST-ip'); INSERT INTO failures VALUES('TEST-new',1,300)")
        additions = {name: tuple(row for row in snapshot(self.end)['tables'][name][1] if row not in snapshot(self.start)['tables'][name][1]) for name in ('auth_log', 'failures')}
        self.assertTrue(self.passes(expected_additions=additions))
        self.mutate('UPDATE failures SET count=3 WHERE rowid=1')
        self.assertFalse(self.passes(expected_additions=additions))
    def test_schema_changed_fails(self):
        self.mutate('CREATE INDEX TEST_index ON sessions(expiry)')
        self.assertFalse(self.passes())
    def test_cli_private_output_and_no_writes(self):
        before = self.start.read_bytes(), self.end.read_bytes()
        output = io.StringIO()
        with patch('sys.argv', ['check', str(self.start), str(self.end)]), contextlib.redirect_stdout(output):
            self.assertEqual(main(), 0)
        for line in output.getvalue().splitlines():
            self.assertRegex(line, r'^[a-f0-9]{8} [a-f0-9]{8} [0-9]+ [0-9]+ identical$')
        self.assertEqual(before, (self.start.read_bytes(), self.end.read_bytes()))
    def test_missing_database_not_created(self):
        path = Path(self.tmp.name) / 'absent.db'
        with self.assertRaises(sqlite3.OperationalError):
            snapshot(path)
        self.assertFalse(path.exists())

if __name__ == '__main__':
    unittest.main()
