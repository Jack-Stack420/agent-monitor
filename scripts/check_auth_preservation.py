#!/usr/bin/env python3
"""Semantic auth preservation; only mode=ro transactions, no Store construction.
Output order: schema, owner, secrets, auth_log, failures, sessions, other tables.
Each line: starting/current digest prefixes, row counts, identical/different.
"""
import argparse
from collections import Counter
import hashlib
import math
from pathlib import Path
import sqlite3
import time

IDLE = 12 * 3600

def digest(value):
    return hashlib.sha256(repr(value).encode()).hexdigest()

def snapshot(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        schema = tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))
        tables = {}
        for kind, name, _, _ in schema:
            if kind != 'table':
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            columns = tuple(row[1] for row in db.execute('PRAGMA table_info(' + quoted + ')'))
            # rowid detects replacement/deletion even when duplicate audit rows exist.
            rows = tuple(sorted(db.execute('SELECT rowid,* FROM ' + quoted), key=repr))
            tables[name] = (columns, rows)
        return {'schema': schema, 'tables': tables}
    finally:
        db.close()

def compare(before, after, now=None, expected_additions=None):
    """Additions must be exact row tuples recorded for deliberate check actions.
    No blanket login exception: existing audit/failure rows cannot change.
    Sessions can never gain hashes, even with an additions manifest.
    """
    now = time.time() if now is None else now
    expected_additions = expected_additions or {}
    results = []
    def record(left, right, passed):
        results.append((digest(left)[:8], digest(right)[:8], len(left), len(right), bool(passed)))
    record(before['schema'], after['schema'], before['schema'] == after['schema'])
    names = ['owner', 'secrets', 'auth_log', 'failures', 'sessions']
    names += sorted((set(before['tables']) | set(after['tables'])) - set(names))
    for name in names:
        oldcols, old = before['tables'].get(name, ((), ()))
        newcols, new = after['tables'].get(name, ((), ()))
        passed = oldcols == newcols and name in before['tables'] and name in after['tables']
        if name in ('auth_log', 'failures'):
            # Counter preserves duplicates; rowid detects alterations to existing rows.
            additions = Counter(expected_additions.get(name, ()))
            passed &= Counter(new) == Counter(old) + additions
        elif name == 'sessions' and passed:
            fields = ('rowid',) + oldcols
            try:
                def keyed(rows):
                    return {dict(zip(fields, r))['hash']: dict(zip(fields, r)) for r in rows}
                a, b = keyed(old), keyed(new)
                passed &= len(a) == len(old) and len(b) == len(new) and not (b.keys() - a.keys())
                for key, row in a.items():
                    if key not in b:
                        passed &= row['expiry'] <= now or row['last_seen'] <= now - IDLE
                    else:
                        current = b[key]
                        passed &= all(current[k] == v for k, v in row.items() if k not in ('last_seen', 'expiry'))
                        passed &= all(isinstance(current[k], (int, float)) and math.isfinite(current[k]) for k in ('last_seen', 'expiry'))
                        passed &= current['last_seen'] >= row['last_seen'] and current['last_seen'] <= now
            except (KeyError, TypeError, ValueError):
                passed = False
        else:
            passed &= old == new
        record(old, new, passed)
    return results

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before')
    parser.add_argument('after')
    args = parser.parse_args()
    try:
        results = compare(snapshot(args.before), snapshot(args.after))
    except (OSError, sqlite3.Error, ValueError):
        print('different')
        return 1
    for left, right, old, new, passed in results:
        print(left, right, old, new, 'identical' if passed else 'different')
    return int(not all(row[-1] for row in results))

if __name__ == '__main__':
    raise SystemExit(main())
