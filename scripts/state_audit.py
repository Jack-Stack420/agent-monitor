"""Read-only diagnostic table viewer. MONITOR_DB optionally selects an offline copy."""
import datetime
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
if len(sys.argv)!=3 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',sys.argv[1]) or not re.fullmatch(r'[0-9]{1,9}',sys.argv[2]) or int(sys.argv[2])<1:
    sys.exit('Usage: state_audit.sh AGENT_ID MINUTES (positive integer)')
try:
    path=Path(os.environ.get('MONITOR_DB',Path(__file__).resolve().parents[1]/'data/monitor.db'))
    uri=path.resolve().as_uri()+'?mode=ro'
    with sqlite3.connect(uri,uri=True,timeout=5) as db:
        db.execute('PRAGMA query_only=ON')
        cursor=db.execute('SELECT * FROM agent_state_log WHERE agentId=? AND timestamp>=? ORDER BY timestamp',(sys.argv[1],int(time.time()*1000)-int(sys.argv[2])*60000))
        headers=[col[0] for col in cursor.description]
        rows=cursor.fetchall()
except (OSError,ValueError,sqlite3.Error):
    sys.exit('Audit unavailable (database or diagnostic table not available)')
if not rows:
    print('No diagnostic rows in this interval.')
else:
    values=[]
    for row in rows:
        row=list(row)
        row[0]=datetime.datetime.fromtimestamp(row[0]/1000,datetime.timezone.utc).isoformat(timespec='seconds')
        values.append(['unknown' if v is None else str(v) for v in row])
    widths=[max(len(h),*(len(r[i]) for r in values)) for i,h in enumerate(headers)]
    def show(row):print(' | '.join(v.ljust(widths[i]) for i,v in enumerate(row)))
    show(headers);print('-+-'.join('-'*w for w in widths))
    for row in values:show(row)
