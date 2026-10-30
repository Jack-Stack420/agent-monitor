"""TEST-only credentials generated in memory; all callers use temporary roots."""
import secrets
import threading
import json
import shutil
from pathlib import Path
import api
import collector

def fixture_cookie(server):
    value=secrets.token_urlsafe(32)
    server.auth.set_password(value)
    token=server.auth.attempt(value,'127.0.0.1')
    return 'cp_session='+token

def browser_server():
    import tempfile
    tmp=tempfile.TemporaryDirectory(prefix='monitor-auth-TEST-')
    root=Path(tmp.name)
    cfg=dict(api.DEFAULTS,port=8787)
    (root/'config.json').write_text(json.dumps(cfg))
    shutil.copy2(api.ROOT/'lexicon.json',root/'lexicon.json')
    shutil.copytree(api.ROOT/'web',root/'web')
    db=collector.connect(root/'data/monitor.db')
    import time
    now=int(time.time()*1000)
    raw={k:json.loads((api.ROOT/'fixtures'/(k+'.json')).read_text()) for k in collector.COMMANDS}
    collector.collect(db,now=now,runner=lambda k,e:(collector.project(k,raw[k]),None));db.close()
    server=api.Server(root,0);server.allowed_hosts=(f'127.0.0.1:{server.server_port}',)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return tmp,server
if __name__=='__main__':
    # Private stdin/stdout pipe to browser runner; never a file or console log.
    tmp,server=browser_server()
    value=secrets.token_urlsafe(32);server.auth.set_password(value)
    print(json.dumps({'base':f'http://127.0.0.1:{server.server_port}/','password':value}),flush=True)
    try:input()
    except EOFError:pass
    finally:server.shutdown();server.server_close();tmp.cleanup()
