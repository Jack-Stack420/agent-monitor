#!/usr/bin/env python3
"""One low-priority check; sampled aggregate process-group RSS, bounded cleanup.
Usage: nice -n 10 ionice -c3 python3 scripts/resource_check.py NAME COMMAND ...
No captured child output is persisted or printed except safe test summaries.
"""
import ctypes,json,os,signal,subprocess,sys,tempfile,time
from pathlib import Path
ctypes.CDLL(None).prctl(36,1,0,0,0)  # adopt/reap orphaned Chrome descendants
name,*command=sys.argv[1:]
start=time.monotonic();peak=0
with tempfile.TemporaryFile() as output:
    p=subprocess.Popen(command,stdout=output,stderr=output,start_new_session=True)
    def members():
        found=[]
        for path in Path('/proc').glob('[0-9]*/stat'):
            try:
                fields=path.read_text().rsplit(')',1)[1].split()
                if int(fields[2])==p.pid:
                    rss=int(fields[21])*os.sysconf('SC_PAGE_SIZE');found.append((int(path.parent.name),rss))
            except (OSError,ValueError,IndexError):pass
        return found
    while p.poll() is None:
        peak=max(peak,sum(rss for _,rss in members()))
        if time.monotonic()-start>240:
            os.killpg(p.pid,signal.SIGTERM);break
        time.sleep(.1)
    rc=p.wait()
    # Terminate only this check's remaining process group, never existing services.
    remaining=members()
    if remaining:
        try:os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        time.sleep(.3)
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    while True:
        try:
            child,_=os.waitpid(-1,os.WNOHANG)
            if child==0:time.sleep(.05);continue
        except ChildProcessError:break
    remaining=members()
    output.seek(0);raw=output.read().decode(errors='replace')
    # All fixtures are synthetic; emit only totals, never request/header/label text.
    import re
    summary=re.findall(r'Ran \d+ tests? in [0-9.]+s|^OK$|^FAILED.*$',raw,re.M)
    result={'check':name,'exit':rc,'duration_seconds':round(time.monotonic()-start,3),'peak_group_rss_mib':round(peak/1048576,2),'remaining_processes':len(remaining),'summary':summary}
    if rc:
        result['failure_types']=re.findall(r'^(?:FAIL|ERROR): ([A-Za-z0-9_]+)',raw,re.M)
        result['safe_failure_tail']=[line for line in raw.splitlines() if line.startswith(('AssertionError','TypeError','ValueError','Error:'))][:8]
    print(json.dumps(result))
    sys.exit(rc or bool(remaining))
