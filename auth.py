"""Single-owner authentication; the telemetry database remains read-only."""
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import sqlite3
import time
import re

N, R, P, KEY_BYTES = 32768, 8, 1, 32
IDLE, ABSOLUTE = 12*3600, 7*86400
# Common-password stems are policy data, never usable/test passwords.
COMMON = ('password', 'qwerty', 'letmein', 'welcome', 'admin', '123456', 'iloveyou', 'changeme', 'correcthorsebatterystaple')

def policy(value):
    if not isinstance(value,str):return False
    normalized=''.join(c for c in value.casefold() if c.isalnum())
    return isinstance(value,str) and 14 <= len(value) <= 512 and len(set(value))>1 and not any(normalized.startswith(s) for s in COMMON)

def derive(value, salt, n=N, r=R, p=P, length=KEY_BYTES):
    return hashlib.scrypt(value.encode('utf-8'),salt=salt,n=n,r=r,p=p,dklen=length,maxmem=128*1024*1024)

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

class Store:
    def __init__(self,path,scope='lan'):
        if scope not in ('lan','tailscale-proxy'):raise ValueError('invalid authentication scope')
        self.scope=scope
        self.path=Path(path)
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.path.parent.chmod(0o700)
        if self.path.is_symlink(): raise ValueError('unsafe authentication path')
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd)
        self.path.chmod(0o600)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY CHECK(id=1),salt BLOB,hash BLOB,n INTEGER,r INTEGER,p INTEGER,length INTEGER);
CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY,created REAL,last_seen REAL,expiry REAL);
CREATE TABLE IF NOT EXISTS failures (subject TEXT PRIMARY KEY,count INTEGER NOT NULL,until REAL NOT NULL);
CREATE TABLE IF NOT EXISTS auth_log (time REAL NOT NULL,result TEXT NOT NULL,ip TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY CHECK(id=1),csrf BLOB NOT NULL);''')
            db.execute('INSERT OR IGNORE INTO secrets VALUES (1,?)',(secrets.token_bytes(32),))
    def csrf_token(self,purpose,session='',now=None):
        if purpose not in ('/login','/logout'):raise ValueError('invalid purpose')
        timestamp=int(time.time() if now is None else now)
        message=str(timestamp)+'_'+secrets.token_hex(32)
        with self.connect() as db:key=db.execute('SELECT csrf FROM secrets WHERE id=1').fetchone()[0]
        signature=hmac.new(key,(purpose+'|'+digest(session)+'|'+message).encode(),hashlib.sha256).hexdigest()
        return message+'_'+signature
    def valid_csrf(self,token,purpose,session='',now=None):
        if not isinstance(token,str) or not re.fullmatch(r'[0-9]{1,12}_[a-f0-9]{64}_[a-f0-9]{64}',token):return False
        timestamp,nonce,signature=token.split('_')
        age=(time.time() if now is None else now)-int(timestamp)
        if age<0 or age>1800 or purpose not in ('/login','/logout'):return False
        with self.connect() as db:key=db.execute('SELECT csrf FROM secrets WHERE id=1').fetchone()[0]
        expected=hmac.new(key,(purpose+'|'+digest(session)+'|'+timestamp+'_'+nonce).encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature,expected)
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.execute('PRAGMA secure_delete=ON')
        return db
    def configured(self):
        with self.connect() as db: return bool(db.execute('SELECT 1 FROM owner WHERE id=1').fetchone())
    def set_password(self,value):
        if not policy(value): raise ValueError('Use at least 14 characters, at most 512, and avoid common passwords.')
        salt=secrets.token_bytes(16); key=derive(value,salt)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR REPLACE INTO owner VALUES (1,?,?,?,?,?,?)',(salt,key,N,R,P,KEY_BYTES))
            db.execute('DELETE FROM sessions');db.execute('DELETE FROM failures')
    def attempt(self,value,ip,now=None):
        now=time.time() if now is None else now
        try: ip=str(ipaddress.ip_address(ip))
        except ValueError: ip='unknown'
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM auth_log WHERE time < ?',(now-90*86400,))
            db.execute('DELETE FROM sessions WHERE expiry<=? OR last_seen<=?',(now,now-IDLE))
            row=db.execute('SELECT salt,hash,n,r,p,length FROM owner WHERE id=1').fetchone()
            salt,key,n,r,p,length=row or (bytes(16),bytes(KEY_BYTES),N,R,P,KEY_BYTES)
            candidate=derive(value,salt,n,r,p,length)
            matches=hmac.compare_digest(candidate,key) and row is not None
            prefix='' if self.scope=='lan' else self.scope+':'
            subjects=(prefix+'global',prefix+'ip:'+ip)
            states=[db.execute('SELECT count,until FROM failures WHERE subject=?',(s,)).fetchone() or (0,0) for s in subjects]
            blocked=any(state[1]>now for state in states)
            if matches and not blocked:
                token=secrets.token_urlsafe(32)
                db.execute('INSERT INTO sessions VALUES (?,?,?,?)',(digest(token),now,now,now+ABSOLUTE))
                for s in subjects: db.execute('DELETE FROM failures WHERE subject=?',(s,))
                db.execute('INSERT INTO auth_log VALUES (?,?,?)',(now,'success',ip))
                return token
            if not blocked:
                for s,(count,_) in zip(subjects,states):
                    count+=1;delay=min(900,2**min(10,max(0,count-5))) if count>=5 else 0
                    db.execute('INSERT OR REPLACE INTO failures VALUES (?,?,?)',(s,count,now+delay))
            db.execute('INSERT INTO auth_log VALUES (?,?,?)',(now,'throttled' if blocked else 'failure',ip))
            return None
    def session(self,token,now=None):
        if not token or len(token)>128:return False
        now=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM sessions WHERE expiry<=? OR last_seen<=?',(now,now-IDLE))
            row=db.execute('SELECT 1 FROM sessions WHERE hash=?',(digest(token),)).fetchone()
            if row:db.execute('UPDATE sessions SET last_seen=? WHERE hash=?',(now,digest(token)))
            return bool(row)
    def revoke(self,token=None):
        with self.connect() as db:
            if token is None:db.execute('DELETE FROM sessions')
            else:db.execute('DELETE FROM sessions WHERE hash=?',(digest(token),))
    def audit(self,result,ip):
        try:ip=str(ipaddress.ip_address(ip))
        except ValueError:ip='unknown'
        if result=='proxy_rejected':ip=''
        if result not in ('rejected','proxy_rejected'):raise ValueError('invalid audit result')
        now=time.time()
        with self.connect() as db:
            db.execute('DELETE FROM auth_log WHERE time<?',(now-90*86400,))
            db.execute('INSERT INTO auth_log VALUES (?,?,?)',(now,result,ip))
    def status(self):
        now=time.time()
        with self.connect() as db:
            return {'password_set':bool(db.execute('SELECT 1 FROM owner').fetchone()),'failures':dict(db.execute('SELECT subject,count FROM failures')),'active_sessions':db.execute('SELECT COUNT(*) FROM sessions WHERE expiry>? AND last_seen>?',(now,now-IDLE)).fetchone()[0]}


def set_tailscale_owner(root, value):
    """Private local-only owner setup. Never log the supplied identity."""
    value=value.strip().lower()
    if not value or len(value)>320 or any(c.isspace() or ord(c)<33 or ord(c)==127 for c in value):
        raise ValueError('Invalid owner login; unchanged.')
    directory=Path(root)/'data/auth'
    directory.mkdir(parents=True,exist_ok=True,mode=0o700);directory.chmod(0o700)
    path=directory/'tailscale_owner'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:
        os.fchmod(out.fileno(),0o600);out.write(value+'\n')


def tailscale_owner(root):
    path=Path(root)/'data/auth/tailscale_owner'
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd) as src:
            if os.fstat(src.fileno()).st_mode & 0o077:return None
            value=src.read(322).strip()
        if not value or len(value)>320 or any(c.isspace() or ord(c)<33 or ord(c)==127 for c in value):return None
        return value.lower()
    except (OSError,UnicodeError):return None
