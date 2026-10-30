// Real headless Chrome/CDP check; prints counts/booleans only, never task text.
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {checkTask9} from './task9_checks.mjs';
import {checkTask10} from './task10_checks.mjs';
import {checkTask12} from './task12_checks.mjs';
import {checkTask12b} from './task12b_checks.mjs';
import {checkTask8} from './task8_checks.mjs';
// TEST-only temporary telemetry/auth databases and in-memory generated password.
const fixture=spawn('/usr/bin/python3',['-B','auth_fixture.py'],{stdio:['pipe','pipe','ignore']});
const setup=await new Promise((resolve,reject)=>{let buf='';fixture.stdout.on('data',d=>{buf+=d;const i=buf.indexOf('\n');if(i>=0)resolve(JSON.parse(buf.slice(0,i)));});fixture.on('exit',()=>reject(Error('TEST fixture exited')));});
const base=setup.base;
const profile=await mkdtemp(join(tmpdir(),'monitor-chrome-'));
const chrome=spawn('/usr/bin/google-chrome',['--headless','--no-sandbox','--disable-dev-shm-usage','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']});
let ws;
try {
 const endpoint=await new Promise((resolve,reject)=>{let out='';chrome.stderr.on('data',d=>{out+=d;const m=out.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(m)resolve(m[1]);});chrome.on('exit',()=>reject(Error('Chrome exited')));setTimeout(()=>reject(Error('Chrome startup timeout')),10000).unref();});
 const port=new URL(endpoint).port;
 const target=await (await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
 ws=new WebSocket(target.webSocketDebuggerUrl);await new Promise(r=>ws.addEventListener('open',r,{once:true}));
 let postId=null,postStatus=null,policy=null;const extra=new Map();
 let id=0;const pending=new Map(), errors=[];const requests=[];
 ws.addEventListener('message',e=>{const m=JSON.parse(e.data);
 if(m.method==='Network.requestWillBeSent'&&m.params.request.method==='POST')postId=m.params.requestId;
 if(m.method==='Network.requestWillBeSentExtraInfo'&&!extra.has(m.params.requestId))extra.set(m.params.requestId,m.params.headers);
 if(m.method==='Network.responseReceived'&&m.params.response.url===base+'login')policy=m.params.response.headers['Referrer-Policy'];
 if(m.method==='Network.responseReceivedExtraInfo'&&m.params.requestId===postId&&postStatus===null)postStatus=m.params.statusCode;
if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}}else if(m.method==='Runtime.exceptionThrown'||(m.method==='Log.entryAdded'&&m.params.entry.level==='error')||(m.method==='Runtime.consoleAPICalled'&&m.params.type==='error'))errors.push({event:m.method,host:m.params.entry?.url?new URL(m.params.entry.url).host:null,status:m.params.entry?.text?.match(/status of ([0-9]+)/)?.[1]||null});else if(m.method==='Network.requestWillBeSent')requests.push(m.params.request.url);});
 const call=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({id:key,method,params}));});
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error('Browser evaluation failed');return r.result.value;};
 await call('Runtime.enable');await call('Log.enable');await call('Page.enable');await call('Network.enable');
 await call('Page.navigate',{url:base+'login'});
 await new Promise(r=>setTimeout(r,700));
 // Focus, type and click through trusted browser input; no DOM value injection.
 await evaluate('document.querySelector("#password").focus();true');
 await call('Input.insertText',{text:setup.password});
 const button=await evaluate('(()=>{const r=document.querySelector("button[type=submit]").getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()');
 await call('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...button});
 await call('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...button});
 setup.password=null;
 await new Promise(r=>setTimeout(r,700));
 const raw=extra.get(postId)||{};const postHeaders=Object.fromEntries(['Origin','Referer','Sec-Fetch-Site','Sec-Fetch-Mode','Sec-Fetch-Dest'].map(k=>[k,Object.entries(raw).find(([n])=>n.toLowerCase()===k.toLowerCase())?.[1]??'(absent)']));
 console.log(JSON.stringify({policy,postHeaders,postStatus,errors,externalHosts:[...new Set(requests.filter(u=>!u.startsWith(base)&&!u.startsWith('data:')).map(u=>new URL(u).host))],dashboard:await evaluate("!!document.querySelector('#app')")}));
} finally {ws?.close();chrome.kill('SIGTERM');await new Promise(r=>chrome.once('exit',r));await rm(profile,{recursive:true,force:true});fixture.stdin.end('done\n');await new Promise(r=>fixture.once('exit',r));}
