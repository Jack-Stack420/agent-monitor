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
const proxyMode=process.env.MONITOR_TEST_PROXY==='1';
const fixture=spawn('/usr/bin/python3',['-B',proxyMode?'proxy_fixture.py':'auth_fixture.py'],{stdio:['pipe','pipe','ignore']});
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
 let loginPostId=null,loginPostStatus=null;const wireHeaders=new Map(),responsePolicies=[];
 let id=0;const pending=new Map(), errors=[];const requests=[];
 ws.addEventListener('message',e=>{const m=JSON.parse(e.data);
 if(m.method==='Network.requestWillBeSent'&&m.params.request.method==='POST'&&m.params.request.url===base+'login')loginPostId=m.params.requestId;
 if(m.method==='Network.requestWillBeSentExtraInfo'&&!wireHeaders.has(m.params.requestId))wireHeaders.set(m.params.requestId,m.params.headers);
 if(m.method==='Network.responseReceivedExtraInfo'){
  if(m.params.requestId===loginPostId&&loginPostStatus===null)loginPostStatus=m.params.statusCode;
  responsePolicies.push(Object.entries(m.params.headers).find(([k])=>k.toLowerCase()==='referrer-policy')?.[1]);
 }
 if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}}else if(m.method==='Runtime.exceptionThrown'||(m.method==='Log.entryAdded'&&m.params.entry.level==='error')||(m.method==='Runtime.consoleAPICalled'&&m.params.type==='error'))errors.push({event:m.method,source:m.params.entry?.source||null,host:m.params.entry?.url?new URL(m.params.entry.url).host:null,status:m.params.entry?.text?.match(/status of ([0-9]+)/)?.[1]||null,cause:/Content Security Policy|violat/i.test(m.params.entry?.text||'')?'CSP':/Failed to load resource/.test(m.params.entry?.text||'')?'resource load':m.method});else if(m.method==='Network.requestWillBeSent')requests.push(m.params.request.url);});
 const call=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({id:key,method,params}));});
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error('Browser evaluation failed');return r.result.value;};
 await call('Runtime.enable');await call('Log.enable');await call('Page.enable');await call('Network.enable');
 await call('Page.navigate',{url:base});
 await new Promise(r=>setTimeout(r,700));
 assert.equal(await evaluate('location.pathname'),'/login','Fresh top-level URL reaches login');
 assert.equal(await evaluate('!!document.querySelector("#password")'),true);
 assert.ok([...wireHeaders.values()].some(h=>Object.entries(h).some(([k,v])=>k.toLowerCase()==='sec-fetch-site'&&v==='none')));
 const loginWidths=[];
 for(const width of [320,375,390,768,1000,1280,1440,1920,2560]){
  await call('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:false});
  assert.equal(await evaluate('document.documentElement.scrollWidth<=innerWidth'),true);loginWidths.push(width);
 }
 // Focus, type and click through trusted browser input; no DOM value injection.
 await evaluate('document.querySelector("#password").focus();true');
 await call('Input.insertText',{text:setup.password});
 const button=await evaluate('(()=>{const r=document.querySelector("button[type=submit]").getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()');
 await call('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...button});
 await call('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...button});
 setup.password=null;
 await new Promise(r=>setTimeout(r,700));
 await call('Emulation.setDeviceMetricsOverride',{width:1280,height:1000,deviceScaleFactor:1,mobile:false});
 await new Promise(r=>setTimeout(r,4000));
 assert.equal(await evaluate("!!document.querySelector('#app')"),true,'Native login form reaches authenticated dashboard');
 const browserCookies=(await call('Network.getCookies',{urls:[base]})).cookies;
 const prefix=proxyMode?'__Host-':'';
 assert.ok(browserCookies.some(c=>c.name===prefix+'cp_session'),'Browser accepted session cookie');
 assert.ok(browserCookies.some(c=>c.name===prefix+'cp_csrf'),'Browser accepted CSRF cookie');
 for(const c of browserCookies.filter(c=>c.name===prefix+'cp_session'||c.name===prefix+'cp_csrf')){
  assert.equal(c.secure,proxyMode);assert.equal(c.httpOnly,true);assert.equal(c.sameSite,'Strict');assert.equal(c.path,'/');
 }
 if(proxyMode){
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await new Promise(r=>setTimeout(r,500));
  assert.equal(await evaluate("document.documentElement.scrollWidth<=innerWidth && !!document.querySelector('#app')"),true,'390px authenticated phone dashboard');
  await call('Emulation.setDeviceMetricsOverride',{width:1280,height:1000,deviceScaleFactor:1,mobile:false});
 }
 const loginHeaders=Object.fromEntries(['Origin','Referer','Sec-Fetch-Site','Sec-Fetch-Mode','Sec-Fetch-Dest'].map(k=>[k,Object.entries(wireHeaders.get(loginPostId)||{}).find(([n])=>n.toLowerCase()===k.toLowerCase())?.[1]??'(absent)']));
 assert.deepEqual(loginHeaders,{'Origin':new URL(base).origin,'Referer':base+'login','Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'});
 assert.equal(loginPostStatus,302,'Native form POST accepted, before redirect');
 assert.equal(requests.some(u=>u===base+'favicon.ico'),false,'Inline favicon avoids protected-resource errors');
 const task10=await checkTask10(evaluate);
 const result=await evaluate('(async()=>{const raw=await (await fetch(API_URL)).json();return {cards:document.querySelectorAll(".spirit").length,agents:raw.agents.length,bars:document.querySelectorAll(".bar").length,windows:raw.limits.reduce((n,p)=>n+p.windows.length,0),errorPanel:document.querySelector("#app").textContent.includes("Cannot reach"),sample:document.querySelectorAll(".tag").length,stale:!!document.querySelector(".warn"),expectedStale:raw.health.stale};})()');
 assert.equal(result.cards,result.agents);assert.equal(result.bars,result.windows);assert.equal(result.errorPanel,false);assert.equal(result.sample,0);assert.equal(result.stale,result.expectedStale);
 const colors=await evaluate(`(async()=>{
   const raw=await (await fetch(API_URL)).json();
   const live=adapt(raw);render(live);
   const inspect=()=>({segments:[...document.querySelectorAll('.chart>div:first-child>div')].reverse().map(e=>({color:getComputedStyle(e).backgroundColor,height:e.getBoundingClientRect().height})),legend:[...document.querySelectorAll('.legend i')].map(e=>getComputedStyle(e).backgroundColor)});
   const liveChart=inspect();
   const t=raw.agents[0];
   raw.agents=[0,1,2].map(i=>({...t,id:'synthetic-color-'+i,name:'Synthetic '+i,accent_color:i===1?'#123abc':null}));
   raw.tokens.daily=[{date:'2026-10-28',by_agent:Object.fromEntries(raw.agents.map(a=>[a.id,100]))}];
   raw.gateway={...(raw.gateway||{}),hostUtilization:0.918};
   const first=adapt(raw);render(first);const chart=inspect();
   const host=[...document.querySelectorAll('.stats .lbl')].find(e=>e.textContent==='HOST LOAD').parentElement.querySelector('b').textContent;
   const before=Object.fromEntries(first.agents.map(a=>[a.id,a.accent]));
   raw.agents.reverse();const reordered=adapt(raw).agents.every(a=>a.accent===before[a.id]);
   raw.agents=raw.agents.slice(0,1);adapt(raw);
   raw.agents=first.agents.map(a=>({...t,id:a.id,accent_color:a.id==='synthetic-color-1'?'#123abc':null}));
   const reappeared=adapt(raw).agents.every(a=>a.accent===before[a.id]);
   raw.agents[1].accent_color=null;
   const overrideRemoved=adapt(raw).agents[1].accent!=='#123abc';
   await load();
   return {liveMatches:liveChart.segments.every((e,i)=>e.color===liveChart.legend[i]),liveDistinct:new Set(liveChart.legend).size===live.agents.length,syntheticMatches:chart.segments.every((e,i)=>e.color===chart.legend[i]),syntheticDistinct:new Set(chart.legend).size===3,visible:chart.segments.every(e=>e.height>0),override:chart.legend[1]==='rgb(18, 58, 188)',reordered,reappeared,overrideRemoved,host};
 })()`);
 assert.deepEqual(colors,{liveMatches:true,liveDistinct:true,syntheticMatches:true,syntheticDistinct:true,visible:true,override:true,reordered:true,reappeared:true,overrideRemoved:true,host:'92%'});
 const task7=await evaluate("(async()=>{\nconst raw=await (await fetch(API_URL)).json(),t=raw.agents[0],widths=[],fallbacks=[];\nfor(const count of [1,2,7]){\nraw.tokens.daily=Array.from({length:count},(_,i)=>({date:'2026-10-'+(20+i),by_agent:{[t.id]:100}}));render(adapt(raw));\nwidths.push([...document.querySelectorAll('.chart>div')].every(e=>e.getBoundingClientRect().width>0&&e.getBoundingClientRect().width<=72.01));\n}\nfor(const [kind,expected] of [['direct','Direct session'],['spawn','Spawn-child session'],['spawn-child','Spawn-child session'],['subagent','Spawn-child session'],['cron','Scheduled job'],['other','Session']]){\nraw.agents=[{...t,task:{label:null,kind,ageMs:0}}];raw.log=[{timestamp:raw.generatedAt,type:'session_finished',agent:t.id,status:'done',label:null,kind}];render(adapt(raw));\nfallbacks.push(document.querySelector('.duty').textContent===expected&&document.querySelector('.log .x').textContent===expected);\n}\nraw.agents[0].task.label='Synthetic title';raw.log[0].label='Synthetic title';render(adapt(raw));\nconst labelWins=document.querySelector('.duty').textContent==='Synthetic title'&&document.querySelector('.log .x').textContent==='Synthetic title';\nconst note=document.querySelector('#app').textContent.includes('ESTIMATED FROM SESSION TOKEN TOTALS');await load();return {widths:widths.every(Boolean),fallbacks:fallbacks.every(Boolean),labelWins,note};\n})()");
 assert.deepEqual(task7,{widths:true,fallbacks:true,labelWins:true,note:true});
 const safety=await evaluate('(async()=>{const raw=await (await fetch(API_URL)).json();raw.health.stale=true;raw.agents[0].name="<img src=x onerror=alert(1)>";render(adapt(raw));const stale=!!document.querySelector(".warn");const textOnly=!document.querySelector("#app img");const original=window.fetch;window.fetch=async()=>{throw new Error("synthetic offline")};await load();const error=document.querySelector(".warn").textContent.includes("Cannot reach the monitor API");window.fetch=original;await load();return {stale,textOnly,error};})()');
 assert.deepEqual(safety,{stale:true,textOnly:true,error:true});
 const task8=await checkTask8(call,evaluate);
 const task9=await checkTask9(call,evaluate);
 const task12=await checkTask12(call,evaluate);
 const task12b=await checkTask12b(call,evaluate);
 assert.equal(requests.filter(u=>!u.startsWith(base)&&!u.startsWith('data:')).length,0,'External resource requests');
 const expiry=await evaluate("(async()=>{const original=window.fetch;window.fetch=async()=>new Response('{}',{status:401});await load();const ok=sessionExpired&&timer===null&&document.querySelector('#app a')?.getAttribute('href')==='/login'&&document.querySelector('#app').textContent.includes('Session expired');window.fetch=original;sessionExpired=false;await load();return ok;})()");
 assert.equal(expiry,true);
 await evaluate('signedOut();true');await new Promise(r=>setTimeout(r,700));
 assert.equal(await evaluate('location.pathname'),'/login');
 assert.equal(await evaluate(`document.querySelector('link[rel="icon"]').getAttribute("href")`),'data:,');
 assert.ok(responsePolicies.length>0);
 assert.equal(responsePolicies.every(p=>p==='same-origin'),true,'Policy on every browser HTTP response, including redirects');
 console.log(JSON.stringify({authentication:{freshTopLevelLogin:true,proxyMode,phone390:proxyMode,loginWidths,nativeForm:true,postStatus:loginPostStatus,sameOriginFormHeaders:true,responsePoliciesChecked:responsePolicies.length,sessionExpiredStopsPolling:expiry,logout:true},task12b,task12,task10,live:result,task7,task8,task9,syntheticChecks:safety,colorAndLoadChecks:colors,consoleErrors:errors.length,browserErrorDetails:errors,externalHosts:[...new Set(requests.filter(u=>!u.startsWith(base)&&!u.startsWith('data:')).map(u=>new URL(u).host))],externalRequests:requests.filter(u=>!u.startsWith(base)&&!u.startsWith('data:')).length}));
 assert.equal(requests.filter(u=>!u.startsWith(base)&&!u.startsWith('data:')).length,0,'External requests including logout');
 assert.equal(errors.length,0,'Browser console/runtime errors');
} finally {ws?.close();chrome.kill('SIGTERM');await new Promise(r=>chrome.once('exit',r));await rm(profile,{recursive:true,force:true});fixture.stdin.end('done\n');await new Promise(r=>fixture.once('exit',r));}
