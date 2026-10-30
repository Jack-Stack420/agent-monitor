
/* ============================================================
   CONFIG
   ============================================================ */
const API_URL = '/api/overview';   // read-only JSON from the local collector API
const REFRESH_MS = 30000;
const USE_SAMPLE = false;           // production API mode

/* Wording. Any key can be overridden by model.lexicon from the API (lexicon.json). */
const LEX = {
  alertsTitle:"Alerts", alertsEmpty:"All quiet. No active alerts.", alertInfo:"Info", alertWarn:"Warn", alertAlarm:"Alarm", alertCritical:"Critical", alertDismiss:"Dismiss", alertSoundOn:"Sound on", alertSoundOff:"Sound off", alertsResolved:"Resolved in the last 24 hours",
  title:'AGENT MONITOR', subtitle:'LOCAL AGENT STATUS',
  sampleTag:'SAMPLE DATA', staleTag:'COLLECTOR STALE',
  agents:'AGENTS', working:'WORKING', recent:'RECENT', idle:'IDLE',
  currentRite:'CURRENT TASK', lastRite:'LAST TASK', lastComm:'LAST ACTIVE', ritesToday:'TASKS TODAY',
  offences:'ERRORS', mood:'STATUS', moodOk:'HEALTHY', moodBad:'DEGRADED',
  limits:'USAGE LIMITS', radar:'LIMITS RADAR', credits:'CREDITS',
  gateway:'GATEWAY', tokens:'TOKENS USED', log:'TASK LOG',
  stOk:'OK', stWarn:'LOW', stCrit:'CRITICAL',
  logRunning:'RUNNING', logDone:'DONE', logFailed:'FAILED',
  footer:'SELF-HOSTED AGENT MONITOR'
};
let TH = { warn:70, alarm:80, crit:90 };   // override from model.thresholds
const PALETTE = ['#c9a24b','#e9dfc9','#e8863a','#8fb0ba','#b5654a','#9bbf8a','#c98fb0'];
// Reserve slots in first-seen API order, including agents with overrides.
// Retain assignments across refreshes, reordering, hiding and reappearance.
const agentColors = new Map();

/* ============================================================
   VIEW MODEL (what render() expects). Note: map the real
   API response to this shape inside adapt().
   {
     updatedAtMs, stale:boolean, lexicon?:{}, thresholds?:{warn,alarm,crit},
     agents:[{id,name,model,status:'working'|'recent'|'idle',
              task:string|null, taskKind:string|null, lastMs:number|null,
              sessionsToday:number, failedToday:number, accent?:string}],
     limits:[{provider,plan,label,pct,resetsAtMs}],
     unreportedProviders:[string],
     credits:{amount,unit}|null,
     gateway:{reachable,latencyMs,service,memoryMb,hostLoadPct}|null,
     days:[{day, tokens:{[agentId]:number}}],
     log:[{atMs, agentName, what, status:'running'|'done'|'failed'}]
   }
   ============================================================ */
function sessionKindDisplay(kind){
  return ({direct:'Direct session',spawn:'Spawn-child session','spawn-child':'Spawn-child session',subagent:'Spawn-child session',cron:'Scheduled job'})[kind] || 'Session';
}

/* Map the read-only API to the reference view model. */
function adapt(raw){
  const at = raw.generatedAt, agents = raw.agents || [];
  const names = new Map(agents.map(a=>[a.id,a.name]));
  const g = raw.gateway;
  return {
    updatedAtMs:raw.health.last_run, stale:raw.health.stale,
    alerts:raw.alertRows || [], alertSummary:raw.alerts || {active:0,highest:null},
    lexicon:raw.lexicon?.dashboard || {},
    thresholds:{warn:raw.thresholds.warn,alarm:raw.thresholds.alarm,crit:raw.thresholds.critical},
    agents:agents.map((a,i)=>({id:a.id,name:a.name,model:a.model || 'unknown',status:a.status,
      task:a.task.label,taskKind:a.task.kind,lastMs:a.task.ageMs==null?null:at-a.task.ageMs,
      sessionsToday:a.sessionsToday,failedToday:a.failedToday,accent:accentFor({id:a.id,accent:a.accent_color},i)})),
    limits:(raw.limits || []).flatMap(p=>p.windows.map(w=>({provider:p.provider,plan:p.plan,
      id:w.id || JSON.stringify([p.provider,w.label]),label:w.label || 'Unknown window',pct:w.usedPercent,resetsAtMs:w.resetAt}))),
    unreportedProviders:(raw.limits || []).filter(p=>!p.windows.length).map(p=>p.provider),
    credits:raw.credits.balances[0] || null,
    creditBalances:raw.credits.balances,
    gateway:g?{reachable:g.reachable,latencyMs:g.connectLatencyMs,service:g.runtimeState,
      memoryMb:g.rssBytes==null?'unknown':Math.round(g.rssBytes/1048576),hostLoadPct:typeof g.hostUtilization==='number' && Number.isFinite(g.hostUtilization) && g.hostUtilization>=0 && g.hostUtilization<=1 ? Math.round(g.hostUtilization*100) : null}:null,
    days:(raw.tokens.daily || []).map(d=>({day:d.date,tokens:d.by_agent || {}})),
    log:(raw.log || []).map(e=>({atMs:e.timestamp,model:e.model,totalTokens:e.totalTokens,start:e.sessionStartedAt,duration:e.durationMs,agentId:e.agent,kind:e.kind || e.type || 'unknown',agentName:names.get(e.agent) || e.command || 'Collector',
      what:e.label || (e.kind ? sessionKindDisplay(e.kind) : null) || e.category || 'Collector event',status:e.type==='collector_error'?'failed':e.status}))
  };
}

/* ============================================================
   HELPERS. All API text goes through textContent, never innerHTML.
   ============================================================ */
const NS = 'http://www.w3.org/2000/svg';
function h(tag, attrs, ...kids){
  const e = document.createElement(tag);
  for (const [k,v] of Object.entries(attrs||{})){
    if (k==='class') e.className = v; else if (k==='style') e.style.cssText = v; else e.setAttribute(k,v);
  }
  for (const k of kids.flat()){ if (k==null) continue; if (k.nodeType) e.append(k); else { const t = document.createTextNode(''); t.textContent = String(k); e.append(t); } }
  return e;
}
function sv(tag, attrs, ...kids){
  const e = document.createElementNS(NS, tag);
  for (const [k,v] of Object.entries(attrs||{})) e.setAttribute(k,v);
  for (const k of kids.flat()){ if (k==null) continue; if (k.nodeType) e.append(k); else { e.textContent = String(k); } }
  return e;
}
const pad = n => String(n).padStart(2,'0');
function ago(ms){
  if (ms==null) return 'unknown';
  const s = Math.max(0, Math.round((Date.now()-ms)/1000));
  if (s<60) return s+' s ago';
  if (s<3600) return Math.floor(s/60)+' min ago';
  if (s<86400) return Math.floor(s/3600)+' h ago';
  return Math.floor(s/86400)+' d ago';
}
function until(ms){
  if (ms==null) return 'unknown';
  const m = Math.max(0, Math.round((ms-Date.now())/60000));
  if (m<60) return m+' min';
  if (m<2880) return Math.floor(m/60)+' h '+pad(m%60)+' m';
  return Math.round(m/1440)+' days';
}
function clock(ms){ const d = new Date(ms); return pad(d.getHours())+':'+pad(d.getMinutes()); }
function level(pct){ return pct>=TH.crit ? 'crit' : (pct>=TH.warn ? 'warn' : 'ok'); }
function levelColor(pct){ const l = level(pct); return l==='crit' ? 'var(--red)' : (l==='warn' ? 'var(--orange)' : 'var(--brass)'); }
function levelWord(pct){ const l = level(pct); return l==='crit' ? LEX.stCrit : (l==='warn' ? LEX.stWarn : LEX.stOk); }
function accentFor(agent, i){
  if (!agentColors.has(agent.id)) agentColors.set(agent.id, PALETTE[agentColors.size % PALETTE.length]);
  return /^#[0-9a-f]{6}$/i.test(agent.accent || '') ? agent.accent : agentColors.get(agent.id);
}
const BINARY = '01001000 01101111 01101100 01111001 00100000 01101111 01101001 01101100 00100000 01100110 01101100 01101111 01110111 01110011 00100000 01110100 01110010 01110101 01100101 ';

// Alert identities exclude mutable text, counts and last-seen timestamps.
const ALERT_RANK={info:0,warn:1,alarm:2,critical:3};
const ALERT_WORD={info:'alertInfo',warn:'alertWarn',alarm:'alertAlarm',critical:'alertCritical'};
const DISMISS_STORAGE='monitor-dismissed-alerts';
const DISMISS_KEY=/^[a-z0-9_:.-]{1,80}$/;
function validatedDismissals(value){
  const clean=Object.create(null);
  if(!value||![Object.prototype,null].includes(Object.getPrototypeOf(value)))return clean;
  let count=0;
  for(const [key,severity] of Object.entries(value)){
    if(count>=200)break;
    if(DISMISS_KEY.test(key)&&!['__proto__','constructor','prototype'].includes(key)&&typeof severity==='string'&&Object.hasOwn(ALERT_RANK,severity)){clean[key]=severity;count++;}
  }
  return clean;
}
function readDismissals(){
  try {
    const stored=localStorage.getItem(DISMISS_STORAGE);
    if(stored===null)return Object.create(null);
    if(stored.length>20480||new TextEncoder().encode(stored).length>20480){localStorage.removeItem(DISMISS_STORAGE);return Object.create(null);}
    const parsed=JSON.parse(stored);
    if(!parsed||Object.getPrototypeOf(parsed)!==Object.prototype){localStorage.removeItem(DISMISS_STORAGE);return Object.create(null);}
    const clean=validatedDismissals(parsed);
    localStorage.setItem(DISMISS_STORAGE,JSON.stringify(clean));
    return clean;
  } catch {try{localStorage.removeItem(DISMISS_STORAGE);}catch{}return Object.create(null);}
}
let dismissedAlerts=readDismissals(),soundEnabled=false,audioContext=null;
let previousAlerts=null;
let resolvedAlertsExpanded=false,hasAlertSnapshot=false,alertRowsCache=[];
try {soundEnabled=localStorage.getItem('monitor-alert-sound')==='true';}catch{}
function saveDismissals(){
  dismissedAlerts=validatedDismissals(dismissedAlerts);
  try{localStorage.setItem(DISMISS_STORAGE,JSON.stringify(dismissedAlerts));}catch{}
}
function alertKey(a){
  if(a.id!=null&&DISMISS_KEY.test('id:'+a.id))return 'id:'+a.id;
  const identity=JSON.stringify(['subject',a.rule,a.subject_key??a.subjectKey??a.subject??a.agentId??a.windowLabel??'global']);
  // Bounded opaque identity; exclude mutable text/count/timestamps.
  return 'subject:'+ [2166136261,2246822507,3266489909,668265263].map(seed=>{
    let hash=seed;for(let i=0;i<identity.length;i++)hash=Math.imul(hash^identity.charCodeAt(i),16777619);
    return (hash>>>0).toString(16).padStart(8,'0');
  }).join('');
}
function severityText(severity){return LEX[ALERT_WORD[severity]]||LEX.alertInfo;}
function severityShape(severity,x=10,y=10){
  const attrs={fill:'none',stroke:'#e9dfc9','stroke-width':2,'data-severity-shape':severity};
  if(severity==='critical')return sv('rect',{...attrs,x:x-7,y:y-7,width:14,height:14});
  if(severity==='alarm')return sv('polygon',{...attrs,points:[x+","+(y-9),(x+9)+","+y,x+","+(y+9),(x-9)+","+y].join(" ")});
  if(severity==='warn')return sv('polygon',{...attrs,points:[x+","+(y-9),(x+9)+","+(y+7),(x-9)+","+(y+7)].join(" ")});
  return sv('circle',{...attrs,cx:x,cy:y,r:7});
}
function severityMarker(severity){return h('span',{class:'severity-marker','data-severity':severity},sv('svg',{width:20,height:20,viewBox:'0 0 20 20','aria-hidden':'true'},severityShape(severity)),severityText(severity));}
function activeAlerts(m=currentModel){return (m?.alerts||[]).filter(a=>a.state==='active' && Object.hasOwn(ALERT_RANK,a.severity));}
function matchedAlertWindow(a,m=currentModel){
  if(a.rule!=='limit_window'||typeof a.windowLabel!=='string')return null;
  const matches=(m?.limits||[]).filter(l=>l.label===a.windowLabel&&
    (typeof a.provider!=='string'||!a.provider||l.provider===a.provider));
  return matches.length===1?matches[0]:null;
}
function windowAlert(l){return activeAlerts().filter(a=>matchedAlertWindow(a)===l).sort((a,b)=>ALERT_RANK[b.severity]-ALERT_RANK[a.severity])[0];}
function playAlertTone(){
  if(!audioContext || audioContext.state!=='running')return;
  try {const oscillator=audioContext.createOscillator(),gain=audioContext.createGain(),t=audioContext.currentTime;
    oscillator.frequency.value=660;gain.gain.setValueAtTime(0.06,t);gain.gain.exponentialRampToValueAtTime(0.001,t+0.16);
    oscillator.connect(gain);gain.connect(audioContext.destination);oscillator.start(t);oscillator.stop(t+0.18);
  } catch {}
}
async function toggleAlertSound(){
  soundEnabled=!soundEnabled;
  if(soundEnabled){try {audioContext=audioContext||new (window.AudioContext||window.webkitAudioContext)();await audioContext.resume();} catch {soundEnabled=false;}}
  try {localStorage.setItem('monitor-alert-sound',String(soundEnabled));}catch{}
  if(currentModel&&!sessionExpired)render(currentModel);
}
function updateAlertSignals(m,active){
  const count=active.filter(a=>ALERT_RANK[a.severity]>=1).length;
  document.title=(count?'('+count+') ':'')+'Agent Monitor';
  const highest=active.reduce((s,a)=>ALERT_RANK[a.severity]>ALERT_RANK[s]?a.severity:s,'info');
  const summary=m.alertSummary?.highest;
  const severity=ALERT_RANK[summary]>ALERT_RANK[highest]?summary:highest;
  const icon=document.querySelector('link[rel="icon"]');
  if(icon){const svg=sv('svg',{xmlns:NS,viewBox:'0 0 20 20'},severityShape(severity));icon.href='data:image/svg+xml,'+encodeURIComponent(new XMLSerializer().serializeToString(svg));}
  const now=new Map(active.map(a=>[alertKey(a),a.severity]));
  // The first successful snapshot establishes a baseline, not a new arrival.
  if(previousAlerts && soundEnabled && !document.hidden && active.some(a=>ALERT_RANK[a.severity]>=2&&!previousAlerts.has(alertKey(a))))playAlertTone();
  previousAlerts=now;
}
function alertPanel(m){
  const all=activeAlerts(m).sort((a,b)=>ALERT_RANK[b.severity]-ALERT_RANK[a.severity]||(b.firstSeen||0)-(a.firstSeen||0));
  updateAlertSignals(m,all);
  const visible=all.filter(a=>!Object.hasOwn(dismissedAlerts,alertKey(a))||ALERT_RANK[a.severity]>ALERT_RANK[dismissedAlerts[alertKey(a)]]);
  const panel=h('section',{class:'panel alerts-panel','aria-label':LEX.alertsTitle},
    h('div',{class:'cardhead'},h('h2',{},LEX.alertsTitle),h('span',{class:'sub alerts-summary'},String(m.alertSummary?.active??all.length)+' active'+(m.alertSummary?.highest?' · '+severityText(m.alertSummary.highest):'')),button(soundEnabled?LEX.alertSoundOn:LEX.alertSoundOff,toggleAlertSound,{'aria-pressed':String(soundEnabled),'data-focus':'alert-sound',id:'alert-sound'})));
  const row=(a,resolved=false)=>{
    const agent=m.agents.find(agent=>agent.id===a.agentId);
    const window=matchedAlertWindow(a,m);
    const detail=window ? (window.provider+' '+(window.plan||'')+' '+window.label).trim().toUpperCase()+' · '+(window.pct==null?'unknown':window.pct+'%')+' · resets in '+until(window.resetsAtMs) : null;
    const text=h('div',{class:'alert-copy'},h('p',{class:'alert-message'},a.message),detail?h('p',{class:'sub alert-limit'},detail):null,
      h('p',{class:'sub'},ago(a.firstSeen)+' · '+(agent?.name||a.agentId||a.windowLabel||a.rule)));
    const item=h('li',{class:'alert-row','data-alert-key':alertKey(a)},severityMarker(a.severity),text);
    if(!resolved)item.append(button(LEX.alertDismiss,()=>{dismissedAlerts[alertKey(a)]=a.severity;saveDismissals();render(currentModel);},{'data-dismiss':alertKey(a),'data-focus':'dismiss:'+alertKey(a)}));
    return item;
  };
  panel.append(visible.length?h('ul',{class:'alert-list active-alerts'},visible.map(a=>row(a))):h('p',{class:'sub alerts-empty'},LEX.alertsEmpty));
  const resolved=(m.alerts||[]).filter(a=>a.state==='resolved'&&Object.hasOwn(ALERT_RANK,a.severity)&&a.resolvedAt>=Date.now()-86400000&&a.resolvedAt<=Date.now()).sort((a,b)=>b.resolvedAt-a.resolvedAt);
  const details=h('details',{class:'resolved-alerts'},h('summary',{},LEX.alertsResolved+' ('+resolved.length+')'),h('ul',{class:'alert-list'},resolved.map(a=>row(a,true))));
  details.open=resolvedAlertsExpanded;
  details.addEventListener('toggle',()=>{
    if(!details.isConnected||details.open===resolvedAlertsExpanded)return;
    resolvedAlertsExpanded=details.open;if(resolvedAlertsExpanded)load();
  });
  panel.append(details);
  return panel;
}

/* ============================================================
   RENDER
   ============================================================ */
function gearIcon(){
  return sv('svg',{width:56,height:56,viewBox:'0 0 44 44',fill:'none',stroke:'#c9a24b','stroke-width':2.5,'stroke-linecap':'round','aria-hidden':'true'},
    sv('circle',{cx:22,cy:22,r:8}), sv('circle',{cx:22,cy:22,r:14}),
    sv('path',{d:'M22 3V8M22 36V41M3 22H8M36 22H41M8.6 8.6L12 12M32 32L35.4 35.4M35.4 8.6L32 12M12 32L8.6 35.4'}));
}

function spiritCard(a){
  const working = a.status==='working';
  const statusWord = working ? LEX.working : (a.status==='recent' ? LEX.recent : LEX.idle);
  const badge = working
    ? h('span',{class:'badge on'}, statusWord)
    : h('span',{class:'badge off'}, statusWord);
  const duty = a.task || (a.taskKind ? sessionKindDisplay(a.taskKind) : 'No record');
  const bad = a.failedToday>0;
  const card = h('article',{class:'panel spirit',role:'button',tabindex:0,'aria-pressed':String(state.agent===a.id),'data-agent':a.id,'data-focus':'card:'+a.id},
    h('div',{class:'cardhead'},
      h('div',{}, h('h3',{}, a.name.toUpperCase()), h('p',{class:'sub'}, a.id+' · '+a.model)),
      badge),
    h('div',{}, h('p',{class:'lbl'}, working ? LEX.currentRite : LEX.lastRite), h('p',{class:'duty'}, duty)),
    h('div',{class:'stats'},
      h('div',{}, h('span',{class:'lbl'}, LEX.lastComm), h('b',{}, ago(a.lastMs))),
      h('div',{}, h('span',{class:'lbl'}, LEX.ritesToday), h('b',{}, a.sessionsToday)),
      h('div',{}, h('span',{class:'lbl'}, LEX.offences), h('b',{style:'color:'+(bad?'var(--red)':'var(--bone)')}, a.failedToday)),
      h('div',{}, h('span',{class:'lbl'}, LEX.mood), h('b',{style:'color:'+(bad?'var(--red)':'var(--bone)')}, bad?LEX.moodBad:LEX.moodOk))));
  card.addEventListener('click',()=>selectAgent(a.id));
  card.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();if(!e.repeat)selectAgent(a.id);}});
  return card;
}

function radar(limits){
  const n = limits.length || 1;
  const svg = sv('svg',{viewBox:'0 0 380 380',width:'100%',role:'group',
    'aria-label':'Radar of limit consumption. Distance from the centre is the share used.'});
  svg.append(sv('path',{d:'M190 190 L190 20 A170 170 0 0 1 310 70 Z',fill:'#c9a24b','fill-opacity':.12}));
  [34,68,102].forEach(r=>svg.append(sv('circle',{cx:190,cy:190,r,fill:'none',stroke:'#5a3a33','stroke-width':1.5})));
  svg.append(sv('circle',{cx:190,cy:190,r:170*TH.alarm/100,fill:'none',stroke:'#c9a24b','stroke-width':1.5,'stroke-dasharray':'4 5'}));
  svg.append(sv('circle',{cx:190,cy:190,r:170,fill:'none',stroke:'#7a5248','stroke-width':2}));
  svg.append(sv('path',{d:'M190 20V360M20 190H360',stroke:'#3a2420','stroke-width':1.5}));
  svg.append(sv('circle',{cx:190,cy:190,r:5,fill:'#c9a24b'}));
  [['20',153],['40',119],['60',85],['80',51]].forEach(([t,y])=>svg.append(sv('text',{x:196,y,'font-size':11,fill:t==='80'?'#c9a24b':'#a89886','font-family':'Share Tech Mono,monospace'},t)));
  limits.forEach((l,i)=>{
    const r = Math.min(100,l.pct)/100*170, a = ((40 + i*(360/n))%360)*Math.PI/180;
    const x = Math.round((190 + r*Math.sin(a))*10)/10, y = Math.round((190 - r*Math.cos(a))*10)/10;
    const blip = sv('g',{tabindex:0,class:'radar-blip',role:'img'});
    const detail=l.provider+' · '+l.label+'\nPercent used: '+(l.pct==null?'unknown':l.pct+'%')+'\nReset time: '+exactTime(l.resetsAtMs);
    attachTooltip(blip,detail);
    const alert=windowAlert(l), shape = i%3;
    if(alert) blip.append(severityShape(alert.severity,x,y));
    else
    if (shape===0) blip.append(sv('circle',{cx:x,cy:y,r:9,fill:'#c9a24b'}));
    else if (shape===1) blip.append(sv('circle',{cx:x,cy:y,r:9,fill:'#150b09',stroke:'#e9dfc9','stroke-width':3}));
    else blip.append(sv('polygon',{points:`${x},${y-11} ${x+11},${y} ${x},${y+11} ${x-11},${y}`,fill:'#e8863a'}));
    svg.append(blip);
    const left = x>250;
    svg.append(sv('text',{x:left?x-14:x+14,y:y+4,'text-anchor':left?'end':'start','font-size':12,'font-weight':700,fill:'#e9dfc9','font-family':'Share Tech Mono,monospace'}, l.label.toUpperCase()+' '+(l.pct==null?'unknown':l.pct+'%')+(alert?' · '+severityText(alert.severity):'')));
  });
  return svg;
}

function limitBar(l){
  const container=h('div',{},
    h('div',{class:'barhead'}, h('span',{}, (l.provider+' '+(l.plan||'')+' · '+l.label).toUpperCase()),
      h('span',{style:'color:'+levelColor(l.pct)+';letter-spacing:.08em'}, (l.pct==null?'NOT REPORTED':levelWord(l.pct))+' · '+(l.pct==null?'unknown':l.pct+'%'))),
    h('div',{class:'bar',role:'button',tabindex:0,'aria-expanded':String(state.expanded===l.id),'data-focus':'limit:'+l.id}, h('i',{style:'width:'+Math.min(100,l.pct)+'%;background:'+levelColor(l.pct)}), h('u',{style:'left:'+TH.alarm+'%'})),
    h('p',{class:'sub',style:'margin-top:4px'}, 'Resets in '+until(l.resetsAtMs)));
  const alert=windowAlert(l);
  if(alert)container.querySelector('.barhead').append(severityMarker(alert.severity));
  const bar=container.querySelector('.bar');
  const toggle=async()=>{state.expanded=state.expanded===l.id?'':l.id;writeHash();render(currentModel);if(state.expanded)await loadHistory();};
  bar.addEventListener('click',toggle);
  bar.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();if(!e.repeat)toggle();}});
  if(state.expanded===l.id)container.append(sparkline(l.id));
  return container;
}
function sparkline(id){
  const points=historyData?.find(w=>w.id===id)?.points||[];
  if(!points.length)return h('p',{class:'sub limit-history'},historyError?'History unavailable':historyData?'No history in the last 72 hours':'Loading history…');
  const values=points.map(p=>p.usedPercent),min=Math.min(...values),max=Math.max(...values);
  const low=Math.min(0,min,TH.alarm),high=Math.max(100,max,TH.alarm),y=v=>100-(v-low)/(high-low)*80;
  const first=points[0].timestamp,span=Math.max(1,points.at(-1).timestamp-first);
  return h('div',{class:'limit-history'},h('p',{class:'sub'},'72 hours · Min '+min+'% · Max '+max+'%'),
    sv('svg',{viewBox:'0 0 320 120',width:'100%',role:'img','aria-label':'Limit history'},
      sv('line',{x1:10,x2:310,y1:y(TH.alarm),y2:y(TH.alarm),stroke:'#e9dfc9','stroke-dasharray':'4 4',class:'alarm-line'}),
      sv('polyline',{points:points.map(p=>(10+(p.timestamp-first)/span*300)+','+y(p.usedPercent)).join(' '),fill:'none',stroke:'#c9a24b','stroke-width':2}),
      ...points.length===1?[sv('circle',{cx:10,cy:y(values[0]),r:3,fill:'#c9a24b'})]:[],
      sv('text',{x:10,y:115,fill:'#a89886','font-size':10},'Alarm '+TH.alarm+'%')));
}
async function requestData(url){const r=await fetch(url,{cache:'no-store'});if(r.status===401){expireSession();throw new Error('unauthorized');}
    if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}
async function loadHistory(){
  try{historyData=(await requestData('/api/limits/history?hours=72')).data;historyError=false;}
  catch{historyData=null;historyError=true;}
  if(currentModel&&!sessionExpired)render(currentModel);
}
function tokenRanges(){return h('div',{class:'controls',role:'group','aria-label':'Token range'},[7,14,30].map(days=>button(days+' days',()=>{state.range=days;writeHash();load();},{'aria-pressed':String(state.range===days),'data-range':days,'data-focus':'range:'+days})));}


function render(m){
  currentModel=m;
  validateState(m.agents||[],m.limits||[]);
  const focused=document.activeElement?.getAttribute('data-focus');
  const selection=focused==='search'?[document.activeElement.selectionStart,document.activeElement.selectionEnd]:null;
  hideTooltip();
  Object.assign(LEX, m.lexicon||{});
  if (m.thresholds) TH = Object.assign({}, TH, m.thresholds);
  const agents = m.agents||[], limits = m.limits||[];
  const working = agents.filter(a=>a.status==='working').length;
  const idle = agents.length - working;
  const offences = agents.reduce((n,a)=>n+(a.failedToday||0),0);
  const app = document.getElementById('app');
  app.replaceChildren();

  app.append(h('div',{class:'ribbon','aria-hidden':'true'}, BINARY.repeat(3)));
  app.append(h('header',{class:'head'},
    h('div',{class:'brand'}, gearIcon(), h('div',{}, h('h1',{}, LEX.title), h('p',{}, LEX.subtitle))),
    h('div',{class:'meta'}, USE_SAMPLE ? h('span',{class:'tag'}, LEX.sampleTag) : null, h('span',{}, 'Updated '+ago(m.updatedAtMs)), headerControls())));
  if (m.stale) app.append(h('div',{class:'warn',role:'alert'}, LEX.staleTag+': the collector has not reported recently, so this data may be out of date.'));

  app.append(h('section',{class:'strip','aria-label':'Summary'},
    h('span',{}, agents.length+' '+LEX.agents), h('span',{style:'color:var(--brass)'}, working+' '+LEX.working),
    h('span',{style:'color:var(--dim)'}, idle+' '+LEX.idle), h('span',{style:'color:var(--red)'}, offences+' '+LEX.offences),
    m.gateway ? h('span',{style:'color:var(--brass)'}, m.gateway.reachable ? 'GATEWAY REACHABLE · '+m.gateway.latencyMs+' MS' : 'GATEWAY UNREACHABLE') : null));

  app.append(alertPanel(m));

  app.append(h('section',{class:'row agents-row','aria-label':'Agents'}, agents.map(spiritCard)));

  const lim = h('div',{class:'panel',role:'group','aria-label':'Limits', style:'gap:16px'}, h('h2',{}, LEX.limits));
  if (limits.length) limits.forEach(l=>lim.append(limitBar(l)));
  else lim.append(h('p',{class:'sub'}, 'No provider has reported limit windows yet.'));
  (m.unreportedProviders||[]).forEach(p=>lim.append(h('p',{class:'sub',style:'border-top:1px solid var(--line);padding-top:12px'}, p.toUpperCase()+' · LIMITS NOT REPORTED BY THE PROVIDER')));
  lim.append(h('p',{class:'sub'}, 'PALE LINE = '+TH.alarm+'% · PAST IT AN ALERT IS RAISED'));

  const right = h('div',{class:'limits-column',style:'flex:1 1 560px;min-width:0;display:flex;flex-direction:column;gap:22px'}, lim);
  for (const balance of (m.creditBalances || (m.credits?[m.credits]:[]))) right.append(h('div',{class:'panel',style:'flex-direction:row;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 24px;padding:22px 28px'},
    h('div',{}, h('h2',{}, LEX.credits), h('p',{class:'sub',style:'margin-top:4px'}, 'CREDIT BALANCE REMAINING')),
    h('p',{class:'big'}, (balance.amount==null?'unknown':Number(balance.amount).toFixed(1))+' ', h('small',{}, String(balance.unit||'').toUpperCase()))));
  const gatewayColumn = h('div',{class:'gateway-column'});
  if (m.gateway) {
    const g = m.gateway, cell = (k,v)=>h('div',{}, h('span',{class:'lbl'}, k), h('b',{style:'display:block;font:400 18px var(--mono);margin-top:2px'}, v));
    gatewayColumn.append(h('div',{class:'panel gateway-panel',style:'padding:22px 28px;gap:10px'}, h('h2',{}, LEX.gateway),
      h('div',{class:'stats'}, cell('LINK', g.reachable?'REACHABLE':'UNREACHABLE'), cell('LATENCY', g.latencyMs+' MS'),
        cell('SERVICE', String(g.service).toUpperCase()), cell('MEMORY', g.memoryMb+' MB'), cell('HOST LOAD', g.hostLoadPct==null?'unknown':g.hostLoadPct+'%'))));
  }
  const telemetry=h('section',{class:'row top telemetry'},
    h('aside',{class:'panel radar-panel',style:'flex:0 1 460px'}, h('h2',{}, LEX.radar), radar(limits),
      h('p',{class:'sub',style:'line-height:1.5'}, 'DISTANCE FROM THE CENTRE IS THE SHARE OF A LIMIT CONSUMED. THE DASHED BRASS RING IS THE '+TH.alarm+'% ALARM LINE.')),
    right, gatewayColumn);
  app.append(telemetry);

  const days = m.days||[];
  const totals = days.map(d=>Object.values(d.tokens||{}).reduce((s,v)=>s+v,0));
  const max = Math.max(1, ...totals);
  const chart = h('div',{class:'chart'}, days.map((d,di)=>h('div',{},
    h('small',{}, Math.round(totals[di]/1000)+'k'),
    ...agents.slice().reverse().map((a)=>{ const i = agents.indexOf(a); const v = (d.tokens||{})[a.id]||0; const segment=h('div',{class:'token-segment'+(state.agent&&state.agent!==a.id?' dimmed':''),tabindex:0,role:'img','data-agent':a.id,style:'height:'+(v>0?Math.max(1,v/max*150):0)+'px;background:'+accentFor(a,i)}); attachTooltip(segment,a.name+' · '+d.day+'\nTokens: '+v); return segment; }))));
  const tokens = h('article',{class:'panel token-panel'}, h('h2',{}, LEX.tokens), tokenRanges(), chart,
    h('div',{class:'days'}, days.map(d=>h('span',{}, d.day))),
    h('div',{class:'legend'}, agents.map((a,i)=>h('span',{}, h('i',{style:'background:'+accentFor(a,i)}), a.name.toUpperCase()))),
    h('p',{class:'sub'}, 'ESTIMATED FROM SESSION TOKEN TOTALS'));

  gatewayColumn.append(tokens);
  const log=h('article',{class:'panel log-panel',style:'gap:0'},h('h2',{},LEX.log),logControls(agents),
    h('table',{class:'log-table'},h('caption',{id:'log-count'}),
      h('thead',{},h('tr',{},['Time','Agent','Task','Kind','Result'].map(t=>h('th',{scope:'col'},t)))),h('tbody',{id:'log-rows'})),
    button('Show more',showMore,{'data-focus':'more',id:'show-more'}));
  log.querySelector('#show-more').disabled=state.limit>=LOG_MAX||loading;
  app.append(log);
  renderLogRows();
  layoutPanels();
  app.append(h('footer',{class:'foot'}, LEX.footer));
  if(focused) [...app.querySelectorAll('[data-focus]')].find(e=>e.getAttribute('data-focus')===focused)?.focus();
  if(selection)app.querySelector('#task-search').setSelectionRange(...selection);
}

function layoutPanels(){
  const app=document.getElementById('app'), column=app.querySelector('.gateway-column');
  if(!column)return;
  const gateway=app.querySelector('.gateway-panel'),tokens=app.querySelector('.token-panel');
  if(matchMedia('(min-width:1000px)').matches){if(gateway)column.append(gateway);column.append(tokens);}
  else {if(gateway)app.querySelector('.limits-column').append(gateway);app.insertBefore(tokens,app.querySelector('.log-panel'));}
}
function renderError(err){
  const app = document.getElementById('app');
  hideTooltip();
  app.replaceChildren(headerControls(),h('div',{class:'warn',role:'alert'}, 'Cannot reach the monitor API at '+API_URL+'. Check that the service is running. ('+err.message+')'));
}

// State is validated only against the current API roster, never CSS selectors or HTML.
const STATUSES=['all','running','done','failed'];
const LOG_MAX=100, LOG_STEP=20;
const state={agent:'',status:'all',search:'',limit:20,paused:false,range:7,expanded:''};
let historyData=null,historyError=false;
let currentModel=null, lastUpdated=null, loading=false, timer=null, tooltipId=0, reloadRequested=false, loadGeneration=0;
try {state.paused=localStorage.getItem('monitor-paused')==='true';} catch {}
function exactTime(ms){return ms==null?'unknown':new Date(ms).toISOString();}
function validateState(agents,limits=currentModel?.limits||[]){
  if(![7,14,30].includes(state.range))state.range=7;
  if(!limits.some(l=>l.id===state.expanded))state.expanded='';
  if(!agents.some(a=>a.id===state.agent))state.agent='';
  if(!STATUSES.includes(state.status))state.status='all';
}
function readHash(agents,limits=currentModel?.limits||[]){
  const params=new URLSearchParams(location.hash.slice(1));
  const one=k=>params.getAll(k).length===1?params.get(k):null;
  state.agent=agents.some(a=>a.id===one('agent'))?one('agent'):'';
  state.status=STATUSES.includes(one('status'))?one('status'):'all';
  state.range=[7,14,30].includes(Number(one('range')))?Number(one('range')):7;
  state.expanded=limits.some(l=>l.id===one('window'))?one('window'):'';
  const q=one('q');
  // Restrict bookmarked searches to printable task-title text, not markup/control strings.
  state.search=typeof q==='string'&&q.length<=200&&!/[<>\x00-\x1f\x7f]/.test(q)?q:'';
  writeHash();
}
function writeHash(){
  const p=new URLSearchParams();
  if(state.agent)p.set('agent',state.agent);
  if(state.status!=='all')p.set('status',state.status);
  if(state.search)p.set('q',state.search);
  if(state.range!==7)p.set('range',state.range);
  if(state.expanded)p.set('window',state.expanded);
  const hash=p.toString();
  history.replaceState(null,'',location.pathname+location.search+(hash?'#'+hash:''));
}
function button(text,fn,attrs={}){const b=h('button',{type:'button',...attrs},text);b.addEventListener('click',fn);return b;}
function selectAgent(id){
  if(!currentModel?.agents.some(a=>a.id===id))return;
  state.agent=state.agent===id?'':id;writeHash();render(currentModel);
}
let sessionExpired=false;
function expireSession(){
 sessionExpired=true;reloadRequested=false;clearTimeout(timer);timer=null;
 document.getElementById('app').replaceChildren(h('div',{class:'warn'},'Session expired, sign in again. ',h('a',{href:'/login'},'Sign in')));
}
async function signedOut(){
 const csrf=document.querySelector('meta[name="cp-csrf"]').content;
 await fetch('/logout',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf})});location.href='/login';
}
function headerControls(){
  return h('div',{class:'controls'},
    h('span',{},'Signed in'),button('Sign out',signedOut,{'data-focus':'signout'}),
    button('Refresh now',()=>load(),{'data-focus':'refresh'}),
    button(state.paused?'Resume auto-refresh':'Pause auto-refresh',togglePause,{'data-focus':'pause','aria-pressed':String(state.paused)}),
    h('span',{id:'last-updated'},'Last updated: '+(lastUpdated?new Date(lastUpdated).toLocaleTimeString():'not yet')+(document.hidden?' · polling suspended (tab hidden)':'')));
}
function togglePause(){
  state.paused=!state.paused;
  try{localStorage.setItem('monitor-paused',String(state.paused));}catch{}
  schedulePoll();if(currentModel&&!sessionExpired)render(currentModel);
}
function schedulePoll(){
  clearTimeout(timer);timer=null;
  if(!sessionExpired&&!state.paused&&!document.hidden)timer=setTimeout(()=>load(),REFRESH_MS);
}
function logControls(agents){
  const agentChips=h('div',{class:'filter-group',role:'group','aria-label':'Filter by agent'},
    button('All agents',()=>{state.agent='';writeHash();render(currentModel);},{'aria-pressed':String(!state.agent),'data-focus':'all-agents'}),
    agents.map(a=>button(a.name,()=>selectAgent(a.id),{'aria-pressed':String(state.agent===a.id),'data-agent-chip':a.id,'data-focus':'chip:'+a.id})));
  const statuses=h('div',{class:'filter-group',role:'group','aria-label':'Filter by status'},STATUSES.map(status=>button(status,()=>{
    state.status=status;writeHash();render(currentModel);
  },{'aria-pressed':String(state.status===status),'data-status':status,'data-focus':'status:'+status})));
  const search=h('input',{type:'search',id:'task-search',maxlength:200,placeholder:'Search task titles','data-focus':'search'});
  search.value=state.search;
  search.addEventListener('input',()=>{state.search=search.value.slice(0,200);writeHash();renderLogRows();});
  return h('div',{class:'filters'},agentChips,statuses,h('label',{for:'task-search'},'Search task titles'),search);
}
function filteredLog(){return (currentModel?.log||[]).filter(e=>(!state.agent||e.agentId===state.agent)&&(state.status==='all'||e.status===state.status)&&e.what.toLocaleLowerCase().includes(state.search.toLocaleLowerCase()));}
function renderLogRows(){
  const rows=document.getElementById('log-rows');if(!rows)return;
  const entries=filteredLog();
  rows.replaceChildren(...entries.map(e=>{
    const word=e.status==='failed'?LEX.logFailed:e.status==='running'?LEX.logRunning:LEX.logDone;
    const color=e.status==='failed'?'var(--red)':e.status==='running'?'var(--brass)':'var(--bone)';
    const row=h('tr',{class:'log',tabindex:0,role:'button','aria-expanded':'false'},h('td',{class:'t'},clock(e.atMs)),h('td',{class:'w'},e.agentName.toUpperCase()),h('td',{class:'x'},e.what),h('td',{class:'kind'},e.kind),h('td',{style:'color:'+color},word));
    const toggle=()=>{
      if(row.nextElementSibling?.classList.contains('log-detail')){row.nextElementSibling.remove();row.setAttribute('aria-expanded','false');return;}
      row.setAttribute('aria-expanded','true');
      row.after(h('tr',{class:'log-detail'},h('td',{colspan:5},'Kind: '+e.kind+' · Model: '+(e.model||'unknown')+' · Tokens: '+(e.totalTokens??'unknown')+' · Start: '+exactTime(e.start)+' · Duration: '+(e.duration==null?'unknown':e.duration+' ms'))));
    };
    row.addEventListener('click',toggle);row.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();if(!event.repeat)toggle();}});
    return row;
  }));
  document.getElementById('log-count').textContent=entries.length+' matching rows / '+(currentModel?.log.length||0)+' loaded (request limit '+state.limit+' / '+LOG_MAX+')';
}
async function showMore(){if(state.limit>=LOG_MAX||loading)return;state.limit=Math.min(LOG_MAX,state.limit+LOG_STEP);await load();}
function hideTooltip(){document.querySelector('.tooltip')?.remove();}
function attachTooltip(el,text){
  const id='value-tip-'+(++tooltipId);
  const nameId=id+'-name';
  el.append(el.namespaceURI===NS?sv('title',{id:nameId},text):h('span',{id:nameId,class:'sr-only'},text));
  el.setAttribute('aria-labelledby',nameId);
  const show=()=>{hideTooltip();const tip=h('div',{id,class:'tooltip',role:'tooltip'},text);document.body.append(tip);el.setAttribute('aria-describedby',id);
    const r=el.getBoundingClientRect();tip.style.left=Math.max(8,Math.min(r.left,innerWidth-tip.offsetWidth-8))+'px';tip.style.top=Math.max(8,Math.min(r.bottom+8,innerHeight-tip.offsetHeight-8))+'px';};
  const hide=()=>{hideTooltip();el.removeAttribute('aria-describedby');};
  el.addEventListener('mouseenter',show);el.addEventListener('mouseleave',hide);
  el.addEventListener('focus',show);el.addEventListener('blur',hide);
  el.addEventListener('keydown',e=>{if(e.key==='Escape')hide();});
}
let hashRestored=false;
async function load(){
  if(sessionExpired)return;
  const generation=++loadGeneration;
  if(loading){reloadRequested=true;return;}
  loading=true;
  try {
    const r=await fetch(API_URL,{cache:'no-store'});
    if(r.status===401){expireSession();throw new Error('unauthorized');}
    if(!r.ok)throw new Error('HTTP '+r.status);
    const raw=await r.json();
    if(state.limit>LOG_STEP){
      const log=await fetch('/api/log?limit='+Math.min(LOG_MAX,Math.max(1,state.limit)),{cache:'no-store'});
      if(log.status===401){expireSession();throw new Error('unauthorized');}
      if(!log.ok)throw new Error('HTTP '+log.status);
      raw.log=(await log.json()).data;
    }
    const fetchAlerts=!hasAlertSnapshot||Number(raw.alerts?.active)>0||resolvedAlertsExpanded;
    raw.alertRows=fetchAlerts?(await requestData('/api/alerts?state=all&limit=200')).data||[]:
      alertRowsCache.filter(a=>a.state==='resolved');
    const model=adapt(raw);
    if(!hashRestored){readHash(model.agents,model.limits);hashRestored=true;}
    const range=state.range;
    if(range!==7)model.days=((await requestData('/api/tokens?days='+range)).data.daily||[]).map(d=>({day:d.date,tokens:d.by_agent||{}}));
    if(state.expanded){try{historyData=(await requestData('/api/limits/history?hours=72')).data;historyError=false;}catch{historyError=true;historyData=null;}}
    // Loads are serialized; a queued refresh invalidates the in-flight result.
    // Never publish data fetched for an older selection (including 7-day data).
    if(sessionExpired||generation!==loadGeneration||range!==state.range)return;
    hasAlertSnapshot=true;alertRowsCache=raw.alertRows;
    // Forget dismissals only after a successful snapshot observes the lifecycle ended.
    // This lets a later synthetic occurrence with the same rule/subject reappear.
    const activeKeys=new Set(activeAlerts(model).map(alertKey));
    for(const key of Object.keys(dismissedAlerts))if(!activeKeys.has(key))delete dismissedAlerts[key];
    saveDismissals();
    validateState(model.agents,model.limits);writeHash();lastUpdated=Date.now();
    loading=false;render(model);
  } catch(e){if(!sessionExpired&&generation===loadGeneration)renderError(e);} finally {loading=false;if(reloadRequested&&!sessionExpired){reloadRequested=false;queueMicrotask(()=>load());}else schedulePoll();}
}
matchMedia('(min-width:1000px)').addEventListener('change',layoutPanels);
window.addEventListener('hashchange',()=>{if(currentModel){const previous=state.range;readHash(currentModel.agents);render(currentModel);if(previous!==state.range)load();else if(state.expanded)loadHistory();}});
document.addEventListener('visibilitychange',()=>{schedulePoll();if(currentModel)render(currentModel);});
load();
