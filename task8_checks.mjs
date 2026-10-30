// Synthetic-only CDP regressions; never return task labels or DOM dumps.
import assert from 'node:assert/strict';
export async function checkTask8(call,evaluate){
 await call('Page.bringToFront');
 await call('Emulation.setFocusEmulationEnabled',{enabled:true});
 const widths=[];
 for(const width of [640,999,1000,1499,1500,1799,1800,2400]){
  await call('Emulation.setDeviceMetricsOverride',{width,height:1100,deviceScaleFactor:1,mobile:false});
  const got=await evaluate('('+(()=>{layoutPanels();const css=s=>getComputedStyle(document.querySelector(s));const box=s=>document.querySelector(s).getBoundingClientRect();return {width:box('.wrap').width,columns:css('.telemetry').gridTemplateColumns.split(' ').length,agentsGrid:css('.agents-row').display,font:parseFloat(css('body').fontSize),radar:box('.radar-panel svg').width,radarPanel:box('.radar-panel').width,fullLog:Math.abs(box('.log-panel').width-box('.wrap').width)<1,mobileGateway:document.querySelector('.gateway-panel')?.parentElement.classList.contains('limits-column'),mobileTokens:document.querySelector('.token-panel').parentElement.id==='app',overflow:document.documentElement.scrollWidth>innerWidth};}).toString()+')()');
  assert.equal(got.columns,width<1000?1:width<1500?2:3,'Telemetry breakpoint '+width);
  assert.equal(got.agentsGrid,width<1000?'flex':'grid');assert.equal(got.font,width>=1800?16.5:15);
  if(width>=1000)assert.ok(Math.abs(got.width-Math.min(width*.96,2200))<1);
  else {assert.equal(got.mobileGateway,true);assert.equal(got.mobileTokens,true);}
  assert.ok(got.radar<=got.radarPanel&&got.radar>0);assert.equal(got.fullLog,true);assert.equal(got.overflow,false,'No horizontal overflow '+width);widths.push(width);
 }
 const interactions=await evaluate('('+(async()=>{
  state.agent='';state.status='all';state.search='';
  const live=await (await fetch(API_URL)).json(),template=live.agents[0];
  const raw=structuredClone(live);
  raw.agents=['synthetic-one','synthetic-two','synthetic-new'].map((id,i)=>({...template,id,name:'Synthetic '+i,task:{label:'Synthetic title',kind:'direct',ageMs:0}}));
  raw.tokens.daily=[{date:'2026-10-28',by_agent:Object.fromEntries(raw.agents.map(a=>[a.id,123456]))}];
  raw.limits=[{provider:'synthetic',windows:[{label:'Synthetic window',usedPercent:37.25,resetAt:1800000000000}]}];
  raw.log=[['synthetic-one','failed','Synthetic Alpha'],['synthetic-one','done','Synthetic Beta'],['synthetic-two','running','Synthetic Alpha']].map(([agent,status,label])=>({agent,status,label,kind:'direct',timestamp:1800000000000}));
  render(adapt(raw));
  const count=()=>document.querySelectorAll('#log-rows tr').length;
  const cards=()=>[...document.querySelectorAll('.spirit')];
  const dynamic=cards().length===3&&document.querySelectorAll('[data-agent-chip]').length===3;
  cards()[0].click();
  const selection=state.agent==='synthetic-one'&&count()===2&&cards()[0].getAttribute('aria-pressed')==='true'&&document.querySelectorAll('.dimmed').length===2;
  cards()[0].focus();cards()[0].dispatchEvent(new KeyboardEvent('keydown',{key:' '}));
  const spaceClears=!state.agent&&count()===3;
  cards()[0].dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}));
  const enterSelects=state.agent==='synthetic-one'&&document.activeElement===cards()[0]&&getComputedStyle(cards()[0]).outlineStyle!=='none';
  document.querySelector('[data-status="failed"]').click();
  const status=count()===1&&state.status==='failed';
  document.querySelector('[data-agent-chip="synthetic-two"]').click();
  const chip=state.agent==='synthetic-two'&&count()===0;
  document.querySelector('[data-agent-chip="synthetic-one"]').click();
  const input=document.querySelector('#task-search');input.value='beta';input.dispatchEvent(new Event('input'));
  const search=count()===0&&location.hash.includes('q=beta');input.value='alpha';input.dispatchEvent(new Event('input'));
  const combined=count()===1;
  history.replaceState(null,'','#agent=synthetic-new&status=running&q=Synthetic');readHash(currentModel.agents);render(currentModel);
  const restored=state.agent==='synthetic-new'&&state.status==='running'&&state.search==='Synthetic'&&count()===0;
  let malicious=true;
  for(const hash of ['#agent=%3Cimg%20src=x%20onerror=alert(1)%3E&status=evil&q=%3Cscript%3E&url=https://invalid.example','#agent=__proto__&status=constructor&q=%00','#agent=synthetic-one&agent=synthetic-two&status=failed&status=done','#agent=unknown&status=RUNNING&q='+('x'.repeat(201))]){
    history.replaceState(null,'',hash);readHash(currentModel.agents);render(currentModel);
    malicious&&=!state.agent&&state.status==='all'&&!state.search&&!document.querySelector('#app img,#app script')&&!location.hash;
  }
  history.replaceState(null,'','#agent=synthetic-one&status=done');window.dispatchEvent(new HashChangeEvent('hashchange'));
  const hashEvent=state.agent==='synthetic-one'&&state.status==='done';
  raw.agents=raw.agents.slice(1);render(adapt(raw));const removed=!state.agent;
  state.status='all';render(adapt(raw));
  const radar=document.querySelector('.radar-blip');radar.focus();
  const radarTip=document.querySelector('.tooltip')?.textContent.includes('37.25%')&&document.querySelector('.tooltip')?.textContent.includes('2027-01-15T08:00:00.000Z');
  radar.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));
  const escape=!document.querySelector('.tooltip');
  const segment=document.querySelector('.token-segment');segment.dispatchEvent(new MouseEvent('mouseenter'));
  const tokenHover=document.querySelector('.tooltip')?.textContent.includes('123456');segment.dispatchEvent(new MouseEvent('mouseleave'));
  segment.focus();const tokenFocus=!!document.querySelector('.tooltip');segment.blur();
  const originalFetch=window.fetch, originalSet=window.setTimeout,originalClear=window.clearTimeout;
  const jobs=new Map();let jobId=0,calls=[];
  clearTimeout(timer);timer=null;
  window.setTimeout=(fn,ms)=>{jobs.set(++jobId,{fn,ms});return jobId;};window.clearTimeout=id=>jobs.delete(id);
  window.fetch=async(url,options)=>{calls.push([url,options?.method||'GET']);return {ok:true,json:async()=>url.startsWith('/api/log')?{data:raw.log}:raw};};
  const wasPaused=state.paused;state.paused=false;schedulePoll();
  const defaultPolling=jobs.size===1&&[...jobs.values()][0].ms===30000;
  document.querySelector('[data-focus="pause"]').click();const paused=state.paused&&jobs.size===0;
  const before=calls.length;await load();
  const manual=calls.length>before&&state.paused&&jobs.size===0&&!!lastUpdated;
  document.querySelector('[data-focus="pause"]').click();const resumed=!state.paused&&jobs.size===1;
  Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));
  const hidden=jobs.size===0;
  Object.defineProperty(document,'hidden',{configurable:true,value:false});document.dispatchEvent(new Event('visibilitychange'));const visible=jobs.size===1;
  for(let i=0;i<7;i++)await showMore();
  const limits=calls.filter(([u])=>u.startsWith('/api/log')).map(([u])=>Number(new URL(u,location.origin).searchParams.get('limit')));
  const more=limits.join(',')==='40,60,80,100'&&state.limit===100&&document.querySelector('#show-more').disabled;
  const getOnly=calls.every(([,method])=>method==='GET');
  clearTimeout(timer);timer=null;window.fetch=originalFetch;window.setTimeout=originalSet;window.clearTimeout=originalClear;delete document.hidden;
  state.agent='';state.status='all';state.search='';state.limit=20;state.paused=wasPaused;writeHash();try{localStorage.setItem('monitor-paused',String(wasPaused));}catch{}await load();
  return {dynamic,chip,selection,spaceClears,enterSelects,status,search,combined,restored,malicious,hashEvent,removed,radarTip,escape,tokenHover,tokenFocus,defaultPolling,paused,manual,resumed,hidden,visible,more,getOnly};
 }).toString()+')()');
 for(const [key,value]of Object.entries(interactions))assert.equal(value,true,key);
 return {widths,interactions};
}
