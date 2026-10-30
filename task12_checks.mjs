import assert from 'node:assert/strict';
export async function checkTask12(call,evaluate){
 const result=await evaluate('('+(async()=>{
  const raw=await (await fetch(API_URL)).json();
  const m=adapt(raw),now=Date.now();m.alertSummary={active:0,highest:null};m.alerts=[];
  const saved={dismissed:dismissedAlerts,sound:soundEnabled,previous:previousAlerts,context:audioContext};
  dismissedAlerts={};soundEnabled=false;previousAlerts=null;
  render(m);
  const flags={empty:!!document.querySelector('.alerts-empty'),soundDefault:document.querySelector('#alert-sound').getAttribute('aria-pressed')==='false',belowSummary:document.querySelector('.strip').nextElementSibling.classList.contains('alerts-panel')};
  const mk=(severity,id,extra={})=>({id,rule:'failed_sessions',agentId:m.agents[0]?.id,severity,state:'active',message:'Synthetic '+severity,firstSeen:now-60000,lastSeen:now,...extra});
  m.alerts=['info','warn','alarm','critical'].map((s,i)=>mk(s,9000+i));render(m);
  flags.severities=[...document.querySelectorAll('.active-alerts>.alert-row>.severity-marker')].map(e=>e.dataset.severity).join(',')==='critical,alarm,warn,info';
  flags.shapes=['circle','polygon','polygon','rect'].every((tag,i)=>document.querySelector('.active-alerts [data-severity-shape="'+['info','warn','alarm','critical'][i]+'"]').tagName===tag);
  flags.title=document.title==='(3) Agent Monitor';
  flags.favicon=decodeURIComponent(document.querySelector('link[rel="icon"]').href).includes('<rect');
  m.alerts=[mk('warn',9100)];render(m);document.querySelector('[data-dismiss]').click();
  flags.dismiss=!document.querySelector('.active-alerts');
  m.alerts[0].message='Synthetic changed count 999';m.alerts[0].lastSeen+=1000;render(m);
  flags.noReappearance=!document.querySelector('.active-alerts');
  m.alerts[0].severity='alarm';render(m);flags.escalation=!!document.querySelector('.active-alerts');
  m.alerts=[mk('warn',9101)];render(m);flags.newIdentity=!!document.querySelector('.active-alerts');
  m.alerts=[mk('warn',undefined,{rule:'collector_stale',agentId:null,windowLabel:'collector'})];render(m);const key=alertKey(m.alerts[0]);document.querySelector('[data-dismiss]').click();m.alerts[0].lastSeen+=5000;m.alerts[0].message='Synthetic stale changed';render(m);
  flags.syntheticStable=key===alertKey(m.alerts[0])&&!document.querySelector('.active-alerts');
  m.alerts[0].severity='critical';render(m);flags.syntheticEscalation=!!document.querySelector('.active-alerts');
  m.limits=[{id:'synthetic-window',provider:'openai',plan:'plus',label:'5h',pct:82,resetsAtMs:now+8040000}];
  m.alerts=[mk('alarm',9200,{rule:'limit_window',agentId:null,windowLabel:'5h'})];render(m);
  const enrichment=document.querySelector('.alert-limit')?.textContent;
  flags.enrichment=enrichment==='OPENAI PLUS 5H · 82% · resets in 2 h 14 m';
  flags.limitMarkers=!!document.querySelector('.barhead [data-severity="alarm"]')&&!!document.querySelector('.radar-blip [data-severity-shape="alarm"]')&&[...document.querySelectorAll('.radar-panel text')].some(e=>e.textContent.includes('Alarm'));
  m.alerts[0].windowLabel='missing';render(m);flags.unmatched=!document.querySelector('.alert-limit');
  m.alerts=[mk('info',9300,{state:'resolved',resolvedAt:now-1000}),mk('info',9301,{state:'resolved',resolvedAt:now-86400001})];render(m);
  flags.resolved=!document.querySelector('.resolved-alerts').open&&document.querySelectorAll('.resolved-alerts .alert-row').length===1;
  document.querySelector('.resolved-alerts').open=true;flags.resolvedExpandable=document.querySelector('.resolved-alerts').open;
  flags.quietTitle=document.title==='Agent Monitor';
  const payload='<img src=x onerror=alert(1)>\n'+'X'.repeat(20000);
  m.agents[0].name=payload;m.alerts=[mk('critical',9400,{message:payload})];render(m);
  flags.textOnly=!document.querySelector('#app img,#app script')&&document.querySelector('.alert-message').textContent===payload&&document.querySelector('.alert-copy').textContent.includes(payload);
  // Stub the WebAudio device, keeping the actual toggle and tone implementation.
  const NativeAudio=window.AudioContext;let tones=0,resumes=0;
  window.AudioContext=class {state='suspended';currentTime=0;destination={};async resume(){resumes++;this.state='running';}createOscillator(){return {frequency:{value:0},connect(){},start(){tones++;},stop(){}};}createGain(){return {gain:{setValueAtTime(){},exponentialRampToValueAtTime(){}},connect(){}};}};
  audioContext=null;soundEnabled=false;render(m);document.querySelector('#alert-sound').click();await Promise.resolve();await Promise.resolve();
  flags.soundClick=soundEnabled&&resumes===1&&tones===0&&localStorage.getItem('monitor-alert-sound')==='true';
  m.alerts.push(mk('alarm',9401),mk('critical',9402));render(m);render(m);
  flags.oneTone=tones===1;m.alerts[0].message='Synthetic changed';render(m);flags.noRepeatTone=tones===1;
  m.alerts.push(mk('info',9403));render(m);m.alerts.at(-1).severity='critical';render(m);flags.noEscalationTone=tones===1;
  document.querySelector('#alert-sound').click();await Promise.resolve();m.alerts.push(mk('critical',9404));render(m);flags.soundOff=tones===1&&!soundEnabled;
  window.AudioContext=NativeAudio;audioContext=saved.context;
  window.__alertWidthModel=m;
  dismissedAlerts=saved.dismissed;soundEnabled=saved.sound;previousAlerts=saved.previous;
  try{localStorage.setItem('monitor-alert-sound',String(saved.sound));localStorage.setItem('monitor-dismissed-alerts',JSON.stringify(saved.dismissed));}catch{}
  return flags;
 }).toString()+')()');
 for(const [key,value] of Object.entries(result))assert.equal(value,true,'Alerts: '+key);
 const widths=[];
 for(const width of [640,999,1000,1499,1500,1799,1800,2400]){
  await call('Emulation.setDeviceMetricsOverride',{width,height:1100,deviceScaleFactor:1,mobile:false});
  const fits=await evaluate('render(window.__alertWidthModel);document.documentElement.scrollWidth<=innerWidth');
  assert.equal(fits,true,'Alert layout '+width);widths.push(width);
 }
 await evaluate('delete window.__alertWidthModel;load()');
 return {checks:Object.keys(result).length,widths};
}
