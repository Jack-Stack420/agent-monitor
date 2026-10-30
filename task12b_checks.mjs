import assert from 'node:assert/strict';
export async function checkTask12b(call,evaluate){
 const result=await evaluate('('+(async()=>{
  const waitFor=async predicate=>{const end=performance.now()+5000;while(!predicate()){if(performance.now()>end)throw Error('Synthetic wait timed out');await new Promise(r=>setTimeout(r,20));}};
  await waitFor(()=>!loading&&!reloadRequested);
  const saved={storage:localStorage.getItem(DISMISS_STORAGE),dismissed:dismissedAlerts,paused:state.paused,range:state.range,limit:state.limit,expanded:state.expanded,resolved:resolvedAlertsExpanded,loaded:hasAlertSnapshot,cache:alertRowsCache,model:currentModel,sound:soundEnabled};
  state.paused=true;clearTimeout(timer);soundEnabled=false;
  const flags={};
  let output=0;const methods=['log','info','warn','error','debug'],consoleMethods=methods.map(k=>console[k]);
  for(const k of methods)console[k]=()=>{output++;};
  try{
   const cases=[['huge','x'.repeat(20481)],['array','["critical"]'],['malformed','{'],['null','null'],['number','42'],['string','"warn"'],['boolean','true']];
   for(const [name,value] of cases){localStorage.setItem(DISMISS_STORAGE,value);const clean=readDismissals();flags[name]=Object.getPrototypeOf(clean)===null&&Object.keys(clean).length===0&&localStorage.getItem(DISMISS_STORAGE)===null;}
   localStorage.setItem(DISMISS_STORAGE,'{"__proto__":{"polluted":true},"constructor":"critical","prototype":"alarm","id:1":"warn","id:2":3,"id:3":null,"id:4":[],"id:5":{},"id:6":true,"id:7":"constructor","UPPER":"warn","bad key":"info"}');
   const clean=readDismissals(),stored=JSON.parse(localStorage.getItem(DISMISS_STORAGE));
   flags.hostile=Object.getPrototypeOf(clean)===null&&Object.keys(clean).join(',')==='id:1'&&clean['id:1']==='warn'&&Object.keys(stored).join(',')==='id:1'&&({}).polluted===undefined;
   const many=Object.fromEntries(Array.from({length:250},(_,i)=>['id:'+i,'info']));localStorage.setItem(DISMISS_STORAGE,JSON.stringify(many));
   const capped=readDismissals();flags.cap=Object.keys(capped).length===200&&Object.keys(JSON.parse(localStorage.getItem(DISMISS_STORAGE))).length===200;
   localStorage.setItem(DISMISS_STORAGE,JSON.stringify({['x'.repeat(80)]:'critical',['y'.repeat(81)]:'warn'}));flags.keyLength=Object.keys(readDismissals()).join('')==='x'.repeat(80);
   dismissedAlerts=Object.assign(Object.create(null),many,{bad:'invalid'});saveDismissals();flags.writeValidated=Object.getPrototypeOf(dismissedAlerts)===null&&Object.keys(dismissedAlerts).length===200&&!Object.hasOwn(JSON.parse(localStorage.getItem(DISMISS_STORAGE)),'bad');
   const nativeGet=Storage.prototype.getItem;try{Storage.prototype.getItem=()=>{throw Error('synthetic blocked storage');};flags.blocked=Object.keys(readDismissals()).length===0;}finally{Storage.prototype.getItem=nativeGet;}
   flags.silent=output===0;
  }finally{methods.forEach((k,i)=>console[k]=consoleMethods[i]);}
  const raw=await (await fetch(API_URL)).json(),m=adapt(raw),now=Date.now();
  m.alertSummary={active:1,highest:'alarm'};m.limits=[{id:'synthetic-a',provider:'synthetic-one',label:'shared',pct:82},{id:'synthetic-b',provider:'synthetic-two',label:'shared',pct:90}];
  const alert={id:9800,rule:'limit_window',windowLabel:'shared',state:'active',severity:'alarm',message:'Synthetic ambiguous alert',firstSeen:now};m.alerts=[alert];dismissedAlerts=Object.create(null);resolvedAlertsExpanded=false;render(m);
  const noMarkers=()=>!document.querySelector('.barhead .severity-marker,.radar-blip [data-severity-shape]');
  flags.ambiguousLabel=noMarkers()&&!document.querySelector('.alert-limit')&&document.querySelector('.alert-message').textContent===alert.message;
  alert.provider='synthetic-two';render(m);flags.provider=matchedAlertWindow(alert,m)===m.limits[1]&&document.querySelectorAll('.barhead .severity-marker').length===1&&document.querySelector('.alert-limit').textContent.startsWith('SYNTHETIC-TWO');
  m.limits.push({...m.limits[1],id:'synthetic-c'});render(m);flags.ambiguousProvider=noMarkers()&&!document.querySelector('.alert-limit');
  alert.provider='synthetic-missing';render(m);flags.providerNoFallback=noMarkers()&&!document.querySelector('.alert-limit');
  const nativeFetch=window.fetch,calls=[];let active=0,rows=[];
  raw.alerts={active:0,highest:null};state.range=7;state.limit=20;state.expanded='';resolvedAlertsExpanded=false;hasAlertSnapshot=false;alertRowsCache=[];
  window.fetch=async(url,options)=>{calls.push([url,options?.method||'GET',options?.cache]);return {ok:true,json:async()=>url===API_URL?{...raw,alerts:{active,highest:active?'alarm':null}}:{data:rows}};};
  const alertsURL='/api/alerts?state=all&limit=200';
  const sequence=async expected=>{calls.length=0;await load();return JSON.stringify(calls)===JSON.stringify(expected.map(url=>[url,'GET','no-store']));};
  try{
   flags.firstLoad=await sequence([API_URL,alertsURL]);
   flags.quietRefresh=await sequence([API_URL]);
   active=1;rows=[alert];flags.activeRefresh=await sequence([API_URL,alertsURL]);
   active=0;flags.clearedActive=await sequence([API_URL])&&activeAlerts().length===0;
   rows=[{...alert,state:'resolved',resolvedAt:now}];calls.length=0;
   document.querySelector('.resolved-alerts').open=true;
   await waitFor(()=>resolvedAlertsExpanded&&!loading&&!reloadRequested&&calls.length===2);
   flags.expandFetch=calls[0][0]===API_URL&&calls[1][0]===alertsURL&&document.querySelector('.resolved-alerts').open&&document.querySelectorAll('.resolved-alerts .alert-row').length===1;
   flags.expandedRefresh=await sequence([API_URL,alertsURL]);
   document.querySelector('.resolved-alerts').open=false;await waitFor(()=>!resolvedAlertsExpanded);
   flags.collapsedRefresh=await sequence([API_URL]);
  }finally{
   window.fetch=nativeFetch;state.paused=saved.paused;state.range=saved.range;state.limit=saved.limit;state.expanded=saved.expanded;resolvedAlertsExpanded=saved.resolved;hasAlertSnapshot=saved.loaded;alertRowsCache=saved.cache;dismissedAlerts=saved.dismissed;soundEnabled=saved.sound;
   if(saved.storage===null)localStorage.removeItem(DISMISS_STORAGE);else localStorage.setItem(DISMISS_STORAGE,saved.storage);
   render(saved.model);schedulePoll();
  }
  return flags;
 }).toString()+')()');
 for(const [key,value] of Object.entries(result))assert.equal(value,true,'Task12b: '+key);
 // Exercise hostile input during actual script startup, not just parser calls.
 const startup=await call('Page.addScriptToEvaluateOnNewDocument',{source:"localStorage.setItem('monitor-dismissed-alerts','x'.repeat(20481));"});
 try{
  await call('Page.reload',{ignoreCache:true});
  let ready=false;for(let i=0;i<250;i++){ready=await evaluate("typeof currentModel!=='undefined'&&currentModel!==null&&!loading");if(ready)break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(ready,true,'Hostile startup completes');
  assert.equal(await evaluate("Object.getPrototypeOf(dismissedAlerts)===null&&Object.keys(dismissedAlerts).length===0"),true,'Hostile startup discarded');
 }finally{await call('Page.removeScriptToEvaluateOnNewDocument',{identifier:startup.identifier});}
 return {checks:Object.keys(result).length+2};
}
