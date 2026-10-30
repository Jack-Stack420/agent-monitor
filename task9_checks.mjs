// Synthetic data only; report booleans, never display labels.
import assert from 'node:assert/strict';
export async function checkTask9(call,evaluate){
 const result=await evaluate('('+(async()=>{
  clearTimeout(timer);timer=null;state.paused=true;
  const originalFetch=window.fetch;
  const live=await (await originalFetch(API_URL)).json();
  const template=live.agents[0];
  const raw=structuredClone(live);
  raw.agents=[{...template,id:'synthetic-history',name:'Synthetic',task:{kind:'direct',label:null,ageMs:0}}];
  raw.limits=[{provider:'synthetic',windows:[{id:'synthetic-window',label:'Synthetic',usedPercent:40}]}];
  raw.log=[{timestamp:1800000000000,agent:'synthetic-history',kind:'direct',status:'done',model:'synthetic/model',totalTokens:123,sessionStartedAt:1799999995000,durationMs:5000}];
  raw.tokens.daily=[];
  const calls=[];
  window.fetch=async(url,options)=>{
    calls.push([url,options?.method||'GET']);
    const data=url.startsWith('/api/tokens')?{data:{daily:[{date:'2026-10-28',by_agent:{'synthetic-history':Number(new URL(url,location.origin).searchParams.get('days'))}}]}}:
      url.startsWith('/api/limits/history')?{data:[{id:'synthetic-window',points:[{timestamp:1,usedPercent:10},{timestamp:2,usedPercent:90}]}]}:raw;
    return {ok:true,json:async()=>structuredClone(data)};
  };
  const settle=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
  const waitFor=async(predicate,message)=>{
    const deadline=performance.now()+5000;
    while(!predicate()){
      if(performance.now()>=deadline)throw new Error(message+' (timeout after 5000 ms)');
      await new Promise(resolve=>setTimeout(resolve,20));
    }
  };
  const matchesRange=days=>state.range===days&&!loading&&!reloadRequested&&currentModel.days[0]?.tokens['synthetic-history']===days&&document.querySelector('[data-range="'+days+'"]').getAttribute('aria-pressed')==='true';
  state.agent='';state.status='all';state.search='';state.limit=20;state.range=7;state.expanded='';render(adapt(raw));
  document.querySelector('[data-range="14"]').click();await waitFor(()=>matchesRange(14),'history range: selection and displayed token data must both finish at 14');
  const fourteen=calls.some(([u])=>u==='/api/tokens?days=14')&&state.range===14&&currentModel.days[0].tokens['synthetic-history']===14&&location.hash.includes('range=14');
  document.querySelector('[data-range="30"]').click();await waitFor(()=>matchesRange(30),'history range: selection and displayed token data must both finish at 30');
  const thirty=calls.some(([u])=>u==='/api/tokens?days=30')&&state.range===30;
  let bar=document.querySelector('.bar');bar.click();await settle();
  const expanded=state.expanded==='synthetic-window'&&document.querySelector('.limit-history svg polyline')!==null&&document.querySelector('.alarm-line')!==null&&document.querySelector('.limit-history').textContent.includes('Min 10% · Max 90%')&&location.hash.includes('window=synthetic-window');
  bar=document.querySelector('.bar');bar.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}));await settle();
  const enterCollapses=!state.expanded&&!document.querySelector('.limit-history');
  bar=document.querySelector('.bar');bar.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}));await settle();
  const enterExpands=!!document.querySelector('.limit-history svg');
  const row=document.querySelector('#log-rows .log');row.click();
  const detail=document.querySelector('.log-detail')?.textContent||'';
  const details=['Kind: direct','Model: synthetic/model','Tokens: 123','2027-01-15T07:59:55.000Z','Duration: 5000 ms'].every(v=>detail.includes(v));
  row.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}));const detailCollapses=!document.querySelector('.log-detail');
  history.replaceState(null,'','#range=14&window=synthetic-window');hashRestored=false;await load();
  const restored=state.range===14&&state.expanded==='synthetic-window'&&!!document.querySelector('.limit-history svg')&&currentModel.days[0].tokens['synthetic-history']===14;
  history.replaceState(null,'','#range=30&window=synthetic-window');window.dispatchEvent(new HashChangeEvent('hashchange'));await waitFor(()=>matchesRange(30),'history hashEvent: range and displayed token data must both finish at 30');
  const hashEvent=state.range===30&&currentModel.days[0].tokens['synthetic-history']===30;
  // Hold the old response until the user has selected a newer range.
  // Serialized loading must discard it, then fetch the final range.
  const fixtureFetch=window.fetch;
  let unblock,oldRequested=false,oldReleased=false;
  const gate=new Promise(resolve=>{unblock=resolve;});
  window.fetch=async(url,options)=>{
    if(url==='/api/tokens?days=14'){oldRequested=true;await gate;oldReleased=true;}
    return fixtureFetch(url,options);
  };
  const originalRender=render,publications=[];
  render=model=>{publications.push({range:state.range,data:model.days[0]?.tokens['synthetic-history']});originalRender(model);};
  state.expanded='';
  document.querySelector('[data-range="14"]').click();
  await waitFor(()=>oldRequested,'history rapid: old token request must start');
  document.querySelector('[data-range="30"]').click();
  unblock();
  await waitFor(()=>matchesRange(30),'history rapid: final range and displayed token data must both finish at 30');
  const rapid=oldReleased&&state.range===30&&currentModel.days[0].tokens['synthetic-history']===30&&!loading;
  const staleResponse=publications.length>0&&publications.every(p=>p.range===30&&p.data===30);
  render=originalRender;window.fetch=fixtureFetch;
  history.replaceState(null,'','#range=999&window=%3Cimg%3E');readHash(currentModel.agents);render(currentModel);
  const rejects=state.range===7&&!state.expanded&&!location.hash&&!document.querySelector('#app img');
  state.expanded='synthetic-window';historyData=null;historyError=true;render(currentModel);
  const failed=document.querySelector('.limit-history').textContent==='History unavailable';
  historyData=[];historyError=false;render(currentModel);
  const empty=document.querySelector('.limit-history').textContent==='No history in the last 72 hours';
  const getOnly=calls.every(([,method])=>method==='GET');
  state.expanded='';state.range=7;state.paused=false;writeHash();window.fetch=originalFetch;await load();
  return {fourteen,thirty,expanded,enterCollapses,enterExpands,details,detailCollapses,restored,hashEvent,rapid,staleResponse,rejects,failed,empty,getOnly};
 }).toString()+')().catch(error=>({failure:/^history (range|hashEvent|rapid):/.test(error.message)?error.message:"history browser evaluation failed"}))');
 if(result.failure)assert.fail(result.failure);
 for(const [key,value] of Object.entries(result))assert.equal(value,true,'history '+key);
 return result;
}
