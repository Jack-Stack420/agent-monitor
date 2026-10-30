import assert from 'node:assert/strict';
export async function checkTask10(evaluate) {
 const result=await evaluate('('+ (async()=>{
  const faces=[[500,'Chakra Petch'],[600,'Chakra Petch'],[700,'Chakra Petch'],[400,'Share Tech Mono']];
  const loaded=[];
  for(const [weight,family] of faces){
   const spec=weight+' 16px "'+family+'"';
   const items=await document.fonts.load(spec,'Latin · …');
   loaded.push(items.length===1&&items[0].status==='loaded'&&document.fonts.check(spec,'Latin · …'));
  }
  await document.fonts.ready;
  const resources=performance.getEntriesByType('resource').filter(r=>r.name.endsWith('.woff2'));
  const page=await fetch('/',{cache:'no-store'});
  const csp=page.headers.get('Content-Security-Policy');
  const assets=await Promise.all(resources.map(r=>fetch(r.name,{cache:'no-store'})));
  const fontHeaders=assets.every(r=>r.status===200&&r.headers.get('Content-Type')==='font/woff2'&&r.headers.get('Cache-Control')==='no-store'&&r.headers.get('X-Content-Type-Options')==='nosniff');
  return {loaded,localFontResources:resources.length,allLocal:resources.every(r=>new URL(r.name).origin===location.origin),csp,fontHeaders};
 }).toString()+')()');
 assert.deepEqual(result.loaded,[true,true,true,true]);
 assert.equal(result.localFontResources,4);
 assert.equal(result.allLocal,true);
 assert.equal(result.fontHeaders,true);
 assert.equal(result.csp,"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
 return result;
}
