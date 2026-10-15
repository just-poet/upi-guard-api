// ASSETS is injected at build time. API keys exist only in runtime environment bindings.
const paths=new Set(['/health','/score-payment','/confirm-demo-payment','/review-label','/assessment-action','/assessments','/metrics','/evaluation-results','/pattern-lab/prepare-candidate','/demo-data']);
const json=(data,status)=>Response.json(data,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
export default {
 async fetch(request,env){
  const url=new URL(request.url);
  if(paths.has(url.pathname)){
   if(!env.BACKEND_URL||!env.BACKEND_API_KEY)return json({detail:'The payment service is not configured yet.'},503);
   let origin;try{origin=new URL(env.BACKEND_URL);}catch{return json({detail:'Invalid backend configuration.'},503);}
   if(origin.protocol!=='https:'||origin.username||origin.password)return json({detail:'The backend must use HTTPS.'},503);
   const identity=request.headers.get('oai-authenticated-user-id');
   if(!identity)return json({detail:'Sign in to access your payment-check workspace.'},401);
   const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('upi-guard:'+identity));
   const client=Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
   const headers=new Headers({'Content-Type':'application/json','X-API-Key':env.BACKEND_API_KEY,'X-Demo-Client-ID':client});
   if(!['GET','POST','DELETE'].includes(request.method))return json({detail:'Method not allowed.'},405);
   if(Number(request.headers.get('Content-Length')||0)>32768)return json({detail:'Request too large.'},413);
   const controller=new AbortController();
   const timeout=setTimeout(()=>controller.abort(),25000);
   try{
    const body=['POST','DELETE'].includes(request.method)?await request.text():undefined;
    if(body&&body.length>32768)return json({detail:'Request too large.'},413);
    const response=await fetch(new URL(url.pathname,origin).href,{method:request.method,headers,body,redirect:'error',signal:controller.signal});
    const contentType=response.headers.get('Content-Type')||'';
    if(!contentType.includes('application/json'))return json({detail:'The payment service returned an unexpected response.'},502);
    return new Response(response.body,{status:response.status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
   }catch(error){
    console.error('UPI Guard upstream request failed',String(error?.name||'Error'),String(error?.message||'Unknown failure'));
    return json({detail:'The payment service is temporarily unavailable. Please try again.'},503);
   }finally{clearTimeout(timeout);}
  }
  const asset=ASSETS[url.pathname];
  if(!asset)return new Response('Not found',{status:404});
  return new Response(request.method==='HEAD'?null:asset.body,{headers:{'Content-Type':asset.type,'Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'}});
 }
};
