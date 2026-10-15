// ASSETS is injected at build time. API keys exist only in runtime environment bindings.
const paths=new Set(['/health','/score-payment','/confirm-demo-payment','/review-label','/assessment-action','/assessments','/metrics','/evaluation-results','/pattern-lab/prepare-candidate','/demo-data','/analyze-message','/analyze-qr','/companion/pair','/companion/devices','/companion/revoke']);
const json=(data,status)=>Response.json(data,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const guestCookie='__Host-upi-guard-guest';
const hex=bytes=>Array.from(new Uint8Array(bytes),n=>n.toString(16).padStart(2,'0')).join('');
function guestSession(request){
 const token=request.headers.get('Cookie')?.split(';').map(value=>value.trim()).find(value=>value.startsWith(guestCookie+'='))?.slice(guestCookie.length+1);
 if(/^[a-f0-9]{64}$/.test(token||''))return {token,cookie:null};
 const fresh=hex(crypto.getRandomValues(new Uint8Array(32)));
 return {token:fresh,cookie:`${guestCookie}=${fresh}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`};
}
async function workspace(request,env){
 const identity=request.headers.get('oai-authenticated-user-id');
 if(identity)return {client:hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('upi-guard:'+identity))),cookie:null};
 const guest=guestSession(request);
 const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.BACKEND_API_KEY),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return {client:hex(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode('upi-guard:guest:'+guest.token))),cookie:guest.cookie};
}
export default {
 async fetch(request,env){
  const url=new URL(request.url);
  if(paths.has(url.pathname)){
   if(!env.BACKEND_URL||!env.BACKEND_API_KEY)return json({detail:'The payment service is not configured yet.'},503);
   let origin;try{origin=new URL(env.BACKEND_URL);}catch{return json({detail:'Invalid backend configuration.'},503);}
   if(origin.protocol!=='https:'||origin.username||origin.password)return json({detail:'The backend must use HTTPS.'},503);
   if(request.headers.get('Sec-Fetch-Site')==='cross-site'||(request.headers.get('Origin')&&request.headers.get('Origin')!==url.origin))return json({detail:'Open UPI Guard to run this check.'},403);
   const {client,cookie}=await workspace(request,env);
   const headers=new Headers({'Content-Type':'application/json','X-API-Key':env.BACKEND_API_KEY,'X-Demo-Client-ID':client});
   if(!['GET','POST','DELETE'].includes(request.method))return json({detail:'Method not allowed.'},405);
   if(Number(request.headers.get('Content-Length')||0)>32768)return json({detail:'Request too large.'},413);
   const controller=new AbortController();
   const timeout=setTimeout(()=>controller.abort(),25000);
   try{
    const body=['POST','DELETE'].includes(request.method)?await request.text():undefined;
    if(body&&body.length>32768)return json({detail:'Request too large.'},413);
    const response=await fetch(new URL(url.pathname,origin).href,{method:request.method,headers,body,redirect:'manual',signal:controller.signal});
    if(response.status>=300&&response.status<400)return json({detail:'The payment service returned an unexpected redirect.'},502);
    const contentType=response.headers.get('Content-Type')||'';
    if(!contentType.includes('application/json'))return json({detail:'The payment service returned an unexpected response.'},502);
    return new Response(response.body,{status:response.status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(cookie?{'Set-Cookie':cookie}:{})}});
   }catch(error){
    console.error('UPI Guard upstream request failed',String(error?.name||'Error'),String(error?.message||'Unknown failure'));
    return json({detail:'The payment service is temporarily unavailable. Please try again.'},503);
   }finally{clearTimeout(timeout);}
  }
  const asset=ASSETS[url.pathname];
  if(!asset)return new Response('Not found',{status:404});
  const body=asset.base64?Uint8Array.from(atob(asset.base64),c=>c.charCodeAt(0)):asset.body;
  const cookie=url.pathname==='/'&&!request.headers.has('oai-authenticated-user-id')?guestSession(request).cookie:null;
  return new Response(request.method==='HEAD'?null:body,{headers:{'Content-Type':asset.type,'Cache-Control':url.pathname==='/'?'no-store':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin',...(cookie?{'Set-Cookie':cookie}:{}),...(asset.filename?{'Content-Disposition':'attachment; filename="'+asset.filename+'"'}:{})}});
 }
};
