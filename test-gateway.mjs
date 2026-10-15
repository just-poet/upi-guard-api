import assert from 'node:assert/strict';
import fs from 'node:fs';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const source=fs.readFileSync(new URL('./dist/server/index.js',import.meta.url),'utf8');
const {default:gateway}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const base='https://example.chatgpt.site';
const env={BACKEND_URL:'https://backend.example',BACKEND_API_KEY:'gateway-test-key'};
let forwarded;
const originalFetch=globalThis.fetch;
globalThis.fetch=async(url,options)=>{forwarded={url:String(url),...options};return Response.json({records:[]});};
try{
 const landing=await gateway.fetch(new Request(base+'/'),env);
 const guestCookie=landing.headers.get('Set-Cookie');
 assert.ok(guestCookie.startsWith('__Host-upi-guard-guest='));
 for(const flag of ['HttpOnly','Secure','SameSite=Lax','Path=/'])assert.ok(guestCookie.includes(flag));
 assert.equal(landing.headers.get('Cache-Control'),'no-store');
 const guestHeaders={Cookie:guestCookie.split(';')[0],'X-Demo-Client-ID':'spoofed-workspace'};
 assert.equal((await gateway.fetch(new Request(base+'/assessments',{headers:guestHeaders}),env)).status,200);
 const guestClient=forwarded.headers.get('x-demo-client-id');
 assert.equal(guestClient.length,64);assert.notEqual(guestClient,'spoofed-workspace');
 assert.equal((await gateway.fetch(new Request(base+'/metrics',{headers:guestHeaders}),env)).headers.get('Set-Cookie'),null);
 assert.equal(forwarded.headers.get('x-demo-client-id'),guestClient);
 await gateway.fetch(new Request(base+'/assessments'),env);
 assert.notEqual(forwarded.headers.get('x-demo-client-id'),guestClient);
 const freshLanding=await gateway.fetch(new Request(base+'/'),env);
 assert.notEqual(freshLanding.headers.get('Set-Cookie'),guestCookie);
 const returningLanding=await gateway.fetch(new Request(base+'/',{headers:guestHeaders}),env);
 assert.equal(returningLanding.headers.get('Set-Cookie'),null);
 const invalidCookie=await gateway.fetch(new Request(base+'/',{headers:{Cookie:'__Host-upi-guard-guest=invalid'}}),env);
 assert.ok(invalidCookie.headers.get('Set-Cookie').startsWith('__Host-upi-guard-guest='));
 for(const route of ['/analyze-message','/companion/pair','/companion/devices','/companion/revoke']){
  assert.equal((await gateway.fetch(new Request(base+route,{headers:guestHeaders}),env)).status,200);
  assert.equal(forwarded.headers.get('x-demo-client-id'),guestClient);
 }
 assert.equal((await gateway.fetch(new Request(base+'/analyze-message',{method:'POST',headers:{...guestHeaders,Origin:'https://unrelated.example'},body:'{}'}),env)).status,403);
 assert.equal((await gateway.fetch(new Request(base+'/assessments',{headers:{...guestHeaders,'Sec-Fetch-Site':'cross-site'}}),env)).status,403);
 assert.equal((await gateway.fetch(new Request(base+'/assessments'),{})).status,503);
 const request=new Request(base+'/assessments',{headers:{'oai-authenticated-user-id':'test-user','X-Demo-Client-ID':'spoofed-workspace'}});
 assert.equal((await gateway.fetch(request,env)).status,200);
 assert.equal(forwarded.url,'https://backend.example/assessments');
 assert.equal(forwarded.headers.get('x-api-key'),'gateway-test-key');
 assert.equal(forwarded.headers.get('x-demo-client-id').length,64);
 assert.notEqual(forwarded.headers.get('x-demo-client-id'),guestClient);
 assert.notEqual(forwarded.headers.get('x-demo-client-id'),'spoofed-workspace');
 assert.equal(forwarded.redirect,'manual');
 for(const route of ['/analyze-message','/analyze-qr']){
  const body=JSON.stringify(route.endsWith('message')?{message:'test message'}:{payload:'https://example.com'});
  const req=new Request(base+route,{method:'POST',headers:{'oai-authenticated-user-id':'test-user','Content-Type':'application/json'},body});
  assert.equal((await gateway.fetch(req,env)).status,200);
  assert.equal(forwarded.url,'https://backend.example'+route);
  assert.equal(forwarded.body,body);
 }
 globalThis.fetch=async()=>new Response(null,{status:302,headers:{Location:'https://unrelated.example'}});
 assert.equal((await gateway.fetch(request,env)).status,502);
 const html=await(await gateway.fetch(new Request(base+'/'),env)).text();
 assert.ok(html.includes('api-client.js'));assert.ok(!html.includes(env.BACKEND_API_KEY));
 for(const asset of ['/tools.js','/vendor/jsQR.js'])assert.equal((await gateway.fetch(new Request(base+asset),env)).status,200);
 for(const asset of ['/downloads/upi-guard-extension.zip','/downloads/upi-guard-windows.zip']){
  const response=await gateway.fetch(new Request(base+asset),env);assert.equal(response.status,200);assert.equal(response.headers.get('Content-Type'),'application/zip');assert.ok(response.headers.get('Content-Disposition').includes('attachment'));const bytes=new Uint8Array(await response.arrayBuffer());assert.equal(String.fromCharCode(...bytes.slice(0,2)),'PK');
 }
 assert.equal((await gateway.fetch(new Request(base+'/not-an-api'),env)).status,404);
 console.log('PASS anonymous sessions, workspace isolation, origin checks, signed-in identity, secret isolation, path allowlist, missing configuration, and assets');
}finally{globalThis.fetch=originalFetch;}
