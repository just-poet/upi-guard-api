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
 assert.equal((await gateway.fetch(new Request(base+'/assessments'),env)).status,401);
 assert.equal((await gateway.fetch(new Request(base+'/assessments'),{})).status,503);
 const request=new Request(base+'/assessments',{headers:{'oai-authenticated-user-id':'test-user','X-Demo-Client-ID':'spoofed-workspace'}});
 assert.equal((await gateway.fetch(request,env)).status,200);
 assert.equal(forwarded.url,'https://backend.example/assessments');
 assert.equal(forwarded.headers.get('x-api-key'),'gateway-test-key');
 assert.equal(forwarded.headers.get('x-demo-client-id').length,64);
 assert.notEqual(forwarded.headers.get('x-demo-client-id'),'spoofed-workspace');
 assert.equal(forwarded.redirect,'manual');
 globalThis.fetch=async()=>new Response(null,{status:302,headers:{Location:'https://unrelated.example'}});
 assert.equal((await gateway.fetch(request,env)).status,502);
 const html=await(await gateway.fetch(new Request(base+'/'),env)).text();
 assert.ok(html.includes('api-client.js'));assert.ok(!html.includes(env.BACKEND_API_KEY));
 assert.equal((await gateway.fetch(new Request(base+'/not-an-api'),env)).status,404);
 console.log('PASS gateway identity, secret isolation, path allowlist, missing configuration, and assets');
}finally{globalThis.fetch=originalFetch;}
