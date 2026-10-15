const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/kumar/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
 const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:4174');await page.locator('.service-status.connected').waitFor();
 const before=await page.evaluate(()=>state.records.length);
 async function choose(id){await page.locator('[data-view="consumer"]').click();await page.locator('[data-action="scenarios"]').click();await page.locator(`[data-scenario="${id}"]`).click();}
 async function check(){const response=page.waitForResponse(r=>r.url().endsWith('/score-payment')&&r.request().method()==='POST');await page.locator('#check-form button[type="submit"]').click();assert.equal((await response).status(),200);await page.locator('.loading').waitFor({state:'hidden'});}
 await choose('merchant');await check();assert.match(await page.locator('h1').textContent(),/No strong risk/);await page.locator('[data-action="verify"]').click();await page.locator('[data-action="complete-payment"]').click();await page.waitForFunction(()=>document.querySelector('h1')?.textContent.includes('Demo complete'));
 console.log('PASS browser → trained scoring API → signed confirmation → persisted completion');
 await choose('refund');await check();assert.match(await page.locator('h1').textContent(),/don’t match/);await page.locator('[data-action="show-result"]').click();await page.locator('[data-action="cancel-payment"]').click();await page.waitForFunction(()=>document.querySelector('h1')?.textContent.includes('Payment cancelled'));await page.locator('[data-action="open-analyst-record"]').click();await page.locator('[data-action="review-fraudulent"]').click();await page.waitForFunction(()=>state.records.find(r=>r.id===selectedRecord)?.review==='Fraudulent');
 console.log('PASS refund → cancellation → backend audit → analyst label');
 await choose('change');await check();await page.locator('[data-action="change-recipient"]').click();await page.waitForFunction(()=>document.querySelector('h1')?.textContent==='Payment details changed');const res=page.waitForResponse(r=>r.url().endsWith('/score-payment'));await page.locator('[data-action="reassess"]').click();assert.equal((await res).status(),200);await page.locator('.loading').waitFor({state:'hidden'});assert.match(await page.locator('h1').textContent(),/different account/);
 console.log('PASS recipient invalidation and new server assessment (no local fallback)');
 await choose('job');await check();assert.equal(await page.evaluate(()=>assessment.category),'Unfamiliar pattern');await page.locator('[data-view="analyst"]').click();await page.locator('.side-nav [data-page="patterns"]').click();await page.locator('[data-action="pattern-examples"]').click();await page.locator('#overlay [data-investigate]').first().click();await page.locator('[data-action="review-investigate"]').click();await page.waitForFunction(()=>state.records.find(r=>r.id===selectedRecord)?.review==='Needs investigation');await page.locator('.side-nav [data-page="patterns"]').click();await page.locator('[data-action="prepare-candidate"]').click();await page.locator('[data-action="confirm-candidate"]').click();await page.waitForFunction(()=>document.querySelector('h1')?.textContent==='Evaluate the whole picture.');assert.match(await page.locator('main').textContent(),/88.53%/);assert.match(await page.locator('main').textContent(),/100.00%/);
 console.log('PASS job-deposit review, server candidate selection and supplied evaluation results');
 await page.reload();await page.locator('.service-status.connected').waitFor();assert.equal(await page.evaluate(()=>state.records.length),before+5);assert.equal(await page.evaluate(()=>state.candidate),'prepared');
 console.log('PASS persistence after page reload');
 await page.locator('[data-view="analyst"]').click();await page.locator('.side-nav [data-page="overview"]').click();await page.screenshot({path:'.qa-results/connected-analyst.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.locator('[data-view="consumer"]').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:'.qa-results/connected-mobile.png',fullPage:true});
 await page.route('**/score-payment',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Test service unavailable.'})}));await choose('merchant');await page.locator('#check-form button[type="submit"]').click();await page.locator('.error').waitFor();assert.match(await page.locator('.error').textContent(),/unavailable/);assert.equal(await page.evaluate(()=>assessment),null);
 assert.deepEqual(errors,[]);console.log('PASS unavailable API shows an error instead of fabricating an assessment; zero browser errors');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
