const { chromium } = require('C:/Users/kumar/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const p = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  
  await p.goto('http://127.0.0.1:4173');
  await p.locator('[data-view="analyst"]').click();
  await p.locator('.side-nav [data-page="evaluation"]').click();
  await p.waitForTimeout(500);
  
  const outPath = path.join(__dirname, 'evaluation-ui.png');
  await p.screenshot({ path: outPath, fullPage: true });
  console.log('Saved UI screenshot to:', outPath);
  
  await browser.close();
})().catch(err => {
  console.error(err);
  process.exit(1);
});
