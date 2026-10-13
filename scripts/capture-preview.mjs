import { chromium } from '../apps/ui/node_modules/playwright-core/index.mjs';
import { resolve } from 'node:path';
const root=resolve(import.meta.dirname,'..');
const browser=await chromium.launch({channel:process.env.WPI_BROWSER_CHANNEL??'msedge',headless:true});
try {
  const page=await browser.newPage({viewport:{width:1360,height:1020},deviceScaleFactor:1});
  await page.goto('http://127.0.0.1:1420/');
  await page.getByRole('button',{name:'Browse files'}).waitFor();
  await page.waitForFunction(()=>!document.querySelector('button[disabled]')?.textContent?.includes('Browse files'));
  await page.screenshot({path:resolve(root,'docs/workspace-preview.png'),fullPage:true});
} finally { await browser.close(); }
