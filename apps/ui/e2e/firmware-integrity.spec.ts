import { test, expect, type Page } from '@playwright/test';
import { resolve } from 'node:path';

// Exercise the real worker/WASM with controlled local-file delays and failures.
// The module wrapper queues messages until the dynamic import installs its handler.
async function fileHook(page: Page, mode: 'delay' | 'short' | 'error') {
  await page.addInitScript(mode => {
    const BaseWorker = window.Worker;
    window.Worker = class extends BaseWorker {
      constructor(url: string | URL, options?: WorkerOptions) {
        const source = `
          const queue=[]; self.onmessage=e=>queue.push(e);
          let preparing=false, preparations=0, firstHashChunk=false, release;
          const cancellation=new Promise(resolve=>{release=resolve;});
          self.addEventListener('message',e=>{
            if(e.data.action==='recovery_prepare'){preparing=true;preparations++;firstHashChunk=false;}
            if(e.data.action==='cancel')release();
          });
          const original=Blob.prototype.arrayBuffer;
          Blob.prototype.arrayBuffer=async function(){
            // Hold the second preparation after one real hash chunk until a
            // cancel event arrives. A 150 ms click window races under CPU load.
            if(${JSON.stringify(mode)}==='delay' && preparations===2 && firstHashChunk)await cancellation;
            if(preparing && (${JSON.stringify(mode)}==='delay' || this.size===1048576)){
              await new Promise(resolve=>setTimeout(resolve,150));
              if(${JSON.stringify(mode)}==='error')throw new DOMException('Local file became unreadable','NotReadableError');
              const data=await original.call(this);
              if(this.size===1048576)firstHashChunk=true;
              return ${JSON.stringify(mode)}==='short'?data.slice(0,-1):data;
            }
            return original.call(this);
          };
          await import(${JSON.stringify(String(url))});
          for(const event of queue)self.onmessage(event);
        `;
        super(URL.createObjectURL(new Blob([source], { type: 'text/javascript' })), options);
      }
    };
  }, mode);
}
const fixture = resolve(import.meta.dirname, '../../../tests/fixtures/synthetic-mainos.ffu');

test('cancelling a partial hash clears old results and allows a fresh verification', async ({ page }) => {
  await fileHook(page, 'delay');
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(fixture);
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('button', { name: 'Export preparation' })).toBeVisible();
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect.poll(() => page.getByRole('progressbar').evaluate((node: HTMLProgressElement) => node.value > 0 && node.value < node.max), { intervals: [10] }).toBe(true);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Operation cancelled');
  await expect(page.getByRole('button', { name: 'Export preparation' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Chunk integrity' })).toContainText('Passed');
});

for (const mode of ['short', 'error'] as const) {
  test(`a ${mode} file read publishes no complete fingerprint or preparation`, async ({ page }) => {
    await fileHook(page, mode);
    await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
    await page.locator('input[type=file]').setInputFiles(fixture);
    await page.getByRole('button', { name: 'Check preparation' }).click();
    await expect(page.getByRole('alert')).toContainText(mode === 'short' ? 'truncated' : 'unreadable');
    await expect(page.getByRole('button', { name: 'Export preparation' })).toHaveCount(0);
  });
}
