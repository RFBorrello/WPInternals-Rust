import { test, expect, type Page } from '@playwright/test';
import { resolve } from 'node:path';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');
async function open(page: Page, existing = false) {
  await page.addInitScript(({ existing }) => {
    Object.defineProperty(navigator, 'usb', { configurable: true, value: { requestDevice() { throw new Error('Package requested USB'); }, getDevices() { throw new Error('Package enumerated USB'); }, addEventListener() {}, removeEventListener() {} } });
    window.showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory(); const handle = await root.getFileHandle('test-package-output', { create: true });
      if (existing) { const writer = await handle.createWritable(); await writer.write('preserve existing'); await writer.close(); }
      return handle;
    };
  }, { existing });
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a-package.ffu'));
  const card = page.getByRole('region', { name: 'Spec A offline preparation' });
  await expect(card.getByRole('button', { name: 'Build offline package' })).toBeDisabled();
  await card.getByLabel('Select donor FFU', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a-package.ffu'));
  return card;
}
test('real package worker rejects unsupported donor, removes scratch files and publishes no ZIP', async ({ page }) => {
  const card = await open(page);
  await card.getByRole('button', { name: 'Build offline package' }).click();
  await expect(page.getByRole('alert')).toContainText('no catalog version matches');
  const state = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory(); const names = [];
    for await (const name of (root as unknown as { keys(): AsyncIterable<string> }).keys()) names.push(name);
    return { names, size: (await (await root.getFileHandle('test-package-output')).getFile()).size };
  });
  expect(state).toEqual({ names: ['test-package-output'], size: 0 });
  await expect(card.getByRole('button', { name: 'Export package report' })).toHaveCount(0);
});
test('package refuses nonempty outputs and preserves their bytes', async ({ page }) => {
  const card = await open(page, true);
  await card.getByRole('button', { name: 'Build offline package' }).click();
  await expect(page.getByRole('alert')).toContainText('new empty package file');
  expect(await page.evaluate(async () => (await (await (await navigator.storage.getDirectory()).getFileHandle('test-package-output')).getFile()).text())).toBe('preserve existing');
});
test('package browser fallback explains native requirements', async ({ page }) => {
  const card = await open(page); await page.evaluate(() => { window.showSaveFilePicker = undefined; });
  await card.getByRole('button', { name: 'Build offline package' }).click();
  await expect(page.getByRole('alert')).toContainText('desktop app');
});
test('real WASM package cancellation occurs before I/O and completed sessions cannot be reused', async ({ page }) => {
  const pkg = resolve(import.meta.dirname, '../../../crates/wpi-wasm/pkg');
  await page.route('**/package-test/wpi_wasm.js', route => route.fulfill({ path: resolve(pkg, 'wpi_wasm.js'), contentType: 'text/javascript' }));
  await page.route('**/package-test/wpi_wasm_bg.wasm', route => route.fulfill({ path: resolve(pkg, 'wpi_wasm_bg.wasm'), contentType: 'application/wasm' }));
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const wasm = await import(/* @vite-ignore */ '/package-test/wpi_wasm.js'); await wasm.default();
    const builder = new wasm.BrowserSpecAPackage(); let reads = 0;
    const io = Array.from({ length: 5 }, () => () => { reads++; throw new Error('Unexpected I/O'); });
    let cancelled = '', repeated = '';
    try { builder.finish_json(4000000n, io, new Uint8Array(), () => false); } catch (error) { cancelled = String(error); }
    try { builder.finish_json(4000000n, io, new Uint8Array(), () => true); } catch (error) { repeated = String(error); }
    builder.free(); return { cancelled, repeated, reads };
  });
  expect(result.cancelled).toContain('cancelled'); expect(result.repeated).toContain('completed session'); expect(result.reads).toBe(0);
});
