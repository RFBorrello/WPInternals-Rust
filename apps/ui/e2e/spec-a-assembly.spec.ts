import { test, expect, type Page } from '@playwright/test';
import { resolve } from 'node:path';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');
async function open(page: Page, existing = false) {
  await page.addInitScript(({ existing }) => {
    Object.defineProperty(navigator, 'usb', { configurable: true, value: { requestDevice() { throw new Error('Assembly requested USB'); }, getDevices() { throw new Error('Assembly enumerated USB'); }, addEventListener() {}, removeEventListener() {} } });
    window.showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const handle = await root.getFileHandle('test-assembly-output', { create: true });
      if (existing) { const writer = await handle.createWritable(); await writer.write('existing source'); await writer.close(); }
      return handle;
    };
  }, { existing });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a-offline.ffu'));
  return page.getByRole('region', { name: 'Spec A offline preparation' });
}
test('real worker rebuilds a new unsigned UEFI copy and exports metadata without USB', async ({ page }) => {
  const card = await open(page);
  await card.getByRole('button', { name: 'Save rebuilt UEFI copy' }).click();
  await expect(card.getByRole('status')).toContainText('UEFI offline copy saved and verified');
  const bytes = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const file = await (await root.getFileHandle('test-assembly-output')).getFile();
    const bytes = new Uint8Array(await file.arrayBuffer());
    return { size: file.size, signature: Array.from(bytes.slice(24,40)) };
  });
  expect(bytes).toEqual({ size: 32768, signature: Array(16).fill(0) });
  const download = page.waitForEvent('download');
  await card.getByRole('button', { name: 'Export assembly report' }).click();
  const stream = await (await download).createReadStream(); const chunks = [];
  for await (const chunk of stream!) chunks.push(chunk);
  expect(JSON.parse(Buffer.concat(chunks).toString())).toMatchObject({ patched_executables: 2, preserved_other_files: true, signature_removed: true, phone_writes_enabled: false });
});
test('nonempty destinations are refused and existing bytes preserved', async ({ page }) => {
  const card = await open(page, true);
  await card.getByRole('button', { name: 'Save rebuilt UEFI copy' }).click();
  await expect(page.getByRole('alert')).toContainText('Choose a new empty output');
  expect(await page.evaluate(async () => (await (await (await navigator.storage.getDirectory()).getFileHandle('test-assembly-output')).getFile()).text())).toBe('existing source');
  await expect(card.getByRole('button', { name: 'Export assembly report' })).toHaveCount(0);
});
test('unsupported EFIESP donor fails without output publication or scratch residue', async ({ page }) => {
  const card = await open(page);
  await expect(card.getByRole('button', { name: 'Save assembled EFIESP copy' })).toBeDisabled();
  await card.getByLabel('Select donor FFU', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a-offline.ffu'));
  await card.getByRole('button', { name: 'Save assembled EFIESP copy' }).click();
  await expect(page.getByRole('alert')).toContainText('REGF'); // Synthetic old fixture deliberately contains a four-byte BCD.
  const state = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const names = []; for await (const name of (root as unknown as { keys(): AsyncIterable<string> }).keys()) names.push(name);
    return { names, size: (await (await root.getFileHandle('test-assembly-output')).getFile()).size };
  });
  expect(state).toEqual({ names: ['test-assembly-output'], size: 0 });
});
test('unsupported browser saving points to desktop without USB', async ({ page }) => {
  const card = await open(page);
  await page.evaluate(() => { window.showSaveFilePicker = undefined; });
  await card.getByRole('button', { name: 'Save rebuilt UEFI copy' }).click();
  await expect(page.getByRole('alert')).toContainText('desktop app');
});
