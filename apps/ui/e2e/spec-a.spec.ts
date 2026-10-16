import { test, expect, type Page } from '@playwright/test';
import { resolve } from 'node:path';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');
async function open(page: Page) {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'usb', { configurable: true, value: { requestDevice() { throw new Error('Offline preparation requested USB'); }, getDevices() { throw new Error('Offline preparation enumerated USB'); }, addEventListener() {}, removeEventListener() {} } });
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a.ffu'));
  const card = page.getByRole('region', { name: 'Spec A offline preparation' });
  await expect(card.getByRole('button', { name: 'Check boot files' })).toBeEnabled();
  return card;
}
test('real worker/WASM inspects boot images and local HEX/SBL3 without USB or enabling writes', async ({ page }) => {
  const card = await open(page);
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card).toContainText('No external engineering SBL3');
  await expect(card.getByRole('row').filter({ hasText: 'SBL2' })).toContainText('Unique patch at 0x40');
  await card.getByLabel('Select raw SBL3', { exact: true }).setInputFiles(resolve(fixtures, 'spec-a/sbl3.bin'));
  await expect(card.getByRole('button', { name: 'Export boot preparation' })).toHaveCount(0);
  await card.getByLabel('Select local loaders', { exact: true }).setInputFiles(resolve(fixtures, 'spec-a/loader.hex'));
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card.getByRole('row').filter({ hasText: 'loader.hex' })).toContainText('Present');
  await expect(card.getByRole('row').filter({ hasText: 'loader.hex' })).toContainText('Matches');
  await expect(card).toContainText('External SBL3 fits');
  const download = page.waitForEvent('download');
  await card.getByRole('button', { name: 'Export boot preparation' }).click();
  const stream = await (await download).createReadStream(); const parts = []; for await (const part of stream!) parts.push(part);
  const report = JSON.parse(Buffer.concat(parts).toString());
  expect(report.phone_writes_enabled).toBe(false);
  expect(report.blockers.length).toBeGreaterThan(0);
  expect(report.stock[2].patch).toMatchObject({ status: 'unique', expected: '2800d0e5', replacement: '0000a0e3' });
  expect(JSON.stringify(report)).not.toMatch(/"serial"|"device_id"|private_key/);
});
test('malformed HEX stays visible as an unusable import and clear removes stale preparation', async ({ page }) => {
  const card = await open(page);
  await card.getByLabel('Select local loaders', { exact: true }).setInputFiles({ name: 'bad.hex', mimeType: 'text/plain', buffer: Buffer.from(':0100000001FE\n:00000001FF\n') });
  await card.getByRole('button', { name: 'Check boot files' }).click();
  // A checksum-correct one-byte input is still not a valid programmer.
  await expect(card.getByRole('row').filter({ hasText: 'bad.hex' })).toContainText('truncated structure');
  await card.getByRole('button', { name: 'Clear imports' }).click();
  await expect(card.getByRole('button', { name: 'Export boot preparation' })).toHaveCount(0);
});
test('oversized boot input is rejected before whole-file copying or report publication', async ({ page }) => {
  const card = await open(page);
  await card.getByLabel('Select raw SBL3', { exact: true }).setInputFiles({ name: 'oversized.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(4 * 1024 * 1024 + 1) });
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(page.getByRole('alert')).toContainText('import limit');
  await expect(card.getByRole('button', { name: 'Export boot preparation' })).toHaveCount(0);
});
test('FFU without the required boot partitions fails explicitly', async ({ page }) => {
  await open(page);
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic.ffu'));
  await expect(page.getByRole('heading', { name: 'synthetic.ffu', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Check boot files' }).click();
  await expect(page.getByRole('alert')).toContainText('SBL1');
  await expect(page.getByRole('button', { name: 'Export boot preparation' })).toHaveCount(0);
});
test('desktop boot preparation uses native IPC and selected paths', async ({ page }) => {
  await page.addInitScript(() => {
    const capabilities = { device_id: null, host: 'windows', transport: 'usb', capabilities: [] };
    let dialogs = 0;
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (command: string, args: Record<string, unknown>) => {
      if (command === 'startup') return { models: [], capabilities };
      if (command === 'capabilities') return capabilities;
      if (command === 'plugin:dialog|open') return ['C:/local/stock.ffu', 'C:/local/engineering.bin', ['C:/local/programmer.hex']][dialogs++];
      if (command === 'inspect_file') return { format: 'FFU', size: 512, ffu: { platform_id: 'SYNTHETIC', chunk_size: 4096 }, gpt: null, filesystem: null, notes: [] };
      if (command === 'prepare_spec_a') {
        if (JSON.stringify(args) !== JSON.stringify({ input: 'C:/local/stock.ffu', sbl3: 'C:/local/engineering.bin', loaders: ['C:/local/programmer.hex'] })) throw new Error('Wrong native import paths');
        return { upstream_revision: 'synthetic', platform_id: 'SYNTHETIC', stock: [], external_sbl3: null, external_sbl3_fits: null, loaders: [], phone_writes_enabled: false, blockers: ['Native IPC preparation received selected imports.'] };
      }
      throw new Error(`Unexpected native command: ${command}`);
    } } });
  });
  await page.goto('/'); await page.getByRole('button', { name: 'Browse files' }).click();
  const card = page.getByRole('region', { name: 'Spec A offline preparation' });
  await card.getByRole('button', { name: 'Import raw SBL3' }).click();
  await expect(card).toContainText('engineering.bin');
  await card.getByRole('button', { name: 'Import local loaders' }).click();
  await expect(card).toContainText('programmer.hex');
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card).toContainText('Native IPC preparation received selected imports.');
});
