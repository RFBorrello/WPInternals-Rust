import { test, expect, type Page } from '@playwright/test';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');
async function open(page: Page, fixture = 'synthetic-spec-a.ffu') {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'usb', { configurable: true, value: { requestDevice() { throw new Error('Offline preparation requested USB'); }, getDevices() { throw new Error('Offline preparation enumerated USB'); }, addEventListener() {}, removeEventListener() {} } });
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, fixture));
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
test('real WASM checks SBL1, compressed UEFI and stock/donor EFIESP with bounded offline files', async ({ page }) => {
  const card = await open(page, 'synthetic-spec-a-offline.ffu');
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card.getByRole('row').filter({ hasText: 'SBL1 prerequisites' })).toContainText('Unique patterns');
  await expect(card.getByRole('row').filter({ hasText: 'Compressed UEFI' })).toContainText('2 targets with unique code patch matches');
  await expect(card.getByRole('row').filter({ hasText: 'Stock EFIESP boot file' })).toContainText('validated donor is required');
  await card.getByLabel('Select donor FFU', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-spec-a-offline.ffu'));
  await expect(card.getByRole('button', { name: 'Export boot preparation' })).toHaveCount(0);
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card.getByRole('row').filter({ hasText: 'Donor EFIESP boot file' })).toContainText('validated donor is required');
  const downloading = page.waitForEvent('download'); await card.getByRole('button', { name: 'Export boot preparation' }).click();
  const stream = await (await downloading).createReadStream(); const parts = []; for await (const part of stream!) parts.push(part);
  const report = JSON.parse(Buffer.concat(parts).toString());
  expect(report.sbl1_prerequisites.payload_generated).toBe(false); expect(report.uefi.rebuilt_image).toBe(false);
  expect(report.efiesp.bcd_present).toBe(true); expect(report.donor_efiesp.status).toBe('unsupported_donor_required');
  expect(report.phone_writes_enabled).toBe(false);
});
test('an oversized LZMA output is reported without publishing UEFI patch previews', async ({ page }) => {
  await open(page);
  const data = await readFile(resolve(fixtures, 'synthetic-spec-a-offline.ffu'));
  const guid = data.indexOf(Buffer.from('98584eee143959429d6edc7bd79403cf', 'hex'));
  expect(guid).toBeGreaterThan(0); data.writeBigUInt64LE(0xffffffffffffffffn, guid + 20 + 5);
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles({ name: 'bad-compression.ffu', mimeType: 'application/octet-stream', buffer: data });
  await expect(page.getByRole('heading', { name: 'bad-compression.ffu', exact: true })).toBeVisible();
  const card = page.getByRole('region', { name: 'Spec A offline preparation' });
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card.getByRole('row').filter({ hasText: 'Compressed UEFI' })).toContainText('exceeds limits');
  await expect(card.getByRole('row').filter({ hasText: 'Compressed UEFI' })).not.toContainText('unique code patch matches');
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
      if (command === 'plugin:dialog|open') return ['C:/local/stock.ffu', 'C:/local/engineering.bin', ['C:/local/programmer.hex'], 'C:/local/donor.ffu'][dialogs++];
      if (command === 'inspect_file') return { format: 'FFU', size: 512, ffu: { platform_id: 'SYNTHETIC', chunk_size: 4096 }, gpt: null, filesystem: null, notes: [] };
      if (command === 'plugin:dialog|save') return 'C:/local/new-output.img';
      if (command === 'assemble_spec_a') {
        if (args.input !== 'C:/local/stock.ffu' || args.donor !== 'C:/local/donor.ffu' || args.output !== 'C:/local/new-output.img' || !['uefi','efiesp'].includes(String(args.component))) throw new Error('Wrong native assembly paths');
        return { original_sha256: 'original', resulting_sha256: `native-${args.component}`, size: 1024, preserved_other_files: true, phone_writes_enabled: false };
      }
      if (command === 'prepare_spec_a') {
        if (JSON.stringify(args) !== JSON.stringify({ input: 'C:/local/stock.ffu', sbl3: 'C:/local/engineering.bin', loaders: ['C:/local/programmer.hex'], donor: 'C:/local/donor.ffu' })) throw new Error('Wrong native import paths');
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
  await card.getByRole('button', { name: 'Import donor FFU' }).click();
  await expect(card).toContainText('donor.ffu');
  await card.getByRole('button', { name: 'Check boot files' }).click();
  await expect(card).toContainText('Native IPC preparation received selected imports.');
  await card.getByRole('button', { name: 'Save rebuilt UEFI copy' }).click();
  await expect(card.getByRole('status')).toContainText('native-uefi');
  await card.getByRole('button', { name: 'Save assembled EFIESP copy' }).click();
  await expect(card.getByRole('status')).toContainText('native-efiesp');
});
