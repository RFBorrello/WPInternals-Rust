import { test, expect } from '@playwright/test';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');

test('browser reads compressed MainOS registry and DSM metadata through bounded WASM NTFS', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles({ name: 'firmware_9.9.9.9.ffu', mimeType: 'application/octet-stream', buffer: await readFile(resolve(fixtures, 'synthetic-mainos.ffu')) });
  await page.getByRole('button', { name: 'Check preparation' }).click();
  const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Firmware version in image', exact: true }) });
  await expect(row).toContainText('Passed'); await expect(row).toContainText('1.2.3.0004');
  await expect(row).toContainText('RegistryFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.reg');
  await expect(row).toContainText('DsmFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.dsm.xml');
  await expect(row).not.toContainText('9.9.9.9');
  const downloadPromise = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export preparation' }).click();
  const report = JSON.parse(await readFile((await (await downloadPromise).path())!, 'utf8'));
  expect(report.plan.executable).toBe(false);
  expect(report.checks.find((c: { key: string }) => c.key === 'signing_catalog').status).not.toBe('passed');
});

test('browser reports corrupt MainOS package metadata and keeps recovery blocked', async ({ page }) => {
  const data = await readFile(resolve(fixtures, 'synthetic-mainos.ffu'));
  // The synthetic registry file is a resident gzip member in MFT record 15.
  const security = Math.ceil((32 + data.readUInt32LE(28)) / 4096) * 4096;
  const record = security + 8192 + 128 * 4096 + 16384 + 15 * 1024;
  const gzip = data.indexOf(Buffer.from([0x1f, 0x8b]), record);
  expect(gzip).toBeLessThan(record + 1024); data[gzip + 10] ^= 0xff;
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles({ name: 'corrupt-mainos.ffu', mimeType: 'application/octet-stream', buffer: data });
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Firmware version in image', exact: true }) })).toContainText('Failed');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('browser reads PLAT firmware metadata instead of a version in the filename', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles({ name: 'firmware_9.9.9.9.ffu', mimeType: 'application/octet-stream', buffer: await readFile(resolve(fixtures, 'synthetic-plat.ffu')) });
  await page.getByRole('button', { name: 'Check preparation' }).click();
  const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Firmware version in image', exact: true }) });
  await expect(row).toContainText('Passed'); await expect(row).toContainText('1.2.3.4');
  await expect(row).not.toContainText('9.9.9.9');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('signed FFU checks signature and table binding while leaving OEM trust unverified', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures, 'synthetic-signed.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  for (const label of ['Catalog signature', 'Signed hash-table binding']) {
    await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: label, exact: true }) })).toContainText('Passed');
  }
  await expect(page.getByRole('row').filter({ hasText: 'Firmware signer trust' })).toContainText('Unverified');
  await expect(page.getByRole('row').filter({ hasText: 'Firmware version in image' })).toContainText('Missing');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('a tampered catalog reports a failed signature without enabling recovery', async ({ page }) => {
  const data = await readFile(resolve(fixtures, 'synthetic-signed.ffu'));
  const catalogStart = data.readUInt32LE(0); const catalogSize = data.readUInt32LE(24);
  data[catalogStart + catalogSize - 1] ^= 1;
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles({ name: 'bad-catalog.ffu', mimeType: 'application/octet-stream', buffer: data });
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Catalog signature', exact: true }) })).toContainText('Failed');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('opens the real WASM engine, inspects FFU, and exports partition bytes', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(() => { Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }); });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures,'synthetic.ffu'));
  await expect(page.getByRole('heading', { name: 'synthetic.ffu' })).toBeVisible();
  await expect(page.getByText('SYNTHETIC.LUMIA.TEST')).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: 'EFIESP' });
  await expect(row).toContainText('2 KiB');
  const downloadPromise = page.waitForEvent('download');
  await row.getByRole('button', { name: 'Extract' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('EFIESP.img');
  const path = await download.path(); expect(path).not.toBeNull();
  expect(await readFile(path!)).toEqual(Buffer.alloc(2048,0xab));
  expect(errors).toEqual([]);
});

test('corrupt image reports an error and leaves the original selection intact', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures,'synthetic.ffu'));
  await expect(page.getByRole('heading', { name: 'synthetic.ffu' })).toBeVisible();
  const data = await readFile(resolve(fixtures,'synthetic.ffu')); data[12288+512+40] ^= 1;
  await page.locator('input[type=file]').setInputFiles({ name:'corrupt.ffu',mimeType:'application/octet-stream',buffer:data });
  await expect(page.getByRole('alert')).toContainText('CRC mismatch');
  await expect(page.getByRole('heading', { name: 'synthetic.ffu' })).toBeVisible();
});

test('capabilities do not advertise phone writes or verified hardware', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByRole('button', { name:'Compatibility',exact:true }).click();
  await expect(page.getByRole('heading', { name: 'Lumia 1020' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Lumia 730' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'Unlock Bootloader' })).toContainText('blocked');
  await expect(page.getByText('No phone/firmware/host combination is hardware verified yet.',{exact:false})).toBeVisible();
});

test('exports upstream-compatible GPT XML', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures,'gpt.bin'));
  await expect(page.getByRole('heading', { name: 'gpt.bin' })).toBeVisible();
  const downloadPromise = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export XML' }).click();
  const download = await downloadPromise; const xml = await readFile((await download.path())!,'utf8');
  expect(xml).toContain('Name="EFIESP"'); expect(xml).toContain('FirstSector="34"');
});

test('connection guide and responsive navigation remain usable', async ({ page }) => {
  await page.goto('/'); await page.getByRole('button', { name: 'Connection guide' }).click();
  await expect(page.getByRole('dialog')).toContainText('Windows ARM64');
  await page.getByRole('button', { name: 'Got it' }).click();
  await page.setViewportSize({width:480,height:900});
  await page.getByRole('button', { name:'Compatibility',exact:true }).click();
  await expect(page.getByRole('heading',{name:'Lumia 1020'})).toBeVisible();
});

test('unsupported WebUSB still permits local firmware inspection', async ({ page }) => {
  await page.addInitScript(() => { Object.defineProperty(Navigator.prototype,'usb',{value:undefined,configurable:true}); });
  await page.goto('/'); await expect(page.getByRole('button',{name:'Browse files'})).toBeEnabled();
  await expect(page.getByRole('button',{name:'Connect a device',exact:true})).toBeDisabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures,'synthetic.ffu'));
  await expect(page.getByRole('heading',{name:'synthetic.ffu'})).toBeVisible();
});

test('permission rejection does not create a connected device', async ({ page }) => {
  await page.addInitScript(() => {
    const usb=Object.assign(new EventTarget(),{requestDevice:async()=>{throw new DOMException('USB permission denied','SecurityError');},getDevices:async()=>[]});
    Object.defineProperty(Navigator.prototype,'usb',{value:usb,configurable:true});
  });
  await page.goto('/'); await expect(page.getByRole('button',{name:'Connect a device',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Connect a device',exact:true}).click();
  await expect(page.getByRole('heading',{name:'No device selected'})).toBeVisible();
  // nusb treats an ungranted chooser request as no selection; no device is claimed.
  await expect(page.getByRole('button',{name:'Connect a device',exact:true})).toBeEnabled();
});

test('recovery preparation is advisory, exports missing checks, and clears on a new image', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures, 'synthetic.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Chunk integrity' })).toContainText('Passed');
  await expect(page.getByRole('row').filter({ hasText: 'Phone identity' })).toContainText('Missing');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export preparation' }).click();
  const result = JSON.parse(await readFile((await (await downloadPromise).path())!, 'utf8'));
  expect(result.plan.executable).toBe(false); expect(result.plan.operation).toBe('stock_flash');
  const input = await readFile(resolve(fixtures, 'synthetic.ffu'));
  expect(result.plan.artifacts[0].sha256).toBe(createHash('sha256').update(input).digest('hex'));
  await expect(page.getByRole('row').filter({ hasText: 'Image fingerprint' })).toContainText('Passed');
  await page.locator('input[type=file]').setInputFiles(resolve(fixtures, 'gpt.bin'));
  await expect(page.getByRole('button', { name: 'Export preparation' })).toHaveCount(0);
});

test('browser detects payload corruption despite valid catalog and records its actual file digest', async ({ page }) => {
  const data = await readFile(resolve(fixtures, 'synthetic-signed.ffu'));
  data[data.length - 1] ^= 1;
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.locator('input[type=file]').setInputFiles({ name: 'bad-payload.ffu', mimeType: 'application/octet-stream', buffer: data });
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Chunk integrity' })).toContainText('Failed');
  await expect(page.getByRole('row').filter({ hasText: 'Chunk integrity' })).toContainText('hash mismatch at chunk');
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Catalog signature', exact: true }) })).toContainText('Passed');
  const downloadPromise = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export preparation' }).click();
  const report = JSON.parse(await readFile((await (await downloadPromise).path())!, 'utf8'));
  expect(report.plan.artifacts[0].sha256).toBe(createHash('sha256').update(data).digest('hex'));
  expect(report.plan.executable).toBe(false);
});
