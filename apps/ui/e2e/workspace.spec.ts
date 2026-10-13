import { test, expect } from '@playwright/test';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');

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
