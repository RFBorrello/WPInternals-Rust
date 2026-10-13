import { expect, test, type Page } from '@playwright/test';

type Behavior = 'success' | 'wrong-id' | 'short-write' | 'timeout' | 'disconnect' | 'missing-interface';

// Mock only the OS WebUSB boundary. The real nusb adapter, descriptor parser,
// WASM protocol codecs, profile selection and React UI run in every test.
async function mockLumia(page: Page, behavior: Behavior = 'success') {
  await page.addInitScript((behavior) => {
    const state = { connected: true, serial: 'SYNTHETIC', firmware: '3051.50009.1451.1003', disconnectDuringRead: false, methods: [] as string[], claims: [] as number[], releases: [] as number[], controls: [] as number[] };
    const interfaces = [0, 1, 2, 3].map(interfaceNumber => ({
      interfaceNumber, claimed: false, alternates: [{ alternateSetting: 0,
        interfaceClass: interfaceNumber === 0 ? 6 : 255, interfaceSubclass: 255, interfaceProtocol: 255 }],
    }));
    const descriptor = [9, 2, 0, 0, 4, 1, 0, 128, 50];
    for (let i = 0; i < 4; i++) {
      const bulk = i === 1 || (i === 3 && behavior !== 'missing-interface');
      descriptor.push(9, 4, i, 0, bulk ? 2 : 0, i === 0 ? 6 : 255, 255, 255, 0);
      if (bulk) descriptor.push(7, 5, 0x80 | i, 2, 64, 0, 0, 7, 5, i, 2, 64, 0, 0);
    }
    descriptor[2] = descriptor.length;
    const deviceDescriptor = [18, 1, 0, 2, 0, 0, 0, 64, 0x21, 4, 0x61, 6, 0, 1, 0, 0, 0, 1];
    let request: { id: number; method: string };
    const configuration = { configurationValue: 1, interfaces };
    const usb = Object.assign(new EventTarget(), {
      requestDevice: async () => device,
      getDevices: async () => state.connected ? [device] : [],
    });
    const device = {
      vendorId: 0x0421, productId: 0x0661, productName: 'Nokia Lumia 909 (RM-875)', manufacturerName: 'Nokia',
      get serialNumber() { return state.serial; }, deviceVersionMajor: 1, deviceVersionMinor: 0, deviceVersionSubminor: 0,
      usbVersionMajor: 2, usbVersionMinor: 0, usbVersionSubminor: 0, deviceClass: 0, deviceSubclass: 0, deviceProtocol: 0,
      configurations: [configuration], configuration, opened: false,
      open: async () => { device.opened = true; },
      controlTransferIn: async (setup: { request: number; value: number }, length: number) => {
        state.controls.push(setup.request);
        if (setup.request !== 6) throw new Error('Unexpected control request');
        const bytes = new Uint8Array((setup.value >> 8 === 1 ? deviceDescriptor : descriptor).slice(0, length));
        return { status: 'ok', data: new DataView(bytes.buffer) };
      },
      claimInterface: async (i: number) => { state.claims.push(i); interfaces[i].claimed = true; },
      releaseInterface: async (i: number) => { state.releases.push(i); interfaces[i].claimed = false; },
      transferOut: async (endpoint: number, data: Uint8Array) => {
        if (endpoint !== 3) throw new Error('Wrong normal-mode endpoint');
        request = JSON.parse(new TextDecoder().decode(data)); state.methods.push(request.method);
        return { status: 'ok', bytesWritten: behavior === 'short-write' ? data.length - 1 : data.length };
      },
      transferIn: async () => {
        if (behavior === 'timeout') return new Promise(() => {});
        if (behavior === 'disconnect' || state.disconnectDuringRead) { state.connected = false; usb.dispatchEvent(new Event('disconnect')); }
        const fields = { ManufacturerModelName: 'RM-875_eu_euro1_267', ProductCode: '059T909', SwVersion: state.firmware };
        const bytes = new TextEncoder().encode(JSON.stringify({ jsonrpc: '2.0', id: behavior === 'wrong-id' ? 99 : request.id, result: fields }));
        return { status: 'ok', data: new DataView(bytes.buffer) };
      },
    };
    Object.defineProperty(Navigator.prototype, 'usb', { value: usb, configurable: true });
    Object.assign(window, { probeFixture: { state, disconnect: () => { state.connected = false; usb.dispatchEvent(new Event('disconnect')); }, reconnect: () => { state.connected = true; } } });
  }, behavior);
}
async function connect(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Connect a device', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Read device information' })).toBeEnabled();
}
async function state(page: Page) {
  return page.evaluate(() => (window as unknown as { probeFixture: { state: { methods: string[]; claims: number[]; releases: number[]; controls: number[] } } }).probeFixture.state);
}

test('normal-mode WebUSB reads model and firmware only through vendor interface 3', async ({ page }) => {
  await mockLumia(page); await connect(page);
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('heading', { name: 'Lumia 1020', exact: true })).toBeVisible();
  await expect(page.getByText('3051.50009.1451.1003', { exact: true })).toBeVisible();
  await expect(page.getByText('Not queried in normal mode', { exact: true })).toBeVisible();
  const observed = await state(page);
  expect(observed.methods).toEqual(['ReadManufacturerModelName', 'ReadProductCode', 'ReadSwVersion']);
  expect(observed.claims).toEqual([3]); expect(observed.releases).toEqual([3]);
  expect(observed.controls.every(request => request === 6)).toBe(true);
  await page.getByRole('button', { name: 'Compatibility', exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Unlock Bootloader' })).toContainText('blocked');
});

for (const behavior of ['wrong-id', 'short-write', 'timeout'] as const) {
  test(`interrupted normal probe (${behavior}) rejects identity and blocks retries`, async ({ page }) => {
    await mockLumia(page, behavior); await connect(page);
    await page.getByRole('button', { name: 'Read device information' }).click();
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Not yet established', { exact: true }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Read device information' }).click();
    await expect(page.getByRole('alert')).toContainText('Previous probe was interrupted');
    const observed = await state(page);
    expect(observed.methods).toEqual(['ReadManufacturerModelName']);
    expect(observed.releases).toEqual([3]);
  });
}

test('normal probe refuses another vendor interface when interface 3 has no bulk endpoints', async ({ page }) => {
  await mockLumia(page, 'missing-interface'); await connect(page);
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('alert')).toContainText('normal mode requires interface 3');
  expect((await state(page)).claims).toEqual([]); expect((await state(page)).methods).toEqual([]);
});

test('a disconnect discards a late identification result', async ({ page }) => {
  await mockLumia(page, 'disconnect'); await connect(page);
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('heading', { name: 'No device selected' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connect a device', exact: true })).toBeEnabled();
  await expect(page.getByRole('heading', { name: 'Lumia 1020', exact: true })).toHaveCount(0);
});

test('timeout requires observed disconnection and renewed selection', async ({ page }) => {
  await mockLumia(page, 'timeout'); await connect(page);
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('alert')).toContainText('timed out', { timeout: 10000 });
  await page.evaluate(() => (window as unknown as { probeFixture: { disconnect(): void } }).probeFixture.disconnect());
  await page.getByRole('button', { name: 'Scan USB devices' }).click();
  await expect(page.getByRole('button', { name: 'Connect a device', exact: true })).toBeEnabled();
  await page.evaluate(() => (window as unknown as { probeFixture: { reconnect(): void } }).probeFixture.reconnect());
  await page.getByRole('button', { name: 'Connect a device', exact: true }).click();
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('alert')).toContainText('USB read timed out', { timeout: 10000 });
  expect((await state(page)).methods).toHaveLength(2);
});

test('mode preview exports a blocked redacted plan without sending mode commands', async ({ page }) => {
  await mockLumia(page); await connect(page);
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('button', { name: 'Remember this phone' })).toBeEnabled();
  const before = (await state(page)).methods;
  await page.getByRole('button', { name: 'Preview mode change' }).click();
  await expect(page.getByText('Mode-change preview · execution blocked')).toBeVisible();
  await expect(page.getByText('Normal → Flash · Normal to Flash: SetDeviceMode / HwReset')).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export mode preview' }).click();
  const file = await (await download).path();
  const fs = await import('node:fs/promises');
  const text = await fs.readFile(file!, 'utf8'); const report = JSON.parse(text);
  expect(report.plan.executable).toBe(false); expect(report.plan.device.serial).toBeNull();
  expect(text).not.toContain('SYNTHETIC'); expect((await state(page)).methods).toEqual(before);
  await page.getByLabel('Expected mode').selectOption('normal');
  await expect(page.getByText('Mode-change preview · execution blocked')).toHaveCount(0);
});

async function rememberAndReconnect(page: Page, change?: 'serial' | 'firmware' | 'missing-serial') {
  await mockLumia(page); await connect(page);
  if (change === 'missing-serial') await page.evaluate(() => {
    (window as unknown as { probeFixture: { state: { serial: string } } }).probeFixture.state.serial = '';
  });
  await page.getByRole('button', { name: 'Read device information' }).click();
  await expect(page.getByRole('button', { name: 'Remember this phone' })).toBeEnabled();
  await page.getByRole('button', { name: 'Remember this phone' }).click();
  await page.getByLabel('Expected mode').selectOption('normal');
  await page.evaluate(change => {
    const f = (window as unknown as { probeFixture: { disconnect(): void; state: { serial: string; firmware: string } } }).probeFixture;
    f.disconnect(); if (change === 'serial') f.state.serial = 'ANOTHER-PHONE'; if (change === 'firmware') f.state.firmware = 'unexpected';
  }, change);
  await expect(page.getByRole('heading', { name: 'No device selected' })).toBeVisible();
  await page.evaluate(() => (window as unknown as { probeFixture: { reconnect(): void } }).probeFixture.reconnect());
  await page.getByRole('button', { name: 'Connect a device', exact: true }).click();
}

test('remembered phone survives reconnection and a fresh probe yields only serial correlation', async ({ page }) => {
  await rememberAndReconnect(page);
  await page.getByRole('button', { name: 'Check reconnection' }).click();
  await expect(page.getByText('Reconnection: Correlated', { exact: true })).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export reconnection check' }).click();
  const fs = await import('node:fs/promises');
  const text = await fs.readFile((await (await download).path())!, 'utf8');
  expect(JSON.parse(text).recovery_authorized).toBe(false); expect(text).not.toContain('SYNTHETIC');
  expect((await state(page)).methods).toEqual(['ReadManufacturerModelName', 'ReadProductCode', 'ReadSwVersion', 'ReadManufacturerModelName', 'ReadProductCode', 'ReadSwVersion']);
  await page.setViewportSize({ width: 390, height: 844 });
  const resultCellsFit = await page.locator('.reconnect-card td:last-child').evaluateAll(cells => cells.length > 0 && cells.every(cell => {
    const rect = cell.getBoundingClientRect(); return rect.left >= 0 && rect.right <= window.innerWidth;
  }));
  expect(resultCellsFit).toBe(true);
  await page.getByRole('button', { name: 'Forget phone' }).click();
  await expect(page.getByRole('button', { name: 'Check reconnection' })).toBeDisabled();
  await expect(page.getByText('Reconnection: Correlated', { exact: true })).toHaveCount(0);
});
for (const change of ['serial', 'firmware'] as const) {
  test(`returning phone ${change} mismatch is rejected`, async ({ page }) => {
    await rememberAndReconnect(page, change);
    await page.getByRole('button', { name: 'Check reconnection' }).click();
    await expect(page.getByText('Reconnection: Mismatch', { exact: true })).toBeVisible();
    expect((await state(page)).methods.every(m => m.startsWith('Read'))).toBe(true);
  });
}
test('missing USB serial cannot correlate identical model and firmware', async ({ page }) => {
  await rememberAndReconnect(page, 'missing-serial');
  await page.getByRole('button', { name: 'Check reconnection' }).click();
  await expect(page.getByText('Reconnection: Unverified', { exact: true })).toBeVisible();
});
test('disconnect discards a late reconnection check', async ({ page }) => {
  await rememberAndReconnect(page);
  await page.evaluate(() => (window as unknown as { probeFixture: { state: { disconnectDuringRead: boolean } } }).probeFixture.state.disconnectDuringRead = true);
  await page.getByRole('button', { name: 'Check reconnection' }).click();
  await expect(page.getByRole('heading', { name: 'No device selected' })).toBeVisible();
  await expect(page.getByText(/^Reconnection:/)).toHaveCount(0);
});
