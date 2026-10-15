import { test, expect } from '@playwright/test';
test('browser backup access explains desktop fallback without requesting USB or changing modes', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'usb', { configurable: true, value: { requestDevice() { throw new Error('Backup check must not request USB'); }, getDevices: async () => [], addEventListener() {}, removeEventListener() {} } });
  });
  await page.goto('/');
  const button = page.getByRole('button', { name: 'Check backup access' });
  await expect(button).toBeEnabled(); await button.click();
  const card = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Backup access' }) });
  await expect(card.getByRole('status')).toContainText('Use the desktop build or CLI');
  await expect(card.getByRole('status')).toContainText('Normal-mode information access does not expose partitions');
  await expect(card).toContainText('This check never changes phone modes or disk settings');
});

test('desktop backup inventory shows an empty result and clears it on a later IPC failure', async ({ page }) => {
  await page.addInitScript(() => {
    let attempts = 0;
    const capabilities = { device_id: null, host: 'windows', transport: 'usb', capabilities: [] };
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: { invoke: async (command: string) => {
      if (command === 'startup') return { models: [], capabilities };
      if (command === 'capabilities') return capabilities;
      if (command === 'storage_discovery') {
        if (attempts++) throw new Error('Storage inventory timed out');
        return { host_supported: true, hardware_validated: false, candidates: [], message: 'Read-only Windows inventory only.' };
      }
      throw new Error(`Unexpected desktop command: ${command}`);
    } } });
  });
  await page.goto('/');
  const button = page.getByRole('button', { name: 'Check backup access' });
  const card = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Backup access' }) });
  await expect(button).toBeEnabled(); await button.click();
  await expect(card.getByRole('status')).toContainText('No recognized phone-storage disk is exposed');
  await button.click();
  await expect(page.getByText('Storage inventory timed out', { exact: true }).first()).toBeVisible();
  await expect(card.getByRole('status')).toHaveCount(0);
});
