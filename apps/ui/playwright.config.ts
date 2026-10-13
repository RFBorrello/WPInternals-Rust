import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  use: { baseURL: 'http://127.0.0.1:1420', headless: true, viewport: { width: 1360, height: 960 }, channel: process.env.WPI_BROWSER_CHANNEL ?? 'msedge' },
  webServer: { command: 'npm run dev', url: 'http://127.0.0.1:1420', reuseExistingServer: !process.env.CI, timeout: 30000 },
});
