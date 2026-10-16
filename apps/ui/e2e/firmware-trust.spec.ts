import { test, expect } from '@playwright/test';
import { resolve } from 'node:path';
const fixtures = resolve(import.meta.dirname, '../../../tests/fixtures');

test('an image-local production PK completes chain signatures but never establishes OEM trust', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-image-issuer.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  const chain = page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Certificate-chain signatures', exact: true }) });
  await expect(chain).toContainText('Passed');
  await expect(chain).toContainText('EFIESP/Nokia/Security/Nokia_Production_PK.bin');
  for (const label of ['OEM trust anchor','Signer revocation','Firmware signer trust']) {
    await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: label, exact: true }) })).toContainText('Unverified');
  }
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('a same-name PK with the wrong key fails the shared browser chain check', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-wrong-issuer.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Catalog signature', exact: true }) })).toContainText('Passed');
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Certificate-chain signatures', exact: true }) })).toContainText('Failed');
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Firmware signer trust', exact: true }) })).toContainText('Failed');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('an internally consistent certificate chain never becomes an OEM trust anchor', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-chain.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  for (const label of ['Catalog signature','Signed hash-table binding','Certificate-chain signatures','Signer certificate dates','Signer key usage','Signer code-signing usage']) {
    await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: label, exact: true }) })).toContainText('Passed');
  }
  for (const label of ['OEM trust anchor','Signer revocation','Firmware signer trust']) {
    await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: label, exact: true }) })).toContainText('Unverified');
  }
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});

test('an unsuitable certificate signing purpose fails trust despite a valid catalog signature', async ({ page }) => {
  await page.goto('/'); await expect(page.getByRole('button', { name: 'Browse files' })).toBeEnabled();
  await page.getByLabel('Select local firmware image', { exact: true }).setInputFiles(resolve(fixtures, 'synthetic-bad-signer.ffu'));
  await page.getByRole('button', { name: 'Check preparation' }).click();
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Catalog signature', exact: true }) })).toContainText('Passed');
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Signer code-signing usage', exact: true }) })).toContainText('Failed');
  await expect(page.getByRole('row').filter({ has: page.getByRole('cell', { name: 'Firmware signer trust', exact: true }) })).toContainText('Failed');
  await expect(page.getByText('Recovery is unavailable.', { exact: false })).toBeVisible();
});
