import { test, expect } from '@playwright/test';

test('landing page responds with 200 and offers SolmaraID sign-in', async ({ page }) => {
  let proofStreamRequests = 0;
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/proof/stream') {
      proofStreamRequests += 1;
    }
  });

  const response = await page.goto('/');
  expect(response?.status()).toBe(200);
  // The Glass Government wordmark is in the layout chrome; the landing hero CTA is
  // the sign-in. Both must be present on the unauthenticated landing.
  await expect(page.getByText('Glass Government')).toBeVisible();
  await expect(page.getByTestId('signin')).toBeVisible();
  // The synthetic-data banner is always visible.
  await expect(page.getByText('Synthetic demo data')).toBeVisible();
  await page.waitForTimeout(1_000);
  expect(proofStreamRequests).toBe(0);
  await expect(page.getByText('Reconnecting to audit feed')).toHaveCount(0);
});
