import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { checkBuiltAnalytics } from './check-built-analytics.mjs';
import {
  DOCS_UMAMI_DOMAINS,
  DOCS_UMAMI_SCRIPT_SRC,
  DOCS_UMAMI_WEBSITE_ID,
  docsAnalyticsConfig,
} from '../src/lib/analytics.mjs';

test('analytics stays disabled outside the canonical released tree', () => {
  assert.equal(
    docsAnalyticsConfig({
      enabled: false,
      websiteId: 'deployment-id',
      scriptSrc: 'https://stats.example.invalid/script.js',
      domains: 'example.invalid',
    }),
    null,
  );
});

test('canonical release analytics uses source-controlled defaults', () => {
  assert.deepEqual(docsAnalyticsConfig({ enabled: true }), {
    websiteId: DOCS_UMAMI_WEBSITE_ID,
    scriptSrc: DOCS_UMAMI_SCRIPT_SRC,
    domains: DOCS_UMAMI_DOMAINS,
  });
  assert.deepEqual(
    docsAnalyticsConfig({
      enabled: true,
      websiteId: '   ',
      scriptSrc: '',
      domains: ' ',
    }),
    {
      websiteId: DOCS_UMAMI_WEBSITE_ID,
      scriptSrc: DOCS_UMAMI_SCRIPT_SRC,
      domains: DOCS_UMAMI_DOMAINS,
    },
  );
});

const trackingBridge = 'https://registrystack.org/tracking-bridge/';
const trackingPreferences =
  `<aside data-registry-shared-tracking data-shared-tracking-bridge-url="${trackingBridge}"></aside>`;

async function builtRoot(t, head, body = '') {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-analytics-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(root, { recursive: true });
  await writeFile(resolve(root, 'index.html'), `<html><head>${head}</head><body>${body}</body></html>`);
  return root;
}

test('built canonical root contains the exact Registry Docs tracker', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
    trackingPreferences,
  );
  await checkBuiltAnalytics(root, { enabled: true });
});

test('built canonical root rejects a different website identity', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="wrong-id" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
    trackingPreferences,
  );
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: true }),
    /source-controlled Registry Docs tracker/,
  );
});

test('built canonical root requires the pinned shared tracking bridge', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
    '<aside data-registry-shared-tracking data-shared-tracking-bridge-url="https://other.example.org/tracking-bridge/"></aside>',
  );
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: true }),
    /source-controlled shared tracking bridge/,
  );
});

test('built canonical root rejects a native Mautic tracker outside the bridge', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}" data-domains="${DOCS_UMAMI_DOMAINS}"></script><script src="https://mautic.example.org/mtc.js"></script>`,
    trackingPreferences,
  );
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: true }),
    /must not load Mautic directly/,
  );
});

test('noncanonical builds reject analytics', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
  );
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: false }),
    /must not contain analytics outside the canonical released tree/,
  );
});

test('noncanonical builds reject shared tracking controls', async (t) => {
  const root = await builtRoot(t, '', trackingPreferences);
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: false }),
    /must not contain shared tracking in this build/,
  );
});

const developmentTracking = { enabled: false, sharedTrackingEnabled: true };

test('public development output requires shared controls while keeping Umami off', async (t) => {
  const root = await builtRoot(t, '', trackingPreferences);
  await checkBuiltAnalytics(root, developmentTracking);
});

test('public development output rejects Umami', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}"></script>`,
    trackingPreferences,
  );
  await assert.rejects(checkBuiltAnalytics(root, developmentTracking), /must not contain analytics/);
});

test('public development output rejects missing, duplicate and untrusted shared controls', async (t) => {
  for (const body of [
    '',
    trackingPreferences + trackingPreferences,
    '<aside data-registry-shared-tracking data-shared-tracking-bridge-url="https://other.example.org/"></aside>',
  ]) {
    const root = await builtRoot(t, '', body);
    await assert.rejects(checkBuiltAnalytics(root, developmentTracking), /shared tracking/);
  }
});

test('public development output rejects a direct native tracker', async (t) => {
  const root = await builtRoot(t, '<script src="https://mautic.example.org/mtc.js"></script>', trackingPreferences);
  await assert.rejects(checkBuiltAnalytics(root, developmentTracking), /must not load Mautic directly/);
});

test('error output cannot offer shared tracking even in an eligible tree', async (t) => {
  const root = await builtRoot(t, '', trackingPreferences);
  await writeFile(resolve(root, '404.html'), '<html><body></body></html>');
  await checkBuiltAnalytics(root, developmentTracking);
  await writeFile(resolve(root, '404.html'), `<html><body>${trackingPreferences}</body></html>`);
  await assert.rejects(checkBuiltAnalytics(root, developmentTracking), /404.html.*must not contain shared tracking/);
});

test('development build command verifies the built tracking profile', async (t) => {
  const root = await builtRoot(t, '', trackingPreferences);
  const checker = new URL('./check-built-analytics.mjs', import.meta.url);
  execFileSync(process.execPath, [checker.pathname, root, '--profile', 'development']);
  await writeFile(resolve(root, 'index.html'), '<html><body></body></html>');
  assert.throws(() => execFileSync(process.execPath, [checker.pathname, root, '--profile', 'development'], { stdio: 'pipe' }));
});
