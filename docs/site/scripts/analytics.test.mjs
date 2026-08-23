import assert from 'node:assert/strict';
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

async function builtRoot(t, body) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-analytics-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(root, { recursive: true });
  await writeFile(resolve(root, 'index.html'), `<html><head>${body}</head></html>`);
  return root;
}

test('built canonical root contains the exact Registry Docs tracker', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="${DOCS_UMAMI_WEBSITE_ID}" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
  );
  await checkBuiltAnalytics(root, { enabled: true });
});

test('built canonical root rejects a different website identity', async (t) => {
  const root = await builtRoot(
    t,
    `<script defer src="${DOCS_UMAMI_SCRIPT_SRC}" data-website-id="wrong-id" data-domains="${DOCS_UMAMI_DOMAINS}"></script>`,
  );
  await assert.rejects(
    checkBuiltAnalytics(root, { enabled: true }),
    /source-controlled Registry Docs tracker/,
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
