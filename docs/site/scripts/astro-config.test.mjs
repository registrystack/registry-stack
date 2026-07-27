import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const configSource = readFileSync(resolve(here, '../astro.config.mjs'), 'utf8');
const helperSource = configSource.match(
  /export function resolveDocsetBuildContext[\s\S]*?^}\n/m,
)?.[0];

assert.ok(helperSource, 'could not load resolveDocsetBuildContext from astro.config.mjs');
const helperUrl = `data:text/javascript,${encodeURIComponent(helperSource)}`;
const { resolveDocsetBuildContext } = await import(helperUrl);

const docsets = {
  current: 'latest',
  released: 'v0.8.4',
  docsets: [
    { id: 'latest', status: 'current' },
    { id: 'v0.8.4', status: 'archived' },
  ],
};
const currentOnlyPath = '/products/registry-notary/opencrvs-onboarding/';

test('current docset without a base keeps current-only redirects internal', () => {
  const context = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: 'latest' });

  assert.equal(context.base, undefined);
  assert.equal(context.isArchivedBuild, false);
  assert.equal(context.isHistoricalArchiveBuild, false);
  assert.equal(context.currentDocsetRedirect(currentOnlyPath), currentOnlyPath);
});

test('current docset with a preview base remains current', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'latest',
    DOCS_BASE: '/preview',
  });

  assert.equal(context.isArchivedBuild, false);
  assert.equal(
    context.currentDocsetRedirect(currentOnlyPath),
    `/preview${currentOnlyPath}`,
  );
});

test('archived docset redirects current-only pages to the Main-source preview', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'v0.8.4',
    DOCS_BASE: '/v/0.8.4/',
  });

  assert.equal(context.isArchivedBuild, true);
  assert.equal(context.isHistoricalArchiveBuild, false);
  assert.equal(
    context.currentDocsetRedirect(currentOnlyPath),
    `https://docs.registrystack.org/preview${currentOnlyPath}`,
  );
});

test('unsupported archive flags cannot make current components and config disagree', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'latest',
    DOCS_BASE: '/snapshot',
    DOCS_ARCHIVE: 'true',
  });

  assert.equal(context.isArchivedBuild, false);
  assert.equal(context.currentDocsetRedirect(currentOnlyPath), `/snapshot${currentOnlyPath}`);
});

test('archived builds disable platform-dependent Pagefind output', () => {
  assert.match(configSource, /pagefind:\s*!isArchivedBuild/);
});

test('only historical archives disable sitemap output', () => {
  assert.match(
    configSource,
    /isHistoricalArchiveBuild\s*\?\s*\[disabledSitemap\]\s*:\s*\[sitemap\(\)\]/,
  );
});
