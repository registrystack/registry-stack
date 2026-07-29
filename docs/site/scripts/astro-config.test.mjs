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
    { id: 'latest', status: 'current', availability: 'unreleased', path: '/dev/' },
    { id: 'v0.8.4', status: 'archived', availability: 'released', path: '/v/0.8.4/' },
  ],
};
const currentOnlyPath = '/products/registry-notary/opencrvs-onboarding/';

test('current docset without a base keeps current-only redirects internal', () => {
  const context = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: 'latest' });

  assert.equal(context.base, undefined);
  assert.equal(context.isArchivedBuild, false);
  assert.equal(context.isHistoricalArchiveBuild, false);
  assert.equal(context.isSearchExcludedBuild, true);
  assert.equal(context.currentDocsetRedirect(currentOnlyPath), currentOnlyPath);
});

test('current docset with a development base remains current', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'latest',
    DOCS_BASE: '/dev',
  });

  assert.equal(context.isArchivedBuild, false);
  assert.equal(
    context.currentDocsetRedirect(currentOnlyPath),
    `/dev${currentOnlyPath}`,
  );
});

test('archived docset redirects current-only pages to protected main', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'v0.8.4',
    DOCS_BASE: '/v/0.8.4/',
  });

  assert.equal(context.isArchivedBuild, true);
  assert.equal(context.isHistoricalArchiveBuild, false);
  assert.equal(
    context.currentDocsetRedirect(currentOnlyPath),
    `https://docs.registrystack.org/dev${currentOnlyPath}`,
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

test('only search-excluded builds disable Pagefind output', () => {
  assert.match(configSource, /pagefind:\s*!isSearchExcludedBuild/);
});

test('released archive builds ignore the mutable released pointer', () => {
  const context = resolveDocsetBuildContext(docsets, {
    DOCS_DOCSET: 'v0.8.4',
    DOCS_BASE: '/',
    DOCS_RELEASED_ARCHIVE: 'true',
  });

  assert.equal(context.isReleasedArchiveBuild, true);
  assert.equal(context.isHistoricalArchiveBuild, false);
  assert.equal(context.isSearchExcludedBuild, false);
});

test('historical archives and unreleased development builds disable sitemap output', () => {
  assert.match(
    configSource,
    /isSearchExcludedBuild\s*\?\s*\[disabledSitemap\]\s*:\s*\[sitemap\(\)\]/,
  );
});
