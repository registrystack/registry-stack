import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

const checker = resolve(import.meta.dirname, 'check-seo.mjs');

function write(root, path, contents) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function docsets(root) {
  write(
    root,
    'src/data/docsets.yaml',
    `current: latest
released: v1
docsets:
  - id: latest
    label: Development
    path: /dev/
    status: current
    availability: unreleased
    source: main
    published_at: 2026-07-27
    description: Main docs.
    products: {}
  - id: v1
    label: v1
    path: /v/v1/
    status: archived
    availability: released
    source: v1
    published_at: 2026-07-27
    description: Released docs.
    products: {}
`,
  );
}

function productionFixture(t) {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-seo-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  docsets(root);
  write(
    root,
    'dist/dev/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );
  write(
    root,
    'dist/v/v1/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );
  write(
    root,
    'dist/index.html',
    '<html><head><link rel="canonical" href="https://docs.registrystack.org/"><link rel="sitemap" href="https://docs.registrystack.org/sitemap-index.xml"></head></html>\n',
  );
  write(
    root,
    'dist/preview/index.html',
    '<html><head><meta name="robots" content="noindex,follow"><meta name="registry-legacy-preview-redirect" content="v1"><link rel="canonical" href="https://docs.registrystack.org/"></head></html>\n',
  );
  write(
    root,
    'dist/sitemap-index.xml',
    '<sitemapindex><sitemap><loc>https://docs.registrystack.org/sitemap-0.xml</loc></sitemap></sitemapindex>\n',
  );
  write(
    root,
    'dist/sitemap-0.xml',
    '<urlset><url><loc>https://docs.registrystack.org/</loc></url></urlset>\n',
  );
  write(
    root,
    'dist/robots.txt',
    'Sitemap: https://docs.registrystack.org/sitemap-index.xml\n',
  );
  return root;
}

function run(root, args = []) {
  return spawnSync(process.execPath, [checker, ...args], { cwd: root, encoding: 'utf8' });
}

test('accepts canonical root, unreleased Main, immutable archives, and legacy redirects', (t) => {
  const result = run(productionFixture(t));
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /1 canonical release HTML files, 1 unreleased Main HTML files, 1 immutable archive HTML files, and 1 legacy redirects/,
  );
});

test('accepts a local unreleased build at dist root', (t) => {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-seo-current-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  docsets(root);
  write(
    root,
    'dist/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );

  const result = run(root, ['--scope', 'current']);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /1 unreleased Main HTML files/);
});

test('accepts a canonical release redirect without a sitemap link', (t) => {
  const root = productionFixture(t);
  write(
    root,
    'dist/old/index.html',
    '<!doctype html><title>Redirect</title><meta http-equiv="refresh" content="0;url=/"><link rel="canonical" href="https://docs.registrystack.org/">\n',
  );

  const result = run(root);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /2 canonical release HTML files/);
});

test('rejects indexable unreleased Main documentation', (t) => {
  const root = productionFixture(t);
  write(root, 'dist/dev/index.html', '<html><head></head></html>\n');

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /unreleased Main but missing robots noindex,follow/);
});

test('rejects an indexable immutable archive', (t) => {
  const root = productionFixture(t);
  write(root, 'dist/v/v1/index.html', '<html><head></head></html>\n');

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /is archived but missing robots noindex,follow/);
});

test('rejects noindex on canonical release documentation', (t) => {
  const root = productionFixture(t);
  write(
    root,
    'dist/index.html',
    '<html><head><meta name="robots" content="noindex,follow"><link rel="canonical" href="https://docs.registrystack.org/"><link rel="sitemap" href="https://docs.registrystack.org/sitemap-index.xml"></head></html>\n',
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /canonical release documentation but has noindex/);
});

test('rejects a legacy redirect canonicalized to development documentation', (t) => {
  const root = productionFixture(t);
  write(
    root,
    'dist/preview/index.html',
    '<html><head><meta name="robots" content="noindex,follow"><meta name="registry-legacy-preview-redirect" content="v1"><link rel="canonical" href="https://docs.registrystack.org/dev/"></head></html>\n',
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /must canonicalize to the released root namespace/);
});

test('rejects non-root URLs in the canonical sitemap', (t) => {
  const root = productionFixture(t);
  write(
    root,
    'dist/sitemap-0.xml',
    '<urlset><url><loc>https://docs.registrystack.org/dev/</loc></url></urlset>\n',
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Canonical sitemap contains a non-root URL/);
});

test('rejects redirect pages in the canonical sitemap', (t) => {
  const root = productionFixture(t);
  write(
    root,
    'dist/old/index.html',
    '<!doctype html><title>Redirect</title><meta http-equiv="refresh" content="0;url=/"><link rel="canonical" href="https://docs.registrystack.org/">\n',
  );
  write(
    root,
    'dist/sitemap-0.xml',
    '<urlset><url><loc>https://docs.registrystack.org/old/</loc></url></urlset>\n',
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Canonical sitemap must not include redirect page/);
});
