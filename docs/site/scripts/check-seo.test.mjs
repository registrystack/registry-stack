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

function fixture(t, canonical = 'https://docs.registrystack.org/v/v1/') {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-seo-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  write(
    root,
    'src/data/docsets.yaml',
    `current: latest
released: v1
docsets:
  - id: latest
    label: Main
    path: /
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
  write(root, 'dist/preview/sitemap-index.xml', '<sitemapindex/>\n');
  write(root, 'dist/preview/index.html', '<html><head></head></html>\n');
  write(
    root,
    'dist/v/v1/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );
  write(
    root,
    'dist/index.html',
    `<html><head>
<meta name="robots" content="noindex,follow">
<meta name="registry-docset-redirect" content="v1">
<link rel="canonical" href="${canonical}">
</head></html>
`,
  );
  return root;
}

function run(root) {
  return spawnSync(process.execPath, [checker], { cwd: root, encoding: 'utf8' });
}

test('accepts preview, immutable archive, and released-root redirect SEO roles', (t) => {
  const result = run(fixture(t));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /1 Main HTML files, 1 archived HTML files, and 1 released-root redirects/);
});

test('rejects a released-root redirect canonicalized outside the released docset', (t) => {
  const result = run(fixture(t, 'https://docs.registrystack.org/preview/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must canonically redirect into released docset v1/);
});
