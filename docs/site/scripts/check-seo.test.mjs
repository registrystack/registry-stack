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

function fixture(t, options = {}) {
  const released = options.released ?? 'v1';
  const releasedPath = options.releasedPath ?? '/v/v1/';
  const canonical =
    options.canonical ?? `https://docs.registrystack.org${releasedPath}`;
  const root = mkdtempSync(resolve(tmpdir(), 'registry-seo-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  write(
    root,
    'src/data/docsets.yaml',
    `current: latest
released: ${released}
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
  - id: ${released}
    label: ${released}
    path: ${releasedPath}
    status: archived
    availability: released
    source: ${released}
    published_at: 2026-07-27
    description: Released docs.
    products: {}
`,
  );
  write(root, 'dist/preview/sitemap-index.xml', '<sitemapindex/>\n');
  write(root, 'dist/preview/index.html', '<html><head></head></html>\n');
  write(
    root,
    `dist${releasedPath}index.html`,
    '<html><head></head></html>\n',
  );
  write(
    root,
    'dist/index.html',
    `<html><head>
<meta name="robots" content="noindex,follow">
<meta name="registry-docset-redirect" content="${released}">
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
  assert.match(
    result.stdout,
    /1 Main HTML files, 1 released HTML files, 0 historical archive HTML files, and 1 released-root redirects/,
  );
});

test('rejects a released-root redirect canonicalized outside the released docset', (t) => {
  const result = run(fixture(t, { canonical: 'https://docs.registrystack.org/preview/' }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must canonically redirect into released docset v1/);
});

test('rejects noindex on the selected released docset', (t) => {
  const root = fixture(t);
  write(
    root,
    'dist/v/v1/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /is the released docset but has robots noindex,follow/);
});

test('accepts the immutable v0.13.0 legacy noindex bundle only while it is selected', (t) => {
  const root = fixture(t, {
    released: 'v0.13.0',
    releasedPath: '/v/0.13.0/',
  });
  write(
    root,
    'dist/v/0.13.0/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );

  const result = run(root);

  assert.equal(result.status, 0, result.stderr);
});
