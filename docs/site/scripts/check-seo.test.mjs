import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

const checker = resolve(import.meta.dirname, 'check-seo.mjs');
const redirect = (canonical) => `<html><head>
<meta name="robots" content="noindex,follow">
<meta name="registry-docset-redirect" content="v1">
<link rel="canonical" href="${canonical}">
</head></html>
`;

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
  write(root, 'dist-production/CNAME', 'docs.registrystack.org\n');
  write(root, 'dist-production/robots.txt', 'User-agent: *\nAllow: /v/v1/\n');
  write(root, 'dist-production/llms.txt', '# Released v1\n');
  write(root, 'dist-production/preview/index.html', redirect(canonical));
  write(
    root,
    'dist-production/v/v1/index.html',
    '<html><head><meta name="robots" content="noindex,follow"></head></html>\n',
  );
  write(root, 'dist-production/index.html', redirect(canonical));
  return root;
}

function run(root) {
  return spawnSync(process.execPath, [checker], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      DOCS_DIST_DIR: resolve(root, 'dist-production'),
    },
  });
}

test('accepts immutable archives and both released-route maps in production', (t) => {
  const result = run(fixture(t));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /0 Main HTML files, 1 archived HTML files, and 2 released-root redirects/);
});

test('rejects a released redirect canonicalized outside the released docset', (t) => {
  const result = run(fixture(t, 'https://docs.registrystack.org/preview/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must canonically redirect into released docset v1/);
});

test('rejects normalized canonical traversal outside the released docset', (t) => {
  const result = run(fixture(t, 'https://docs.registrystack.org/v/v1/%2e%2e/private/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must canonically redirect into released docset v1/);
});

test('rejects ordinary nonarchive HTML in production', (t) => {
  const root = fixture(t);
  write(root, 'dist-production/current/index.html', '<html><head></head></html>\n');

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Production output contains ordinary nonarchive HTML/);
});

test('rejects preview Pagefind, sitemaps, and full or small corpora in production', async (t) => {
  for (const excluded of [
    '_pagefind/pagefind.js',
    'sitemap-index.xml',
    'llms-full.txt',
    'llms-small.txt',
  ]) {
    await t.test(excluded, () => {
      const root = fixture(t);
      write(root, `dist-production/${excluded}`, 'excluded\n');

      const result = run(root);

      assert.equal(result.status, 1);
      assert.match(result.stderr, /contains excluded preview discovery\/search output/);
    });
  }
});
