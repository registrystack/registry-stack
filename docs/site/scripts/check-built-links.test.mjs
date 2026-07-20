import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const checker = resolve(here, 'check-built-links.mjs');

function write(root, path, content) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function fixture(t, archivedHref) {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-built-links-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  write(root, 'dist/index.html', '<html></html>');
  write(root, 'dist/explanation/current/index.html', '<html id="current"></html>');
  write(
    root,
    'dist/v/v1/reference/standards/index.html',
    `<html><a href="${archivedHref}">Evidence</a></html>`,
  );
  write(root, 'src/data/contracts.yaml', '[]\n');
  write(
    root,
    'src/data/standards.yaml',
    `- id: test
  official_url: /not-evidence/
  evidence_docs:
    - label: current
      url: /explanation/current/
`,
  );
  return root;
}

function run(root) {
  return spawnSync(process.execPath, [checker], { cwd: root, encoding: 'utf8' });
}

test('allows an archived standards page to cite root-relative current evidence', (t) => {
  const result = run(fixture(t, '/explanation/current/'));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built link check passed/);
});

test('keeps rejecting unrelated links that escape an archive', (t) => {
  const result = run(fixture(t, '/not-evidence/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /links outside its archive/);
});

test('uses a restored archive link index in the combined link check', (t) => {
  const root = fixture(t, '/explanation/current/');
  write(
    root,
    'dist/.archive-link-indexes/v1.json',
    `${JSON.stringify({
      schema_version: 'registry-docs.link-index.v1',
      cache_key: 'a'.repeat(64),
      docset_id: 'v1',
      archive_path: '/v/v1/',
      pages: [
        {
          file: 'v/v1/reference/standards/index.html',
          url: '/v/v1/reference/standards/',
          ids: [],
          links: ['/not-evidence/'],
        },
      ],
    })}\n`,
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /links outside its archive/);
});

test('rejects a cached index whose page roster omits archive output', (t) => {
  const root = fixture(t, '/explanation/current/');
  write(
    root,
    'dist/.archive-link-indexes/v1.json',
    `${JSON.stringify({
      schema_version: 'registry-docs.link-index.v1',
      cache_key: 'a'.repeat(64),
      docset_id: 'v1',
      archive_path: '/v/v1/',
      pages: [],
    })}\n`,
  );

  const result = run(root);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /page roster does not match/);
});
