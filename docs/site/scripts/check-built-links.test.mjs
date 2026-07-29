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
  write(root, 'dist/v/v2/explanation/current/index.html', '<html id="archived"></html>');
  write(root, 'src/data/contracts.yaml', '[]\n');
  write(
    root,
    'src/data/docsets.yaml',
    `current: latest
released: v1
docsets:
  - id: latest
    label: Latest
    path: /dev/
    status: current
    availability: unreleased
    source: main
    published_at: 2026-07-26
    description: Current docs.
    products: {}
  - id: v1
    label: Version 1
    path: /v/v1/
    status: archived
    availability: released
    source: v1
    published_at: 2026-07-25
    description: Archived docs.
    products: {}
  - id: v2
    label: Version 2
    path: /v/v2/
    status: archived
    availability: released
    source: v2
    published_at: 2026-07-24
    description: Another archived docset.
    products: {}
`,
  );
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

function run(root, args = []) {
  return spawnSync(process.execPath, [checker, ...args], { cwd: root, encoding: 'utf8' });
}

test('allows an archived standards page to cite root-relative current evidence', (t) => {
  const result = run(fixture(t, '/explanation/current/'));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built link check passed/);
});

test('allows archived navigation to the production development mount', (t) => {
  const result = run(fixture(t, '/dev/explanation/current/'));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built link check passed/);
});

test('allows archived navigation through the legacy preview redirect', (t) => {
  const root = fixture(t, '/preview/');
  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built link check passed/);
});

test('does not fall back when the legacy preview mount exists', (t) => {
  const root = fixture(t, '/preview/explanation/current/');
  write(root, 'dist/preview/index.html', '<html></html>');
  const result = run(root);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /links to missing/);
});

test('does not fall back when the production current-docset mount exists', (t) => {
  const root = fixture(t, '/dev/explanation/current/');
  write(root, 'dist/dev/index.html', '<html></html>');
  const result = run(root);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /links to missing/);
});

test('allows archived navigation to another declared archive', (t) => {
  const result = run(fixture(t, '/v/v2/explanation/current/'));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built link check passed/);
});

test('keeps rejecting unrelated links that escape an archive', (t) => {
  const result = run(fixture(t, '/not-evidence/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /links outside its archive/);
});

test('rejects paths that only share the production mount prefix', (t) => {
  const result = run(fixture(t, '/dev-escape/explanation/current/'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /links outside its archive/);
});

test('current scope accepts a declared archive without requiring its target tree', (t) => {
  const root = fixture(t, '/explanation/current/');
  write(root, 'dist/index.html', '<html><a href="/v/v1/missing/">Release</a></html>');
  const current = run(root, ['--scope', 'current']);
  const all = run(root);
  assert.equal(current.status, 0, current.stderr);
  assert.equal(all.status, 1);
  assert.match(all.stderr, /links to missing/);
});

test('current scope rejects links to undeclared archives', (t) => {
  const root = fixture(t, '/explanation/current/');
  write(root, 'dist/index.html', '<html><a href="/v/missing/">Release</a></html>');
  const current = run(root, ['--scope', 'current']);
  assert.equal(current.status, 1);
  assert.match(current.stderr, /links to unknown archive/);
});
