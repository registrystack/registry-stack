import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import {
  checkedDocset,
  corpusRequirements,
  isRegularFile,
  sampleMarkdownFiles,
} from './check-llms-contract.mjs';

const manifest = {
  current: 'latest',
  docsets: [
    {
      id: 'latest',
      path: '/dev/',
      status: 'current',
      products: {
        'registry-manifest': {},
        'registry-evidence': {},
      },
    },
    {
      id: 'v0.38.0',
      path: '/v/0.38.0/',
      status: 'archived',
      products: {
        'registry-manifest': {},
        'registry-evidence': {},
        'registry-relay': {},
      },
    },
    {
      id: 'v0.12.2',
      path: '/v/0.12.2/',
      status: 'archived',
      products: {
        'registry-manifest': {},
        'registry-evidence': {},
        'registry-relay': {},
        'registry-notary': {},
      },
    },
  ],
};

test('current corpus contract samples retained products', () => {
  const docset = checkedDocset(manifest, { DOCS_PUBLIC_BASE: '/dev/' });
  assert.equal(docset.id, 'latest');
  assert.deepEqual(
    corpusRequirements(docset).map(({ label }) => label),
    ['Registry Manifest', 'Evidence Gateway'],
  );
  assert.deepEqual(sampleMarkdownFiles(docset), [
    'explanation/architecture.md',
    'index.md',
    'products/registry-manifest.md',
    'products/registry-evidence.md',
    'tutorials/first-breg.md',
  ]);
});

test('historical Relay docset keeps its original Relay corpus checks', () => {
  const docset = checkedDocset(manifest, { DOCS_DOCSET: 'v0.38.0' });
  assert.deepEqual(
    corpusRequirements(docset).map(({ label }) => label),
    ['Registry Manifest', 'Evidence Gateway', 'Registry Relay'],
  );
  assert.ok(sampleMarkdownFiles(docset).includes('products/registry-relay.md'));
  assert.ok(sampleMarkdownFiles(docset).includes('tutorials/publish-governed-sqlite-registry.md'));
});

test('older historical docset keeps its Registry Notary corpus check', () => {
  const docset = checkedDocset(manifest, { DOCS_DOCSET: 'v0.12.2' });
  assert.deepEqual(
    corpusRequirements(docset).map(({ label }) => label),
    ['Registry Manifest', 'Evidence Gateway', 'Registry Relay', 'Registry Notary'],
  );
});

test('regular-file check rejects redirect directories', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-llms-contract-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(resolve(root, 'redirect.md'));
  await writeFile(resolve(root, 'page.md'), '# Page\n');

  assert.equal(await isRegularFile(resolve(root, 'page.md')), true);
  assert.equal(await isRegularFile(resolve(root, 'redirect.md')), false);
  assert.equal(await isRegularFile(resolve(root, 'missing.md')), false);
});
