import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';

import {
  LINK_INDEX_SCHEMA,
  archiveEnvironmentDigest,
  archiveIdentity,
  archiveOutputDirectory,
  computeArchiveInputDigest,
  restoreArchive,
  storeArchive,
} from './archive-cache.mjs';

const inputDigest = 'a'.repeat(64);

function fixtureDocset(ref = '1'.repeat(40)) {
  return {
    id: 'v1.0.0',
    label: 'v1.0.0',
    path: '/v/1.0.0/',
    status: 'archived',
    source: 'registry-stack-v1.0.0',
    published_at: '2026-01-01',
    description: 'Archive.',
    products: {
      'registry-stack': { version: 'v1.0.0', ref },
      crosswalk: { version: 'v0.2.0', ref: '2'.repeat(40) },
    },
  };
}

function fixtureManifest(docset = fixtureDocset()) {
  return {
    current: 'latest',
    docsets: [
      {
        id: 'latest',
        path: '/',
        status: 'current',
        products: { 'registry-stack': { version: 'v1.1.0', ref: 'HEAD' } },
      },
      docset,
    ],
  };
}

async function temporaryRoot(t) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-archive-cache-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function write(path, body) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, body);
}

test('archive identity is stable but changes with source refs and inputs', () => {
  const docset = fixtureDocset();
  const manifest = fixtureManifest(docset);
  const first = archiveIdentity({ docset, manifest, inputDigest, nodeVersion: '22.12.0' });
  const reordered = archiveIdentity({
    docset: { ...docset, products: Object.fromEntries(Object.entries(docset.products).reverse()) },
    manifest,
    inputDigest,
    nodeVersion: '22.12.0',
  });
  const changedRef = archiveIdentity({
    docset: fixtureDocset('3'.repeat(40)),
    manifest,
    inputDigest,
    nodeVersion: '22.12.0',
  });
  const changedInputs = archiveIdentity({
    docset,
    manifest,
    inputDigest: 'b'.repeat(64),
    nodeVersion: '22.12.0',
  });

  assert.equal(first.cache_key, reordered.cache_key);
  assert.notEqual(first.cache_key, changedRef.cache_key);
  assert.notEqual(first.cache_key, changedInputs.cache_key);
  assert.deepEqual(first.source_refs.map((entry) => entry.name), ['crosswalk', 'registry-stack']);
});

test('archive identity changes with allowlisted build environment without recording values', () => {
  const docset = fixtureDocset();
  const manifest = fixtureManifest(docset);
  const firstEnvironment = archiveEnvironmentDigest({
    PUBLIC_UMAMI_WEBSITE_ID: 'first-site',
    PUBLIC_UMAMI_SCRIPT_SRC: 'https://stats.example/first.js',
    PUBLIC_UMAMI_DOMAINS: 'docs.example',
    UNRELATED_VALUE: 'ignored-one',
  });
  const secondEnvironment = archiveEnvironmentDigest({
    PUBLIC_UMAMI_WEBSITE_ID: 'second-site',
    PUBLIC_UMAMI_SCRIPT_SRC: 'https://stats.example/first.js',
    PUBLIC_UMAMI_DOMAINS: 'docs.example',
    UNRELATED_VALUE: 'ignored-two',
  });
  const first = archiveIdentity({
    docset,
    manifest,
    inputDigest,
    environmentDigest: firstEnvironment,
    nodeVersion: '22.12.0',
  });
  const second = archiveIdentity({
    docset,
    manifest,
    inputDigest,
    environmentDigest: secondEnvironment,
    nodeVersion: '22.12.0',
  });

  assert.notEqual(first.cache_key, second.cache_key);
  assert.match(first.environment_digest, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(first), /first-site|stats\.example|docs\.example/);
  assert.equal(
    archiveEnvironmentDigest({ UNRELATED_VALUE: 'ignored-one' }),
    archiveEnvironmentDigest({ UNRELATED_VALUE: 'ignored-two' }),
  );
});

test('archive output rejects path traversal and nested archive paths', () => {
  for (const path of ['/v/../escape/', '/v/release/nested/', '/elsewhere/release/']) {
    assert.throws(
      () => archiveOutputDirectory('/tmp/docs', { ...fixtureDocset(), path }),
      /safe path below \/v\/|traversal/,
    );
  }
});

test('archive input digest ignores generated output and changes for source input', async (t) => {
  const root = await temporaryRoot(t);
  const source = resolve(root, 'source');
  await write(resolve(source, 'input.txt'), 'one\n');
  const first = await computeArchiveInputDigest({
    inputRoots: [{ label: 'fixture', path: source, docsRoot: source }],
  });
  await write(resolve(source, 'dist/generated.html'), 'unrelated\n');
  const unchanged = await computeArchiveInputDigest({
    inputRoots: [{ label: 'fixture', path: source, docsRoot: source }],
  });
  await write(resolve(source, 'input.txt'), 'two\n');
  const changed = await computeArchiveInputDigest({
    inputRoots: [{ label: 'fixture', path: source, docsRoot: source }],
  });

  assert.equal(first, unchanged);
  assert.notEqual(first, changed);
});

test('store and restore validate exact metadata and output digests', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const cacheRoot = resolve(docsRoot, '.archive-build-cache');
  const docset = fixtureDocset();
  const identity = archiveIdentity({
    docset,
    manifest: fixtureManifest(docset),
    inputDigest,
    nodeVersion: '22.12.0',
  });
  const output = archiveOutputDirectory(docsRoot, docset);
  await write(resolve(output, 'index.html'), '<html id="archive"></html>\n');
  const linkIndex = {
    schema_version: LINK_INDEX_SCHEMA,
    cache_key: identity.cache_key,
    docset_id: docset.id,
    archive_path: docset.path,
    pages: [
      {
        file: 'v/1.0.0/index.html',
        url: '/v/1.0.0/',
        ids: ['archive'],
        links: [],
      },
    ],
  };
  await storeArchive({ docsRoot, cacheRoot, docset, identity, linkIndex });
  await rm(output, { recursive: true, force: true });

  const restored = await restoreArchive({ docsRoot, cacheRoot, docset, identity });

  assert.equal(restored.restored, true);
  assert.match(await readFile(resolve(output, 'index.html'), 'utf8'), /archive/);
  assert.deepEqual(
    JSON.parse(await readFile(resolve(docsRoot, 'dist/.archive-link-indexes/v1.0.0.json'))),
    linkIndex,
  );

  await write(
    resolve(cacheRoot, identity.cache_key, 'site/index.html'),
    '<html>corrupted</html>\n',
  );
  await rm(output, { recursive: true, force: true });
  const corrupt = await restoreArchive({ docsRoot, cacheRoot, docset, identity });
  assert.equal(corrupt.restored, false);
  assert.match(corrupt.reason, /output digest/);
});

test('restore never follows symlinks from a cache entry', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const cacheRoot = resolve(docsRoot, '.archive-build-cache');
  const docset = fixtureDocset();
  const identity = archiveIdentity({
    docset,
    manifest: fixtureManifest(docset),
    inputDigest,
    nodeVersion: '22.12.0',
  });
  const output = archiveOutputDirectory(docsRoot, docset);
  await write(resolve(output, 'index.html'), '<html></html>\n');
  const linkIndex = {
    schema_version: LINK_INDEX_SCHEMA,
    cache_key: identity.cache_key,
    docset_id: docset.id,
    archive_path: docset.path,
    pages: [{ file: 'v/1.0.0/index.html', url: '/v/1.0.0/', ids: [], links: [] }],
  };
  await storeArchive({ docsRoot, cacheRoot, docset, identity, linkIndex });
  await symlink('/etc/passwd', resolve(cacheRoot, identity.cache_key, 'site/escape'));
  await rm(output, { recursive: true, force: true });

  const restored = await restoreArchive({ docsRoot, cacheRoot, docset, identity });

  assert.equal(restored.restored, false);
  assert.match(restored.reason, /cannot contain symlinks/);
});

test('restore rejects a symlinked archive parent', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const external = await temporaryRoot(t);
  const cacheRoot = resolve(docsRoot, '.archive-build-cache');
  const docset = fixtureDocset();
  const identity = archiveIdentity({
    docset,
    manifest: fixtureManifest(docset),
    inputDigest,
    nodeVersion: '22.12.0',
  });
  const output = archiveOutputDirectory(docsRoot, docset);
  await write(resolve(output, 'index.html'), '<html></html>\n');
  const linkIndex = {
    schema_version: LINK_INDEX_SCHEMA,
    cache_key: identity.cache_key,
    docset_id: docset.id,
    archive_path: docset.path,
    pages: [{ file: 'v/1.0.0/index.html', url: '/v/1.0.0/', ids: [], links: [] }],
  };
  await storeArchive({ docsRoot, cacheRoot, docset, identity, linkIndex });
  await rm(resolve(docsRoot, 'dist'), { recursive: true, force: true });
  await symlink(external, resolve(docsRoot, 'dist'));

  const restored = await restoreArchive({ docsRoot, cacheRoot, docset, identity });

  assert.equal(restored.restored, false);
  assert.match(restored.reason, /archive dist root must be a real directory/);
});
