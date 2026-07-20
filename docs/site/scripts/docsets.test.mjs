import assert from 'node:assert/strict';
import test from 'node:test';
import {
  applyDocsetRefs,
  currentProductsMatchRepoManifest,
  filterRepoDocsForDocset,
  validateDocsets,
} from './docsets.mjs';

function validDocsets() {
  return {
    current: 'latest',
    docsets: [
      {
        id: 'latest',
        label: 'Latest',
        path: '/',
        status: 'current',
        source: 'main',
        published_at: '2026-06-13',
        description: 'Current docs.',
        products: {
          'registry-relay': {
            version: 'main snapshot',
            ref: '1111111111111111111111111111111111111111',
          },
        },
      },
      {
        id: 'beta-2026-06-12',
        label: 'Beta 2026-06-12',
        path: '/v/beta-2026-06-12/',
        status: 'archived',
        source: 'registry-stack-beta-2026-06-12',
        published_at: '2026-06-12',
        description: 'Frozen beta docs.',
        products: {
          'registry-relay': {
            version: 'v0.2.0',
            ref: '2222222222222222222222222222222222222222',
          },
        },
      },
    ],
  };
}

function repoManifest() {
  return {
    repos: {
      'registry-relay': {
        ref: '1111111111111111111111111111111111111111',
        version: 'main snapshot',
        remote: 'https://github.com/registrystack/registry-stack',
        local: '../..',
        openapi: 'crates/registry-relay/openapi/registry-relay.openapi.json',
        archive_remote: 'https://github.com/jeremi/registry-relay',
        archive_openapi: 'openapi/registry-relay.openapi.json',
        docs: [{ src: 'docs/README.md', dest: 'products/registry-relay/index' }],
      },
      'registry-platform': {
        ref: '3333333333333333333333333333333333333333',
        docs: [],
      },
    },
  };
}

test('validateDocsets accepts a valid docset manifest', () => {
  assert.doesNotThrow(() => validateDocsets(validDocsets()));
});

test('validateDocsets rejects duplicate docset ids', () => {
  const manifest = validDocsets();
  manifest.docsets[1].id = 'latest';
  assert.throws(() => validateDocsets(manifest), /Duplicate docset id/);
});

test('validateDocsets rejects duplicate archive paths', () => {
  const manifest = validDocsets();
  manifest.docsets.push({
    ...structuredClone(manifest.docsets[1]),
    id: 'another-archive',
  });
  assert.throws(() => validateDocsets(manifest), /Duplicate docset path/);
});

test('validateDocsets rejects archive path traversal and nesting', () => {
  for (const path of ['/v/../escape/', '/v/release/nested/', '/archive/release/']) {
    const manifest = validDocsets();
    manifest.docsets[1].path = path;
    assert.throws(
      () => validateDocsets(manifest),
      /must not contain traversal|safe direct child of \/v\//,
      path,
    );
  }
});

test('validateDocsets rejects non-SHA product refs', () => {
  const manifest = validDocsets();
  manifest.docsets[0].products['registry-relay'].ref = 'main';
  assert.throws(() => validateDocsets(manifest), /must be a full 40-character SHA/);
});

test('applyDocsetRefs fails when an active repo is missing from a docset', () => {
  const manifest = validDocsets();
  delete manifest.docsets[1].products['registry-relay'];
  assert.throws(() => applyDocsetRefs(repoManifest(), manifest.docsets[1]), /no product ref/);
});

test('applyDocsetRefs overrides active repo refs from an archive docset', () => {
  const repos = repoManifest();
  applyDocsetRefs(repos, validDocsets().docsets[1]);
  assert.equal(repos.repos['registry-relay'].ref, '2222222222222222222222222222222222222222');
  assert.equal(repos.repos['registry-relay'].version, 'v0.2.0');
  assert.equal(repos.repos['registry-relay'].remote, 'https://github.com/jeremi/registry-relay');
  assert.equal(repos.repos['registry-relay'].local, undefined);
  assert.equal(repos.repos['registry-relay'].openapi, 'openapi/registry-relay.openapi.json');
  assert.equal(repos.repos['registry-platform'].ref, '3333333333333333333333333333333333333333');
});

test('applyDocsetRefs restores archive source paths from a monorepo manifest', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].docs[0].src = 'crates/registry-relay/docs/README.md';
  repos.repos['registry-relay'].docs[0].archive_src = 'docs/README.md';

  applyDocsetRefs(repos, validDocsets().docsets[1]);

  assert.equal(repos.repos['registry-relay'].docs[0].src, 'docs/README.md');
});

test('applyDocsetRefs keeps monorepo paths for monorepo archive docsets', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].docs[0].src = 'crates/registry-relay/docs/README.md';
  repos.repos['registry-relay'].docs[0].archive_src = 'docs/README.md';
  const docset = {
    ...validDocsets().docsets[1],
    id: 'v0.8.1',
    repo_docs_source: 'monorepo',
  };

  applyDocsetRefs(repos, docset);

  assert.equal(repos.repos['registry-relay'].remote, 'https://github.com/registrystack/registry-stack');
  assert.equal(repos.repos['registry-relay'].local, undefined);
  assert.equal(repos.repos['registry-relay'].openapi, 'crates/registry-relay/openapi/registry-relay.openapi.json');
  assert.equal(repos.repos['registry-relay'].docs[0].src, 'crates/registry-relay/docs/README.md');
});

test('filterRepoDocsForDocset removes entries excluded from selected archive', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].docs.push({
    src: 'docs/new-page.md',
    dest: 'products/registry-relay/new-page',
    exclude_docsets: ['beta-2026-06-12'],
  });

  filterRepoDocsForDocset(repos, validDocsets().docsets[1]);

  assert.deepEqual(
    repos.repos['registry-relay'].docs.map((entry) => entry.src),
    ['docs/README.md'],
  );
});

test('filterRepoDocsForDocset keeps entries not excluded from selected docset', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].docs.push({
    src: 'docs/new-page.md',
    dest: 'products/registry-relay/new-page',
    exclude_docsets: ['some-other-docset'],
  });

  filterRepoDocsForDocset(repos, validDocsets().docsets[1]);

  assert.deepEqual(
    repos.repos['registry-relay'].docs.map((entry) => entry.src),
    ['docs/README.md', 'docs/new-page.md'],
  );
});

test('currentProductsMatchRepoManifest reports latest drift', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].ref = '9999999999999999999999999999999999999999';
  assert.deepEqual(currentProductsMatchRepoManifest(repos, validDocsets()), [
    'registry-relay: repo-docs ref 9999999999999999999999999999999999999999 does not match current docset ref 1111111111111111111111111111111111111111',
  ]);
});
