import assert from 'node:assert/strict';
import test from 'node:test';
import {
  applyDocsetRefs,
  currentProductsMatchRepoManifest,
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
  assert.equal(repos.repos['registry-platform'].ref, '3333333333333333333333333333333333333333');
});

test('currentProductsMatchRepoManifest reports latest drift', () => {
  const repos = repoManifest();
  repos.repos['registry-relay'].ref = '9999999999999999999999999999999999999999';
  assert.deepEqual(currentProductsMatchRepoManifest(repos, validDocsets()), [
    'registry-relay: repo-docs ref 9999999999999999999999999999999999999999 does not match current docset ref 1111111111111111111111111111111111111111',
  ]);
});
