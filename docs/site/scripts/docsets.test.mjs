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
    released: 'beta-2026-06-12',
    docsets: [
      {
        id: 'latest',
        label: 'Latest',
        path: '/dev/',
        status: 'current',
        availability: 'unreleased',
        source: 'main',
        published_at: '2026-06-13',
        description: 'Current docs.',
        products: {
          'registry-relay': {
            version: 'main snapshot',
            ref: 'HEAD',
          },
        },
      },
      {
        id: 'beta-2026-06-12',
        label: 'Beta 2026-06-12',
        path: '/v/beta-2026-06-12/',
        status: 'archived',
        availability: 'released',
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
        ref: 'HEAD',
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

test('validateDocsets requires HEAD for current product refs', () => {
  const manifest = validDocsets();
  manifest.docsets[0].products['registry-relay'].ref = 'main';
  assert.throws(() => validateDocsets(manifest), /must be HEAD for the current docset/);
});

test('validateDocsets accepts the exact canonical tag for archived candidate source products', () => {
  const manifest = validDocsets();
  manifest.docsets.push({
    id: 'v1.2.3',
    label: 'v1.2.3',
    path: '/v/1.2.3/',
    status: 'archived',
    availability: 'candidate',
    source: 'registry-stack-v1.2.3',
    published_at: '2026-08-01',
    description: 'Candidate docs.',
    products: {
      'registry-relay': {
        version: 'v1.2.3',
        ref: 'v1.2.3',
      },
      crosswalk: {
        version: 'crosswalk-core-v0.2.0',
        ref: '3333333333333333333333333333333333333333',
      },
    },
  });

  assert.doesNotThrow(() => validateDocsets(manifest));
});

test('validateDocsets rejects arbitrary tags for archived candidate products', () => {
  for (const ref of ['v1.2.4', 'v01.2.3', 'candidate-v1.2.3']) {
    const manifest = validDocsets();
    manifest.docsets[1].availability = 'candidate';
    manifest.docsets[1].id = 'v1.2.3';
    manifest.docsets[1].products['registry-relay'] = {
      version: 'v1.2.3',
      ref,
    };

    assert.throws(() => validateDocsets(manifest), /must be a full 40-character SHA/);
  }
});

test('validateDocsets requires SHA refs for external candidate products', () => {
  const manifest = validDocsets();
  manifest.docsets[1].availability = 'candidate';
  manifest.docsets[1].id = 'v1.2.3';
  manifest.docsets[1].products.crosswalk = {
    version: 'crosswalk-core-v0.2.0',
    ref: 'v1.2.3',
  };

  assert.throws(() => validateDocsets(manifest), /products\.crosswalk\.ref must be a full 40-character SHA/);
});

test('validateDocsets requires SHA refs for released products', () => {
  const manifest = validDocsets();
  manifest.docsets[1].products['registry-relay'].ref = 'v0.2.0';

  assert.throws(() => validateDocsets(manifest), /must be a full 40-character SHA/);
});

test('validateDocsets rejects candidate and current docsets as released selectors', () => {
  const candidate = validDocsets();
  candidate.docsets[1].availability = 'candidate';
  assert.throws(() => validateDocsets(candidate), /archived released docset/);

  const current = validDocsets();
  current.released = current.current;
  assert.throws(() => validateDocsets(current), /selectors must be different/);
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

test('applyDocsetRefs keeps the checked-out monorepo for an exact pre-tag candidate', () => {
  const repos = repoManifest();
  const candidate = {
    ...validDocsets().docsets[1],
    id: 'v1.2.3',
    status: 'archived',
    availability: 'candidate',
    repo_docs_source: 'monorepo',
    products: {
      'registry-relay': {
        version: 'v1.2.3',
        ref: 'v1.2.3',
      },
    },
  };

  applyDocsetRefs(repos, candidate);

  assert.equal(repos.repos['registry-relay'].ref, 'v1.2.3');
  assert.equal(repos.repos['registry-relay'].version, 'v1.2.3');
  assert.equal(repos.repos['registry-relay'].local, '../..');
  assert.equal(repos.repos['registry-relay'].remote, 'https://github.com/registrystack/registry-stack');
  assert.equal(repos.repos['registry-relay'].openapi, 'crates/registry-relay/openapi/registry-relay.openapi.json');
  assert.equal(repos.repos['registry-relay'].docs[0].src, 'docs/README.md');
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
    'registry-relay: repo-docs ref 9999999999999999999999999999999999999999 does not match current docset ref HEAD',
  ]);
});
