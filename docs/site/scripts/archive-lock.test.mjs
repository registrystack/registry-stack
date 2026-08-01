import assert from 'node:assert/strict';
import test from 'node:test';

import {
  addArchiveLockEntry,
  assertArchiveLockImmutable,
  validateArchiveLock,
} from './archive-lock.mjs';

const digest = 'a'.repeat(64);
const docsets = {
  current: 'latest',
  docsets: [
    { id: 'latest', status: 'current' },
    { id: 'v1.0.0', status: 'archived' },
    { id: 'v0.16.0', status: 'draft', availability: 'failed' },
    { id: 'v1.1.0', status: 'draft', availability: 'candidate' },
  ],
};

function lock(overrides = {}) {
  return {
    schema_version: 'registry-docs.archive-lock.v1',
    archives: {
      'v1.0.0': {
        bundle_sha256: digest,
        tree_sha256: 'b'.repeat(64),
      },
      'v0.16.0': {
        bundle_sha256: 'c'.repeat(64),
        tree_sha256: 'd'.repeat(64),
      },
    },
    ...overrides,
  };
}

test('validates exact archived docset coverage and digest shapes', () => {
  assert.deepEqual(validateArchiveLock(lock(), docsets), []);
  assert.match(
    validateArchiveLock(lock({ archives: {} }), docsets).join('\n'),
    /missing lock-backed docset v1.0.0/,
  );
  assert.match(
    validateArchiveLock(
      lock({
        archives: {
          ...lock().archives,
          latest: { bundle_sha256: digest, tree_sha256: digest },
        },
      }),
      docsets,
    ).join('\n'),
    /contains non-lock-backed docset latest/,
  );
  assert.match(
    validateArchiveLock(
      lock({
        archives: {
          ...lock().archives,
          'v1.1.0': { bundle_sha256: digest, tree_sha256: digest },
        },
      }),
      docsets,
    ).join('\n'),
    /contains non-lock-backed docset v1.1.0/,
  );
  assert.deepEqual(
    validateArchiveLock(lock({
      archives: {
        ...lock().archives,
        'v1.0.0': {
          bundle_sha256: digest,
          root_tree_sha256: 'b'.repeat(64),
          version_tree_sha256: 'c'.repeat(64),
        },
      },
    }), docsets),
    [],
  );
});

test('immutable lock entries can be added but not changed or removed', () => {
  const base = lock();
  const added = lock({
    archives: {
      ...base.archives,
      'v1.1.0': { bundle_sha256: 'c'.repeat(64), tree_sha256: 'd'.repeat(64) },
    },
  });
  assert.deepEqual(assertArchiveLockImmutable(base, added), []);
  assert.match(
    assertArchiveLockImmutable(base, lock({ archives: {} })).join('\n'),
    /was removed/,
  );
  assert.match(
    assertArchiveLockImmutable(
      base,
      lock({
        archives: {
          'v1.0.0': { ...base.archives['v1.0.0'], tree_sha256: 'e'.repeat(64) },
        },
      }),
    ).join('\n'),
    /was changed/,
  );
});

test('adds a new lock entry but refuses to overwrite immutable bytes', () => {
  const current = lock();
  addArchiveLockEntry(current, 'v1.1.0', {
    bundle_sha256: 'c'.repeat(64),
    tree_sha256: 'd'.repeat(64),
  });
  assert.equal(current.archives['v1.1.0'].bundle_sha256, 'c'.repeat(64));
  assert.throws(
    () => addArchiveLockEntry(current, 'v1.0.0', {
      bundle_sha256: 'e'.repeat(64),
      tree_sha256: 'f'.repeat(64),
    }),
    /already exists/,
  );
});

test('adds both authenticated tree digests for a dual-tree release bundle', () => {
  const current = lock();
  addArchiveLockEntry(current, 'v2.0.0', {
    bundle_sha256: 'c'.repeat(64),
    root_tree_sha256: 'd'.repeat(64),
    version_tree_sha256: 'e'.repeat(64),
  });
  assert.deepEqual(current.archives['v2.0.0'], {
    bundle_sha256: 'c'.repeat(64),
    root_tree_sha256: 'd'.repeat(64),
    version_tree_sha256: 'e'.repeat(64),
  });
});
