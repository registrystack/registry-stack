import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import YAML from 'yaml';

import {
  addArchiveLockEntry,
  assertArchiveLockImmutable,
  assertArchiveLockImmutableForRepository,
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

async function candidateFixture(t, { manifest = {}, candidate = {} } = {}) {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'archive-lock-candidate-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  await mkdir(resolve(repoRoot, 'release/manifests'), { recursive: true });
  await writeFile(
    resolve(repoRoot, 'Cargo.toml'),
    '[workspace.package]\nversion = "1.1.0"\n',
  );
  await writeFile(
    resolve(repoRoot, 'release/manifests/registry-stack-beta-2.yaml'),
    YAML.stringify({
      stack: {
        release: 'beta-2',
        version: '1.1.0',
        source_repo: 'registrystack/registry-stack',
        source_tag: 'v1.1.0',
        ...manifest.stack,
      },
      artifacts: { 'registry-docs': '1.1.0', ...manifest.artifacts },
    }),
  );
  return {
    repoRoot,
    docsets: {
      docsets: [{
        id: 'v1.1.0',
        status: 'archived',
        availability: 'candidate',
        products: {
          'registry-stack': { version: 'v1.1.0', ref: 'v1.1.0' },
        },
        ...candidate,
      }],
    },
  };
}

function lockRefresh() {
  const base = lock({
    archives: {
      ...lock().archives,
      'v1.1.0': { bundle_sha256: 'e'.repeat(64), tree_sha256: 'f'.repeat(64) },
    },
  });
  const current = lock({
    archives: {
      ...base.archives,
      'v1.1.0': { bundle_sha256: '1'.repeat(64), tree_sha256: '2'.repeat(64) },
    },
  });
  return { base, current };
}

function commandFailure(code, stdout = '', stderr = '') {
  const error = new Error(`git exited ${code}`);
  error.code = code;
  error.stdout = stdout;
  error.stderr = stderr;
  return error;
}

test('keeps the current candidate lock immutable when its release tag is published', async (t) => {
  const fixture = await candidateFixture(t);
  const { base, current } = lockRefresh();
  const errors = await assertArchiveLockImmutableForRepository(base, current, {
    ...fixture,
    runCommand: async (command, args, options) => {
      assert.equal(command, 'git');
      assert.deepEqual(args, [
        'ls-remote', '--exit-code', '--refs', '--tags',
        'https://github.com/registrystack/registry-stack.git',
        'refs/tags/v1.1.0',
      ]);
      assert.equal(options.env.GIT_TERMINAL_PROMPT, '0');
      assert.equal(options.timeout, 15_000);
      return {
        stdout: `${'a'.repeat(40)}\trefs/tags/v1.1.0\n`,
        stderr: '',
      };
    },
  });
  assert.match(errors.join('\n'), /immutable archive lock entry v1.1.0 was changed/);
});

test('allows only the current prepared lock to refresh while its origin tag is absent', async (t) => {
  const fixture = await candidateFixture(t);
  const { base, current } = lockRefresh();
  const errors = await assertArchiveLockImmutableForRepository(base, current, {
    ...fixture,
    runCommand: async () => {
      throw commandFailure(2);
    },
  });
  assert.deepEqual(errors, []);

  current.archives['v1.0.0'] = {
    ...current.archives['v1.0.0'],
    tree_sha256: '3'.repeat(64),
  };
  let queried = false;
  const historicalErrors = await assertArchiveLockImmutableForRepository(base, current, {
    ...fixture,
    runCommand: async () => {
      queried = true;
      throw commandFailure(2);
    },
  });
  assert.equal(queried, false);
  assert.match(historicalErrors.join('\n'), /v1.0.0 was changed/);
  assert.match(historicalErrors.join('\n'), /v1.1.0 was changed/);
});

test('fails closed when origin tag absence cannot be proved', async (t) => {
  const fixture = await candidateFixture(t);
  const { base, current } = lockRefresh();
  await assert.rejects(
    assertArchiveLockImmutableForRepository(base, current, {
      ...fixture,
      runCommand: async () => {
        throw commandFailure(128, '', 'authentication failed');
      },
    }),
    /cannot prove release tag v1.1.0 is absent/,
  );
});

test('fails closed on ambiguous or interrupted origin tag lookups', async (t) => {
  const cases = [
    ['exit 2 with output', async () => {
      throw commandFailure(2, 'unexpected output', '');
    }],
    ['successful malformed output', async () => ({
      stdout: 'not-a-tag-record\n',
      stderr: '',
    })],
    ['execution timeout', async () => {
      throw commandFailure('ETIMEDOUT');
    }],
  ];
  for (const [name, runCommand] of cases) {
    await t.test(name, async (context) => {
      const fixture = await candidateFixture(context);
      const { base, current } = lockRefresh();
      await assert.rejects(
        assertArchiveLockImmutableForRepository(base, current, {
          ...fixture,
          runCommand,
        }),
        /cannot prove release tag v1.1.0 is absent/,
      );
    });
  }
});

test('rejects current lock refreshes with the wrong prepared identity', async (t) => {
  const fixture = await candidateFixture(t, {
    manifest: { artifacts: { 'registry-docs': '1.0.0' } },
  });
  const { base, current } = lockRefresh();
  let queried = false;
  const errors = await assertArchiveLockImmutableForRepository(base, current, {
    ...fixture,
    runCommand: async () => {
      queried = true;
      throw commandFailure(2);
    },
  });
  assert.equal(queried, false);
  assert.match(errors.join('\n'), /immutable archive lock entry v1.1.0 was changed/);
});

test('never allows a base lock entry to be removed', async (t) => {
  const fixture = await candidateFixture(t);
  const { base, current } = lockRefresh();
  delete current.archives['v1.1.0'];
  let queried = false;
  const errors = await assertArchiveLockImmutableForRepository(base, current, {
    ...fixture,
    runCommand: async () => {
      queried = true;
      throw commandFailure(2);
    },
  });
  assert.equal(queried, false);
  assert.match(errors.join('\n'), /immutable archive lock entry v1.1.0 was removed/);
});
