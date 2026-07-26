import assert from 'node:assert/strict';
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  createArchiveBundle,
  inspectArchiveBundle,
  restoreArchiveBundle,
  treeDigest,
} from './archive-bundle.mjs';

const docset = {
  id: 'v1.2.3',
  path: '/v/1.2.3/',
  status: 'archived',
  source: 'registry-stack-v1.2.3',
  published_at: '2026-07-26',
  products: {
    'registry-stack': {
      version: 'v1.2.3',
      ref: 'a'.repeat(40),
    },
  },
};

async function fixture(t) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-bundle-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const output = resolve(root, 'dist/v/1.2.3');
  await mkdir(resolve(output, 'guide'), { recursive: true });
  await writeFile(resolve(output, 'index.html'), '<h1>Archive</h1>\n');
  await writeFile(resolve(output, 'guide/index.html'), '<p>Guide</p>\n');
  return { root, output };
}

test('creates byte-for-byte deterministic archive bundles and restores them', async (t) => {
  const { root, output } = await fixture(t);
  const firstPath = resolve(root, 'first.tar.gz');
  const secondPath = resolve(root, 'second.tar.gz');
  const first = await createArchiveBundle({ docsRoot: root, docset, bundlePath: firstPath });
  await chmod(resolve(output, 'index.html'), 0o600);
  const second = await createArchiveBundle({ docsRoot: root, docset, bundlePath: secondPath });

  assert.equal(first.bundle_sha256, second.bundle_sha256);
  assert.equal(first.tree_sha256, second.tree_sha256);
  assert.deepEqual(await readFile(firstPath), await readFile(secondPath));

  await rm(output, { recursive: true });
  const restored = await restoreArchiveBundle({
    docsRoot: root,
    bundlePath: secondPath,
    docset,
    expectedBundleSha256: second.bundle_sha256,
    expectedTreeSha256: second.tree_sha256,
  });
  assert.equal(await readFile(resolve(restored.output, 'guide/index.html'), 'utf8'), '<p>Guide</p>\n');
  assert.deepEqual(await readFile(restored.public_bundle), await readFile(secondPath));
});

test('rejects a bundle that does not match the immutable digest', async (t) => {
  const { root } = await fixture(t);
  const bundlePath = resolve(root, 'archive.tar.gz');
  const result = await createArchiveBundle({ docsRoot: root, docset, bundlePath });
  await writeFile(bundlePath, Buffer.concat([await readFile(bundlePath), Buffer.from('changed')]));

  await assert.rejects(
    inspectArchiveBundle({
      bundlePath,
      docset,
      expectedBundleSha256: result.bundle_sha256,
      expectedTreeSha256: result.tree_sha256,
    }),
    /does not match lock/,
  );
});

test('rejects oversized bundles before reading or extracting them', async (t) => {
  const { root } = await fixture(t);
  const bundlePath = resolve(root, 'oversized.tar.gz');
  const handle = await open(bundlePath, 'w');
  await handle.truncate(256 * 1024 * 1024 + 1);
  await handle.close();

  await assert.rejects(
    inspectArchiveBundle({
      bundlePath,
      docset,
      expectedBundleSha256: 'a'.repeat(64),
      expectedTreeSha256: 'b'.repeat(64),
    }),
    /no larger than/,
  );
});

test('rejects symlinks in immutable archive trees', async (t) => {
  const { output } = await fixture(t);
  await symlink('index.html', resolve(output, 'linked.html'));
  await assert.rejects(treeDigest(output), /cannot contain symlinks/);
});

test('rejects docset metadata drift even when given a valid bundle digest', async (t) => {
  const { root } = await fixture(t);
  const bundlePath = resolve(root, 'archive.tar.gz');
  const result = await createArchiveBundle({ docsRoot: root, docset, bundlePath });

  await assert.rejects(
    inspectArchiveBundle({
      bundlePath,
      docset: { ...docset, source: 'different-source' },
      expectedBundleSha256: result.bundle_sha256,
      expectedTreeSha256: result.tree_sha256,
    }),
    /metadata does not match/,
  );
});
