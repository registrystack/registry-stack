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
  ARCHIVE_BUNDLE_DIGEST_MISMATCH,
  ARCHIVE_BUNDLE_SCHEMA,
  LEGACY_ARCHIVE_BUNDLE_SCHEMA,
  SINGLE_TREE_ARCHIVE_BUNDLE_SCHEMA,
  archiveMetadata,
  archiveSourceRefs,
  assertArchiveMetadataMatchesDocset,
  createArchiveBundle,
  inspectArchiveBundle,
  releaseRootOutputDirectory,
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
  const rootOutput = releaseRootOutputDirectory(root, docset);
  await mkdir(resolve(output, 'guide'), { recursive: true });
  await mkdir(resolve(rootOutput, 'guide'), { recursive: true });
  await writeFile(resolve(output, 'index.html'), '<h1>Archive</h1>\n');
  await writeFile(resolve(output, 'guide/index.html'), '<p>Guide</p>\n');
  await writeFile(resolve(rootOutput, 'index.html'), '<h1>Canonical release</h1>\n');
  await writeFile(resolve(rootOutput, 'guide/index.html'), '<p>Root guide</p>\n');
  return { root, rootOutput, output };
}

test('creates byte-for-byte deterministic archive bundles and restores them', async (t) => {
  const { root, output } = await fixture(t);
  const firstPath = resolve(root, 'first.tar.gz');
  const secondPath = resolve(root, 'second.tar.gz');
  const first = await createArchiveBundle({ docsRoot: root, docset, bundlePath: firstPath });
  await chmod(resolve(output, 'index.html'), 0o600);
  const second = await createArchiveBundle({ docsRoot: root, docset, bundlePath: secondPath });

  assert.equal(first.bundle_sha256, second.bundle_sha256);
  assert.equal(first.root_tree_sha256, second.root_tree_sha256);
  assert.equal(first.version_tree_sha256, second.version_tree_sha256);
  assert.deepEqual(await readFile(firstPath), await readFile(secondPath));

  await rm(output, { recursive: true });
  const restored = await restoreArchiveBundle({
    docsRoot: root,
    bundlePath: secondPath,
    docset,
    expectedBundleSha256: second.bundle_sha256,
    expectedRootTreeSha256: second.root_tree_sha256,
    expectedVersionTreeSha256: second.version_tree_sha256,
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
      expectedRootTreeSha256: result.root_tree_sha256,
      expectedVersionTreeSha256: result.version_tree_sha256,
    }),
    (error) => {
      assert.match(error.message, /does not match lock/);
      assert.equal(error.code, ARCHIVE_BUNDLE_DIGEST_MISMATCH);
      return true;
    },
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

test('requires both release trees unless historical single-tree mode is explicit', async (t) => {
  const { root, rootOutput } = await fixture(t);
  await rm(rootOutput, { recursive: true });
  await assert.rejects(
    createArchiveBundle({
      docsRoot: root,
      docset,
      bundlePath: resolve(root, 'missing-root.tar.gz'),
    }),
    /canonical release root output must be a real directory/,
  );
});

test('dual-tree metadata binds the release tag, route, and both tree digests', async (t) => {
  const { root } = await fixture(t);
  const bundlePath = resolve(root, 'archive.tar.gz');
  const result = await createArchiveBundle({ docsRoot: root, docset, bundlePath });

  assert.deepEqual(archiveMetadata(docset, {
    rootTreeSha256: result.root_tree_sha256,
    versionTreeSha256: result.version_tree_sha256,
  }), {
    schema_version: ARCHIVE_BUNDLE_SCHEMA,
    release_tag: 'v1.2.3',
    root_tree_sha256: result.root_tree_sha256,
    version_path: '/v/1.2.3/',
    version_tree_sha256: result.version_tree_sha256,
  });
  await inspectArchiveBundle({
    bundlePath,
    docset: { ...docset, source: 'different-source', products: {} },
    expectedBundleSha256: result.bundle_sha256,
    expectedRootTreeSha256: result.root_tree_sha256,
    expectedVersionTreeSha256: result.version_tree_sha256,
  });
  await assert.rejects(
    inspectArchiveBundle({
      bundlePath,
      docset: { ...docset, id: 'v1.2.4', path: '/v/1.2.4/' },
      expectedBundleSha256: result.bundle_sha256,
      expectedRootTreeSha256: result.root_tree_sha256,
      expectedVersionTreeSha256: result.version_tree_sha256,
    }),
    /metadata does not match/,
  );
});

test('historical v2 single-tree bundles remain parseable and restorable', async (t) => {
  const { root, output } = await fixture(t);
  const bundlePath = resolve(root, 'single-tree.tar.gz');
  const result = await createArchiveBundle({
    docsRoot: root,
    docset,
    bundlePath,
    singleTree: true,
  });

  assert.equal(result.metadata.schema_version, SINGLE_TREE_ARCHIVE_BUNDLE_SCHEMA);
  await rm(output, { recursive: true });
  const restored = await restoreArchiveBundle({
    docsRoot: root,
    bundlePath,
    docset,
    expectedBundleSha256: result.bundle_sha256,
    expectedTreeSha256: result.tree_sha256,
  });
  assert.equal(
    await readFile(resolve(restored.output, 'guide/index.html'), 'utf8'),
    '<p>Guide</p>\n',
  );
});

test('historical v1 metadata remains parseable with its source refs', () => {
  assert.doesNotThrow(() => assertArchiveMetadataMatchesDocset({
    schema_version: LEGACY_ARCHIVE_BUNDLE_SCHEMA,
    docset_id: docset.id,
    archive_path: docset.path,
    source: docset.source,
    published_at: docset.published_at,
    source_refs: [{
      name: 'registry-stack',
      version: 'v1.2.3',
      ref: 'a'.repeat(40),
    }],
    tree_sha256: 'b'.repeat(64),
  }, docset));
});

test('archive source refs preserve the explicit historical English order', () => {
  assert.deepEqual(
    archiveSourceRefs({
      products: {
        zeta: { version: '1', ref: 'z' },
        'äther': { version: '2', ref: 'a-umlaut' },
        alpha: { version: '3', ref: 'a' },
      },
    }).map(({ name }) => name),
    ['alpha', 'äther', 'zeta'],
  );
});
