import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

import { canonicalJson, fileDigest } from './archive-bundle.mjs';
import {
  PREVIEW_AVAILABILITY,
  PREVIEW_BASE,
  PREVIEW_DOCSET,
  PREVIEW_RELEASE_COORDINATE,
  PREVIEW_RELEASE_COORDINATE_STATUS,
  packageUnreleasedPreview,
} from './package-unreleased-preview.mjs';

const buildCommit = 'a'.repeat(40);
const buildTree = 'b'.repeat(40);
const pullRequestHead = 'c'.repeat(40);
const pullRequestBase = 'd'.repeat(40);

async function fixture(t) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-preview-test-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const previewRoot = resolve(docsRoot, 'dist/preview');
  const dataDir = resolve(docsRoot, 'src/data');
  await Promise.all([
    mkdir(resolve(previewRoot, 'guide'), { recursive: true }),
    mkdir(dataDir, { recursive: true }),
  ]);
  await writeFile(resolve(previewRoot, 'index.html'), '<h1>Preview</h1>\n');
  await writeFile(resolve(previewRoot, 'guide/index.html'), '<p>Guide</p>\n');
  await writeFile(resolve(docsRoot, 'package-lock.json'), '{"lockfileVersion":3}\n');
  await writeFile(
    resolve(dataDir, 'docsets.yaml'),
    YAML.stringify({
      current: PREVIEW_DOCSET,
      released: 'v0.13.0',
      docsets: [
        {
          id: PREVIEW_DOCSET,
          label: 'Main source',
          path: '/',
          status: 'current',
          availability: PREVIEW_AVAILABILITY,
          source: 'main',
          published_at: '2026-07-27',
          description: 'Unreleased preview.',
          products: {
            product: { version: 'main', ref: 'HEAD' },
          },
        },
        {
          id: 'v0.13.0',
          label: 'v0.13.0',
          path: '/v/0.13.0/',
          status: 'archived',
          availability: 'released',
          source: 'v0.13.0',
          published_at: '2026-07-25',
          description: 'Released docs.',
          products: {
            product: { version: 'v0.13.0', ref: 'e'.repeat(40) },
          },
        },
      ],
    }),
  );
  return { docsRoot, previewRoot };
}

test('receipt binds the unreleased preview inputs and PR coordinate', async (t) => {
  const { docsRoot } = await fixture(t);
  const result = await packageUnreleasedPreview({
    docsRoot,
    outputRoot: resolve(docsRoot, 'evidence-a'),
    buildCommit,
    buildTree,
    eventName: 'pull_request',
    pullRequestHead,
    pullRequestBase,
    nodeVersion: 'v22.12.0',
  });

  assert.deepEqual(result.receipt.build, {
    commit_sha: buildCommit,
    tree_sha: buildTree,
  });
  assert.deepEqual(result.receipt.pull_request, {
    head_sha: pullRequestHead,
    base_sha: pullRequestBase,
  });
  assert.deepEqual(result.receipt.docset, {
    id: PREVIEW_DOCSET,
    availability: PREVIEW_AVAILABILITY,
    release_coordinate: PREVIEW_RELEASE_COORDINATE,
    release_coordinate_status: PREVIEW_RELEASE_COORDINATE_STATUS,
    base: PREVIEW_BASE,
  });
  assert.equal(result.receipt.build_environment.node_version, 'v22.12.0');
  assert.equal(
    result.receipt.build_environment.package_lock_sha256,
    await fileDigest(resolve(docsRoot, 'package-lock.json')),
  );
  assert.equal(
    result.receipt.artifacts.inventory.sha256,
    fileDigestFromString(`${canonicalJson(result.inventory)}\n`),
  );
  assert.equal(
    result.receipt.artifacts.preview_tar.sha256,
    await fileDigest(result.tar_path),
  );
  assert.match(result.receipt.artifacts.preview_tree_sha256, /^[0-9a-f]{64}$/);
});

test('package bytes and receipt digests are deterministic', async (t) => {
  const { docsRoot } = await fixture(t);
  const inputs = {
    docsRoot,
    buildCommit,
    buildTree,
    nodeVersion: 'v22.12.0',
  };
  const first = await packageUnreleasedPreview({
    ...inputs,
    outputRoot: resolve(docsRoot, 'evidence-a'),
  });
  const second = await packageUnreleasedPreview({
    ...inputs,
    outputRoot: resolve(docsRoot, 'evidence-b'),
  });

  assert.deepEqual(first.receipt, second.receipt);
  assert.deepEqual(await readFile(first.tar_path), await readFile(second.tar_path));
  assert.deepEqual(
    await readFile(first.inventory_path),
    await readFile(second.inventory_path),
  );
  assert.equal(first.receipt.pull_request, null);
});

test('preview mutation changes tree, inventory, and tar bindings', async (t) => {
  const { docsRoot, previewRoot } = await fixture(t);
  const first = await packageUnreleasedPreview({
    docsRoot,
    outputRoot: resolve(docsRoot, 'evidence-a'),
    buildCommit,
    buildTree,
  });
  await writeFile(resolve(previewRoot, 'guide/index.html'), '<p>Changed</p>\n');
  const second = await packageUnreleasedPreview({
    docsRoot,
    outputRoot: resolve(docsRoot, 'evidence-b'),
    buildCommit,
    buildTree,
  });

  assert.notEqual(
    first.receipt.artifacts.preview_tree_sha256,
    second.receipt.artifacts.preview_tree_sha256,
  );
  assert.notEqual(
    first.receipt.artifacts.inventory.sha256,
    second.receipt.artifacts.inventory.sha256,
  );
  assert.notEqual(
    first.receipt.artifacts.preview_tar.sha256,
    second.receipt.artifacts.preview_tar.sha256,
  );
});

test('rejects symlinks and incomplete PR bindings', async (t) => {
  const { docsRoot, previewRoot } = await fixture(t);
  await symlink('index.html', resolve(previewRoot, 'linked.html'));
  await assert.rejects(
    packageUnreleasedPreview({
      docsRoot,
      outputRoot: resolve(docsRoot, 'evidence-a'),
      buildCommit,
      buildTree,
    }),
    /cannot contain symlinks/,
  );
  await rm(resolve(previewRoot, 'linked.html'));
  await assert.rejects(
    packageUnreleasedPreview({
      docsRoot,
      outputRoot: resolve(docsRoot, 'evidence-b'),
      buildCommit,
      buildTree,
      eventName: 'pull_request',
      pullRequestHead,
    }),
    /requires both head and base SHAs/,
  );
});

function fileDigestFromString(value) {
  return createHash('sha256').update(value).digest('hex');
}
