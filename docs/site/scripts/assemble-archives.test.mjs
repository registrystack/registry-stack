import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import YAML from 'yaml';

import { assembleArchives } from './assemble-archives.mjs';
import { createArchiveBundle } from './archive-bundle.mjs';

const docset = {
  id: 'v1.2.3',
  label: 'v1.2.3',
  path: '/v/1.2.3/',
  status: 'archived',
  availability: 'released',
  source: 'registry-stack-v1.2.3',
  published_at: '2026-07-26',
  description: 'Test archive.',
  products: {
    'registry-stack': {
      version: 'v1.2.3',
      ref: 'a'.repeat(40),
    },
  },
};

async function fixture(t) {
  const sourceRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-assemble-source-'));
  const targetRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-assemble-target-'));
  t.after(() => Promise.all([
    rm(sourceRoot, { recursive: true, force: true }),
    rm(targetRoot, { recursive: true, force: true }),
  ]));

  const sourceOutput = resolve(sourceRoot, 'dist/v/1.2.3');
  await mkdir(sourceOutput, { recursive: true });
  await writeFile(resolve(sourceOutput, 'index.html'), '<h1>Frozen</h1>\n');
  const bundlePath = resolve(sourceRoot, 'bundle.tar.gz');
  const bundle = await createArchiveBundle({ docsRoot: sourceRoot, docset, bundlePath });

  await mkdir(resolve(targetRoot, 'src/data'), { recursive: true });
  await writeFile(
    resolve(targetRoot, 'src/data/docsets.yaml'),
    YAML.stringify({
      current: 'latest',
      released: docset.id,
      docsets: [
        {
          ...docset,
          id: 'latest',
          label: 'Latest',
          path: '/',
          status: 'current',
          availability: 'unreleased',
          source: 'registry-stack-main',
          products: {
            'registry-stack': { version: 'v1.2.3', ref: 'HEAD' },
          },
        },
        docset,
      ],
    }),
  );
  await writeFile(
    resolve(targetRoot, 'src/data/archive-lock.yaml'),
    YAML.stringify({
      schema_version: 'registry-docs.archive-lock.v1',
      archives: {
        [docset.id]: {
          bundle_sha256: bundle.bundle_sha256,
          tree_sha256: bundle.tree_sha256,
        },
      },
    }),
  );
  return { bundlePath, sourceRoot, targetRoot };
}

test('restores a locked release bundle without rebuilding', async (t) => {
  const { bundlePath, targetRoot } = await fixture(t);
  const body = await readFile(bundlePath);
  let buildCalls = 0;
  const result = await assembleArchives({
    docsRoot: targetRoot,
    fetchImpl: async () => new Response(body, { status: 200 }),
    buildArchive: async () => { buildCalls += 1; },
    restoreGeneratedData: async () => {},
  });

  assert.equal(buildCalls, 0);
  assert.equal(result.restored, 1);
  assert.equal(await readFile(resolve(targetRoot, 'dist/v/1.2.3/index.html'), 'utf8'), '<h1>Frozen</h1>\n');
});

test('only bootstraps missing bundles when explicitly allowed', async (t) => {
  const { targetRoot } = await fixture(t);
  const fetchImpl = async () => new Response(null, { status: 404 });
  await assert.rejects(
    assembleArchives({
      docsRoot: targetRoot,
      fetchImpl,
      buildArchive: async () => {},
      restoreGeneratedData: async () => {},
    }),
    /rerun with --bootstrap/,
  );

  let generatedDataRestores = 0;
  const result = await assembleArchives({
    docsRoot: targetRoot,
    bootstrap: true,
    fetchImpl,
    buildArchive: async (_docset, { docsRoot }) => {
      const output = resolve(docsRoot, 'dist/v/1.2.3');
      await mkdir(output, { recursive: true });
      await writeFile(resolve(output, 'index.html'), '<h1>Frozen</h1>\n');
    },
    restoreGeneratedData: async () => { generatedDataRestores += 1; },
  });
  assert.equal(result.bootstrapped, 1);
  assert.equal(generatedDataRestores, 1);
  assert.deepEqual(
    await readFile(resolve(targetRoot, 'dist/_archive-bundles/v1.2.3.tar.gz')),
    await readFile(resolve(targetRoot, '.archive-bundles/v1.2.3.tar.gz')),
  );
});

test('does not fall back after a published bundle fails digest verification', async (t) => {
  const { targetRoot } = await fixture(t);
  let requests = 0;
  await assert.rejects(
    assembleArchives({
      docsRoot: targetRoot,
      fetchImpl: async () => {
        requests += 1;
        return new Response('untrusted', { status: 200 });
      },
      restoreGeneratedData: async () => {},
    }),
    /does not match lock/,
  );
  assert.equal(requests, 1);
});
