import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import YAML from 'yaml';

import { assembleArchives, downloadBundle, parseArgs } from './assemble-archives.mjs';
import {
  createArchiveBundle,
  localArchiveBundlePath,
  releaseRootOutputDirectory,
} from './archive-bundle.mjs';

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

async function fixture(t, { singleTree = true } = {}) {
  const sourceRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-assemble-source-'));
  const targetRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-assemble-target-'));
  t.after(() => Promise.all([
    rm(sourceRoot, { recursive: true, force: true }),
    rm(targetRoot, { recursive: true, force: true }),
  ]));

  const sourceOutput = resolve(sourceRoot, 'dist/v/1.2.3');
  await mkdir(sourceOutput, { recursive: true });
  await writeFile(resolve(sourceOutput, 'index.html'), '<h1>Frozen</h1>\n');
  if (!singleTree) {
    const rootOutput = releaseRootOutputDirectory(sourceRoot, docset);
    await mkdir(rootOutput, { recursive: true });
    await writeFile(resolve(rootOutput, 'index.html'), '<h1>Canonical</h1>\n');
  }
  const bundlePath = resolve(sourceRoot, 'bundle.tar.gz');
  const bundle = await createArchiveBundle({
    docsRoot: sourceRoot,
    docset,
    bundlePath,
    singleTree,
  });

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
          path: '/dev/',
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
        [docset.id]: bundle.tree_sha256
          ? {
              bundle_sha256: bundle.bundle_sha256,
              tree_sha256: bundle.tree_sha256,
            }
          : {
              bundle_sha256: bundle.bundle_sha256,
              root_tree_sha256: bundle.root_tree_sha256,
              version_tree_sha256: bundle.version_tree_sha256,
            },
      },
    }),
  );
  return { bundle, bundlePath, sourceRoot, targetRoot };
}

test('restores only the newest configured semantic archives', async (t) => {
  const { bundlePath, targetRoot } = await fixture(t);
  const manifestPath = resolve(targetRoot, 'src/data/docsets.yaml');
  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  const retained = manifest.docsets[1];
  manifest.published_archive_limit = 1;
  manifest.docsets.push({
    ...retained,
    id: 'v1.1.0',
    label: 'v1.1.0',
    path: '/v/1.1.0/',
    source: 'registry-stack-v1.1.0',
  });
  await writeFile(manifestPath, YAML.stringify(manifest));
  const lockPath = resolve(targetRoot, 'src/data/archive-lock.yaml');
  const lock = YAML.parse(await readFile(lockPath, 'utf8'));
  lock.archives['v1.1.0'] = { ...lock.archives['v1.2.3'] };
  await writeFile(lockPath, YAML.stringify(lock));

  const result = await assembleArchives({
    docsRoot: targetRoot,
    fetchImpl: async () => new Response(await readFile(bundlePath), { status: 200 }),
    restoreGeneratedData: async () => {},
  });

  assert.deepEqual(result.omitted, ['v1.1.0']);
  assert.deepEqual(Object.keys(result.sources), ['v1.2.3']);
});

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

test('recovers from a stale local bundle cache instead of reporting a lock violation', async (t) => {
  const { bundlePath, targetRoot } = await fixture(t);
  const localBundlePath = localArchiveBundlePath(targetRoot, docset);
  await mkdir(resolve(targetRoot, '.archive-bundles'), { recursive: true });
  // A bundle left behind by an earlier `--bootstrap` run, built from a working
  // tree that no longer matches the published lock entry.
  await writeFile(localBundlePath, 'stale bundle bytes from an earlier bootstrap run');

  const body = await readFile(bundlePath);
  let fetches = 0;
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (message) => { warnings.push(message); };
  t.after(() => { console.warn = originalWarn; });

  const result = await assembleArchives({
    docsRoot: targetRoot,
    fetchImpl: async () => {
      fetches += 1;
      return new Response(body, { status: 200 });
    },
    restoreGeneratedData: async () => {},
  });

  assert.equal(fetches, 1);
  assert.equal(result.restored, 1);
  assert.equal(await readFile(resolve(targetRoot, 'dist/v/1.2.3/index.html'), 'utf8'), '<h1>Frozen</h1>\n');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /stale local archive bundle cache/);
  assert.match(warnings[0], new RegExp(localBundlePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(warnings[0], /does not match lock/);
});

test('does not treat a genuinely inconsistent local bundle as a stale cache', async (t) => {
  const { bundlePath, targetRoot } = await fixture(t);
  const localBundlePath = localArchiveBundlePath(targetRoot, docset);
  await mkdir(resolve(targetRoot, '.archive-bundles'), { recursive: true });
  await writeFile(localBundlePath, await readFile(bundlePath));

  // Corrupt the lock's tree digest while keeping its bundle digest correct, so
  // the local bundle passes the outer bundle digest check (this is not a stale
  // cache) but fails the inner tree digest check (this bundle really is
  // inconsistent with its lock entry).
  const lockPath = resolve(targetRoot, 'src/data/archive-lock.yaml');
  const lock = YAML.parse(await readFile(lockPath, 'utf8'));
  lock.archives[docset.id].tree_sha256 = '0'.repeat(64);
  await writeFile(lockPath, YAML.stringify(lock));

  let fetches = 0;
  await assert.rejects(
    assembleArchives({
      docsRoot: targetRoot,
      fetchImpl: async () => {
        fetches += 1;
        return new Response(await readFile(bundlePath), { status: 200 });
      },
      restoreGeneratedData: async () => {},
    }),
    /tree digest .* does not match its lock/,
  );
  assert.equal(fetches, 0);
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
      const rootOutput = releaseRootOutputDirectory(docsRoot, docset);
      await mkdir(rootOutput, { recursive: true });
      await writeFile(resolve(rootOutput, 'index.html'), '<h1>Different root</h1>\n');
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

test('bootstraps candidate-era archives with the indexable canonical root', async (t) => {
  const { targetRoot } = await fixture(t, { singleTree: false });
  let indexable;
  let allowUnpublishedCandidate;
  const result = await assembleArchives({
    docsRoot: targetRoot,
    bootstrap: true,
    fetchImpl: async () => new Response(null, { status: 404 }),
    buildArchive: async (_docset, options) => {
      indexable = options.indexable;
      allowUnpublishedCandidate = options.allowUnpublishedCandidate;
      const output = resolve(options.docsRoot, 'dist/v/1.2.3');
      await mkdir(output, { recursive: true });
      await writeFile(resolve(output, 'index.html'), '<h1>Frozen</h1>\n');
      const rootOutput = releaseRootOutputDirectory(options.docsRoot, docset);
      await mkdir(rootOutput, { recursive: true });
      await writeFile(resolve(rootOutput, 'index.html'), '<h1>Canonical</h1>\n');
    },
    restoreGeneratedData: async () => {},
  });

  assert.equal(indexable, true);
  assert.equal(allowUnpublishedCandidate, true);
  assert.equal(result.bootstrapped, 1);
});

test('reports expected and actual digests when a bootstrap drifts', async (t) => {
  const { bundle, targetRoot } = await fixture(t, { singleTree: false });
  await assert.rejects(
    assembleArchives({
      docsRoot: targetRoot,
      bootstrap: true,
      fetchImpl: async () => new Response(null, { status: 404 }),
      buildArchive: async (_docset, options) => {
        const output = resolve(options.docsRoot, 'dist/v/1.2.3');
        await mkdir(output, { recursive: true });
        await writeFile(resolve(output, 'index.html'), '<h1>Drifted version</h1>\n');
        const rootOutput = releaseRootOutputDirectory(options.docsRoot, docset);
        await mkdir(rootOutput, { recursive: true });
        await writeFile(resolve(rootOutput, 'index.html'), '<h1>Drifted root</h1>\n');
      },
      restoreGeneratedData: async () => {},
    }),
    (error) => {
      assert.match(error.message, /bootstrapped archive v1\.2\.3 does not match/);
      assert.match(error.message, new RegExp(`expected: bundle_sha256=${bundle.bundle_sha256}`));
      assert.match(error.message, new RegExp(`root_tree_sha256=${bundle.root_tree_sha256}`));
      assert.match(error.message, new RegExp(`version_tree_sha256=${bundle.version_tree_sha256}`));
      assert.match(
        error.message,
        /actual: bundle_sha256=[0-9a-f]{64} root_tree_sha256=[0-9a-f]{64} version_tree_sha256=[0-9a-f]{64}/,
      );
      return true;
    },
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

test('skips the exact release bundle supplied by authenticated promotion', async (t) => {
  const { targetRoot } = await fixture(t);
  const manifestPath = resolve(targetRoot, 'src/data/docsets.yaml');
  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  manifest.docsets.push({
    ...docset,
    id: 'v1.3.0',
    label: 'v1.3.0',
    path: '/v/1.3.0/',
    source: 'registry-stack-v1.3.0',
    availability: 'candidate',
  });
  await writeFile(manifestPath, YAML.stringify(manifest));
  const lockPath = resolve(targetRoot, 'src/data/archive-lock.yaml');
  const lock = YAML.parse(await readFile(lockPath, 'utf8'));
  lock.archives['v1.3.0'] = { ...lock.archives[docset.id] };
  await writeFile(lockPath, YAML.stringify(lock));
  const result = await assembleArchives({
    docsRoot: targetRoot,
    excludeDocsetId: docset.id,
    fetchImpl: async () => {
      throw new Error('excluded release must not be downloaded through historical assembly');
    },
    restoreGeneratedData: async () => {},
  });

  assert.deepEqual(result.skipped, [docset.id]);
  assert.deepEqual(result.omitted, ['v1.3.0']);
  assert.equal(result.restored, 0);
  await assert.rejects(
    readFile(resolve(targetRoot, 'dist/v/1.2.3/index.html')),
    /ENOENT/,
  );
  assert.deepEqual(
    parseArgs(['--exclude-docset', docset.id]),
    { bootstrap: false, excludeDocsetId: docset.id },
  );
});

test('retries a transient bundle download failure with backoff before succeeding', async (t) => {
  const { bundlePath, targetRoot } = await fixture(t);
  const output = resolve(targetRoot, 'downloaded.tar.gz');
  let calls = 0;
  const waits = [];
  const restored = await downloadBundle('https://example.test/bundle.tar.gz', output, {
    fetchImpl: async () => {
      calls += 1;
      // A transient upstream failure (a momentary CDN/proxy error), not a
      // missing bundle or a real content problem.
      if (calls < 3) return new Response(null, { status: 503 });
      return new Response(await readFile(bundlePath), { status: 200 });
    },
    wait: async (delayMs) => { waits.push(delayMs); },
  });

  assert.equal(restored, true);
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
  assert.deepEqual(await readFile(output), await readFile(bundlePath));
});

test('does not retry a non-transient bundle download failure', async (t) => {
  const { targetRoot } = await fixture(t);
  const output = resolve(targetRoot, 'downloaded.tar.gz');
  let calls = 0;
  await assert.rejects(
    downloadBundle('https://example.test/bundle.tar.gz', output, {
      fetchImpl: async () => {
        calls += 1;
        return new Response(null, { status: 400 });
      },
      wait: async () => {
        throw new Error('must not wait before retrying a permanent failure');
      },
    }),
    /returned HTTP 400/,
  );
  assert.equal(calls, 1);
});

test('stops retrying a persistent transient bundle download failure after its bounded attempts, status intact', async (t) => {
  const { targetRoot } = await fixture(t);
  const output = resolve(targetRoot, 'downloaded.tar.gz');
  let calls = 0;
  const waits = [];
  await assert.rejects(
    downloadBundle('https://example.test/bundle.tar.gz', output, {
      fetchImpl: async () => {
        calls += 1;
        return new Response(null, { status: 503 });
      },
      wait: async (delayMs) => { waits.push(delayMs); },
    }),
    /returned HTTP 503/,
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
});

test('classifies a dropped connection as a transient bundle download failure', async (t) => {
  const { targetRoot } = await fixture(t);
  const output = resolve(targetRoot, 'downloaded.tar.gz');
  let calls = 0;
  const result = await downloadBundle('https://example.test/bundle.tar.gz', output, {
    fetchImpl: async () => {
      calls += 1;
      if (calls < 2) {
        throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
      }
      return new Response(null, { status: 404 });
    },
    wait: async () => {},
  });

  assert.equal(result, false);
  assert.equal(calls, 2);
});
