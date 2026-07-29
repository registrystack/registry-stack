import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import {
  createArchiveBundle,
  treeDigest,
} from './archive-bundle.mjs';
import {
  parsePromotionArgs,
  stageProductionDocsets,
  validatePromotionInputs,
} from './stage-production-docsets.mjs';

const releasedTag = 'v1.2.3';
const versionPath = '/v/1.2.3/';
const canonical = 'https://docs.registrystack.org';

async function write(root, path, contents) {
  const target = resolve(root, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents);
}

function html(path = '/') {
  return `<html><head><link rel="canonical" href="${canonical}${path}"></head>` +
    `<body><a href="${versionPath}">Version</a></body></html>\n`;
}

async function createFixture(t, { collision = null } = {}) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-production-docsets-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const devRoot = resolve(docsRoot, 'dist/dev');
  const archiveRoot = resolve(docsRoot, 'dist/v/1.2.3');
  await write(devRoot, 'index.html', html('/dev/'));
  await write(
    devRoot,
    'llms.txt',
    'Index: https://docs.registrystack.org/llms.txt\n' +
      'Page: https://docs.registrystack.org/dev/guide/\n',
  );
  await write(
    devRoot,
    'index.md',
    'Page: https://docs.registrystack.org/index.md\n',
  );
  await write(devRoot, 'generated/configuration-reference.v1.json', '{}\n');

  await write(archiveRoot, 'index.html', html('/'));
  await write(archiveRoot, 'start/quickstart/index.html', html('/start/quickstart/'));
  await write(archiveRoot, 'index.md', '# Released index\n');
  await write(archiveRoot, 'llms.txt', '# Released machine docs\n');
  await write(archiveRoot, 'sitemap-index.xml', '<sitemapindex/>\n');
  await write(archiveRoot, 'pagefind/pagefind.js', 'export const search = true;\n');
  await write(archiveRoot, 'pagefind/pagefind-entry.json', '{}\n');
  await write(archiveRoot, 'generated/configuration-reference.v1.json', '{}\n');
  if (collision) await write(archiveRoot, `${collision}/index.html`, html(`/${collision}/`));

  const docset = {
    id: releasedTag,
    path: versionPath,
    status: 'archived',
  };
  const bundlePath = resolve(docsRoot, 'released.tar.gz');
  const bundle = await createArchiveBundle({ docsRoot, docset, bundlePath });
  return { archiveRoot, bundle, bundlePath, devRoot, docsRoot };
}

test('rejects malformed dispatch values before staging', () => {
  assert.throws(
    () => validatePromotionInputs({
      releasedTag: '1.2.3',
      docsSha256: 'a'.repeat(64),
    }),
    /released tag must be canonical/,
  );
  assert.throws(
    () => validatePromotionInputs({
      releasedTag,
      docsSha256: 'A'.repeat(64),
    }),
    /docs SHA-256/,
  );
  assert.throws(
    () => parsePromotionArgs(['--released-tag', releasedTag]),
    /docs SHA-256/,
  );
});

test('promotes unchanged released files to root and the exact version route', async (t) => {
  const fixture = await createFixture(t);
  const originalIndex = await readFile(resolve(fixture.archiveRoot, 'index.html'));

  const result = await stageProductionDocsets({
    docsRoot: fixture.docsRoot,
    releasedTag,
    docsSha256: fixture.bundle.bundle_sha256,
    bundlePath: fixture.bundlePath,
  });

  assert.equal(result.released, releasedTag);
  assert.equal(result.legacyPreviewRedirects, 2);
  assert.equal(result.versionPath, versionPath);
  assert.equal(result.treeSha256, fixture.bundle.tree_sha256);
  assert.deepEqual(
    await readFile(resolve(fixture.docsRoot, 'dist/index.html')),
    originalIndex,
  );
  assert.deepEqual(
    await readFile(resolve(fixture.docsRoot, 'dist/v/1.2.3/index.html')),
    originalIndex,
  );
  assert.equal(
    await treeDigest(resolve(fixture.docsRoot, 'dist/v/1.2.3')),
    fixture.bundle.tree_sha256,
  );
  assert.equal(
    await readFile(resolve(fixture.devRoot, 'llms.txt'), 'utf8'),
    'Index: https://docs.registrystack.org/dev/llms.txt\n' +
      'Page: https://docs.registrystack.org/dev/guide/\n',
  );
  assert.doesNotMatch(
    await readFile(resolve(fixture.docsRoot, 'dist/index.html'), 'utf8'),
    /registry-docset-redirect|http-equiv="refresh"/,
  );
  assert.match(
    await readFile(resolve(fixture.docsRoot, 'dist/preview/index.html'), 'utf8'),
    /registry-legacy-preview-redirect/,
  );
  assert.match(
    await readFile(
      resolve(fixture.docsRoot, 'dist/preview/start/quickstart/index.html'),
      'utf8',
    ),
    /url=\/start\/quickstart\//,
  );
});

test('rejects a release archive digest mismatch', async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    stageProductionDocsets({
      docsRoot: fixture.docsRoot,
      releasedTag,
      docsSha256: 'f'.repeat(64),
      bundlePath: fixture.bundlePath,
    }),
    /does not match lock/,
  );
});

test('rejects release files that collide with /dev/ or assembly mounts', async (t) => {
  const fixture = await createFixture(t, { collision: 'dev' });
  await assert.rejects(
    stageProductionDocsets({
      docsRoot: fixture.docsRoot,
      releasedTag,
      docsSha256: fixture.bundle.bundle_sha256,
      bundlePath: fixture.bundlePath,
    }),
    /collides with reserved production path \/dev\//,
  );
});
