import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

import { treeDigest } from './archive-bundle.mjs';
import { stageProductionDocsets } from './stage-production-docsets.mjs';

async function createFixture(t, {
  releasedAvailability = 'released',
  releasedPages = ['index.html', 'guide/index.html'],
} = {}) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-production-docsets-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const dataDir = resolve(docsRoot, 'src/data');
  const previewRoot = resolve(docsRoot, 'dist/preview');
  const archiveRoot = resolve(docsRoot, 'dist/v/1.0.0');
  await Promise.all([
    mkdir(dataDir, { recursive: true }),
    mkdir(previewRoot, { recursive: true }),
    mkdir(archiveRoot, { recursive: true }),
  ]);
  await writeFile(
    resolve(previewRoot, 'index.html'),
    '<a href="/guide/">Guide</a><a href="/v/1.0.0/">Release</a>\n',
  );
  await mkdir(resolve(previewRoot, 'guide'), { recursive: true });
  await writeFile(resolve(previewRoot, 'guide/index.html'), '<p>Preview guide</p>\n');
  await writeFile(
    resolve(previewRoot, 'index.md'),
    'Index: https://docs.registrystack.org/llms.txt\n',
  );
  await writeFile(
    resolve(previewRoot, 'robots.txt'),
    'Sitemap: https://docs.registrystack.org/sitemap-index.xml\n',
  );
  await writeFile(resolve(previewRoot, 'CNAME'), 'docs.example.test\n');
  for (const page of releasedPages) {
    const path = resolve(archiveRoot, page);
    await mkdir(resolve(path, '..'), { recursive: true });
    await writeFile(path, `<p>Released ${page}</p>\n`);
  }

  const manifest = {
    current: 'latest',
    released: 'v1.0.0',
    docsets: [
      {
        id: 'latest',
        label: 'Main source',
        path: '/',
        status: 'current',
        availability: 'unreleased',
        source: 'main',
        published_at: '2026-07-27',
        description: 'Main source documentation.',
        products: {
          product: { version: 'main', ref: 'HEAD' },
        },
      },
      {
        id: 'v1.0.0',
        label: 'v1.0.0',
        path: '/v/1.0.0/',
        status: 'archived',
        availability: releasedAvailability,
        source: 'v1.0.0',
        published_at: '2026-07-27',
        description: 'Released documentation.',
        products: {
          product: { version: 'v1.0.0', ref: 'a'.repeat(40) },
        },
      },
    ],
  };
  await writeFile(resolve(dataDir, 'docsets.yaml'), YAML.stringify(manifest));
  const lockedDigest = await treeDigest(archiveRoot);
  const lock = {
    schema_version: 'registry-docs.archive-lock.v1',
    archives: {
      'v1.0.0': {
        bundle_sha256: 'b'.repeat(64),
        tree_sha256: lockedDigest,
      },
    },
  };
  await writeFile(resolve(dataDir, 'archive-lock.yaml'), YAML.stringify(lock));
  return { docsRoot, dataDir, previewRoot, archiveRoot, lockedDigest };
}

test('stages root routes as redirects without copying or changing immutable archives', async (t) => {
  const fixture = await createFixture(t);

  const result = await stageProductionDocsets({ docsRoot: fixture.docsRoot });

  assert.deepEqual(result, { released: 'v1.0.0', redirects: 2 });
  assert.equal(await treeDigest(fixture.archiveRoot), fixture.lockedDigest);
  assert.equal(
    await readFile(resolve(fixture.previewRoot, 'index.html'), 'utf8'),
    '<a href="/preview/guide/">Guide</a><a href="/v/1.0.0/">Release</a>\n',
  );
  assert.equal(
    await readFile(resolve(fixture.previewRoot, 'index.md'), 'utf8'),
    'Index: https://docs.registrystack.org/preview/llms.txt\n',
  );
  assert.equal(
    await readFile(resolve(fixture.docsRoot, 'dist/CNAME'), 'utf8'),
    'docs.example.test\n',
  );
  assert.equal(
    await readFile(resolve(fixture.docsRoot, 'dist/robots.txt'), 'utf8'),
    'Sitemap: https://docs.registrystack.org/preview/sitemap-index.xml\n',
  );
  const root = await readFile(resolve(fixture.docsRoot, 'dist/index.html'), 'utf8');
  const guide = await readFile(resolve(fixture.docsRoot, 'dist/guide/index.html'), 'utf8');
  assert.match(root, /registry-docset-redirect/);
  assert.match(root, /url=\/v\/1\.0\.0\//);
  assert.match(guide, /url=\/v\/1\.0\.0\/guide\//);
  assert.doesNotMatch(root, /Released index\.html/);
});

test('rejects a candidate docset selected as released', async (t) => {
  const fixture = await createFixture(t, { releasedAvailability: 'candidate' });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /must select an archived released docset/,
  );
});

test('rejects an archive tree that differs from its immutable lock', async (t) => {
  const fixture = await createFixture(t);
  await writeFile(resolve(fixture.archiveRoot, 'index.html'), '<p>Changed</p>\n');

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /does not match its immutable tree lock/,
  );
});

test('rejects existing root destinations before writing any redirect', async (t) => {
  const fixture = await createFixture(t);
  await writeFile(resolve(fixture.docsRoot, 'dist/index.html'), '<p>Collision</p>\n');

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /production redirect destination already exists/,
  );
  await assert.rejects(
    readFile(resolve(fixture.docsRoot, 'dist/guide/index.html')),
    /ENOENT/,
  );
  await assert.rejects(
    readFile(resolve(fixture.docsRoot, 'dist/CNAME')),
    /ENOENT/,
  );
  await assert.rejects(
    readFile(resolve(fixture.docsRoot, 'dist/robots.txt')),
    /ENOENT/,
  );
});

test('rejects released routes that collide with production mount directories', async (t) => {
  const fixture = await createFixture(t, {
    releasedPages: ['index.html', 'preview/index.html'],
  });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /collides with reserved production path \/preview\//,
  );
});
