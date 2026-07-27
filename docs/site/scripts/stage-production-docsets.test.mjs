import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

import { fileDigest, treeDigest } from './archive-bundle.mjs';
import { stageProductionDocsets } from './stage-production-docsets.mjs';

async function filesBelow(root, current = root) {
  const files = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isDirectory()) files.push(...await filesBelow(root, path));
    else if (entry.isFile()) files.push(relative(root, path).replaceAll('\\', '/'));
  }
  return files.sort();
}

async function createFixture(t, {
  releasedAvailability = 'released',
  releasedPages = ['index.html', 'guide/index.html'],
} = {}) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-production-docsets-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const dataDir = resolve(docsRoot, 'src/data');
  const previewRoot = resolve(docsRoot, 'dist/preview');
  const archiveRoot = resolve(docsRoot, 'dist/v/1.0.0');
  const bundlePath = resolve(docsRoot, 'dist/_archive-bundles/v1.0.0.tar.gz');
  await Promise.all([
    mkdir(dataDir, { recursive: true }),
    mkdir(previewRoot, { recursive: true }),
    mkdir(archiveRoot, { recursive: true }),
    mkdir(dirname(bundlePath), { recursive: true }),
    mkdir(resolve(docsRoot, 'public'), { recursive: true }),
  ]);
  await writeFile(
    resolve(previewRoot, 'index.html'),
    '<p>v0.14.0 candidate sentinel</p>\n',
  );
  await mkdir(resolve(previewRoot, '_pagefind'), { recursive: true });
  await writeFile(resolve(previewRoot, '_pagefind/pagefind.js'), 'preview search\n');
  await writeFile(resolve(previewRoot, 'llms-full.txt'), 'v0.14.0 candidate corpus\n');
  await writeFile(resolve(previewRoot, 'llms-small.txt'), 'v0.14.0 candidate corpus\n');
  await writeFile(resolve(previewRoot, 'sitemap-index.xml'), '<sitemapindex/>\n');
  await writeFile(resolve(previewRoot, 'CNAME'), 'preview.invalid\n');
  await writeFile(resolve(docsRoot, 'public/CNAME'), 'docs.example.test\n');
  for (const page of releasedPages) {
    const path = resolve(archiveRoot, page);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `<p>Released ${page}</p>\n`);
  }
  await writeFile(bundlePath, 'locked release bundle\n');

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
        label: 'Registry Stack v1.0.0',
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
  const bundleDigest = await fileDigest(bundlePath);
  const lock = {
    schema_version: 'registry-docs.archive-lock.v1',
    archives: {
      'v1.0.0': {
        bundle_sha256: bundleDigest,
        tree_sha256: lockedDigest,
      },
    },
  };
  await writeFile(resolve(dataDir, 'archive-lock.yaml'), YAML.stringify(lock));
  return {
    archiveRoot,
    bundleDigest,
    bundlePath,
    docsRoot,
    lockedDigest,
    previewRoot,
    productionRoot: resolve(docsRoot, 'dist-production'),
  };
}

test('builds an allowlisted released-only production tree without changing preview', async (t) => {
  const fixture = await createFixture(t);
  const previewDigest = await treeDigest(fixture.previewRoot);

  const result = await stageProductionDocsets({ docsRoot: fixture.docsRoot });

  assert.deepEqual(result, {
    archives: 1,
    bundles: 1,
    preview_redirects: 2,
    released: 'v1.0.0',
    root_redirects: 2,
  });
  assert.equal(await treeDigest(fixture.previewRoot), previewDigest);
  assert.equal(await treeDigest(fixture.archiveRoot), fixture.lockedDigest);
  assert.equal(
    await treeDigest(resolve(fixture.productionRoot, 'v/1.0.0')),
    fixture.lockedDigest,
  );
  assert.equal(
    await fileDigest(resolve(fixture.productionRoot, '_archive-bundles/v1.0.0.tar.gz')),
    fixture.bundleDigest,
  );
  assert.equal(
    await readFile(resolve(fixture.productionRoot, 'CNAME'), 'utf8'),
    'docs.example.test\n',
  );

  for (const path of [
    'index.html',
    'guide/index.html',
    'preview/index.html',
    'preview/guide/index.html',
  ]) {
    const redirect = await readFile(resolve(fixture.productionRoot, path), 'utf8');
    assert.match(redirect, /registry-docset-redirect/);
    assert.equal(redirect.includes('https://docs.registrystack.org/v/1.0.0/'), true);
    assert.doesNotMatch(redirect, /Released (?:index|guide)/);
  }
  assert.match(
    await readFile(resolve(fixture.productionRoot, 'guide/index.html'), 'utf8'),
    /url=\/v\/1\.0\.0\/guide\//,
  );
  assert.match(
    await readFile(resolve(fixture.productionRoot, 'preview/guide/index.html'), 'utf8'),
    /url=\/v\/1\.0\.0\/guide\//,
  );

  const robots = await readFile(resolve(fixture.productionRoot, 'robots.txt'), 'utf8');
  const llms = await readFile(resolve(fixture.productionRoot, 'llms.txt'), 'utf8');
  assert.equal(robots, 'User-agent: *\nAllow: /v/1.0.0/\n');
  assert.match(llms, /Selected released docset: v1\.0\.0/);
  assert.equal(llms.includes('https://docs.registrystack.org/v/1.0.0/'), true);
  assert.doesNotMatch(`${robots}\n${llms}`, /preview|v0\.14\.0/i);

  const files = await filesBelow(fixture.productionRoot);
  assert.equal(files.some((path) => path.includes('pagefind')), false);
  assert.equal(files.some((path) => path.includes('sitemap')), false);
  assert.equal(files.includes('llms-full.txt'), false);
  assert.equal(files.includes('llms-small.txt'), false);
  assert.equal(
    files
      .filter((path) => path.endsWith('.html') && !path.startsWith('v/'))
      .every((path) => ['index.html', 'guide/index.html', 'preview/index.html', 'preview/guide/index.html'].includes(path)),
    true,
  );
  for (const path of files.filter(
    (entry) => entry.endsWith('.html') && !entry.startsWith('v/'),
  )) {
    assert.match(
      await readFile(resolve(fixture.productionRoot, path), 'utf8'),
      /registry-docset-redirect/,
    );
  }
});

test('rejects a candidate docset selected as released', async (t) => {
  const fixture = await createFixture(t, { releasedAvailability: 'candidate' });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /must select an archived released docset/,
  );
  await assert.rejects(stat(fixture.productionRoot), /ENOENT/);
});

test('fails before production output when an archive digest differs from its lock', async (t) => {
  const fixture = await createFixture(t);
  await writeFile(resolve(fixture.archiveRoot, 'index.html'), '<p>Changed</p>\n');

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /does not match its immutable tree lock/,
  );
  await assert.rejects(stat(fixture.productionRoot), /ENOENT/);
});

test('fails before production output when a bundle digest differs from its lock', async (t) => {
  const fixture = await createFixture(t);
  await writeFile(fixture.bundlePath, 'changed release bundle\n');

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /does not match its immutable bundle lock/,
  );
  await assert.rejects(stat(fixture.productionRoot), /ENOENT/);
});

test('rejects a released route that collides with the reserved preview map', async (t) => {
  const fixture = await createFixture(t, {
    releasedPages: ['index.html', 'preview/index.html'],
  });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /collides with reserved production path \/preview\//,
  );
  await assert.rejects(stat(fixture.productionRoot), /ENOENT/);
});

test('rejects a route whose normalized canonical target escapes the released path', async (t) => {
  const fixture = await createFixture(t, {
    releasedPages: ['index.html', '%2e%2e/escaped/index.html'],
  });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /target must remain within \/v\/1\.0\.0\//,
  );
  await assert.rejects(stat(fixture.productionRoot), /ENOENT/);
});
