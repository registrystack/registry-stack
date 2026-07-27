import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

import { treeDigest } from './archive-bundle.mjs';
import { prepareUnreleasedPreview } from './prepare-unreleased-preview.mjs';

async function fixture(t) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-preview-mount-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const previewRoot = resolve(docsRoot, 'dist/preview');
  const dataDir = resolve(docsRoot, 'src/data');
  await Promise.all([
    mkdir(previewRoot, { recursive: true }),
    mkdir(dataDir, { recursive: true }),
  ]);
  await writeFile(
    resolve(previewRoot, 'index.html'),
    [
      '<a href="/guide/">Guide</a>',
      '<a href="/preview/already/">Preview</a>',
      '<a href="/v/0.13.0/">Release</a>',
      '<img src="/image.png">',
      '',
    ].join('\n'),
  );
  await writeFile(
    resolve(previewRoot, 'index.md'),
    'Index: https://docs.registrystack.org/llms.txt\n',
  );
  await writeFile(
    resolve(previewRoot, 'robots.txt'),
    'Sitemap: https://docs.registrystack.org/sitemap-index.xml\n',
  );
  await writeFile(
    resolve(dataDir, 'docsets.yaml'),
    YAML.stringify({
      current: 'latest',
      released: 'v0.13.0',
      docsets: [
        {
          id: 'latest',
          label: 'Main',
          path: '/',
          status: 'current',
          availability: 'unreleased',
          source: 'main',
          published_at: '2026-07-27',
          description: 'Main.',
          products: { product: { version: 'main', ref: 'HEAD' } },
        },
        {
          id: 'v0.13.0',
          label: 'v0.13.0',
          path: '/v/0.13.0/',
          status: 'archived',
          availability: 'released',
          source: 'v0.13.0',
          published_at: '2026-07-25',
          description: 'Release.',
          products: { product: { version: 'v0.13.0', ref: 'a'.repeat(40) } },
        },
      ],
    }),
  );
  return { docsRoot, previewRoot };
}

test('mounts Main links and discovery URLs without rewriting release routes', async (t) => {
  const { docsRoot, previewRoot } = await fixture(t);
  const result = await prepareUnreleasedPreview({ docsRoot });

  assert.deepEqual(result, { checked: 3, changed: 3 });
  const html = await readFile(resolve(previewRoot, 'index.html'), 'utf8');
  assert.match(html, /href="\/preview\/guide\/"/);
  assert.match(html, /href="\/preview\/already\/"/);
  assert.match(html, /href="\/v\/0\.13\.0\/"/);
  assert.match(html, /src="\/preview\/image\.png"/);
  assert.equal(
    await readFile(resolve(previewRoot, 'index.md'), 'utf8'),
    'Index: https://docs.registrystack.org/preview/llms.txt\n',
  );
  assert.equal(
    await readFile(resolve(previewRoot, 'robots.txt'), 'utf8'),
    'Sitemap: https://docs.registrystack.org/preview/sitemap-index.xml\n',
  );
});

test('preparation is byte-idempotent before production staging', async (t) => {
  const { docsRoot, previewRoot } = await fixture(t);
  await prepareUnreleasedPreview({ docsRoot });
  const first = await treeDigest(previewRoot);
  const result = await prepareUnreleasedPreview({ docsRoot });

  assert.deepEqual(result, { checked: 3, changed: 0 });
  assert.equal(await treeDigest(previewRoot), first);
});
