import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

import { treeDigest } from './archive-bundle.mjs';
import { stageProductionDocsets } from './stage-production-docsets.mjs';

function releasedHtml(route, body) {
  return `<!doctype html><html><head>
<meta name="robots" content="noindex,follow">
<link rel="canonical" href="https://docs.registrystack.org/v/1.0.0${route}">
</head><body>
<aside class="registry-preview-banner" role="note"><p>Versioned archive.</p></aside>
${body}
</body></html>
`;
}

async function createFixture(t, {
  releasedAvailability = 'released',
  releasedPages = ['index.html', 'guide/index.html'],
  releasedRedirectPages = [],
} = {}) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-production-docsets-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const dataDir = resolve(docsRoot, 'src/data');
  const developmentRoot = resolve(docsRoot, 'dist/dev');
  const archiveRoot = resolve(docsRoot, 'dist/v/1.0.0');
  await Promise.all([
    mkdir(dataDir, { recursive: true }),
    mkdir(developmentRoot, { recursive: true }),
    mkdir(archiveRoot, { recursive: true }),
  ]);
  await writeFile(
    resolve(developmentRoot, 'index.html'),
    '<html><head><meta name="robots" content="noindex,follow"></head><body><a href="/dev/guide/">Guide</a></body></html>\n',
  );
  await mkdir(resolve(developmentRoot, 'guide'), { recursive: true });
  await writeFile(
    resolve(developmentRoot, 'guide/index.html'),
    '<html><head><meta name="robots" content="noindex,follow"></head><body>Development guide</body></html>\n',
  );
  await writeFile(
    resolve(developmentRoot, 'index.md'),
    'Index: https://docs.registrystack.org/llms.txt\nFull: https://docs.registrystack.org/llms-full.txt\n',
  );
  await writeFile(
    resolve(developmentRoot, 'llms.txt'),
    'Small: https://docs.registrystack.org/llms-small.txt\n',
  );
  await writeFile(resolve(developmentRoot, 'CNAME'), 'docs.example.test\n');
  for (const page of releasedPages) {
    const path = resolve(archiveRoot, page);
    await mkdir(resolve(path, '..'), { recursive: true });
    const route = page === 'index.html' ? '/' : `/${page.slice(0, -'index.html'.length)}`;
    await writeFile(
      path,
      releasedHtml(
        route,
        `<p>Released ${page}</p><a href="/v/1.0.0/guide/">Guide</a><a href="/preview/guide/">Development</a>`,
      ),
    );
  }
  for (const page of releasedRedirectPages) {
    const path = resolve(archiveRoot, page);
    await mkdir(resolve(path, '..'), { recursive: true });
    await writeFile(
      path,
      '<!doctype html><title>Redirect</title><meta http-equiv="refresh" content="0;url=/v/1.0.0/guide/"><link rel="canonical" href="https://docs.registrystack.org/v/1.0.0/guide/">\n',
    );
  }
  await writeFile(
    resolve(archiveRoot, 'index.md'),
    `Registry stack documentation: machine-readable Markdown.
Index of all pages: https://docs.registrystack.org/llms.txt
Full corpus: https://docs.registrystack.org/llms-full.txt

# Released index

[Guide](/v/1.0.0/guide/)
[External](https://example.test/v/1.0.0/guide/)
`,
  );
  await writeFile(resolve(archiveRoot, 'guide.md'), '# Released guide\n');
  await mkdir(resolve(archiveRoot, 'assets'), { recursive: true });
  await writeFile(
    resolve(archiveRoot, 'assets/app.js'),
    'const local = "/v/1.0.0/guide/"; const external = "https://example.test/v/1.0.0/guide/";\n',
  );
  await writeFile(resolve(archiveRoot, 'assets/image.bin'), Buffer.from([0, 1, 2, 255]));
  await writeFile(resolve(archiveRoot, 'CNAME'), 'archive.invalid\n');

  const manifest = {
    current: 'latest',
    released: 'v1.0.0',
    docsets: [
      {
        id: 'latest',
        label: 'Development (unreleased)',
        path: '/dev/',
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
  return { docsRoot, dataDir, developmentRoot, archiveRoot, lockedDigest };
}

test('promotes the locked release to canonical root without changing its archive', async (t) => {
  const fixture = await createFixture(t);

  const result = await stageProductionDocsets({ docsRoot: fixture.docsRoot });

  assert.deepEqual(result, {
    released: 'v1.0.0',
    promotedFiles: 6,
    canonicalRoutes: 2,
    corpusFiles: 3,
    legacyRedirects: 2,
  });
  assert.equal(await treeDigest(fixture.archiveRoot), fixture.lockedDigest);
  assert.match(
    await readFile(resolve(fixture.docsRoot, 'dist/index.html'), 'utf8'),
    /Released index\.html/,
  );
  const root = await readFile(resolve(fixture.docsRoot, 'dist/index.html'), 'utf8');
  assert.doesNotMatch(root, /noindex/);
  assert.match(root, /href="https:\/\/docs\.registrystack\.org\/"/);
  assert.match(root, /rel="sitemap"/);
  assert.match(root, /<strong>Latest release\.<\/strong>/);
  assert.match(root, /href="\/guide\/"/);
  assert.match(root, /href="\/dev\/guide\/"/);
  assert.equal(
    await readFile(resolve(fixture.docsRoot, 'dist/index.md'), 'utf8'),
    `Registry stack documentation: machine-readable Markdown.
Index of all pages: https://docs.registrystack.org/llms.txt
Full corpus: https://docs.registrystack.org/llms-full.txt

# Released index

[Guide](/guide/)
[External](https://example.test/v/1.0.0/guide/)
`,
  );
  assert.ok(
    (await readFile(resolve(fixture.docsRoot, 'dist/llms.txt'), 'utf8'))
      .includes('https://docs.registrystack.org/llms-full.txt'),
  );
  assert.match(
    await readFile(resolve(fixture.docsRoot, 'dist/llms-full.txt'), 'utf8'),
    /# Released guide/,
  );
  assert.match(
    await readFile(resolve(fixture.docsRoot, 'dist/llms-small.txt'), 'utf8'),
    /# Released index/,
  );
  assert.equal(
    await readFile(resolve(fixture.docsRoot, 'dist/assets/app.js'), 'utf8'),
    'const local = "/guide/"; const external = "https://example.test/v/1.0.0/guide/";\n',
  );
  assert.deepEqual(
    await readFile(resolve(fixture.docsRoot, 'dist/assets/image.bin')),
    Buffer.from([0, 1, 2, 255]),
  );
  assert.equal(
    await readFile(resolve(fixture.docsRoot, 'dist/CNAME'), 'utf8'),
    'docs.example.test\n',
  );
  assert.ok(
    (await readFile(resolve(fixture.docsRoot, 'dist/robots.txt'), 'utf8'))
      .includes('https://docs.registrystack.org/sitemap-index.xml'),
  );
  const sitemap = await readFile(resolve(fixture.docsRoot, 'dist/sitemap-0.xml'), 'utf8');
  assert.match(sitemap, /<loc>https:\/\/docs\.registrystack\.org\/<\/loc>/);
  assert.match(sitemap, /<loc>https:\/\/docs\.registrystack\.org\/guide\/<\/loc>/);
  assert.doesNotMatch(sitemap, /\/dev\/|\/preview\/|\/v\//);
  const legacy = await readFile(
    resolve(fixture.docsRoot, 'dist/preview/guide/index.html'),
    'utf8',
  );
  assert.match(legacy, /registry-legacy-preview-redirect/);
  assert.match(legacy, /url=\/guide\//);
  assert.equal(
    await readFile(resolve(fixture.developmentRoot, 'index.html'), 'utf8'),
    '<html><head><meta name="robots" content="noindex,follow"></head><body><a href="/dev/guide/">Guide</a></body></html>\n',
  );
  assert.equal(
    await readFile(resolve(fixture.developmentRoot, 'index.md'), 'utf8'),
    'Index: https://docs.registrystack.org/dev/llms.txt\nFull: https://docs.registrystack.org/dev/llms-full.txt\n',
  );
  assert.equal(
    await readFile(resolve(fixture.developmentRoot, 'llms.txt'), 'utf8'),
    'Small: https://docs.registrystack.org/dev/llms-small.txt\n',
  );
});

test('rejects a candidate docset selected as released', async (t) => {
  const fixture = await createFixture(t, { releasedAvailability: 'candidate' });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /must select an archived released docset/,
  );
});

test('keeps redirect routes out of the canonical sitemap', async (t) => {
  const fixture = await createFixture(t, {
    releasedRedirectPages: ['old/index.html'],
  });

  const result = await stageProductionDocsets({ docsRoot: fixture.docsRoot });

  assert.equal(result.canonicalRoutes, 2);
  assert.equal(result.legacyRedirects, 3);
  const sitemap = await readFile(resolve(fixture.docsRoot, 'dist/sitemap-0.xml'), 'utf8');
  assert.doesNotMatch(sitemap, /\/old\//);
  assert.match(
    await readFile(resolve(fixture.docsRoot, 'dist/preview/old/index.html'), 'utf8'),
    /registry-legacy-preview-redirect/,
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

test('rejects existing root destinations before promoting any release file', async (t) => {
  const fixture = await createFixture(t);
  await writeFile(resolve(fixture.docsRoot, 'dist/index.html'), '<p>Collision</p>\n');

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /production destination already exists/,
  );
  await assert.rejects(
    readFile(resolve(fixture.docsRoot, 'dist/guide/index.html')),
    /ENOENT/,
  );
  await assert.rejects(
    readFile(resolve(fixture.docsRoot, 'dist/CNAME')),
    /ENOENT/,
  );
});

test('rejects released routes that collide with production mount directories', async (t) => {
  const fixture = await createFixture(t, {
    releasedPages: ['index.html', 'dev/index.html'],
  });

  await assert.rejects(
    stageProductionDocsets({ docsRoot: fixture.docsRoot }),
    /collides with reserved production path \/dev\//,
  );
});
