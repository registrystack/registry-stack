import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import {
  createArchiveBundle,
  releaseRootOutputDirectory,
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
  const rootOutput = releaseRootOutputDirectory(docsRoot, {
    id: releasedTag,
    path: versionPath,
    status: 'archived',
  });
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
  await write(devRoot, 'pagefind/pagefind-entry.json', '{}\n');

  await write(
    archiveRoot,
    'index.html',
    `${html('/')}<script src="/v/1.2.3/_astro/app.js"></script>\n`,
  );
  await write(archiveRoot, '_astro/app.js', 'console.log("version");\n');
  await write(rootOutput, 'index.html', html('/'));
  await write(rootOutput, 'start/when-to-use/index.html', html('/start/when-to-use/'));
  await write(rootOutput, 'index.md', '# Released index\n');
  await write(rootOutput, 'llms.txt', '# Released machine docs\n');
  await write(rootOutput, 'sitemap-index.xml', '<sitemapindex/>\n');
  await write(rootOutput, 'pagefind/pagefind.js', 'export const search = true;\n');
  await write(rootOutput, 'pagefind/pagefind-entry.json', '{}\n');
  if (collision) await write(rootOutput, `${collision}/index.html`, html(`/${collision}/`));

  const docset = {
    id: releasedTag,
    path: versionPath,
    status: 'archived',
  };
  const bundlePath = resolve(docsRoot, 'released.tar.gz');
  const bundle = await createArchiveBundle({ docsRoot, docset, bundlePath });
  return { archiveRoot, bundle, bundlePath, devRoot, docsRoot, rootOutput };
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
  const originalRootIndex = await readFile(resolve(fixture.rootOutput, 'index.html'));
  const originalVersionIndex = await readFile(resolve(fixture.archiveRoot, 'index.html'));

  const result = await stageProductionDocsets({
    docsRoot: fixture.docsRoot,
    releasedTag,
    docsSha256: fixture.bundle.bundle_sha256,
    bundlePath: fixture.bundlePath,
  });

  assert.equal(result.released, releasedTag);
  assert.equal(result.legacyPreviewRedirects, 2);
  assert.equal(result.versionPath, versionPath);
  assert.equal(result.rootTreeSha256, fixture.bundle.root_tree_sha256);
  assert.equal(result.versionTreeSha256, fixture.bundle.version_tree_sha256);
  assert.deepEqual(
    await readFile(resolve(fixture.docsRoot, 'dist/index.html')),
    originalRootIndex,
  );
  assert.deepEqual(
    await readFile(resolve(fixture.docsRoot, 'dist/v/1.2.3/index.html')),
    originalVersionIndex,
  );
  assert.equal(
    await treeDigest(resolve(fixture.docsRoot, 'dist/v/1.2.3')),
    fixture.bundle.version_tree_sha256,
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
      resolve(fixture.docsRoot, 'dist/preview/start/when-to-use/index.html'),
      'utf8',
    ),
    /url=\/start\/when-to-use\//,
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

async function candidateBundle(t, tag) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-candidate-docs-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const version = tag.slice(1);
  const docset = {
    id: tag,
    path: `/v/${version}/`,
    status: 'archived',
  };
  const rootTree = releaseRootOutputDirectory(docsRoot, docset);
  const versionTree = resolve(docsRoot, `dist/v/${version}`);
  await write(
    rootTree,
    'index.html',
    `<html><head><link rel="canonical" href="${canonical}/"></head>` +
      `<body>${tag}<script src="/_astro/app.js"></script></body></html>`,
  );
  await write(rootTree, '_astro/app.js', `console.log("${tag} root");\n`);
  await write(rootTree, 'index.md', `# ${tag}\n`);
  await write(rootTree, 'llms.txt', `# ${tag}\n`);
  await write(rootTree, 'sitemap-index.xml', '<sitemapindex/>\n');
  await write(rootTree, 'pagefind/pagefind.js', 'export const search = true;\n');
  await write(
    versionTree,
    'index.html',
    `<html><head><meta name="robots" content="noindex,follow"></head>` +
      `<body><a href="/v/${version}/guide/">Guide</a>` +
      `<script src="/v/${version}/_astro/app.js"></script></body></html>`,
  );
  await write(
    versionTree,
    'guide/index.html',
    `<html><body>${tag} guide</body></html>`,
  );
  await write(versionTree, '_astro/app.js', `console.log("${tag} version");\n`);
  const bundlePath = resolve(docsRoot, `registry-docs-${tag}.tar.gz`);
  const bundle = await createArchiveBundle({ docsRoot, docset, bundlePath });
  return { bundle, bundlePath, tag, version };
}

test('a second release preserves the first release version links and assets', async (t) => {
  const deployment = await mkdtemp(resolve(tmpdir(), 'registry-docs-two-releases-'));
  t.after(() => rm(deployment, { recursive: true, force: true }));
  await write(resolve(deployment, 'dist/dev'), 'index.html', html('/dev/'));
  const first = await candidateBundle(t, 'v1.0.0');
  const second = await candidateBundle(t, 'v2.0.0');

  await stageProductionDocsets({
    docsRoot: deployment,
    releasedTag: first.tag,
    docsSha256: first.bundle.bundle_sha256,
    bundlePath: first.bundlePath,
  });

  for (const entry of await readdir(resolve(deployment, 'dist'))) {
    if (!['dev', 'v'].includes(entry)) {
      await rm(resolve(deployment, 'dist', entry), { recursive: true, force: true });
    }
  }

  await stageProductionDocsets({
    docsRoot: deployment,
    releasedTag: second.tag,
    docsSha256: second.bundle.bundle_sha256,
    bundlePath: second.bundlePath,
  });

  const historical = await readFile(
    resolve(deployment, 'dist/v/1.0.0/index.html'),
    'utf8',
  );
  assert.match(historical, /href="\/v\/1\.0\.0\/guide\/"/);
  assert.match(historical, /src="\/v\/1\.0\.0\/_astro\/app\.js"/);
  assert.equal(
    await readFile(
      resolve(deployment, 'dist/v/1.0.0/_astro/app.js'),
      'utf8',
    ),
    'console.log("v1.0.0 version");\n',
  );
  assert.match(
    await readFile(
      resolve(deployment, 'dist/v/1.0.0/guide/index.html'),
      'utf8',
    ),
    /v1\.0\.0 guide/,
  );
  assert.equal(
    await readFile(resolve(deployment, 'dist/_astro/app.js'), 'utf8'),
    'console.log("v2.0.0 root");\n',
  );
});
