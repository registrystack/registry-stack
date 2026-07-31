import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  buildDocsetArchive,
  currentSourceGeneratedArtifacts,
  readOptionalRegularFile,
  stagePinnedGeneratedArtifacts,
} from './build-archives.mjs';
import { applyArchiveSeo } from './apply-archive-seo.mjs';

const execFileAsync = promisify(execFile);
const scriptsDir = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptsDir, '..');
const archivedDocset = {
  id: 'v1.2.3',
  path: '/v/1.2.3/',
  status: 'archived',
  availability: 'released',
  products: {
    'registry-stack': {
      version: 'v1.2.3',
      ref: 'a'.repeat(40),
    },
  },
};

test('archive snapshot reads one no-follow regular-file descriptor', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-snapshot-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const regular = resolve(root, 'regular.json');
  const link = resolve(root, 'linked.json');

  await writeFile(regular, '{"source_label":"current"}\n');
  await symlink(regular, link);

  assert.equal(
    (await readOptionalRegularFile(regular)).toString('utf8'),
    '{"source_label":"current"}\n',
  );
  await assert.rejects(
    readOptionalRegularFile(link),
    (error) => error?.code === 'ELOOP' || /regular file/.test(error?.message),
  );
  assert.equal(await readOptionalRegularFile(resolve(root, 'missing.json')), null);
});

test('archive generation excludes current-source generators', async () => {
  const packageJson = JSON.parse(
    await readFile(resolve(docsRoot, 'package.json'), 'utf8'),
  );
  const archiveGeneration = packageJson.scripts['generate:archive'];

  for (const script of [
    'generate-data.mjs',
    'fetch-openapi.mjs',
    'sync-repo-docs.mjs',
    'generate-sidebar.mjs',
  ]) {
    assert.match(archiveGeneration, new RegExp(`scripts/${script.replace('.', '\\.')}`));
  }
  for (const script of [
    'generate-project-starters.mjs',
    'generate-authoring-reference.mjs',
    'generate-diagnostic-references.mjs',
  ]) {
    assert.doesNotMatch(
      archiveGeneration,
      new RegExp(`scripts/${script.replace('.', '\\.')}`),
    );
    assert.match(
      packageJson.scripts.generate,
      new RegExp(`scripts/${script.replace('.', '\\.')}`),
    );
  }
  assert.match(
    packageJson.scripts.build,
    /node scripts\/apply-archive-seo\.mjs dist/,
  );
});

test('candidate archive stages generated artifacts from the checked-out source', async (t) => {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-candidate-ref-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  const calls = [];
  const restore = await stagePinnedGeneratedArtifacts(
    {
      ...archivedDocset,
      availability: 'candidate',
      products: {
        'registry-stack': {
          version: 'v1.2.3',
          ref: 'v1.2.3',
        },
      },
    },
    {
      docsRoot: resolve(repoRoot, 'docs/site'),
      executeGit: async (_command, args) => {
        calls.push(args);
        return { stdout: Buffer.alloc(0) };
      },
    },
  );

  await restore();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].slice(0, 5), ['ls-tree', '-rz', '--name-only', 'HEAD', '--']);
});

test('candidate archive rejects a tag that does not match its release identity', async () => {
  await assert.rejects(
    stagePinnedGeneratedArtifacts({
      ...archivedDocset,
      availability: 'candidate',
      products: {
        'registry-stack': {
          version: 'v1.2.3',
          ref: 'v1.2.4',
        },
      },
    }),
    /must pin products\.registry-stack\.ref to a full commit or its exact candidate tag/,
  );
});

test('single release archive build does not depend on the mutable released pointer', async () => {
  const source = await readFile(resolve(docsRoot, 'scripts/build-archive.mjs'), 'utf8');
  assert.match(source, /buildDocsetArchive\(docset, \{ indexable: true \}\)/);
  assert.doesNotMatch(source, /docset\.id === docsets\.released/);
});

test('selected released archive stays indexable and keeps its sitemap', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-released-seo-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    resolve(root, 'index.html'),
    '<html><head><meta name="robots" content="noindex,follow"><link rel="sitemap" href="sitemap-index.xml"></head></html>',
  );
  await writeFile(resolve(root, 'sitemap-index.xml'), '<sitemapindex/>\n');

  await applyArchiveSeo(root, { indexable: true });

  const html = await readFile(resolve(root, 'index.html'), 'utf8');
  assert.doesNotMatch(html, /noindex,follow/);
  assert.match(html, /rel="sitemap"/);
  assert.equal(
    await readFile(resolve(root, 'sitemap-index.xml'), 'utf8'),
    '<sitemapindex/>\n',
  );
});

test('archived docset builds use isolated generation with release-bound environment', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = [];
  const seoCalls = [];

  await buildDocsetArchive(archivedDocset, {
    docsRoot: root,
    stageGeneratedArtifacts: async () => async () => {},
    runCommand: async (command, args, env) => {
      calls.push({ command, args, env });
    },
    applySeo: async (path, options) => {
      seoCalls.push([path, options]);
    },
  });

  assert.deepEqual(
    calls.map(({ command, args }) => [command, args]),
    [
      ['npm', ['run', 'generate:archive']],
      ['npx', ['astro', 'check']],
      [
        'npx',
        [
          'astro',
          'build',
          '--outDir',
          resolve(root, '.release-docsets/v1.2.3/root'),
        ],
      ],
      ['npx', ['astro', 'build', '--outDir', resolve(root, 'dist/v/1.2.3')]],
    ],
  );
  for (const { env } of calls.slice(0, -1)) {
    assert.equal(env.DOCS_DOCSET, 'v1.2.3');
    assert.equal(env.DOCS_BASE, '/');
    assert.equal(env.DOCS_RELEASED_ARCHIVE, '');
    assert.equal(env.TZ, 'UTC');
    assert.equal(env.PUBLIC_UMAMI_WEBSITE_ID, '');
    assert.equal(env.PUBLIC_UMAMI_SCRIPT_SRC, '');
    assert.equal(env.PUBLIC_UMAMI_DOMAINS, '');
  }
  assert.equal(calls.at(-1).env.DOCS_BASE, '/v/1.2.3/');
  assert.equal(calls.at(-1).env.DOCS_RELEASED_ARCHIVE, '');
  assert.deepEqual(seoCalls, [
    [
      resolve(root, '.release-docsets/v1.2.3/root'),
      { indexable: false },
    ],
    [resolve(root, 'dist/v/1.2.3'), { indexable: false }],
  ]);
});

test('selected released archive builds at the canonical root with release discovery', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-released-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = [];

  await buildDocsetArchive(archivedDocset, {
    docsRoot: root,
    indexable: true,
    stageGeneratedArtifacts: async () => async () => {},
    runCommand: async (_command, _args, env) => calls.push(env),
    applySeo: async () => {},
  });

  assert.equal(calls.length, 4);
  for (const env of calls.slice(0, -1)) {
    assert.equal(env.DOCS_BASE, '/');
    assert.equal(env.DOCS_RELEASED_ARCHIVE, 'true');
  }
  assert.equal(calls.at(-1).DOCS_BASE, '/v/1.2.3/');
  assert.equal(calls.at(-1).DOCS_RELEASED_ARCHIVE, '');
});

test('archive output uses pinned generated artifacts and restores current files', async (t) => {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-ref-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  const siteRoot = resolve(repoRoot, 'docs/site');
  const pinnedPath = currentSourceGeneratedArtifacts[2];
  const absentAtReleasePath = currentSourceGeneratedArtifacts.at(-1);
  const pinnedLocal = resolve(repoRoot, pinnedPath);
  const absentAtReleaseLocal = resolve(repoRoot, absentAtReleasePath);

  await mkdir(dirname(pinnedLocal), { recursive: true });
  await writeFile(pinnedLocal, '{"source_label":"v1.2.3"}\n');
  await execFileAsync('git', ['init', '--quiet'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.name', 'Archive Test'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.email', 'archive@example.invalid'], {
    cwd: repoRoot,
  });
  await execFileAsync('git', ['add', pinnedPath], { cwd: repoRoot });
  await execFileAsync('git', ['commit', '--quiet', '-m', 'release'], { cwd: repoRoot });
  const { stdout: sourceRefOutput } = await execFileAsync(
    'git',
    ['rev-parse', 'HEAD'],
    { cwd: repoRoot },
  );
  const sourceRef = sourceRefOutput.trim();

  await writeFile(pinnedLocal, '{"source_label":"Main source (unreleased)"}\n');
  await mkdir(dirname(absentAtReleaseLocal), { recursive: true });
  await writeFile(absentAtReleaseLocal, '{"source_label":"Main source (unreleased)"}\n');

  const outputCapture = resolve(repoRoot, 'archive-captured.json');
  await buildDocsetArchive(
    {
      ...archivedDocset,
      products: { 'registry-stack': { ref: sourceRef } },
    },
    {
      docsRoot: siteRoot,
      runCommand: async (_command, args) => {
        if (args.includes('build')) {
          await writeFile(outputCapture, await readFile(pinnedLocal));
          await assert.rejects(readFile(absentAtReleaseLocal), { code: 'ENOENT' });
        }
      },
      applySeo: async () => {},
    },
  );

  assert.equal(
    await readFile(outputCapture, 'utf8'),
    '{"source_label":"v1.2.3"}\n',
  );
  assert.equal(
    await readFile(pinnedLocal, 'utf8'),
    '{"source_label":"Main source (unreleased)"}\n',
  );
  assert.equal(
    await readFile(absentAtReleaseLocal, 'utf8'),
    '{"source_label":"Main source (unreleased)"}\n',
  );
});
