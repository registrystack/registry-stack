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
} from './build-archives.mjs';
import { applyArchiveSeo } from './apply-archive-seo.mjs';

const execFileAsync = promisify(execFile);
const scriptsDir = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptsDir, '..');
const archivedDocset = {
  id: 'v1.2.3',
  path: '/v/1.2.3/',
  status: 'archived',
  products: {
    'registry-stack': {
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
    'generate-standard-journeys.mjs',
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

test('every versioned archive is noindex and has no sitemap', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-seo-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    resolve(root, 'index.html'),
    '<html><head><link rel="sitemap" href="sitemap-index.xml"></head></html>',
  );
  await writeFile(resolve(root, 'sitemap-index.xml'), '<sitemapindex/>\n');

  await applyArchiveSeo(root);

  const html = await readFile(resolve(root, 'index.html'), 'utf8');
  assert.match(html, /noindex,follow/);
  assert.doesNotMatch(html, /rel="sitemap"/);
  await assert.rejects(
    readFile(resolve(root, 'sitemap-index.xml'), 'utf8'),
    /ENOENT/,
  );
});

test('archived docset builds use isolated generation with release-bound environment', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = [];
  let seoPath;

  await buildDocsetArchive(archivedDocset, {
    docsRoot: root,
    stageGeneratedArtifacts: async () => async () => {},
    runCommand: async (command, args, env) => {
      calls.push({ command, args, env });
    },
    applySeo: async (path) => {
      seoPath = path;
    },
  });

  assert.deepEqual(
    calls.map(({ command, args }) => [command, args]),
    [
      ['npm', ['run', 'generate:archive']],
      ['npx', ['astro', 'check']],
      ['npx', ['astro', 'build', '--outDir', resolve(root, 'dist/v/1.2.3')]],
    ],
  );
  for (const { env } of calls) {
    assert.equal(env.DOCS_DOCSET, 'v1.2.3');
    assert.equal(env.DOCS_BASE, '/v/1.2.3/');
    assert.equal(env.TZ, 'UTC');
    assert.equal(env.PUBLIC_UMAMI_WEBSITE_ID, '');
    assert.equal(env.PUBLIC_UMAMI_SCRIPT_SRC, '');
    assert.equal(env.PUBLIC_UMAMI_DOMAINS, '');
  }
  assert.equal(seoPath, resolve(root, 'dist/v/1.2.3'));
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
