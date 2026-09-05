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
import { gunzipSync, gzipSync } from 'node:zlib';

import {
  buildDocsetArchive,
  currentSourceGeneratedArtifacts,
  normalizePagefindGzipMetadata,
  readOptionalRegularFile,
  stagePinnedGeneratedArtifacts,
} from './build-archives.mjs';
import { applyArchiveSeo } from './apply-archive-seo.mjs';
import { treeDigest } from './archive-bundle.mjs';

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
const stagedArtifactFixtures = Object.freeze([
  'docs/site/src/data/generated/staged-fixtures',
  'docs/site/public/generated/staged-fixture.v1.json',
]);

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

test('Pagefind gzip streams normalize across platforms without changing content', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-pagefind-gzip-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const left = resolve(root, 'left');
  const right = resolve(root, 'right');
  await mkdir(resolve(left, 'pagefind'), { recursive: true });
  await mkdir(resolve(right, 'pagefind'), { recursive: true });

  const wasm = Buffer.from(
    `\0asm\x01\0\0\0${'architecture-independent WebAssembly'.repeat(256)}`,
  );
  for (const name of ['wasm.en.pagefind', 'wasm.unknown.pagefind']) {
    const leftContents = gzipSync(wasm, { level: 1 });
    const rightContents = gzipSync(wasm, { level: 9 });
    leftContents.writeUInt32LE(1_700_000_000, 4);
    rightContents.writeUInt32LE(1_800_000_000, 4);
    leftContents[9] = 0x03;
    rightContents[9] = 0x13;
    await writeFile(resolve(left, 'pagefind', name), leftContents);
    await writeFile(resolve(right, 'pagefind', name), rightContents);
    assert.notDeepEqual(leftContents, rightContents);
    assert.deepEqual(gunzipSync(leftContents), wasm);
    assert.deepEqual(gunzipSync(rightContents), wasm);
  }

  assert.deepEqual(
    await normalizePagefindGzipMetadata(left),
    { files: 2, normalized: 2 },
  );
  assert.deepEqual(
    await normalizePagefindGzipMetadata(right),
    { files: 2, normalized: 2 },
  );
  for (const name of ['wasm.en.pagefind', 'wasm.unknown.pagefind']) {
    const normalizedLeft = await readFile(resolve(left, 'pagefind', name));
    const normalizedRight = await readFile(resolve(right, 'pagefind', name));
    assert.deepEqual(
      normalizedLeft.subarray(0, 10),
      Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x02, 0xff]),
    );
    assert.deepEqual(normalizedLeft, normalizedRight);
    assert.deepEqual(gunzipSync(normalizedLeft), wasm);
  }
  assert.equal(await treeDigest(left), await treeDigest(right));
  assert.deepEqual(
    await normalizePagefindGzipMetadata(left),
    { files: 2, normalized: 0 },
  );
});

test('Pagefind metadata normalization rejects an unexpected WASM format', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-pagefind-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(resolve(root, 'pagefind'), { recursive: true });
  await writeFile(resolve(root, 'pagefind/wasm.en.pagefind'), 'not gzip');

  await assert.rejects(
    normalizePagefindGzipMetadata(root),
    /must use gzip framing/,
  );
});

test('Pagefind metadata normalization rejects a symlinked output directory', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-pagefind-symlink-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const output = resolve(root, 'output');
  const outside = resolve(root, 'outside');
  await mkdir(output);
  await mkdir(outside);
  const externalWasm = resolve(outside, 'wasm.en.pagefind');
  const contents = gzipSync('must remain unchanged');
  contents.writeUInt32LE(1_700_000_000, 4);
  await writeFile(externalWasm, contents);
  await symlink(outside, resolve(output, 'pagefind'));

  await assert.rejects(
    normalizePagefindGzipMetadata(output),
    /must be a real directory/,
  );
  assert.deepEqual(await readFile(externalWasm), contents);
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
    'generate-evidence-configuration.mjs',
    'generate-breg-configuration.mjs',
    'generate-cli-reference.mjs',
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
  assert.deepEqual(currentSourceGeneratedArtifacts, [
    'docs/site/src/content/docs/reference/cli',
    'docs/site/src/data/generated/cli-reference.json',
  ]);
});

test('archive byte producers pin collation independently of the host locale', async () => {
  for (const path of [
    'scripts/archive-bundle.mjs',
    'scripts/generate-sidebar.mjs',
    'src/components/SpecRegister.astro',
  ]) {
    const source = await readFile(resolve(docsRoot, path), 'utf8');
    const comparisons = [...source.matchAll(/localeCompare\(/g)];
    const pinnedComparisons = [...source.matchAll(/localeCompare\([^)]*, 'en-US'\)/g)];
    assert.ok(comparisons.length > 0, `${path} must keep its explicit archive ordering`);
    assert.equal(pinnedComparisons.length, comparisons.length, path);
  }
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
      artifacts: stagedArtifactFixtures,
      allowUnpublishedCandidate: true,
      resolveCommit: async (ref) => {
        assert.equal(ref, 'v1.2.3');
        return null;
      },
      executeGit: async (_command, args) => {
        calls.push(args);
        return { stdout: Buffer.alloc(0) };
      },
    },
  );

  await restore();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].slice(0, 6), ['ls-tree', '-rz', '-r', '--name-only', 'HEAD', '--']);
});

test('published candidate archive fails closed when its tag is unavailable', async (t) => {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-candidate-missing-tag-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));

  await assert.rejects(
    stagePinnedGeneratedArtifacts(
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
        artifacts: stagedArtifactFixtures,
        resolveCommit: async () => null,
      },
    ),
    /must resolve its exact source tag/,
  );
});

test('published candidate archive stages generated artifacts from its tag', async (t) => {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-candidate-tag-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  const pinnedPath = `${stagedArtifactFixtures[0]}/pinned.json`;
  const pinnedLocal = resolve(repoRoot, pinnedPath);
  await mkdir(dirname(pinnedLocal), { recursive: true });
  await writeFile(pinnedLocal, '{"source_label":"v1.2.3"}\n');
  await execFileAsync('git', ['init', '--quiet'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.name', 'Archive Test'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.email', 'archive@example.invalid'], {
    cwd: repoRoot,
  });
  await execFileAsync('git', ['add', pinnedPath], { cwd: repoRoot });
  await execFileAsync('git', ['commit', '--quiet', '-m', 'release'], { cwd: repoRoot });
  await execFileAsync('git', ['tag', 'v1.2.3'], { cwd: repoRoot });
  await writeFile(pinnedLocal, '{"source_label":"Main source (unreleased)"}\n');

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
      artifacts: stagedArtifactFixtures,
    },
  );

  assert.equal(await readFile(pinnedLocal, 'utf8'), '{"source_label":"v1.2.3"}\n');
  await restore();
  assert.equal(
    await readFile(pinnedLocal, 'utf8'),
    '{"source_label":"Main source (unreleased)"}\n',
  );
});

test('an empty artifact list stages nothing instead of listing the whole tree', async () => {
  const calls = [];
  const restore = await stagePinnedGeneratedArtifacts(archivedDocset, {
    artifacts: [],
    executeGit: async (_command, args) => {
      calls.push(args);
      return { stdout: Buffer.alloc(0) };
    },
  });

  await restore();
  assert.deepEqual(calls, []);
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
  assert.match(source, /buildDocsetArchive\(docset, \{/);
  assert.match(source, /allowUnpublishedCandidate: true/);
  assert.match(source, /indexable: true/);
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
  const normalizationCalls = [];
  const seoCalls = [];
  const analyticsCalls = [];
  const environment = {
    BASE_URL: '/mutable-deployment/',
    CI: 'false',
    DOCS_ARCHIVE_BASE_URL: 'https://mutable.example.invalid/archives',
    DOCS_BASE: '/mutable/',
    DOCS_RELEASE_BASE_URL: 'https://mutable.example.invalid/releases',
    GITHUB_ACTIONS: 'true',
    GITHUB_SHA: 'f'.repeat(40),
    GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_GLOBAL: '/mutable/home/.gitconfig',
    GIT_CONFIG_KEY_0: 'core.autocrlf',
    GIT_CONFIG_NOSYSTEM: '0',
    GIT_CONFIG_VALUE_0: 'true',
    HTTPS_PROXY: 'https://proxy.example.invalid',
    HOME: '/archive-test/home',
    LANG: 'mutable-locale',
    LC_ALL: 'mutable-locale',
    PATH: '/archive-test/bin',
    PUBLIC_UMAMI_WEBSITE_ID: 'mutable-analytics-id',
    RAYON_NUM_THREADS: '64',
    SSL_CERT_FILE: '/archive-test/ca.pem',
    SOURCE_DATE_EPOCH: '1234',
    TMPDIR: '/archive-test/tmp',
    TZ: 'Pacific/Kiritimati',
  };

  await buildDocsetArchive(archivedDocset, {
    docsRoot: root,
    environment,
    stageGeneratedArtifacts: async () => async () => {},
    runCommand: async (command, args, env) => {
      calls.push({ command, args, env });
    },
    normalizePagefind: async (path) => {
      normalizationCalls.push(path);
    },
    applySeo: async (path, options) => {
      seoCalls.push([path, options]);
    },
    verifyAnalytics: async (path, options) => {
      analyticsCalls.push([path, options]);
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
  }
  for (const { env } of calls) {
    assert.equal(env.ASTRO_TELEMETRY_DISABLED, '1');
    assert.equal(env.CI, 'true');
    assert.equal(env.DOCS_DOCSET, 'v1.2.3');
    assert.match(env.HOME, /registry-docs-archive-home-/);
    assert.equal(env.USERPROFILE, env.HOME);
    assert.equal(env.XDG_CACHE_HOME, resolve(env.HOME, '.cache'));
    assert.equal(env.XDG_CONFIG_HOME, resolve(env.HOME, '.config'));
    assert.equal(env.GIT_ATTR_NOSYSTEM, '1');
    assert.equal(env.GIT_CONFIG_COUNT, '1');
    assert.equal(env.GIT_CONFIG_GLOBAL, process.platform === 'win32' ? 'NUL' : '/dev/null');
    assert.equal(env.GIT_CONFIG_KEY_0, 'core.autocrlf');
    assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
    assert.equal(env.GIT_CONFIG_VALUE_0, 'false');
    assert.equal(env.HTTPS_PROXY, 'https://proxy.example.invalid');
    assert.equal(env.LANG, 'C.UTF-8');
    assert.equal(env.LC_ALL, 'C.UTF-8');
    assert.equal(env.NO_COLOR, '1');
    assert.equal(env.PATH, '/archive-test/bin');
    assert.equal(env.SOURCE_DATE_EPOCH, '0');
    assert.equal(env.SSL_CERT_FILE, '/archive-test/ca.pem');
    assert.equal(env.TMPDIR, '/archive-test/tmp');
    assert.equal(env.TZ, 'UTC');
    assert.equal(env.PUBLIC_UMAMI_WEBSITE_ID, '');
    assert.equal(env.PUBLIC_UMAMI_SCRIPT_SRC, '');
    assert.equal(env.PUBLIC_UMAMI_DOMAINS, '');
    assert.equal(env.RAYON_NUM_THREADS, '1');
    for (const key of [
      'BASE_URL',
      'DOCS_ARCHIVE_BASE_URL',
      'DOCS_RELEASE_BASE_URL',
      'GITHUB_ACTIONS',
      'GITHUB_SHA',
    ]) {
      assert.equal(Object.hasOwn(env, key), false);
    }
  }
  assert.equal(calls.at(-1).env.DOCS_BASE, '/v/1.2.3/');
  assert.equal(calls.at(-1).env.DOCS_RELEASED_ARCHIVE, '');
  await assert.rejects(readFile(calls[0].env.HOME), { code: 'ENOENT' });
  assert.deepEqual(normalizationCalls, [
    resolve(root, '.release-docsets/v1.2.3/root'),
    resolve(root, 'dist/v/1.2.3'),
  ]);
  assert.deepEqual(seoCalls, [
    [
      resolve(root, '.release-docsets/v1.2.3/root'),
      { indexable: false },
    ],
    [resolve(root, 'dist/v/1.2.3'), { indexable: false }],
  ]);
  assert.deepEqual(analyticsCalls, [
    [resolve(root, '.release-docsets/v1.2.3/root'), { enabled: false }],
    [resolve(root, 'dist/v/1.2.3'), { enabled: false }],
  ]);
});

test('selected released archive builds at the canonical root with release discovery', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-released-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = [];
  const analyticsCalls = [];
  const rootOutDir = resolve(root, '.release-docsets/v1.2.3/root');
  const stalePagefind = resolve(rootOutDir, 'pagefind/stale-index');

  await buildDocsetArchive(archivedDocset, {
    docsRoot: root,
    indexable: true,
    stageGeneratedArtifacts: async () => async () => {},
    runCommand: async (command, args, env) => {
      calls.push({ command, args, env });
      if (command === 'npx' && args.includes(rootOutDir)) {
        await mkdir(dirname(stalePagefind), { recursive: true });
        await writeFile(stalePagefind, 'filesystem-ordered index');
      }
      if (command === 'node') {
        await assert.rejects(readFile(stalePagefind), { code: 'ENOENT' });
      }
    },
    applySeo: async () => {},
    verifyAnalytics: async (path, options) => {
      analyticsCalls.push([path, options]);
    },
  });

  assert.equal(calls.length, 5);
  assert.deepEqual(
    [calls[3].command, calls[3].args],
    [
      'node',
      [
        'scripts/build-production-search.mjs',
        '--dist-root',
        rootOutDir,
      ],
    ],
  );
  for (const { env } of calls.slice(0, -1)) {
    assert.equal(env.DOCS_BASE, '/');
    assert.equal(env.DOCS_RELEASED_ARCHIVE, 'true');
  }
  assert.equal(calls.at(-1).env.DOCS_BASE, '/v/1.2.3/');
  assert.equal(calls.at(-1).env.DOCS_RELEASED_ARCHIVE, '');
  assert.deepEqual(analyticsCalls, [
    [rootOutDir, { enabled: true }],
    [resolve(root, 'dist/v/1.2.3'), { enabled: false }],
  ]);
});

test('archive output uses pinned generated artifacts and restores current files', async (t) => {
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-ref-'));
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  const siteRoot = resolve(repoRoot, 'docs/site');
  const pinnedPath = `${stagedArtifactFixtures[0]}/pinned.json`;
  const absentAtReleasePath = `${stagedArtifactFixtures[0]}/current-only.json`;
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
      stageGeneratedArtifacts: (docset, options) =>
        stagePinnedGeneratedArtifacts(docset, {
          ...options,
          artifacts: stagedArtifactFixtures,
        }),
      runCommand: async (_command, args) => {
        if (args.includes('build')) {
          await writeFile(outputCapture, await readFile(pinnedLocal));
          await assert.rejects(readFile(absentAtReleaseLocal), { code: 'ENOENT' });
        }
      },
      applySeo: async () => {},
      verifyAnalytics: async () => {},
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
