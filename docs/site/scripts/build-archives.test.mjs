import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';

import { archiveOutputDirectory } from './archive-cache.mjs';
import { buildArchivedDocsets, parseArgs } from './build-archives.mjs';

const inputDigest = 'a'.repeat(64);

function docset(id, path, ref) {
  return {
    id,
    label: id,
    path,
    status: 'archived',
    source: `registry-stack-${id}`,
    published_at: '2026-01-01',
    description: `${id} docs.`,
    products: { 'registry-stack': { version: id, ref } },
  };
}

function manifest() {
  return {
    current: 'latest',
    docsets: [
      {
        id: 'latest',
        label: 'Latest',
        path: '/',
        status: 'current',
        source: 'main',
        published_at: '2026-01-02',
        description: 'Current.',
        products: { 'registry-stack': { version: 'v1.2.0', ref: 'HEAD' } },
      },
      docset('v1.0.0', '/v/1.0.0/', '1'.repeat(40)),
      docset('v1.1.0', '/v/1.1.0/', '2'.repeat(40)),
    ],
  };
}

async function temporaryRoot(t) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-build-archives-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function write(path, body) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, body);
}

function harness(docsRoot) {
  const built = [];
  const commands = [];
  return {
    built,
    commands,
    archiveBuilder: async (selected) => {
      built.push(selected.id);
      const output = archiveOutputDirectory(docsRoot, selected);
      await write(
        resolve(output, 'index.html'),
        `<html id="${selected.id}"><a href="${selected.path}">self</a></html>\n`,
      );
    },
    commandRunner: async (command, args, env) => {
      commands.push({ command, args, docset: env.DOCS_DOCSET });
    },
  };
}

test('no-argument archive mode honors validated environment with a full default', () => {
  assert.deepEqual(parseArgs([], {}), { mode: 'full' });
  assert.deepEqual(parseArgs([], { ARCHIVE_MODE: 'incremental' }), {
    mode: 'incremental',
  });
  assert.deepEqual(parseArgs(['--mode', 'full'], { ARCHIVE_MODE: 'incremental' }), {
    mode: 'full',
  });
  assert.throws(
    () => parseArgs([], { ARCHIVE_MODE: 'partial' }),
    /ARCHIVE_MODE must be incremental or full/,
  );
});

test('incremental mode rebuilds misses then restores exact cache entries', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const first = harness(docsRoot);
  const firstStats = await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'incremental',
    inputDigest,
    archiveBuilder: first.archiveBuilder,
    commandRunner: first.commandRunner,
  });
  assert.deepEqual(firstStats.built, ['v1.0.0', 'v1.1.0']);
  assert.deepEqual(firstStats.restored, []);
  assert.deepEqual(first.commands.map((entry) => entry.docset), ['latest']);

  await rm(resolve(docsRoot, 'dist/v'), { recursive: true, force: true });
  const second = harness(docsRoot);
  const secondStats = await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'incremental',
    inputDigest,
    archiveBuilder: second.archiveBuilder,
    commandRunner: second.commandRunner,
  });

  assert.deepEqual(secondStats.built, []);
  assert.deepEqual(secondStats.restored, ['v1.0.0', 'v1.1.0']);
  assert.deepEqual(second.built, []);
  assert.match(
    await readFile(resolve(docsRoot, 'dist/v/1.0.0/index.html'), 'utf8'),
    /v1.0.0/,
  );
});

test('incremental mode rebuilds a cache entry whose output digest is corrupt', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const first = harness(docsRoot);
  await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'incremental',
    inputDigest,
    archiveBuilder: first.archiveBuilder,
    commandRunner: first.commandRunner,
  });
  const cacheRoot = resolve(docsRoot, '.archive-build-cache');
  const entries = (await import('node:fs/promises')).readdir(cacheRoot);
  const [entry] = (await entries).sort();
  await write(resolve(cacheRoot, entry, 'site/index.html'), 'corrupt\n');
  const second = harness(docsRoot);

  const stats = await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'incremental',
    inputDigest,
    archiveBuilder: second.archiveBuilder,
    commandRunner: second.commandRunner,
  });

  assert.equal(stats.built.length, 1);
  assert.equal(stats.restored.length, 1);
});

test('full mode ignores an existing cache and rebuilds every archive', async (t) => {
  const docsRoot = await temporaryRoot(t);
  const cached = harness(docsRoot);
  await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'incremental',
    inputDigest,
    archiveBuilder: cached.archiveBuilder,
    commandRunner: cached.commandRunner,
  });
  const full = harness(docsRoot);

  const stats = await buildArchivedDocsets({
    docsRoot,
    docsets: manifest(),
    mode: 'full',
    inputDigest,
    archiveBuilder: full.archiveBuilder,
    commandRunner: full.commandRunner,
  });

  assert.deepEqual(stats.restored, []);
  assert.deepEqual(stats.built, ['v1.0.0', 'v1.1.0']);
  assert.deepEqual(full.built, ['v1.0.0', 'v1.1.0']);
  assert.deepEqual(full.commands.map((entry) => entry.docset), ['latest']);
});
