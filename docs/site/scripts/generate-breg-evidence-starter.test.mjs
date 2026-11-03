import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import * as tar from 'tar';
import { packageStarter, starterFiles } from './generate-breg-evidence-starter.mjs';

test('starter archive is repeatable and contains only reviewed inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'breg-starter-archive-'));
  try {
    for (const path of starterFiles) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), `reviewed ${path}\n`);
    }
    await mkdir(join(root, 'starter/secrets'));
    await writeFile(join(root, 'starter/secrets/private-key'), 'MUST NOT BE PACKAGED');
    await packageStarter(root, join(root, 'first.tar.gz'));
    await packageStarter(root, join(root, 'second.tar.gz'));
    assert.deepEqual(await readFile(join(root, 'first.tar.gz')), await readFile(join(root, 'second.tar.gz')));
    const entries = [];
    await tar.list({ file: join(root, 'first.tar.gz'), onReadEntry: entry => { entries.push(entry.path); entry.resume(); } });
    assert.deepEqual(entries, starterFiles);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// Exercise the maintained teaching project rather than manufacturing its inventory.
test('maintained starter archive includes the complete digest-pinned Adapter pack', async () => {
  const source = fileURLToPath(new URL('../../../products/breg/evidence/', import.meta.url));
  const root = await mkdtemp(join(tmpdir(), 'breg-starter-current-'));
  try {
    const output = join(root, 'starter.tar.gz');
    await packageStarter(source, output);
    const entries = new Map();
    await tar.list({ file: output, onReadEntry(entry) {
      const chunks = [];
      entry.on('data', chunk => chunks.push(chunk));
      entry.on('end', () => entries.set(entry.path, Buffer.concat(chunks)));
    } });
    const packRoot = 'offline-starter/adapter-packs/record-status-extract/';
    const pack = JSON.parse(entries.get(packRoot + 'pack.yaml').toString());
    const references = [];
    function collect(value) {
      if (!value || typeof value !== 'object') return;
      if (typeof value.path === 'string' && typeof value.digest === 'string') references.push(value);
      for (const child of Object.values(value)) collect(child);
    }
    collect(pack);
    assert.ok(references.length > 0);
    for (const reference of references) {
      const bytes = entries.get(packRoot + reference.path);
      assert.ok(bytes, 'archive omits governed asset: ' + reference.path);
      assert.equal('sha256:' + createHash('sha256').update(bytes).digest('hex'), reference.digest);
    }
    assert.ok(!entries.has('offline-starter/functions/record-status-extract.rhai'));
    assert.ok(!entries.has('offline-starter/queries/record-status.sql'));
    assert.ok([...entries.keys()].every(path => !path.includes('/.generated/') && !path.includes('/secrets/')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
