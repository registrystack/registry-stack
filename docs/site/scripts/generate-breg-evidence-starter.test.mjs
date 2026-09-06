import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
