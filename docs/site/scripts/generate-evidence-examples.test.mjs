import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import * as tar from 'tar';
import { packageExamples, exampleFiles } from './generate-evidence-examples.mjs';

test('examples archive is repeatable and contains only reviewed inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'evidence-examples-archive-'));
  try {
    for (const path of exampleFiles) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), `reviewed ${path}\n`);
    }
    await mkdir(join(root, 'standalone/.generated/secrets'), { recursive: true });
    await writeFile(join(root, 'standalone/.generated/secrets/signing-key'), 'MUST NOT BE PACKAGED');
    await packageExamples(root, join(root, 'first.tar.gz'));
    await packageExamples(root, join(root, 'second.tar.gz'));
    assert.deepEqual(await readFile(join(root, 'first.tar.gz')), await readFile(join(root, 'second.tar.gz')));
    const entries = [];
    await tar.list({ file: join(root, 'first.tar.gz'), onReadEntry: entry => { entries.push(entry.path); entry.resume(); } });
    assert.deepEqual(entries, exampleFiles);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the inventory names every file of the maintained example projects', async () => {
  const site = join(dirname(new URL(import.meta.url).pathname), '..');
  const examples = join(site, '../../products/evidence/examples');
  const { readdir } = await import('node:fs/promises');
  const found = [];
  for (const project of ['fhir', 'standalone']) {
    for (const entry of await readdir(join(examples, project), { recursive: true, withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const relative = join(entry.parentPath, entry.name).slice(examples.length + 1);
      if (relative.includes('/.generated/') || relative.includes('/.evidence/')) continue;
      found.push(relative);
    }
  }
  assert.deepEqual(found.sort(), exampleFiles);
});
