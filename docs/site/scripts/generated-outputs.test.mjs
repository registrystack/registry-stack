import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '../../..');
const outputs = [
  'docs/site/src/content/docs/reference/cli',
  'docs/site/src/data/generated',
];

test('site reference outputs stay out of source control and PR diffs', () => {
  const tracked = execFileSync('git', ['ls-files', '--', ...outputs], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  assert.equal(tracked, '', 'commit the owning inputs instead of generated site references');
  for (const output of outputs) {
    const path = `${output}/future-output.json`;
    assert.equal(execFileSync('git', ['check-ignore', '--', path], {
      cwd: repoRoot,
      encoding: 'utf8',
    }).trim(), path);
  }
});

test('normal docs commands generate inputs before consuming them', async () => {
  const { scripts } = JSON.parse(await readFile(new URL('../package.json', import.meta.url)));
  for (const name of ['dev', 'build', 'build:dev', 'check:source', 'pretest']) {
    assert.equal(scripts[name].split(' && ')[0], 'npm run generate', name);
  }
  assert.equal(scripts.generate, 'npm run generate:source && npm run generate:archive');
});
