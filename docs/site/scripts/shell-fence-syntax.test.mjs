import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const docsRoot = resolve(import.meta.dirname, '../src/content/docs');
const releaseExerciseReadme = resolve(import.meta.dirname, '../../../release/exercises/README.md');
const owningSourceDocs = [
  resolve(import.meta.dirname, '../../../crates/registry-relay/docs/ops.md'),
  resolve(import.meta.dirname, '../../../products/manifest/docs/validate-and-render.md'),
];

function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) return markdownFiles(path);
      return /\.(?:md|mdx)$/u.test(entry.name) ? [path] : [];
    })
    .toSorted();
}

function shellFences(path) {
  const markdown = readFileSync(path, 'utf8');
  return [...markdown.matchAll(/```(?:sh|bash)\n([\s\S]*?)```/gu)].map(
    (match, index) => ({
      index: index + 1,
      source: match[1],
    }),
  );
}

test('public documentation and release exercises contain POSIX-parseable shell fences', () => {
  const files = [...new Set([...markdownFiles(docsRoot), ...owningSourceDocs, releaseExerciseReadme])];
  let checked = 0;

  for (const path of files) {
    for (const fence of shellFences(path)) {
      checked += 1;
      const result = spawnSync('/bin/sh', ['-n'], {
        input: fence.source,
        encoding: 'utf8',
      });
      assert.equal(
        result.status,
        0,
        `${path} shell fence ${fence.index} must parse with /bin/sh -n:\n${result.stderr}`,
      );
    }
  }

  assert.ok(checked > 100, 'the syntax gate must cover the maintained shell-example surface');
});
