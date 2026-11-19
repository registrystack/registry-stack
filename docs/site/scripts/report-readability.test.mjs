import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';

import { formatReport, measure, proseBlocks, reportReadability, sentences, wordCount } from './report-readability.mjs';

test('proseBlocks drops frontmatter, imports, comments, JSX, code and URLs', () => {
  const source = [
    '---',
    'title: A page. With; punctuation, here',
    '---',
    "import Card from '../../components/Card.astro';",
    '',
    '{/* a comment; with a semicolon */}',
    '',
    '# A heading, not prose',
    '',
    'Run `a; b, c` first. See [the guide](https://example.com/a;b) now.',
    '',
    '<Card title="x; y">',
    '',
    '```sh',
    'echo a; echo b',
    '```',
    '',
    '- First item, kept.',
    '',
    '| Name | Note |',
    '| --- | --- |',
    '| One | A cell. |',
  ].join('\n');
  assert.deepEqual(proseBlocks(source), [
    'Run first. See the guide now.',
    'First item, kept.',
    'Name',
    'Note',
    'One',
    'A cell.',
  ]);
});

test('sentences split at a full stop before a capital and keep abbreviations whole', () => {
  assert.deepEqual(sentences('One two. Three four? Five six'), ['One two.', 'Three four?', 'Five six']);
  assert.deepEqual(sentences('Use a tool, for example e.g. Vale. Then stop.'), [
    'Use a tool, for example e.g. Vale.',
    'Then stop.',
  ]);
  assert.deepEqual(sentences('Version 1.2 is out. Next.'), ['Version 1.2 is out.', 'Next.']);
});

test('wordCount counts hyphenated words once', () => {
  assert.equal(wordCount('A well-known, short sentence.'), 4);
});

test('measure counts long sentences, semicolons and commas', () => {
  const long = Array.from({ length: 26 }, (_, i) => `W${i}`).join(' ');
  const result = measure(`Short one, with a comma; and a semicolon. ${long}.\n`);
  assert.deepEqual(result, { sentences: 2, long: 1, semicolons: 1, commas: 1 });
});

test('a sentence of exactly 25 words is not long', () => {
  const edge = Array.from({ length: 25 }, (_, i) => `w${i}`).join(' ');
  assert.equal(measure(`${edge}.`).long, 0);
});

test('reportReadability reads md and mdx pages and totals them', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'registry-readability-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const docsDir = resolve(root, 'docs');
  for (const [path, body] of [
    ['a.md', 'One. Two; three.\n'],
    ['nested/b.mdx', '---\ntitle: B\n---\n\nFour, five.\n'],
  ]) {
    mkdirSync(dirname(resolve(docsDir, path)), { recursive: true });
    writeFileSync(resolve(docsDir, path), body);
  }
  const report = reportReadability({ docsDir });
  assert.deepEqual(report.pages.map((page) => page.page), ['a.md', 'nested/b.mdx']);
  assert.deepEqual(report.total, { sentences: 3, long: 0, semicolons: 1, commas: 1 });
  assert.match(formatReport(report), /TOTAL \(2 pages\)/);
});
