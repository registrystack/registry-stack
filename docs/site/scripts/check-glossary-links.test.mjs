import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';

import { checkGlossaryLinks, glossaryAnchors, glossaryTerms } from './check-glossary-links.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'registry-glossary-links-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return resolve(root, 'docs');
}

function write(docsDir, relPath, content) {
  const target = resolve(docsDir, relPath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

const glossary = (entries) =>
  `---\ntitle: Glossary\n---\n\n<dl>\n${entries.join('\n')}\n</dl>\n`;

const term = (id, name, body = 'Defined.') =>
  `  <dt${id === undefined ? '' : ` id="${id}"`}>${name}</dt>\n  <dd>${body}</dd>`;

test('glossaryTerms reads each dt with the id it carries', () => {
  const terms = glossaryTerms(glossary([term('record-type', 'Record type'), term(undefined, 'DCAT')]));
  assert.deepEqual(terms, [
    { term: 'Record type', id: 'record-type' },
    { term: 'DCAT', id: undefined },
  ]);
});

test('glossaryAnchors reads links in Markdown and HTML, and in-page anchors only on the glossary', () => {
  const page =
    'A [Record type](../../reference/glossary/#record-type) and <a href="/reference/glossary/#action">an Action</a>.\n' +
    'See <a href="#proposal">below</a>.\n';
  assert.deepEqual(glossaryAnchors(page), ['record-type', 'action']);
  assert.deepEqual(glossaryAnchors(page, { isGlossary: true }), ['record-type', 'action', 'proposal']);
});

test('passes when every term has an id and is linked from another page', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'reference/glossary.mdx', glossary([term('record-type', 'Record type'), term('action', 'Action')]));
  write(docsDir, 'tutorials/first.mdx', '---\ntitle: First\n---\n\nA [Record type](../../reference/glossary/#record-type).\n');
  write(docsDir, 'configure/access.mdx', '---\ntitle: Access\n---\n\nAn [Action](../../reference/glossary/#action).\n');
  const result = checkGlossaryLinks({ docsDir });
  assert.deepEqual(result.errors, []);
  assert.equal(result.terms, 2);
  assert.equal(result.links, 2);
});

test('fails on a term without an id', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'reference/glossary.mdx', glossary([term(undefined, 'DCAT')]));
  const result = checkGlossaryLinks({ docsDir });
  assert.deepEqual(result.errors, ['reference/glossary.mdx: "DCAT" has no id, so no page can link it']);
});

test('fails on a term no page links, and a link from the glossary itself does not count', (t) => {
  const docsDir = fixture(t);
  write(
    docsDir,
    'reference/glossary.mdx',
    glossary([term('record-type', 'Record type'), term('action', 'Action', 'Changes a <a href="#record-type">Record type</a>.')]),
  );
  write(docsDir, 'tutorials/first.mdx', '---\ntitle: First\n---\n\nAn [Action](../../reference/glossary/#action).\n');
  const result = checkGlossaryLinks({ docsDir });
  assert.deepEqual(result.errors, [
    'reference/glossary.mdx: "record-type" is linked from no page; link it or delete it',
  ]);
});

test('fails on a link to a term the glossary does not define', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'reference/glossary.mdx', glossary([term('action', 'Action')]));
  write(
    docsDir,
    'tutorials/first.mdx',
    '---\ntitle: First\n---\n\nAn [Action](../../reference/glossary/#action) and a [Planner](../../reference/glossary/#planner).\n',
  );
  const result = checkGlossaryLinks({ docsDir });
  assert.deepEqual(result.errors, [
    'tutorials/first.mdx: links glossary term "planner", which the glossary does not define',
  ]);
});

test('fails on an id defined twice', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'reference/glossary.mdx', glossary([term('action', 'Action'), term('action', 'Action receipt')]));
  write(docsDir, 'tutorials/first.mdx', '---\ntitle: First\n---\n\nAn [Action](../../reference/glossary/#action).\n');
  const result = checkGlossaryLinks({ docsDir });
  assert.deepEqual(result.errors, ['reference/glossary.mdx: id "action" is defined twice']);
});
