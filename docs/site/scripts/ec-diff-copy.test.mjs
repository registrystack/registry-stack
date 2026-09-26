import assert from 'node:assert/strict';
import test from 'node:test';

import { ExpressiveCode } from 'expressive-code';
import { toHtml } from 'hast-util-to-html';

import { pluginDiffCopy } from '../src/lib/ec-diff-copy.mjs';

async function copiedText(code, language, meta = '') {
  const ec = new ExpressiveCode({ plugins: [pluginDiffCopy()] });
  const { renderedGroupAst } = await ec.render({ code, language, meta });
  const [, dataCode] = toHtml(renderedGroupAst).match(/data-code="([^"]*)"/u);
  return dataCode.replaceAll('\x7F', '\n');
}

test('a diff block copies the file as it reads after the change', async () => {
  const code = '-a: [x]\n-b: [x]\n+a: [x, y]\n+b: [x, y]\n c: [x]';
  assert.equal(await copiedText(code, 'diff', 'lang="yaml"'), 'a: [x, y]\nb: [x, y]\nc: [x]');
});

test('a diff block keeps the indentation its lines have relative to each other', async () => {
  const code = ' fields:\n-  - {id: a}\n+  - {id: b}';
  assert.equal(await copiedText(code, 'diff'), 'fields:\n  - {id: b}');
});

test('a real diff file and any other language copy unchanged', async () => {
  const patch = '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b';
  assert.equal(await copiedText(patch, 'diff'), patch);
  assert.equal(await copiedText('-a\n+b', 'text'), '-a\n+b');
});

test('a line that only looks removed in another language copies unchanged', async () => {
  assert.equal(await copiedText('a\n-b', 'yaml', 'del={2}'), 'a\n-b');
});
