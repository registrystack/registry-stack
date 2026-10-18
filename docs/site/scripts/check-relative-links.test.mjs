import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';

import { checkRelativeLinks, rootAbsoluteLinks } from './check-relative-links.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'registry-relative-links-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return resolve(root, 'docs');
}

function write(dir, relPath, content) {
  const target = resolve(dir, relPath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

test('rootAbsoluteLinks reports a root-absolute Markdown link with its line', () => {
  const links = rootAbsoluteLinks('Intro.\n\nSee [how it works](/explanation/how-evidence-works/).\n');
  assert.deepEqual(links, [{ line: 3, target: '/explanation/how-evidence-works/' }]);
});

test('rootAbsoluteLinks reports root-absolute images, definitions, and HTML hrefs', () => {
  const links = rootAbsoluteLinks(
    '![diagram](/images/flow.svg)\n\n' +
      '[ref]: /reference/glossary/\n\n' +
      '<a href="/reference/cli/">CLI</a>\n\n' +
      "<p>Read <a href='/tutorials/first/'>this</a>.</p>\n",
  );
  assert.deepEqual(links, [
    { line: 1, target: '/images/flow.svg' },
    { line: 3, target: '/reference/glossary/' },
    { line: 5, target: '/reference/cli/' },
    { line: 7, target: '/tutorials/first/' },
  ]);
});

test('rootAbsoluteLinks reads HTML href and src in every valid attribute spelling', () => {
  const links = rootAbsoluteLinks(
    '<a href = "/spaced/">spaced</a>\n\n' +
      '<A HREF="/upper/">upper</A>\n\n' +
      '<a href=/bare/>bare</a>\n\n' +
      '<img alt="flow" src="/images/flow.svg">\n',
  );
  assert.deepEqual(links, [
    { line: 1, target: '/spaced/' },
    { line: 3, target: '/upper/' },
    { line: 5, target: '/bare/' },
    { line: 7, target: '/images/flow.svg' },
  ]);
});

test('rootAbsoluteLinks ignores HTML comments but keeps the lines after them', () => {
  const links = rootAbsoluteLinks(
    '<div>\n<!-- <a href="/old/">old</a>\n<img src="/old.svg"> -->\n<a href="/kept/">kept</a>\n</div>\n',
  );
  assert.deepEqual(links, [{ line: 4, target: '/kept/' }]);
});

test('rootAbsoluteLinks does not read attributes that only end in href or src', () => {
  const links = rootAbsoluteLinks('<a data-href="/data/" href="../rel/">x</a> <img data-src="/lazy.svg" src="x.svg">\n');
  assert.deepEqual(links, []);
});

test('rootAbsoluteLinks ignores relative, external, protocol-relative, and fragment links', () => {
  const links = rootAbsoluteLinks(
    '[rel](../how-evidence-works/) [deep](../../explanation/x/#part) ' +
      '[ext](https://example.org/a/) [mail](mailto:a@example.org) ' +
      '[proto](//cdn.example.org/x.js) [frag](#section)\n\n' +
      '<a href="//cdn.example.org/">cdn</a> <a href="#top">top</a> <a href="../x/">x</a>\n',
  );
  assert.deepEqual(links, []);
});

test('rootAbsoluteLinks ignores code spans, fenced code, and frontmatter', () => {
  const links = rootAbsoluteLinks(
    '---\ntitle: Test\ndescription: "[not](/a/link/)"\n---\n\n' +
      'A `[not-a-link](/nope/)` code span.\n\n' +
      '```yaml\npath: /var/lib/x\nlink: [x](/nope/)\nhref="/nope/"\n```\n',
  );
  assert.deepEqual(links, []);
});

test('rootAbsoluteLinks keeps line numbers counted from the top of the file after frontmatter', () => {
  const links = rootAbsoluteLinks('---\ntitle: Test\n---\n\n[x](/a/)\n');
  assert.deepEqual(links, [{ line: 5, target: '/a/' }]);
});

test('checkRelativeLinks names the file, line, and target and asks for a relative link', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'configure/page.mdx', '---\ntitle: Test\n---\n\n[how](/explanation/how-evidence-works/#flow)\n');
  write(docsDir, 'tutorials/fine.md', '---\ntitle: Fine\n---\n\n[rel](../../explanation/how-evidence-works/)\n');

  const result = checkRelativeLinks({ docsDir });
  assert.equal(result.checked, 2);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /^configure\/page\.mdx:5: /);
  assert.match(result.errors[0], /\/explanation\/how-evidence-works\/#flow/);
  assert.match(result.errors[0], /relative link/);
});

test('checkRelativeLinks passes when every page links relatively', (t) => {
  const docsDir = fixture(t);
  write(docsDir, 'index.mdx', '---\ntitle: Home\n---\n\n[start](tutorials/first/)\n');

  assert.deepEqual(checkRelativeLinks({ docsDir }), { checked: 1, errors: [] });
});
