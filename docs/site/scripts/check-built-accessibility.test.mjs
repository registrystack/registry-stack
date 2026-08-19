import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const checker = resolve(here, 'check-built-accessibility.mjs');
const criticalPaths = [
  'index.html',
  'start/when-to-use/index.html',
  'tutorials/publish-governed-sqlite-registry/index.html',
  'verify/index.html',
  'generated-artifacts/index.html',
  'operate/index.html',
];

function page(overrides = '') {
  return `<!doctype html><html lang="en"><body><main><h1>Page title</h1><img src="logo.svg" alt="Logo"><a href="/next">Next</a><button>Continue</button><input id="email"><label for="email">Email</label></main>${overrides}</body></html>`;
}

function fixture(t, html) {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-built-a11y-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const path of criticalPaths) {
    const file = resolve(root, 'dist', path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, html);
  }
  return root;
}

function run(root) {
  return spawnSync(process.execPath, [checker], { cwd: root, encoding: 'utf8' });
}

test('accepts accessible built HTML and identifies itself as a static gate', (t) => {
  const result = run(fixture(t, page('<img src="decoration.svg" alt="">')));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Built static critical-path accessibility gate passed/);
});

for (const [name, html, expected] of [
  ['missing html lang', page().replace(' lang="en"', ''), /html lang/],
  ['multiple main landmarks', page('<main><h1>Second</h1></main>'), /exactly one main landmark/],
  ['multiple h1 elements in main', page().replace('</main>', '<h1>Second</h1></main>'), /exactly one h1 in main/],
  ['meaningful image without alt text', page().replace(' alt="Logo"', ''), /image is missing nonempty alt text/],
  ['unnamed interactive control', page().replace('<button>Continue</button>', '<button></button>'), /interactive <button> is missing an accessible name/],
  ['positive tabindex', page().replace('<a href="/next">', '<a tabindex="1" href="/next">'), /positive tabindex/],
  ['duplicate IDs', page().replace('<input id="email">', '<input id="email"><span id="email"></span>'), /duplicate id/],
]) {
  test(`rejects ${name}`, (t) => {
    const result = run(fixture(t, html));
    assert.equal(result.status, 1);
    assert.match(result.stderr, expected);
  });
}

test('ignores a violating page outside the closed critical-path list', (t) => {
  const root = fixture(t, page());
  const file = resolve(root, 'dist', 'unrelated', 'index.html');
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, '<html><body><button></button></body></html>');
  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
});
