import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import {
  checkEvidenceAnchors,
  extractAnchors,
  parseAnchor,
  parseArguments,
} from './check-evidence-anchors.mjs';

function write(root, path, contents) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function repository(t) {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-evidence-anchors-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  write(root, 'crates/demo/src/lib.rs', 'pub fn verify_source_shape() {}\n');
  write(root, 'crates/demo/src/other.rs', 'pub const SOURCE_LIMIT: usize = 4;\n');
  write(root, 'crates/demo/tests/cli_contract.rs', 'fn covers_the_binary() {}\n');
  write(root, 'crates/demo/tests/language_server.rs', 'fn reports_editor_diagnostics() {}\n');
  return root;
}

function check(root, body, options = {}) {
  write(root, 'docs/site/src/content/docs/page.mdx', `---\ntitle: Page\n---\n\n${body}\n`);
  return checkEvidenceAnchors({ repoRoot: root, ...options });
}

test('extracts multi-line anchors with the line they start on', () => {
  const anchors = extractAnchors('one\ntwo\n{/* Evidence: crates/demo/src/lib.rs\n   holds it. */}\n');
  assert.equal(anchors.length, 1);
  assert.equal(anchors[0].line, 3);
  assert.match(anchors[0].body, /holds it\./);
});

test('accepts an anchor whose path exists and whose symbol resolves', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs, verify_source_shape(). */}');
  assert.deepEqual(result.errors, []);
  assert.equal(result.anchors, 1);
  assert.equal(result.paths, 1);
  assert.equal(result.symbols, 1);
});

test('reports a cited path that does not exist', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/absent.rs holds the check. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /^page\.mdx:5 /);
  assert.match(result.errors[0], /crates\/demo\/src\/absent\.rs/);
});

test('reports a line reference past the end of the file with the real line count', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs:40-42 holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:40-42/);
  assert.match(result.errors[0], /has 1 line\b/);
});

test('reports a symbol that appears in no cited path', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs, absent_test_name. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /absent_test_name/);
});

test('accepts a symbol that appears in the second of two cited paths', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs and crates/demo/src/other.rs define SOURCE_LIMIT. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('resolves a relative continuation against the crate root of the last full path', (t) => {
  const root = repository(t);
  const passing = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, verify_source_shape(); src/other.rs, SOURCE_LIMIT. */}',
  );
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.paths, 2);

  const failing = check(root, '{/* Evidence: crates/demo/src/lib.rs and src/absent.rs. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /crates\/demo\/src\/absent\.rs/);
});

test('resolves a bare sibling filename against the directory of the last full path', (t) => {
  const root = repository(t);
  const passing = check(
    root,
    '{/* Evidence: crates/demo/tests/cli_contract.rs and language_server.rs pin the surfaces. */}',
  );
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.paths, 2);

  const elsewhere = check(
    root,
    '{/* Evidence: crates/demo/tests/cli_contract.rs and other.rs, SOURCE_LIMIT. */}',
  );
  assert.deepEqual(elsewhere.errors, []);
  assert.equal(elsewhere.paths, 2);
});

test('leaves a bare filename the repository does not own out of the path check', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs accepts the values an adopter writes in origins.yaml. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
});

test('resolves a bare line range against the most recently cited path', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/other.rs:1, and :305-309. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/other\.rs:305-309/);
  assert.match(result.errors[0], /has 1 line\b/);
});

test('carries a bare line range past a filename the repository does not own', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/other.rs:1 writes origins.yaml, then :305-309. */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/other\.rs:305-309/);
});

test('does not treat a cited filename stem as a symbol', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/tests/cli_contract.rs pins the tooling inventory. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.symbols, 0);
});

test('skips prose words that carry a symbol shape but are on the allowlist', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs backs the JavaScript and TypeScript bindings. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.symbols, 0);
});

test('skips the symbol check when an anchor cites no path', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: the operator contract states does_not_own. */}');
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 0);
  assert.equal(result.symbols, 0);
});

test('reads a continuation with no full path before it against the docs site', (t) => {
  const root = repository(t);
  write(root, 'docs/site/src/data/projects.yaml', '- id: demo\n  does_not_own: []\n');
  const resolved = check(root, '{/* Evidence: src/data/projects.yaml, does_not_own. */}');
  assert.deepEqual(resolved.errors, []);
  assert.equal(resolved.paths, 1);

  const unresolved = check(root, '{/* Evidence: src/data/absent.yaml, does_not_own. */}');
  assert.deepEqual(unresolved.errors, []);
  assert.equal(unresolved.paths, 0);
});

test('counts line-range citations and fails them only under strict line references', (t) => {
  const root = repository(t);
  const relaxed = check(root, '{/* Evidence: crates/demo/src/lib.rs:1, verify_source_shape(). */}');
  assert.deepEqual(relaxed.errors, []);
  assert.equal(relaxed.lineRefs, 1);

  const strict = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs:1, verify_source_shape(). */}',
    { strictLineRefs: true },
  );
  assert.equal(strict.errors.length, 1);
  assert.match(strict.errors[0], /crates\/demo\/src\/lib\.rs:1/);
  assert.match(strict.errors[0], /line numbers drift/);
});

test('takes the last segment of a qualified symbol path', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/codes.rs', 'pub enum ProblemCode { AuditUnavailable }\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/codes.rs, ProblemCode::AuditUnavailable. */}',
  );
  assert.deepEqual(result.errors, []);
});

test('parses the strict line reference flag', () => {
  assert.deepEqual(parseArguments([]), { strictLineRefs: false });
  assert.deepEqual(parseArguments(['--strict-line-refs']), { strictLineRefs: true });
  assert.throws(() => parseArguments(['--unknown']), /usage: check-evidence-anchors\.mjs/);
});

test('parses citations and symbols without touching the filesystem', () => {
  const parsed = parseAnchor(
    'crates/demo/src/lib.rs:12-14 defines verify_source_shape() and SOURCE_LIMIT.',
  );
  assert.deepEqual(
    parsed.citations.map((citation) => citation.candidates[0]),
    ['crates/demo/src/lib.rs'],
  );
  assert.deepEqual(parsed.citations[0].start, 12);
  assert.deepEqual(parsed.citations[0].end, 14);
  assert.deepEqual(parsed.symbols, ['verify_source_shape', 'SOURCE_LIMIT']);
});
