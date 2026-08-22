import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

import {
  REPOSITORY_ROOTS,
  checkEvidenceAnchors,
  extractAnchors,
  extractSymbols,
  parseAnchor,
  parseArguments,
} from './check-evidence-anchors.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

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

test('reports a citation whose path climbs out of the repository', (t) => {
  const root = repository(t);
  const outside = resolve(root, '..', 'registry-evidence-anchors-outside.txt');
  writeFileSync(outside, 'held outside the repository\n');
  t.after(() => rmSync(outside, { force: true }));
  const result = check(
    root,
    '{/* Evidence: crates/../../registry-evidence-anchors-outside.txt holds it. */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/\.\.\/\.\.\/registry-evidence-anchors-outside\.txt/);
  assert.match(result.errors[0], /leaves the repository/);
});

test('reports a citation whose real path leaves the repository through a symlink', (t) => {
  const root = repository(t);
  const outside = resolve(root, '..', 'registry-evidence-anchors-linked.rs');
  writeFileSync(outside, 'pub fn held_outside_the_repository() {}\n');
  t.after(() => rmSync(outside, { force: true }));
  symlinkSync(outside, resolve(root, 'crates/demo/src/linked.rs'));
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/linked.rs, held_outside_the_repository(). */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/linked\.rs/);
  assert.match(result.errors[0], /leaves the repository/);
});

test('refuses a repository-root file a symlink leads out of', (t) => {
  const root = repository(t);
  const outside = resolve(root, '..', 'registry-evidence-anchors-root-linked.toml');
  writeFileSync(outside, '[bans]\nmultiple_versions = "deny"\n');
  t.after(() => rmSync(outside, { force: true }));
  symlinkSync(outside, resolve(root, 'deny.toml'));
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, and deny.toml, multiple_versions. */}',
  );
  assert.equal(result.errors.length, 2);
  assert.match(result.errors[0], /deny\.toml/);
  assert.match(result.errors[0], /leaves the repository/);
  // The file outside the checkout is never read, so the symbol it holds stays unfound.
  assert.match(result.errors[1], /multiple_versions/);
});

test('resolves a sibling beside its cited path though the root file of that name escapes', (t) => {
  const root = repository(t);
  const outside = resolve(root, '..', 'registry-evidence-anchors-root-shadow.rs');
  writeFileSync(outside, 'pub const SOURCE_LIMIT: usize = 9;\n');
  t.after(() => rmSync(outside, { force: true }));
  symlinkSync(outside, resolve(root, 'other.rs'));
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, and other.rs, SOURCE_LIMIT. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('reports a line reference past the end of the file with the real line count', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs:40-42 holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:40-42/);
  assert.match(result.errors[0], /has 1 line\b/);
});

test('reports a line reference that starts before the first line', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs:0 holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:0/);
  assert.match(result.errors[0], /starts at line 1/);
});

test('reports a line range that ends before it starts', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wide.rs', 'one\ntwo\nthree\nfour\nfive\nsix\n');
  const result = check(root, '{/* Evidence: crates/demo/src/wide.rs:5-3 holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/wide\.rs:5-3/);
  assert.match(result.errors[0], /ends at or after its start/);
});

test('reports a bare line range that ends before it starts', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wide.rs', 'one\ntwo\nthree\nfour\nfive\nsix\n');
  const result = check(root, '{/* Evidence: crates/demo/src/wide.rs:1, and :5-3. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/wide\.rs:5-3/);
  assert.match(result.errors[0], /ends at or after its start/);
});

test('reports a line suffix the anchor cut short', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wide.rs', 'one\ntwo\nthree\nfour\nfive\nsix\n');
  const result = check(root, '{/* Evidence: crates/demo/src/wide.rs:5- holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/wide\.rs:5-/);
  assert.match(result.errors[0], /a line or a first and last line/);
  assert.equal(result.lineRefs, 1);
});

test('reports a line reference the anchor spelled with something other than a number', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs:abc holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:abc/);
  assert.match(result.errors[0], /a line or a first and last line/);
  assert.equal(result.lineRefs, 1);
});

test('reports a line reference the anchor ran into the word behind it', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs:1foo holds it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:1foo/);
  assert.match(result.errors[0], /a line or a first and last line/);
});

test('leaves a colon the prose writes after a cited path alone', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs: it holds verify_source_shape(). */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
  assert.equal(result.lineRefs, 0);
});

test('leaves a well-formed line reference the prose punctuates alone', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wide.rs', 'one\ntwo\nthree\nfour\nfive\nsix\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/wide.rs:1-2, crates/demo/src/wide.rs:3-4; crates/demo/src/wide.rs:5-6. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.lineRefs, 3);
});

test('leaves a hyphen the prose carries after a line reference alone', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wide.rs', 'one\ntwo\nthree\nfour\nfive\nsix\n');
  const result = check(root, '{/* Evidence: crates/demo/src/wide.rs:5 - the middle of it. */}');
  assert.deepEqual(result.errors, []);
});

test('reports a symbol that appears in no cited path', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/lib.rs, absent_test_name. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /absent_test_name/);
});

test('checks a lower camel case symbol against the cited paths', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/wire.rs', 'pub struct Body { packageRevision: u32 }\n');
  const passing = check(root, '{/* Evidence: crates/demo/src/wire.rs carries packageRevision. */}');
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.symbols, 1);

  const failing = check(root, '{/* Evidence: crates/demo/src/wire.rs carries packageRevison. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /packageRevison/);
});

test('checks an all-uppercase wire value against the cited paths', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/algorithms.rs', 'const ALLOWED: [&str; 2] = ["ES256", "RS256"];\n');
  const passing = check(root, '{/* Evidence: crates/demo/src/algorithms.rs allows ES256. */}');
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.symbols, 1);

  const failing = check(root, '{/* Evidence: crates/demo/src/algorithms.rs allows ES265. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /ES265/);
});

test('leaves a version word and an acronym the prose spells in capitals unchecked', () => {
  assert.deepEqual(extractSymbols('the V2 registry contract serves JSON over HTTP'), []);
  assert.deepEqual(extractSymbols('the profile allows ES256 and RS256'), ['ES256', 'RS256']);
});

test('checks an upper camel case name that runs an initialism into it', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/token.rs', 'pub enum OAuthErrorCode {\n    InvalidClient,\n}\n');
  const passing = check(root, '{/* Evidence: crates/demo/src/token.rs, OAuthErrorCode. */}');
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.symbols, 1);

  const failing = check(root, '{/* Evidence: crates/demo/src/token.rs, OAuthErrorKind. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /OAuthErrorKind/);
});

test('leaves an acronym the prose spells with one lower-case run unchecked', () => {
  assert.deepEqual(extractSymbols('the OpenAPI description of the SQLite source'), []);
  assert.deepEqual(extractSymbols('the SDMX profile, the JWKS endpoint, and EdDSA'), []);
  assert.deepEqual(extractSymbols('the OpenCRVS demo signs with SHA'), []);
  assert.deepEqual(extractSymbols('it reads HTTPRedirectHandler'), ['HTTPRedirectHandler']);
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

test('expands a brace list into one citation per entry', () => {
  const parsed = parseAnchor('crates/demo/src/{lib,other}.rs carry it.');
  assert.deepEqual(
    parsed.citations.map((citation) => [citation.form, citation.candidates[0]]),
    [
      ['full', 'crates/demo/src/lib.rs'],
      ['full', 'crates/demo/src/other.rs'],
    ],
  );
  assert.ok(parsed.citations.every((citation) => citation.reportMissing));
});

test('reports the entry of a brace list that does not exist', (t) => {
  const root = repository(t);
  const passing = check(root, '{/* Evidence: crates/demo/src/{lib,other}.rs carry it. */}');
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.paths, 2);

  const failing = check(root, '{/* Evidence: crates/demo/src/{lib,absent}.rs carry it. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /crates\/demo\/src\/absent\.rs/);
  assert.match(failing.errors[0], /does not exist/);
  assert.equal(failing.paths, 2);
});

test('expands a brace list a sentence ends on', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: the surfaces sit in crates/demo/src/{lib,other}.rs. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('carries a line reference into every entry of a brace list', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/{lib,other}.rs:40 carry it. */}');
  assert.equal(result.errors.length, 2);
  assert.match(result.errors[0], /crates\/demo\/src\/lib\.rs:40/);
  assert.match(result.errors[1], /crates\/demo\/src\/other\.rs:40/);
  assert.equal(result.lineRefs, 2);
});

test('expands a brace list a continuation carries', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, then src/{other,absent}.rs. */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/absent\.rs/);
  assert.equal(result.paths, 3);
});

test('leaves a brace group the prose writes out of the citations', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs returns { claim, allowed }. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
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

test('resolves a bare sibling filename against the most recently cited path', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/handler.rs', 'fn prepares_the_request() {}\n');
  write(root, 'crates/demo/tests/handler.rs', 'fn covers_the_handler() {}\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs; tests/cli_contract.rs; handler.rs, covers_the_handler. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 3);
});

test('leaves the anchor where it is when one bare sibling filename follows another', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo holds cli_contract.rs and language_server.rs. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 3);
});

test('resolves a bare sibling filename against the repository root', (t) => {
  const root = repository(t);
  write(root, 'deny.toml', '[bans]\nmultiple_versions = "deny"\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, and deny.toml, multiple_versions. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('prefers a file inside the cited unit over the one at the repository root', (t) => {
  const root = repository(t);
  write(root, 'README.md', 'The workspace README names workspace_wide_only.\n');
  write(root, 'crates/demo/reference/README.md', 'The crate README names crate_local_only.\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, and README.md, crate_local_only. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('reads a bare script filename beside the path it sits with', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/scripts/extract.rhai', 'let extracted = source_value;\n');
  write(root, 'crates/demo/scripts/prepare.rhai', 'let request_url = source_base;\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/scripts/extract.rhai and prepare.rhai, request_url. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
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

test('reports a bare sibling Rust file no cited unit holds', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/tests/cli_contract.rs and absent.rs pin the surfaces. */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/tests\/absent\.rs, which does not exist/);
  assert.equal(result.paths, 2);
});

test('reports a bare Rust filename that opens an anchor and names nothing', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: absent.rs, and crates/demo/src/lib.rs reads it. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /absent\.rs, which does not exist/);
});

test('resolves a bare child directory against the directory cited before it', (t) => {
  const root = repository(t);
  write(root, 'products/demo/projects/protected-read/README.md', 'It names bounded_read_shape.\n');
  const result = check(
    root,
    '{/* Evidence: products/demo/projects/ then protected-read/, bounded_read_shape. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('reports a bare child directory the cited directory does not hold', (t) => {
  const root = repository(t);
  write(root, 'products/demo/projects/protected-read/README.md', 'It names bounded_read_shape.\n');
  const result = check(root, '{/* Evidence: products/demo/projects/ then renamed-read/. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /products\/demo\/projects\/renamed-read/);
});

test('reads one bare child directory against the last, so a chain resolves', (t) => {
  const root = repository(t);
  write(root, 'products/demo/projects/protected-read/governed/registry.yaml', 'id: demo\n');
  const result = check(
    root,
    '{/* Evidence: products/demo/projects/ protected-read/ governed/ holds it. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 3);
});

test('reports a line reference the anchor continued with a dot', (t) => {
  const root = repository(t);
  const continued = check(root, '{/* Evidence: crates/demo/src/lib.rs:1.5 holds it. */}');
  assert.equal(continued.errors.length, 1);
  assert.match(continued.errors[0], /a line reference names a line or a first and last line/);

  // A full stop that ends the sentence is punctuation the prose wrote, not a reference the
  // anchor carried on, so it leaves the line it does name alone.
  const ended = check(root, '{/* Evidence: crates/demo/src/lib.rs:1. It holds the shape. */}');
  assert.deepEqual(ended.errors, []);
  assert.equal(ended.lineRefs, 1);
});

test('reads a JavaScript or TypeScript sibling as a citation, not a dotted key path', (t) => {
  const root = repository(t);
  write(root, 'editors/vscode/src/extension.ts', 'export const activateEditor = 1;\n');
  write(root, 'editors/vscode/src/projectRoot.ts', 'export const rootOf = 2;\n');
  write(root, 'crates/demo/client.js', 'export const requestShape = 3;\n');
  write(root, 'crates/demo/index.js', 'export const entryShape = 4;\n');
  // Read as a dotted key path instead, the name would demand a symbol spelled `ts`.
  assert.deepEqual(
    parseAnchor('editors/vscode/src/extension.ts and projectRoot.ts hold it.').symbols,
    [],
  );
  const typescript = check(
    root,
    '{/* Evidence: editors/vscode/src/extension.ts and projectRoot.ts, rootOf. */}',
  );
  assert.deepEqual(typescript.errors, []);
  assert.equal(typescript.paths, 2);

  const javascript = check(root, '{/* Evidence: crates/demo/client.js and index.js, entryShape. */}');
  assert.deepEqual(javascript.errors, []);
  assert.equal(javascript.paths, 2);
});

test('reads an extensionless script under a cited directory', (t) => {
  const root = repository(t);
  write(
    root,
    'release/scripts/registry-release',
    '#!/usr/bin/env python3\nartifact_inventory_errors = []\n',
  );
  const result = check(root, '{/* Evidence: release/scripts/ reports artifact_inventory_errors. */}');
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
  assert.equal(result.symbols, 1);
});

test('reads a bare child against the directory the anchor resolved, not the first guess', (t) => {
  const root = repository(t);
  write(root, 'schemas/registry/profile/registry.schema.json', '{ "title": "profile_form" }\n');
  // The shared root resolves at the repository, the third candidate, because the crate
  // cited before it keeps no schemas/ of its own. A child read against the first candidate
  // instead would find no directory there and drop the citation unchecked.
  const held = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, then schemas/registry/ profile/, profile_form. */}',
  );
  assert.deepEqual(held.errors, []);
  assert.equal(held.paths, 3);

  const renamed = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, then schemas/registry/ absent/. */}',
  );
  assert.equal(renamed.errors.length, 1);
  assert.match(renamed.errors[0], /schemas\/registry\/absent/);
});

test('reads a trailing-slash name that follows an extensionless file as prose', (t) => {
  const root = repository(t);
  write(root, 'release/scripts/registry-release', '#!/usr/bin/env python3\nprint("pack")\n');
  const result = check(
    root,
    '{/* Evidence: release/scripts/registry-release writes output/ and manifests/. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
});

test('continues a bare child under an extensionless directory the repository holds', (t) => {
  const root = repository(t);
  write(root, 'products/demo/projects/protected-read/README.md', 'It names bounded_read_shape.\n');
  const result = check(
    root,
    '{/* Evidence: products/demo/projects then protected-read/, bounded_read_shape. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('leaves a trailing-slash name that follows a cited file out of the citations', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs writes governed/ and generated/ into the package. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
});

test('leaves a slash the prose writes out of the citations', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs decides read and/or write at https://example.org/. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
});

test('resolves a bare filename that opens an anchor against the repository root', (t) => {
  const root = repository(t);
  write(root, 'deny.toml', '[bans]\nmultiple_versions = "deny"\n');
  const result = check(
    root,
    '{/* Evidence: deny.toml, multiple_versions, and crates/demo/src/lib.rs. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 2);
});

test('searches the tree for a bare filename that opens an anchor', (t) => {
  const root = repository(t);
  write(root, 'products/demo/reference/CONFIG.md', 'The reference names bundle_signing_key.\n');
  const result = check(root, '{/* Evidence: CONFIG.md, bundle_signing_key. */}');
  assert.deepEqual(result.errors, []);
  assert.equal(result.paths, 1);
});

test('leaves a bare filename that opens an anchor and names nothing out of the path check', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: origins.yaml is the adopter file, crates/demo/src/lib.rs reads it. */}',
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

test('reports an anchor that cites no path at all', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: the operator contract states does_not_own. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /^page\.mdx:5 /);
  assert.match(result.errors[0], /cites no path in this repository/);
  assert.equal(result.paths, 0);
  assert.equal(result.symbols, 0);
});

test('reports an anchor none of whose citations resolve', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: origins.yaml carries the source_kind an adopter sets. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /resolves none of the paths it cites/);
  assert.equal(result.paths, 0);
  assert.equal(result.symbols, 0);
});

test('leaves an anchor whose citations were reported to report itself again', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: crates/demo/src/absent.rs holds does_not_own. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /crates\/demo\/src\/absent\.rs/);
  assert.match(result.errors[0], /does not exist/);
});

test('reads a continuation with no full path before it against the docs site', (t) => {
  const root = repository(t);
  write(root, 'docs/site/src/data/projects.yaml', '- id: demo\n  does_not_own: []\n');
  const resolved = check(root, '{/* Evidence: src/data/projects.yaml, does_not_own. */}');
  assert.deepEqual(resolved.errors, []);
  assert.equal(resolved.paths, 1);
});

test('reports a continuation the docs site does not hold', (t) => {
  const root = repository(t);
  const result = check(root, '{/* Evidence: src/data/absent.yaml, does_not_own. */}');
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /docs\/site\/src\/data\/absent\.yaml/);
  assert.match(result.errors[0], /does not exist/);
  assert.equal(result.paths, 1);
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

test('checks every segment of a qualified symbol path that carries a symbol shape', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/codes.rs', 'pub enum ProblemCode { AuditUnavailable }\n');
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/codes.rs, ProblmCode::AuditUnavailable. */}',
  );
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /ProblmCode/);
  assert.equal(result.symbols, 2);
});

test('leaves the segments of a qualified path that name no symbol unchecked', () => {
  assert.deepEqual(extractSymbols('std::fs::read_to_string reads it.'), ['read_to_string']);
  assert.deepEqual(extractSymbols('ProblemCode::AuditUnavailable is returned.'), [
    'ProblemCode',
    'AuditUnavailable',
  ]);
});

test('checks every segment of a dotted key path one segment gives a shape', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/keys.rs', 'const KEY: &str = "transport_absences.credentials";\n');
  const passing = check(
    root,
    '{/* Evidence: crates/demo/src/keys.rs holds transport_absences.credentials. */}',
  );
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.symbols, 2);

  const failing = check(
    root,
    '{/* Evidence: crates/demo/src/keys.rs holds transport_absences.credntials. */}',
  );
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /credntials/);
});

test('leaves a dotted token no segment gives a shape out of the symbols', (t) => {
  const root = repository(t);
  const result = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs is served from id.registrystack.org. */}',
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.symbols, 0);
});

test('reads a dotted key path segment by segment and a domain name not at all', () => {
  assert.deepEqual(extractSymbols('the request sets transport_absences.credentials'), [
    'transport_absences',
    'credentials',
  ]);
  assert.deepEqual(extractSymbols('published at id.registrystack.org since v0.9.0'), []);
});

test('skips the wildcard segment of a dotted key path', () => {
  assert.deepEqual(extractSymbols('sources.*.authentication.source_kind names it'), [
    'sources',
    'authentication',
    'source_kind',
  ]);
});

test('reads an identifier spelled with empty parentheses as a symbol', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/app.rs', 'pub fn router() -> Router {}\n');
  const passing = check(root, '{/* Evidence: crates/demo/src/app.rs builds router(). */}');
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.symbols, 1);

  const failing = check(root, '{/* Evidence: crates/demo/src/app.rs builds routes(). */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /routes/);
});

test('leaves a word the prose follows with a parenthesis out of the symbols', () => {
  assert.deepEqual(extractSymbols('the check (see below) and the note(s) it carries'), []);
  assert.deepEqual(extractSymbols('router(), prepare()'), ['router', 'prepare']);
});

test('keeps ordinary prose words out of the symbols a lower camel case name is read from', () => {
  assert.deepEqual(extractSymbols('the source an evidence deployment reads is packageRevision.'), [
    'packageRevision',
  ]);
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

test('root CI runs the anchor check on every pull request and gates the branch on it', () => {
  const workflow = YAML.parse(
    readFileSync(resolve(repositoryRoot, '.github/workflows/ci.yml'), 'utf8'),
  );
  const command = 'node docs/site/scripts/check-evidence-anchors.mjs';
  const running = Object.entries(workflow.jobs).filter(([, job]) =>
    (job.steps ?? []).some((step) => (step.run ?? '').includes(command)),
  );
  assert.equal(running.length, 1);
  const [jobId, job] = running[0];

  // The anchors cite source across the whole workspace, so a job the changed-path
  // classifier can skip is a gate that misses the renames it exists to catch.
  assert.equal(job.if, undefined);
  assert.deepEqual(job.needs ?? [], []);
  // No install and no build: the checker imports only node:fs, node:path, and node:url.
  assert.equal(
    (job.steps ?? []).some((step) => (step.run ?? '').includes('npm ci')),
    false,
  );
  // A job the aggregate does not wait on can fail without blocking the branch.
  assert.ok(workflow.jobs['ci-result'].needs.includes(jobId));
});

test('names every top-level directory the repository tracks as a citation root', () => {
  // A citation root the list does not name parses as no citation at all, so the anchor
  // carrying it is checked against nothing. Git is what says which directories the
  // repository keeps: a listing of the checkout also carries build output and local
  // tooling, and which of those are present differs between a clean CI checkout and a
  // working machine, so a listing would fail for reasons that are not drift.
  const tracked = execFileSync('git', ['ls-tree', '-d', '--name-only', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  })
    .split('\n')
    .filter((name) => name !== '');
  assert.ok(tracked.length > 0);
  // The roots are regular expression source, so a dot-directory carries its escape.
  const named = new Set(REPOSITORY_ROOTS.map((root) => root.replaceAll('\\', '')));
  assert.deepEqual(
    tracked.filter((name) => !named.has(name)),
    [],
  );
});

test('reads a citation into a top-level directory beside the crates and products', (t) => {
  const root = repository(t);
  write(root, 'editors/vscode/package.json', '{ "contributes": { "packageRevision": 1 } }\n');
  write(root, 'docker/compose/docker-compose.yaml', 'services:\n  evidence: {}\n');
  write(root, '.cargo/config.toml', '[build]\nrustflags = ["--cfg", "source_neutral"]\n');
  const passing = check(
    root,
    '{/* Evidence: editors/vscode/package.json, packageRevision; docker/compose/docker-compose.yaml; .cargo/config.toml, source_neutral. */}',
  );
  assert.deepEqual(passing.errors, []);
  assert.equal(passing.paths, 3);

  const failing = check(root, '{/* Evidence: editors/vscode/absent.json carries it. */}');
  assert.equal(failing.errors.length, 1);
  assert.match(failing.errors[0], /editors\/vscode\/absent\.json/);
  assert.match(failing.errors[0], /does not exist/);
});

test('reads a citation that starts at a shared root nearest first', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/schemas/authoring/registry.schema.json', '{ "title": "authoring_form" }\n');
  write(root, 'schemas/registry-notary.config.schema.json', '{ "title": "notary_config" }\n');
  const nearer = check(
    root,
    '{/* Evidence: crates/demo/src/lib.rs, then schemas/authoring/registry.schema.json, authoring_form. */}',
  );
  assert.deepEqual(nearer.errors, []);
  assert.equal(nearer.paths, 2);

  const atTheRoot = check(
    root,
    '{/* Evidence: schemas/registry-notary.config.schema.json, notary_config. */}',
  );
  assert.deepEqual(atTheRoot.errors, []);
  assert.equal(atTheRoot.paths, 1);
});

test('reads a one-word name only where the anchor spells it qualified', (t) => {
  const root = repository(t);
  write(root, 'crates/demo/src/rule.rs', 'pub enum AccessRule {\n    Public(String),\n}\n');
  // A one-word name carries no shape holding it apart from a capitalized prose word,
  // and every sentence an anchor opens starts with one.
  assert.deepEqual(extractSymbols('AccessRule is Public or Protected'), ['AccessRule']);
  // The last segment of a qualified name is read whatever its shape; a qualifier is
  // read by shape, so a one-word type that only ever qualifies stays outside the check.
  assert.deepEqual(extractSymbols('AccessRule::Public reads it'), ['AccessRule', 'Public']);
  assert.deepEqual(extractSymbols('Command::run() reads it'), ['run']);

  const bare = check(root, '{/* Evidence: crates/demo/src/rule.rs, AccessRule is Protectd. */}');
  assert.deepEqual(bare.errors, []);
  const qualified = check(root, '{/* Evidence: crates/demo/src/rule.rs, AccessRule::Protectd. */}');
  assert.equal(qualified.errors.length, 1);
  assert.match(qualified.errors[0], /Protectd/);
});
