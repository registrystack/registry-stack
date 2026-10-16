import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

// The PublicSchema tutorial quotes the embedded snapshot pin. The optional
// products/breg/evidence/organization-selection.yaml also follows it, but the
// Evidence composition tutorial uses an explicit authored registry instead.

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');

function readRepo(relative) {
  return readFileSync(resolve(repoRoot, relative), 'utf8');
}

const pin = YAML.parse(readRepo('crates/registry-linkml/publicschema/PIN.yaml'));

test('the embedded PublicSchema pin names a commit and a version', () => {
  assert.match(pin.commit, /^[0-9a-f]{40}$/);
  assert.match(pin.version, /^\d+\.\d+\.\d+$/);
});

test('the shipped optional PublicSchema selection tracks the embedded revision', () => {
  const selection = YAML.parse(readRepo('products/breg/evidence/organization-selection.yaml'));
  assert.equal(selection.modelRevision, pin.commit, 'modelRevision must equal PIN.yaml commit');
  assert.equal(selection.modelVersion, pin.version, 'modelVersion must equal PIN.yaml version');
});

test('the Evidence composition tutorial uses the explicit authored source registry', () => {
  const page = readRepo('docs/site/src/content/docs/tutorials/evidence-from-breg.mdx');
  assert.match(page, /cp -R teaching-inputs\/registry \.\/registry/);
  assert.match(page, /bregctl check \.\/registry/);
  assert.match(page, /bregctl generate evidence-source \.\/registry/);
  assert.doesNotMatch(page, /bregctl init[^\n]*--model|save this selection as `organization-selection.yaml`/);
});

// Hand-written current pages; generated trees and dated records are not restated versions.
function currentPages(dir = resolve(siteRoot, 'src/content/docs'), prefix = '') {
  const pages = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const page = `${prefix}${entry.name}`;
    if (entry.isDirectory()) {
      if (!['products', 'decisions'].includes(page) && page !== 'reference/cli') {
        pages.push(...currentPages(resolve(dir, entry.name), `${page}/`));
      }
    } else if (/\.mdx?$/.test(entry.name) && page !== 'changelog.mdx') {
      pages.push(page);
    }
  }
  return pages;
}

test('every current page names the embedded PublicSchema version', () => {
  const named = [];
  for (const page of currentPages()) {
    const text = readRepo(`docs/site/src/content/docs/${page}`);
    for (const match of text.matchAll(/PublicSchema\s+(\d+\.\d+\.\d+)/g)) {
      named.push({ page, version: match[1] });
    }
  }
  assert.ok(
    named.some((entry) => entry.page === 'tutorials/derive-a-registry-from-publicschema.mdx'),
    'the PublicSchema tutorial must still name the snapshot version',
  );
  assert.deepEqual(
    named.filter((entry) => entry.version !== pin.version),
    [],
    `every "PublicSchema X.Y.Z" must name PIN.yaml version ${pin.version}`,
  );
});

// `readme()` in crates/registry-bregctl/src/init_from_model/render.rs writes the attribution from
// one format literal. Read that literal, so a wording change there fails here as surely as a sync.
function attributionTemplate() {
  const source = readRepo('crates/registry-bregctl/src/init_from_model/render.rs');
  const literal = source.match(/"(The concepts, properties, and code lists in this project[^"]*)",\s*\n\s*plan\.model\.repository, plan\.model\.license, plan\.model\.license_url\s*\n/);
  assert.ok(literal, 'render.rs readme() must still format the attribution from repository, license and licenseUrl');
  // A Rust string continuation drops the backslash, the newline and the next line's indentation.
  const template = literal[1].replace(/\\\n\s*/g, '');
  assert.deepEqual(
    template.match(/\{[a-z_]*\}/g),
    ['{model}', '{version}', '{revision}', '{}', '{}', '{}'],
    'the attribution placeholders changed; update this check with render.rs',
  );
  return template;
}

test('the PublicSchema tutorial quotes the attribution init writes for the embedded pin', () => {
  const page = readRepo('docs/site/src/content/docs/tutorials/derive-a-registry-from-publicschema.mdx');
  const note = page.match(/:::note\[Keep the attribution notice\]\n"([\s\S]*?)"\n/);
  assert.ok(note, 'the tutorial must quote the README attribution notice');

  // The page renders each bare URL readme() writes as a self-labelled markdown link.
  const quoted = note[1]
    .replace(/\[([^\]]+)\]\(\1\)/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  const positional = [pin.repository, pin.license, pin.licenseUrl];
  const expected = attributionTemplate()
    .replace('{model}', 'PublicSchema')
    .replace('{version}', pin.version)
    .replace('{revision}', pin.commit)
    .replace(/\{\}/g, () => positional.shift());
  assert.equal(quoted, expected);
});
