import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

// The tutorials hand-copy the embedded PublicSchema snapshot pin (#1400). `sync-snapshot.sh`
// rewrites PIN.yaml; these checks fail until the tutorial copies follow it. A sync must also move
// products/breg/evidence/organization-selection.yaml, which registry-bregctl tests hold to the
// pin, and that path selects the docs job in CI.

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

test('the Evidence tutorial selection is the shipped selection at the embedded revision', () => {
  const page = readRepo('docs/site/src/content/docs/tutorials/evidence-from-breg.mdx');
  const shipped = readRepo('products/breg/evidence/organization-selection.yaml');

  const intro = page.indexOf('save this selection as `organization-selection.yaml`');
  assert.notEqual(intro, -1, 'the tutorial must still introduce organization-selection.yaml');
  const block = page.slice(intro).match(/^```yaml\n([\s\S]*?)^```$/m);
  assert.ok(block, 'organization-selection.yaml must follow as a yaml code block');
  const snippet = block[1];

  const selection = YAML.parse(snippet);
  assert.equal(selection.modelRevision, pin.commit, 'modelRevision must equal PIN.yaml commit');
  assert.equal(selection.modelVersion, pin.version, 'modelVersion must equal PIN.yaml version');
  assert.equal(snippet, shipped, 'the snippet must match products/breg/evidence/organization-selection.yaml');
});

test('the PublicSchema tutorial quotes the attribution init writes for the embedded pin', () => {
  const page = readRepo('docs/site/src/content/docs/tutorials/derive-a-registry-from-publicschema.mdx');
  const note = page.match(/:::note\[Keep the attribution notice\]\n"([\s\S]*?)"\n/);
  assert.ok(note, 'the tutorial must quote the README attribution notice');

  // The markdown link form renders the bare URL `readme()` in
  // crates/registry-bregctl/src/init_from_model/render.rs writes.
  const quoted = note[1]
    .replace(/\[([^\]]+)\]\(\1\)/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  const expected =
    `The concepts, properties, and code lists in this project are derived from PublicSchema ${pin.version}, `
    + `revision ${pin.commit} (${pin.repository}), licensed under ${pin.license} (${pin.licenseUrl}). `
    + 'The derivation selects, renames, and retypes definitions, so this project is a modified form of '
    + 'the model. Keep this notice with the project and with any package built from it.';
  assert.equal(quoted, expected);
});
