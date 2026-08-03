// Unit tests for src/lib/doc-personas.mjs.
//
// Run with: node --test scripts/doc-personas.test.mjs
// (also picked up by `npm test` via "scripts/**/*.test.mjs")

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

import { DOC_PERSONAS } from '../src/lib/doc-personas.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const whenToUse = resolve(here, '../src/content/docs/start/when-to-use.mdx');

/**
 * The roles named in the "Who does what" section of start/when-to-use.mdx,
 * which is the page a persona label sends a reader to. Scoped to that section
 * so an ordinary "- The ... is ..." bullet elsewhere on the page is not read as
 * a role definition.
 * @returns {string[]}
 */
function definedRoles() {
  const source = readFileSync(whenToUse, 'utf8');
  const section = source.match(/^### Who does what$([\s\S]*?)^#{2,3} /m);
  assert.ok(section, 'when-to-use.mdx must keep a "Who does what" section');
  return [...section[1].matchAll(/^- The (.+?) is /gm)].map((match) => match[1]);
}

test('every persona label is a persona the site defines', () => {
  // start/when-to-use.mdx is where the four deployment roles are defined for
  // readers. A label that names a role the page does not define sends a reader
  // looking for an explanation that is not there.
  const defined = definedRoles();

  assert.ok(defined.length > 0, 'when-to-use.mdx must define at least one role');
  for (const persona of DOC_PERSONAS) {
    assert.ok(
      defined.includes(persona),
      `"${persona}" is a valid frontmatter label but when-to-use.mdx defines no such role`,
    );
  }
});

test('every role the site defines is available as a label', () => {
  // The other direction: a role readers are told about, with no tutorial able
  // to claim it, is a gap in the onboarding spine rather than a stray label.
  for (const role of definedRoles()) {
    assert.ok(
      DOC_PERSONAS.includes(role),
      `when-to-use.mdx defines the role "${role}" but no tutorial can be labeled with it`,
    );
  }
});
