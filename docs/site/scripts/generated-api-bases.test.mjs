// Unit tests for src/lib/generated-api-bases.mjs.
//
// Run with: node --test scripts/generated-api-bases.test.mjs
// (also picked up by `npm test` via "scripts/**/*.test.mjs")

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

import {
  GENERATED_API_BASES,
  isGeneratedApiDir,
  isGeneratedApiPath,
} from '../src/lib/generated-api-bases.mjs';

const here = dirname(fileURLToPath(import.meta.url));

test('every starlight-openapi base registered in astro.config.mjs is listed', () => {
  // astro.config.mjs is where a new API reference is registered. Anything it
  // registers has no Markdown twin, so a base missing from this list ships
  // pages that advertise a .md the build never generates.
  const config = readFileSync(resolve(here, '../astro.config.mjs'), 'utf8');
  const registered = [...config.matchAll(/^\s*base:\s*'(reference\/apis\/[^']+)'/gm)].map(
    (match) => match[1],
  );

  assert.ok(registered.length > 0, 'astro.config.mjs must register at least one API base');
  for (const base of registered) {
    assert.ok(
      GENERATED_API_BASES.includes(base),
      `${base} is registered in astro.config.mjs but missing from GENERATED_API_BASES`,
    );
  }
});

test('a generated base and its descendants are recognised', () => {
  assert.equal(isGeneratedApiDir('reference/apis/evidence'), true);
  assert.equal(isGeneratedApiDir('reference/apis/evidence/operations/createevidence'), true);
  assert.equal(isGeneratedApiPath('/reference/apis/evidence/'), true);
  assert.equal(isGeneratedApiPath('/reference/apis/evidence/operations/gethealth/'), true);
});

test('the hand-authored narrative pages keep their Markdown twin', () => {
  // reference/apis/registry-evidence is a real content-collection entry and
  // shares a prefix with the generated base, so prefix matching must not
  // swallow it.
  assert.equal(isGeneratedApiDir('reference/apis/registry-evidence'), false);
  assert.equal(isGeneratedApiPath('/reference/apis/registry-evidence/'), false);
  assert.equal(isGeneratedApiDir('reference/apis'), false);
  assert.equal(isGeneratedApiPath('/reference/apis/'), false);
});
