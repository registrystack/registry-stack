#!/usr/bin/env node
// Post-build assertion script: verifies that the AI corpus files and sample
// per-page Markdown files exist and have the expected content.
//
// Run after `npx astro build`:
//   node scripts/check-llms.mjs
//
// Exits non-zero with a descriptive message on any failure.

import { readFile, access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const distDir = resolve(here, '../dist');

let passed = 0;
let failed = 0;

/** @param {string} label @param {boolean} ok @param {string} [detail] */
function assert(label, ok, detail) {
  if (ok) {
    console.log(`  ok  ${label}`);
    passed += 1;
  } else {
    console.error(`  FAIL  ${label}${detail ? `\n        ${detail}` : ''}`);
    failed += 1;
  }
}

/** @param {string} rel */
async function readDist(rel) {
  return readFile(resolve(distDir, rel), 'utf8');
}

/** @param {string} rel */
async function exists(rel) {
  try {
    await access(resolve(distDir, rel));
    return true;
  } catch {
    return false;
  }
}

console.log('check-llms: verifying AI corpus files in dist/\n');

// ---- 1. Required corpus files exist ----
const corpusFiles = ['llms.txt', 'llms-full.txt', 'llms-small.txt'];
const corpusPresent = await Promise.all(corpusFiles.map((f) => exists(f)));
for (let i = 0; i < corpusFiles.length; i += 1) {
  assert(`dist/${corpusFiles[i]} exists`, corpusPresent[i]);
}

// ---- 2. llms-full.txt contains both product names ----
if (corpusPresent[1]) {
  const full = await readDist('llms-full.txt');
  assert(
    'llms-full.txt mentions "registry-relay"',
    /registry.relay/i.test(full),
    'expected "registry-relay" (case-insensitive) in llms-full.txt',
  );
  assert(
    'llms-full.txt mentions "registry-notary"',
    /registry.notary/i.test(full),
    'expected "registry-notary" (case-insensitive) in llms-full.txt',
  );
  // Verify at least one tutorial appears in the full corpus.
  assert(
    'llms-full.txt contains at least one tutorial page',
    /tutorial/i.test(full),
    'expected at least one tutorial reference in llms-full.txt',
  );
}

// ---- 3. llms.txt has the discovery pointer lines ----
if (corpusPresent[0]) {
  const index = await readDist('llms.txt');
  assert(
    'llms.txt references llms-full.txt',
    index.includes('llms-full.txt'),
    'expected "llms-full.txt" link in llms.txt',
  );
  assert(
    'llms.txt references llms-small.txt',
    index.includes('llms-small.txt'),
    'expected "llms-small.txt" link in llms.txt',
  );
}

// ---- 4. Sample per-page .md file begins with the discovery header ----
const DISCOVERY_HEADER = 'Registry stack documentation: machine-readable Markdown.';
const sampleFiles = [
  'explanation/architecture.md',
  'index.md',
  'products/registry-relay.md',
  'tutorials/publish-spreadsheet-secured-registry-api.md',
];

for (const f of sampleFiles) {
  const fileExists = await exists(f);
  assert(`dist/${f} exists`, fileExists);
  if (fileExists) {
    const content = await readDist(f);
    assert(
      `dist/${f} starts with the discovery header`,
      content.startsWith(DISCOVERY_HEADER),
      `first line is:\n        ${content.split('\n')[0]}`,
    );
    assert(
      `dist/${f} contains llms.txt URL`,
      content.includes('https://docs.registrystack.org/llms.txt'),
    );
    assert(
      `dist/${f} contains llms-full.txt URL`,
      content.includes('https://docs.registrystack.org/llms-full.txt'),
    );
  }
}

// ---- 5. Per-page .md file title heading ----
const archFile = 'explanation/architecture.md';
if (await exists(archFile)) {
  const arch = await readDist(archFile);
  assert(
    'dist/explanation/architecture.md has an H1 heading',
    /^# .+/m.test(arch),
    'no H1 heading found',
  );
  assert(
    'dist/explanation/architecture.md has a description blockquote',
    /^> .+/m.test(arch),
    'no description blockquote found',
  );
}

// ---- Summary ----
console.log(`\ncheck-llms: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
