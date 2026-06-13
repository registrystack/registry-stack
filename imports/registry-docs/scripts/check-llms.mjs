#!/usr/bin/env node
// Post-build assertion script: verifies that the AI corpus files and sample
// per-page Markdown files exist and have the expected content.
//
// Run after `npx astro build`:
//   node scripts/check-llms.mjs
//
// Exits non-zero with a descriptive message on any failure.

import { readFile, access, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const distDir = resolve(here, '../dist');

// Load the discovery header from its single source of truth so this post-build
// check fails loudly if the built corpus or any per-page .md drifts from it.
// We extract the template-literal value with a regex rather than importing the
// .ts (this script runs under plain node, no transpiler).
const pageMarkdownSource = await readFile(resolve(here, '../src/lib/page-markdown.ts'), 'utf8');
const headerMatch = pageMarkdownSource.match(/DISCOVERY_HEADER = `([\s\S]*?)`/);
if (!headerMatch) {
  console.error('check-llms: could not extract DISCOVERY_HEADER from src/lib/page-markdown.ts');
  process.exit(1);
}
const DISCOVERY_HEADER = headerMatch[1];
const HEADER_LINES = DISCOVERY_HEADER.split('\n');

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

/**
 * Recursively collect the directory of every index.html under dist/, returned
 * as a slash path relative to dist/ ('' for the site root). Used to drive the
 * exhaustive per-page .md coverage check.
 * @param {string} rel
 * @returns {Promise<string[]>}
 */
async function findPageDirs(rel = '') {
  const out = [];
  const entries = await readdir(resolve(distDir, rel || '.'), { withFileTypes: true });
  for (const entry of entries) {
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...(await findPageDirs(childRel)));
    } else if (entry.name === 'index.html') {
      out.push(rel);
    }
  }
  return out;
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

// ---- 3. llms.txt carries the full discovery header (drift guard) ----
// astro.config.mjs feeds DISCOVERY_HEADER into the plugin's `details`, so every
// line must surface in the built llms.txt. Asserting line-by-line means a
// change to the header in page-markdown.ts that doesn't reach the corpus fails
// here instead of shipping a silently-divergent pointer.
if (corpusPresent[0]) {
  const index = await readDist('llms.txt');
  for (const line of HEADER_LINES) {
    assert(
      `llms.txt contains discovery header line: "${line}"`,
      index.includes(line),
      'expected this DISCOVERY_HEADER line in llms.txt',
    );
  }
  assert(
    'llms.txt references llms-small.txt',
    index.includes('llms-small.txt'),
    'expected "llms-small.txt" link in llms.txt',
  );
}

// ---- 4. Sample per-page .md files begin with the full discovery header ----
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

// ---- 6. Exhaustive coverage: every real page has a sibling .md ----
// Walk dist/ for index.html files and require a matching .md for each, so a
// page that silently loses its Markdown twin fails the build instead of
// passing on the sampled checks above. Redirect stubs (meta-refresh) and the
// built-in 404 have no docs entry and thus no .md, so they are skipped, exactly
// mirroring the is404/redirect handling in the .astro components.
const pageDirs = await findPageDirs();
let covered = 0;
let skipped = 0;
for (const dir of pageDirs) {
  if (dir === '404') {
    skipped += 1;
    continue;
  }
  const html = await readDist(`${dir ? `${dir}/` : ''}index.html`);
  if (/http-equiv=["']?refresh/i.test(html)) {
    skipped += 1; // redirect stub, no backing page
    continue;
  }
  const mdRel = dir === '' ? 'index.md' : `${dir}.md`;
  assert(`page /${dir}${dir ? '/' : ''} has ${mdRel}`, await exists(mdRel));
  covered += 1;
}
console.log(`  ..  ${covered} pages checked for .md coverage (${skipped} redirect/404 stubs skipped)`);

// ---- Summary ----
console.log(`\ncheck-llms: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
