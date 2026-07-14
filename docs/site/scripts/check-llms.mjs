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
import YAML from 'yaml';

const here = fileURLToPath(new URL('.', import.meta.url));
const distDir = process.env.DOCS_DIST_DIR
  ? resolve(process.env.DOCS_DIST_DIR)
  : resolve(here, '../dist');
const docsDir = resolve(here, '../src/content/docs');

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

// Site roots: the main build root plus every archived docset mount point.
// A page served at one of these roots maps its Markdown to "<root>/index.md"
// (mirroring the URL), whereas every other page maps to "<dir>.md". Driven by
// the docsets manifest so archive mount points are never hard-coded here.
const docsetsManifest = JSON.parse(
  await readFile(resolve(here, '../src/data/generated/docsets.json'), 'utf8'),
);
const rootDirs = new Set(docsetsManifest.docsets.map((d) => d.path.replace(/^\/+|\/+$/g, '')));
rootDirs.add(''); // main build root, in case the manifest omits the '/' docset

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

/**
 * Find every Starlight draft source and map its content ID to built outputs.
 * @param {string} rel
 * @returns {Promise<Array<{ source: string, title: string, pagePath: string, htmlRel: string, mdRel: string }>>}
 */
async function findDraftPages(rel = '') {
  const out = [];
  const entries = await readdir(resolve(docsDir, rel || '.'), { withFileTypes: true });
  for (const entry of entries) {
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...(await findDraftPages(childRel)));
      continue;
    }
    if (!entry.isFile() || !/\.(?:md|mdx)$/.test(entry.name)) continue;

    const source = await readFile(resolve(docsDir, childRel), 'utf8');
    const frontmatterMatch = source.match(/^---\n([\s\S]*?)\n---\n/);
    if (!frontmatterMatch) throw new Error(`${childRel} has no parseable YAML frontmatter`);
    const data = YAML.parse(frontmatterMatch[1]);
    if (data.draft !== true) continue;

    const id = childRel.replace(/\.(?:md|mdx)$/, '');
    const pagePath = id === 'index' ? '' : id.replace(/\/index$/, '');
    out.push({
      source: childRel,
      title: data.title,
      pagePath,
      htmlRel: pagePath ? `${pagePath}/index.html` : 'index.html',
      mdRel: pagePath ? `${pagePath}.md` : 'index.md',
    });
  }
  return out;
}

/** @param {string} value */
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The full and small corpora delimit page entries with an H1. llms.txt can
 * evolve into a page index, so also reject a title-and-canonical-URL entry.
 * @param {string} file
 * @param {string} content
 * @param {{ title: string, pagePath: string }} page
 */
function hasDraftCorpusEntry(file, content, page) {
  const heading = new RegExp(`^# ${escapeRegExp(page.title)}$`, 'm');
  if (heading.test(content)) return true;
  if (file !== 'llms.txt') return false;

  const canonicalUrl = `https://docs.registrystack.org/${page.pagePath ? `${page.pagePath}/` : ''}`;
  return content.includes(`[${page.title}](${canonicalUrl})`);
}

console.log('check-llms: verifying AI corpus files in dist/\n');

// ---- 1. Required corpus files exist ----
const corpusFiles = ['llms.txt', 'llms-full.txt', 'llms-small.txt'];
const corpusPresent = await Promise.all(corpusFiles.map((f) => exists(f)));
const corpusContents = new Map();
for (let i = 0; i < corpusFiles.length; i += 1) {
  assert(`dist/${corpusFiles[i]} exists`, corpusPresent[i]);
  if (corpusPresent[i]) corpusContents.set(corpusFiles[i], await readDist(corpusFiles[i]));
}

// ---- 2. llms-full.txt contains both product names ----
if (corpusPresent[1]) {
  const full = corpusContents.get('llms-full.txt');
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
  const index = corpusContents.get('llms.txt');
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

// ---- 4. Starlight drafts do not leak into machine-readable outputs ----
// Draft HTML routes may exist only as redirect stubs. Draft source content
// must never produce a Markdown endpoint or corpus page.
const draftPages = await findDraftPages();
for (const page of draftPages) {
  assert(
    `draft ${page.source} does not emit dist/${page.mdRel}`,
    !(await exists(page.mdRel)),
    `remove the draft page from src/pages/[...slug].md.ts getStaticPaths`,
  );

  const htmlPresent = await exists(page.htmlRel);
  const html = htmlPresent ? await readDist(page.htmlRel) : '';
  const isRedirect = /http-equiv=["']?refresh/i.test(html);
  assert(
    `draft ${page.source} has no published HTML content`,
    !htmlPresent || isRedirect,
    `dist/${page.htmlRel} exists and is not a redirect stub`,
  );
  for (const [file, content] of corpusContents) {
    assert(
      `${file} excludes draft entry "${page.title}"`,
      !hasDraftCorpusEntry(file, content, page),
      `found a corpus page entry for draft source ${page.source}`,
    );
  }
}
console.log(`  ..  ${draftPages.length} draft pages checked for machine-output leaks`);

// ---- 5. Sample per-page .md files begin with the full discovery header ----
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

// ---- 6. Per-page .md file title heading ----
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

// ---- 7. Exhaustive coverage: every real page has a sibling .md ----
// Walk dist/ for index.html files and require a matching .md for each, so a
// page that silently loses its Markdown twin fails the build instead of
// passing on the sampled checks above. Redirect stubs (meta-refresh) and the
// built-in 404 have no docs entry and thus no .md, so they are skipped, exactly
// mirroring the is404/redirect handling in the .astro components.
// starlight-openapi injects the API reference operation pages as virtual routes
// (not docs content-collection entries), so they have no per-page .md twin. They
// are excluded from the llms corpus (reference/apis/** in astro.config.mjs) and
// from this coverage check. Matches the generated bases reference/apis/relay and
// reference/apis/notary, but NOT the hand-authored narrative pages
// reference/apis/registry-relay / registry-notary, which keep their .md.
const generatedApiBases = ['reference/apis/relay', 'reference/apis/notary'];
const isGeneratedApiPage = (dir) =>
  generatedApiBases.some((b) => dir === b || dir.startsWith(`${b}/`));

const pageDirs = await findPageDirs();
let covered = 0;
let skipped = 0;
for (const dir of pageDirs) {
  if (dir === '404') {
    skipped += 1;
    continue;
  }
  if (isGeneratedApiPage(dir)) {
    skipped += 1; // plugin-generated API route, no backing .md by design
    continue;
  }
  const html = await readDist(`${dir ? `${dir}/` : ''}index.html`);
  if (/http-equiv=["']?refresh/i.test(html)) {
    skipped += 1; // redirect stub, no backing page
    continue;
  }
  const mdRel = rootDirs.has(dir) ? `${dir ? `${dir}/` : ''}index.md` : `${dir}.md`;
  assert(`page /${dir}${dir ? '/' : ''} has ${mdRel}`, await exists(mdRel));
  covered += 1;
}
console.log(`  ..  ${covered} pages checked for .md coverage (${skipped} redirect/404 stubs skipped)`);

// ---- Summary ----
console.log(`\ncheck-llms: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
