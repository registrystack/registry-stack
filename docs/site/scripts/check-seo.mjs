import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { loadDocsets } from './docsets.mjs';

const distDir = resolve(process.env.DOCS_DIST_DIR || 'dist');
const publicOrigin = 'https://docs.registrystack.org';
const redirectMarker =
  /<meta\s+name=["']registry-docset-redirect["']\s+content=["'][^"']+["']\s*\/?>/;

function scopeFromArgs(args) {
  if (args.length === 0) return 'all';
  if (args.length === 2 && args[0] === '--scope' && ['all', 'current'].includes(args[1])) {
    return args[1];
  }
  throw new Error('usage: check-seo.mjs [--scope current|all]');
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function htmlFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await htmlFiles(path));
    if (entry.isFile() && entry.name.endsWith('.html')) files.push(path);
  }
  return files;
}

async function excludedProductionFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (
      entry.isDirectory() &&
      !['_pagefind', 'pagefind'].includes(entry.name)
    ) {
      files.push(...await excludedProductionFiles(path));
    } else if (
      ['_pagefind', 'pagefind', 'llms-full.txt', 'llms-small.txt'].includes(entry.name) ||
      /^sitemap(?:-[0-9]+|-index)?\.xml$/.test(entry.name)
    ) {
      files.push(path);
    }
  }
  return files;
}

function archiveRootForFile(file, archivedDocsets) {
  const rel = relative(distDir, file).replaceAll('\\', '/');
  return archivedDocsets.find((docset) => rel.startsWith(docset.path.replace(/^\//, '')));
}

function canonicalIsWithinReleasedDocset(canonical, releasedPath) {
  try {
    const url = new URL(canonical);
    return (
      url.origin === publicOrigin &&
      !url.search &&
      !url.hash &&
      url.href === `${publicOrigin}${url.pathname}` &&
      url.pathname.startsWith(releasedPath)
    );
  } catch {
    return false;
  }
}

const manifest = await loadDocsets();
const archivedDocsets = manifest.docsets.filter((docset) => docset.status === 'archived');
const releasedDocset = manifest.docsets.find((docset) => docset.id === manifest.released);
const scope = scopeFromArgs(process.argv.slice(2));
const errors = [];
let currentChecked = 0;
let archivedChecked = 0;
let redirectsChecked = 0;
const previewDir = join(distDir, 'preview');
const previewEntrypoint = join(previewDir, 'index.html');
const previewHtml = await exists(previewEntrypoint)
  ? await readFile(previewEntrypoint, 'utf8')
  : null;
const productionLayout = previewHtml !== null && redirectMarker.test(previewHtml);
const mountedCurrentLayout = previewHtml !== null && !productionLayout;
const currentOutput = mountedCurrentLayout ? previewDir : distDir;

if (!productionLayout && !await exists(join(currentOutput, 'sitemap-index.xml'))) {
  errors.push(`Main sitemap is missing: ${join(currentOutput, 'sitemap-index.xml')}`);
}

if (productionLayout) {
  for (const file of await excludedProductionFiles(distDir)) {
    errors.push(`Production output contains excluded preview discovery/search output: ${file}`);
  }
  for (const file of ['CNAME', 'robots.txt', 'llms.txt']) {
    if (!await exists(join(distDir, file))) {
      errors.push(`Production output is missing released-only ${file}`);
    }
  }
  const rootEntrypoint = join(distDir, 'index.html');
  const rootHtml = await exists(rootEntrypoint)
    ? await readFile(rootEntrypoint, 'utf8')
    : '';
  if (!redirectMarker.test(rootHtml)) {
    errors.push('Production output root must be a released-docset redirect');
  }
}

if (scope === 'all') {
  for (const docset of archivedDocsets) {
    const archiveDir = join(distDir, docset.path);
    const archiveSitemap = join(archiveDir, 'sitemap-index.xml');
    const archiveSitemapPage = join(archiveDir, 'sitemap-0.xml');
    if (await exists(archiveSitemap)) {
      errors.push(`Archived docset ${docset.id} must not publish sitemap-index.xml`);
    }
    if (await exists(archiveSitemapPage)) {
      errors.push(`Archived docset ${docset.id} must not publish sitemap-0.xml`);
    }
  }
}

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  const isArchived = Boolean(archiveRootForFile(file, archivedDocsets));
  const isProductionRedirect = redirectMarker.test(html);
  if (scope === 'current' && (isArchived || isProductionRedirect)) continue;
  const hasNoindex = /<meta\s+name=["']robots["']\s+content=["']noindex,follow["']\s*\/?>/.test(html);
  const hasSitemapLink = /<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/i.test(html);

  if (isProductionRedirect) {
    redirectsChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is a root redirect but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is a root redirect but links a sitemap`);
    }
    const canonical = html.match(
      /<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']+)["'])[^>]*>/i,
    )?.[1];
    if (!canonicalIsWithinReleasedDocset(canonical, releasedDocset.path)) {
      errors.push(
        `${relative('.', file)} must canonically redirect into released docset ${manifest.released}`,
      );
    }
  } else if (isArchived) {
    archivedChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is archived but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is archived but links a sitemap`);
    }
  } else {
    currentChecked += 1;
    if (hasNoindex) {
      errors.push(`${relative('.', file)} is Main but has robots noindex,follow`);
    }
  }
}

if (scope === 'all' && archivedDocsets.length > 0 && archivedChecked === 0) {
  errors.push('No archived HTML files were checked.');
}
if (scope === 'all' && productionLayout && redirectsChecked === 0) {
  errors.push('No released-root redirect HTML files were checked.');
}
if (scope === 'all' && productionLayout && currentChecked > 0) {
  errors.push('Production output contains ordinary nonarchive HTML.');
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(
  `SEO check passed: ${currentChecked} Main HTML files, ${archivedChecked} archived HTML files, and ${redirectsChecked} released-root redirects checked.`,
);
