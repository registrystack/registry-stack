import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { loadDocsets } from './docsets.mjs';

const distDir = 'dist';

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

function archiveRootForFile(file, archivedDocsets) {
  const rel = relative(distDir, file).replaceAll('\\', '/');
  return archivedDocsets.find((docset) => rel.startsWith(docset.path.replace(/^\//, '')));
}

const manifest = await loadDocsets();
const archivedDocsets = manifest.docsets.filter((docset) => docset.status === 'archived');
const errors = [];
let latestChecked = 0;
let archivedChecked = 0;

if (!await exists(join(distDir, 'sitemap-index.xml'))) {
  errors.push('Latest sitemap is missing: dist/sitemap-index.xml');
}

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

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  const isArchived = Boolean(archiveRootForFile(file, archivedDocsets));
  const hasNoindex = /<meta\s+name=["']robots["']\s+content=["']noindex,follow["']\s*\/?>/.test(html);
  const hasSitemapLink = /<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/i.test(html);

  if (isArchived) {
    archivedChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is archived but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is archived but links a sitemap`);
    }
  } else {
    latestChecked += 1;
    if (hasNoindex) {
      errors.push(`${relative('.', file)} is latest but has robots noindex,follow`);
    }
  }
}

if (archivedDocsets.length > 0 && archivedChecked === 0) {
  errors.push('No archived HTML files were checked.');
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`SEO check passed: ${latestChecked} latest HTML files and ${archivedChecked} archived HTML files checked.`);
