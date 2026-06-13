import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const robotsMeta = '<meta name="robots" content="noindex,follow">';

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

function removeSitemapLinks(html) {
  return html.replace(/\s*<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/gi, '');
}

function addNoindex(html) {
  if (/<meta\s+name=["']robots["'][^>]*>/i.test(html)) {
    return html.replace(/<meta\s+name=["']robots["'][^>]*>/i, robotsMeta);
  }
  return html.replace('</head>', `${robotsMeta}</head>`);
}

export async function applyArchiveSeo(outDir) {
  for (const file of await htmlFiles(outDir)) {
    const html = await readFile(file, 'utf8');
    const updated = addNoindex(removeSitemapLinks(html));
    if (updated !== html) await writeFile(file, updated);
  }

  await rm(join(outDir, 'sitemap-index.xml'), { force: true });
  await rm(join(outDir, 'sitemap-0.xml'), { force: true });
}
