import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, join, normalize, relative } from 'node:path';

const distDir = 'dist';
const attrPattern = /\s(?:href|src)=["']([^"']+)["']/g;
const idPattern = /\sid=["']([^"']+)["']/g;

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

function splitUrl(raw) {
  const [withoutHash, fragment] = raw.split('#');
  return [withoutHash.split('?')[0], fragment];
}

function pageUrl(file) {
  const rel = relative(distDir, file);
  if (rel === 'index.html') return '/';
  if (rel.endsWith('/index.html')) return `/${rel.slice(0, -'index.html'.length)}`;
  return `/${rel}`;
}

function resolveInternal(raw, fromFile) {
  if (raw === '' || raw.startsWith('#') || isExternal(raw)) {
    return null;
  }

  let url = raw;
  if (!url.startsWith('/')) {
    const current = pageUrl(fromFile);
    const currentDir = current.endsWith('/') ? current : dirname(current);
    url = normalize(join(currentDir, url));
    if (!url.startsWith('/')) url = `/${url}`;
  }

  return url;
}

function archiveRoot(file) {
  const match = pageUrl(file).match(/^\/v\/[^/]+\//);
  return match?.[0] ?? null;
}

function isExternal(raw) {
  return (
    raw.startsWith('http://') ||
    raw.startsWith('https://') ||
    raw.startsWith('mailto:') ||
    raw.startsWith('tel:') ||
    raw.startsWith('data:')
  );
}

function targetPath(url) {
  const [path] = splitUrl(url);
  if (path === '/' || path === '') return join(distDir, 'index.html');
  if (path.endsWith('/')) return join(distDir, path, 'index.html');
  return join(distDir, path);
}

const errors = [];
let checked = 0;
const idsByFile = new Map();

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  const ids = new Set();
  for (const match of html.matchAll(idPattern)) ids.add(match[1]);
  idsByFile.set(file, ids);
}

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  for (const match of html.matchAll(attrPattern)) {
    const raw = match[1];
    const root = archiveRoot(file);
    if (
      root &&
      raw.startsWith('/') &&
      raw !== '/' &&
      !raw.startsWith(root) &&
      !isExternal(raw)
    ) {
      errors.push(`${relative('.', file)} links outside its archive: ${raw}`);
      continue;
    }

    const url = resolveInternal(raw, file);
    if (!url) continue;

    checked += 1;
    const [path, fragment] = splitUrl(url);
    const target = targetPath(path);
    if (!await exists(target)) {
      errors.push(`${relative('.', file)} links to missing ${raw}`);
      continue;
    }

    if (fragment && target.endsWith('.html')) {
      const ids = idsByFile.get(target) ?? new Set();
      if (!ids.has(fragment)) {
        errors.push(`${relative('.', file)} links to missing fragment ${raw}`);
      }
    }
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Built link check passed: ${checked} internal links and assets checked.`);
