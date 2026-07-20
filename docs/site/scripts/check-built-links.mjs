import { lstat, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { dirname, join, normalize, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  LINK_INDEX_SCHEMA,
  archiveOutputDirectory,
  validateLinkIndexLocation,
} from './archive-cache.mjs';
import { extractEvidenceUrlsFromYaml } from './check-evidence-links.mjs';

const attrPattern = /\s(?:href|src)=["']([^"']+)["']/g;
const idPattern = /\sid=["']([^"']+)["']/g;
const sha256Pattern = /^[0-9a-f]{64}$/;

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !rel.startsWith(sep));
}

async function htmlFiles(dir) {
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`built-link input must be a real directory: ${dir}`);
  }
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`built-link input cannot contain symlinks: ${path}`);
    }
    if (entry.isDirectory()) files.push(...(await htmlFiles(path)));
    if (entry.isFile() && entry.name.endsWith('.html')) files.push(path);
  }
  return files.sort();
}

function splitUrl(raw) {
  const [withoutHash, fragment] = raw.split('#');
  return [withoutHash.split('?')[0], fragment];
}

function pageUrl(distDir, file) {
  const rel = relative(distDir, file).replaceAll(sep, '/');
  if (rel === 'index.html') return '/';
  if (rel.endsWith('/index.html')) return `/${rel.slice(0, -'index.html'.length)}`;
  return `/${rel}`;
}

function resolveInternal(raw, fromUrl) {
  if (raw === '' || raw.startsWith('#') || isExternal(raw)) return null;

  let url = raw;
  if (!url.startsWith('/')) {
    const currentDir = fromUrl.endsWith('/') ? fromUrl : dirname(fromUrl);
    url = normalize(join(currentDir, url));
    if (!url.startsWith('/')) url = `/${url}`;
  }
  return url;
}

function archiveRootFromUrl(url) {
  const match = url.match(/^\/v\/[^/]+\//);
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

function targetPath(distDir, url) {
  const [path] = splitUrl(url);
  const rel = path.replace(/^\/+/, '');
  if (path === '/' || path === '') return join(distDir, 'index.html');
  if (path.endsWith('/')) return join(distDir, rel, 'index.html');
  return join(distDir, rel);
}

async function scanPage(distDir, file) {
  const html = await readFile(file, 'utf8');
  return {
    file: relative(distDir, file).replaceAll(sep, '/'),
    url: pageUrl(distDir, file),
    ids: [...new Set([...html.matchAll(idPattern)].map((match) => match[1]))].sort(),
    links: [...html.matchAll(attrPattern)].map((match) => match[1]),
  };
}

export async function createArchiveLinkIndex({ docsRoot, docset, cacheKey }) {
  if (!sha256Pattern.test(cacheKey)) throw new Error('link index cache key must be sha256 text');
  const distDir = resolve(docsRoot, 'dist');
  const outDir = archiveOutputDirectory(docsRoot, docset);
  const pages = [];
  for (const file of await htmlFiles(outDir)) pages.push(await scanPage(distDir, file));
  return {
    schema_version: LINK_INDEX_SCHEMA,
    cache_key: cacheKey,
    docset_id: docset.id,
    archive_path: docset.path,
    pages,
  };
}

export async function writeArchiveLinkIndex({ docsRoot, docset, index }) {
  const indexDir = await validateLinkIndexLocation(docsRoot);
  const path = resolve(indexDir, `${docset.id}.json`);
  if (!isWithin(indexDir, path)) throw new Error(`unsafe archive link-index path for ${docset.id}`);
  await mkdir(indexDir, { recursive: true });
  await writeFile(path, `${JSON.stringify(index, null, 2)}\n`);
  return path;
}

async function currentEvidencePaths(dataDir) {
  const paths = new Set();
  for (const kind of ['contracts', 'standards']) {
    const source = await readFile(join(dataDir, `${kind}.yaml`), 'utf8');
    for (const url of extractEvidenceUrlsFromYaml(source, kind)) {
      if (url.startsWith('/')) paths.add(splitUrl(url)[0]);
    }
  }
  return paths;
}

async function loadCachedPages(distDir) {
  const indexDir = resolve(distDir, '.archive-link-indexes');
  if (!(await exists(indexDir))) return { pages: [], indexedFiles: new Set(), errors: [] };
  const pages = [];
  const indexedFiles = new Set();
  const errors = [];
  for (const entry of await readdir(indexDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) {
      errors.push(`Archive link-index directory contains unexpected entry ${entry.name}`);
      continue;
    }
    const path = resolve(indexDir, entry.name);
    let index;
    try {
      index = JSON.parse(await readFile(path, 'utf8'));
    } catch (error) {
      errors.push(`${relative('.', path)} is not valid JSON: ${error.message}`);
      continue;
    }
    if (
      index.schema_version !== LINK_INDEX_SCHEMA ||
      !sha256Pattern.test(index.cache_key) ||
      typeof index.docset_id !== 'string' ||
      !/^\/v\/[a-z0-9][a-z0-9.-]*\/$/.test(index.archive_path) ||
      !Array.isArray(index.pages)
    ) {
      errors.push(`${relative('.', path)} has an invalid archive link-index shape`);
      continue;
    }
    const archiveDir = resolve(distDir, index.archive_path.replace(/^\/+|\/+$/g, ''));
    if (!isWithin(resolve(distDir, 'v'), archiveDir)) {
      errors.push(`${relative('.', path)} archive path escapes dist/v`);
      continue;
    }
    const actualFiles = new Set(
      (await htmlFiles(archiveDir)).map((file) => relative(distDir, file).replaceAll(sep, '/')),
    );
    const declaredFiles = new Set();
    for (const page of index.pages) {
      const file = resolve(distDir, page?.file ?? '');
      const rel = relative(distDir, file).replaceAll(sep, '/');
      if (
        typeof page?.file !== 'string' ||
        !isWithin(archiveDir, file) ||
        page.file !== rel ||
        typeof page.url !== 'string' ||
        page.url !== pageUrl(distDir, file) ||
        !Array.isArray(page.ids) ||
        !page.ids.every((id) => typeof id === 'string') ||
        !Array.isArray(page.links) ||
        !page.links.every((link) => typeof link === 'string')
      ) {
        errors.push(`${relative('.', path)} contains an invalid indexed page`);
        continue;
      }
      if (declaredFiles.has(rel)) errors.push(`${relative('.', path)} indexes ${rel} twice`);
      declaredFiles.add(rel);
      indexedFiles.add(file);
      pages.push(page);
    }
    if (
      actualFiles.size !== declaredFiles.size ||
      [...actualFiles].some((file) => !declaredFiles.has(file))
    ) {
      errors.push(`${relative('.', path)} page roster does not match its archive output`);
    }
  }
  return { pages, indexedFiles, errors };
}

export async function checkBuiltLinks({
  distDir = resolve(process.cwd(), 'dist'),
  dataDir = resolve(process.cwd(), 'src/data'),
} = {}) {
  const errors = [];
  let checked = 0;
  const cached = await loadCachedPages(distDir);
  errors.push(...cached.errors);
  const pages = [...cached.pages];
  for (const file of await htmlFiles(distDir)) {
    if (cached.indexedFiles.has(file)) continue;
    pages.push(await scanPage(distDir, file));
  }

  const idsByFile = new Map();
  for (const page of pages) {
    const file = resolve(distDir, page.file);
    if (!isWithin(distDir, file)) {
      errors.push(`Indexed page escapes dist: ${page.file}`);
      continue;
    }
    idsByFile.set(file, new Set(page.ids));
  }
  const evidencePaths = await currentEvidencePaths(dataDir);

  for (const page of pages) {
    for (const raw of page.links) {
      const root = archiveRootFromUrl(page.url);
      if (
        root &&
        raw.startsWith('/') &&
        raw !== '/' &&
        !raw.startsWith(root) &&
        !evidencePaths.has(splitUrl(raw)[0]) &&
        !isExternal(raw)
      ) {
        errors.push(`${page.file} links outside its archive: ${raw}`);
        continue;
      }

      const url = resolveInternal(raw, page.url);
      if (!url) continue;
      checked += 1;
      const [path, fragment] = splitUrl(url);
      const target = targetPath(distDir, path);
      if (!isWithin(distDir, target)) {
        errors.push(`${page.file} links outside dist: ${raw}`);
        continue;
      }
      if (!(await exists(target))) {
        errors.push(`${page.file} links to missing ${raw}`);
        continue;
      }
      if (fragment && target.endsWith('.html')) {
        const ids = idsByFile.get(target) ?? new Set();
        if (!ids.has(fragment)) {
          errors.push(`${page.file} links to missing fragment ${raw}`);
        }
      }
    }
  }
  return { checked, errors, cachedPages: cached.pages.length };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const result = await checkBuiltLinks();
    if (result.errors.length > 0) {
      console.error(result.errors.join('\n'));
      process.exitCode = 1;
    } else {
      console.log(
        `Built link check passed: ${result.checked} internal links and assets checked` +
          ` (${result.cachedPages} cached archive pages).`,
      );
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
