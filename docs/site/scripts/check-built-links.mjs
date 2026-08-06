import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, join, normalize, relative, resolve } from 'node:path';

import { extractEvidenceUrlsFromYaml } from './check-evidence-links.mjs';
import { loadDocsets } from './docsets.mjs';
import { CURRENT_PRODUCTION_DOCSET_PATH } from '../src/lib/docset-path.mjs';
import { publishedArchiveDocsets } from '../src/lib/docset-retention.mjs';

const distDir = resolve(process.env.DOCS_DIST_DIR || 'dist');
const attrPattern = /\s(?:href|src)=["']([^"']+)["']/g;
const idPattern = /\sid=["']([^"']+)["']/g;
const LEGACY_PREVIEW_PATH = '/preview/';

function scopeFromArgs(args) {
  if (args.length === 0) return 'all';
  if (args.length === 2 && args[0] === '--scope' && ['all', 'current'].includes(args[1])) {
    return args[1];
  }
  throw new Error('usage: check-built-links.mjs [--scope current|all]');
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

function isWithinRoot(path, root) {
  return path === root.slice(0, -1) || path.startsWith(root);
}

function resolveTarget(path) {
  const target = targetPath(path);
  for (const [mount, mountExists] of [
    [CURRENT_PRODUCTION_DOCSET_PATH, productionCurrentMountExists],
    [LEGACY_PREVIEW_PATH, legacyPreviewMountExists],
  ]) {
    if (mountExists || !isWithinRoot(path, mount)) continue;
    const relativePath = path === mount.slice(0, -1)
      ? '/'
      : `/${path.slice(mount.length)}`;
    return targetPath(relativePath);
  }
  return target;
}

async function currentEvidencePaths() {
  const paths = new Set();
  const dataDir = join('src', 'data');
  for (const kind of ['contracts', 'standards']) {
    const source = await readFile(join(dataDir, `${kind}.yaml`), 'utf8');
    for (const url of extractEvidenceUrlsFromYaml(source, kind)) {
      if (url.startsWith('/')) paths.add(splitUrl(url)[0]);
    }
  }
  return paths;
}

const errors = [];
let checked = 0;
const idsByFile = new Map();
const evidencePaths = await currentEvidencePaths();
const scope = scopeFromArgs(process.argv.slice(2));
const archivedRootPattern = /^\/v\/[^/]+\//;
const productionCurrentMountExists = await exists(
  targetPath(CURRENT_PRODUCTION_DOCSET_PATH),
);
const legacyPreviewMountExists = await exists(targetPath(LEGACY_PREVIEW_PATH));
const docsets = await loadDocsets();
const archivedRoots = new Set(
  docsets.docsets
    .filter((docset) => docset.status === 'archived')
    .map((docset) => docset.path),
);
const publishedArchivedRoots = new Set(
  publishedArchiveDocsets(docsets).map((docset) => docset.path),
);
const retiredArchivedRoots = new Set(
  [...archivedRoots].filter((root) => !publishedArchivedRoots.has(root)),
);
const declaredArchiveDestinations = new Set([
  CURRENT_PRODUCTION_DOCSET_PATH,
  LEGACY_PREVIEW_PATH,
  ...archivedRoots,
]);

const files = (await htmlFiles(distDir)).filter(
  (file) => scope === 'all' || archiveRoot(file) === null,
);

for (const file of files) {
  const html = await readFile(file, 'utf8');
  const ids = new Set();
  for (const match of html.matchAll(idPattern)) ids.add(match[1]);
  idsByFile.set(file, ids);
}

for (const file of files) {
  const html = await readFile(file, 'utf8');
  const sourcePath = pageUrl(file);
  const isFrozenPublishedPage =
    productionCurrentMountExists &&
    !isWithinRoot(sourcePath, CURRENT_PRODUCTION_DOCSET_PATH) &&
    !isWithinRoot(sourcePath, LEGACY_PREVIEW_PATH);
  for (const match of html.matchAll(attrPattern)) {
    const raw = match[1];
    const root = archiveRoot(file);
    const rawPath = splitUrl(raw)[0];
    if (
      root &&
      raw.startsWith('/') &&
      raw !== '/' &&
      !isWithinRoot(rawPath, root) &&
      !evidencePaths.has(rawPath) &&
      ![...declaredArchiveDestinations].some((path) => isWithinRoot(rawPath, path)) &&
      !isExternal(raw)
    ) {
      errors.push(`${relative('.', file)} links outside its archive: ${raw}`);
      continue;
    }

    const url = resolveInternal(raw, file);
    if (!url) continue;
    const archivedRoot = splitUrl(url)[0].match(archivedRootPattern)?.[0];
    if (scope === 'current' && archivedRoot) {
      checked += 1;
      if (!archivedRoots.has(archivedRoot)) {
        errors.push(`${relative('.', file)} links to unknown archive ${raw}`);
      }
      continue;
    }

    checked += 1;
    const [path, fragment] = splitUrl(url);
    if (
      isFrozenPublishedPage &&
      archivedRoot &&
      retiredArchivedRoots.has(archivedRoot)
    ) {
      continue;
    }
    const target = resolveTarget(path);
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
