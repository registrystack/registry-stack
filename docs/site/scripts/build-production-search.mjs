import { lstat, readFile, readdir } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const reservedRootDirectories = new Set([
  '_archive-bundles',
  'dev',
  'pagefind',
  'preview',
  'v',
]);

async function existingInfo(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function collectCanonicalHtml(distRoot, current = distRoot) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (current === distRoot && reservedRootDirectories.has(entry.name)) continue;
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`canonical documentation cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectCanonicalHtml(distRoot, path));
    } else if (info.isFile() && entry.name.endsWith('.html')) {
      files.push(path);
    }
  }
  return files;
}

function routeForHtml(distRoot, file) {
  const rel = relative(distRoot, file).replaceAll(sep, '/');
  if (rel === 'index.html') return '/';
  if (rel.endsWith('/index.html')) return `/${rel.slice(0, -'index.html'.length)}`;
  return `/${rel}`;
}

function rejectPagefindErrors(label, result) {
  if (result.errors?.length) {
    throw new Error(`${label}: ${result.errors.join('; ')}`);
  }
}

export async function buildProductionSearch({
  docsRoot = process.cwd(),
  distRoot = resolve(docsRoot, 'dist'),
  pagefindModule,
} = {}) {
  distRoot = resolve(docsRoot, distRoot);
  const outputPath = resolve(distRoot, 'pagefind');
  const distInfo = await existingInfo(distRoot);
  if (!distInfo?.isDirectory() || distInfo.isSymbolicLink()) {
    throw new Error(`production dist root must be a real directory: ${distRoot}`);
  }
  if (await existingInfo(outputPath)) {
    throw new Error(`production search destination already exists: ${outputPath}`);
  }

  const pages = [];
  for (const file of await collectCanonicalHtml(distRoot)) {
    const content = await readFile(file, 'utf8');
    if (!content.includes('data-pagefind-body')) continue;
    if (/<meta\s+http-equiv=["']refresh["']/i.test(content)) continue;
    pages.push({ content, url: routeForHtml(distRoot, file) });
  }
  if (pages.length === 0) {
    throw new Error('canonical documentation contains no searchable pages');
  }
  pages.sort((left, right) => left.url.localeCompare(right.url));

  const pagefind = pagefindModule ?? await import('pagefind');
  const created = await pagefind.createIndex();
  rejectPagefindErrors('could not create production search index', created);
  if (!created.index) throw new Error('Pagefind did not return a production search index');

  try {
    for (const page of pages) {
      rejectPagefindErrors(
        `could not index canonical route ${page.url}`,
        await created.index.addHTMLFile(page),
      );
    }
    const written = await created.index.writeFiles({ outputPath });
    rejectPagefindErrors('could not write production search index', written);
  } finally {
    await created.index.deleteIndex();
    await pagefind.close?.();
  }

  const entrypoint = resolve(outputPath, 'pagefind.js');
  const entrypointInfo = await existingInfo(entrypoint);
  if (!entrypointInfo?.isFile() || entrypointInfo.isSymbolicLink()) {
    throw new Error(`production search entrypoint was not generated: ${entrypoint}`);
  }
  for (const asset of ['pagefind-ui.js', 'pagefind-ui.css']) {
    const path = resolve(outputPath, asset);
    const info = await existingInfo(path);
    if (!info?.isFile() || info.isSymbolicLink()) {
      throw new Error(`production search UI asset was not generated: ${path}`);
    }
  }
  return { pages: pages.length, outputPath };
}

export function parseProductionSearchArguments(args) {
  if (args.length === 0) return {};
  if (args.length === 2 && args[0] === '--dist-root' && args[1]) {
    return { distRoot: args[1] };
  }
  throw new Error('usage: build-production-search.mjs [--dist-root <path>]');
}

async function main() {
  const result = await buildProductionSearch(
    parseProductionSearchArguments(process.argv.slice(2)),
  );
  console.log(
    `Generated canonical Pagefind search for ${result.pages} released documentation page(s).`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
