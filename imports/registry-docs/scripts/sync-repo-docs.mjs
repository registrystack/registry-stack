// Build-time docs aggregation (Wave 3).
//
// Reads src/data/repo-docs.yaml, pulls the allowlisted markdown from each
// product repo (sibling checkout in dev, shallow clone at the pinned ref in
// CI), adapts it into Starlight pages, and writes them under
// src/content/docs/products/<repo>/. The output is a build artifact: it is
// gitignored and regenerated on every `npm run generate`.
//
// The repos stay GitHub-native plain markdown. All Starlight adaptation
// (frontmatter derivation, link rewriting, asset copying) happens here so a
// developer editing a product repo never has to know Starlight exists.
//
// No silent failures: a missing source file, a missing referenced asset, or an
// intra-repo link to an allowlisted-but-missing target is reported as a warning
// or error, never swallowed.

import { access, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { dirname, join, normalize, posix, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import YAML from 'yaml';

const run = promisify(execFile);

const root = process.cwd();
const dataDir = resolve(root, 'src/data');
const docsDir = resolve(root, 'src/content/docs');
const outputRoot = resolve(docsDir, 'products');
const cacheRoot = resolve(root, '.repo-docs-cache');

const today = new Date().toISOString().slice(0, 10);

const warnings = [];
function warn(message) {
  warnings.push(message);
  console.warn(`warning: ${message}`);
}

function fail(message) {
  console.error(`error: ${message}`);
  process.exitCode = 1;
  throw new Error(message);
}

async function isDir(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

// Resolve a repo source: prefer the sibling checkout, otherwise shallow-clone
// the remote at the pinned ref into the cache. Fail loudly if neither resolves.
async function resolveSource(repoId, repo) {
  const localPath = repo.local ? resolve(root, repo.local) : null;
  if (localPath && (await isDir(localPath))) {
    return { path: localPath, mode: 'local' };
  }

  if (!repo.remote || !repo.ref) {
    const localHint = repo.local ? ` at ${repo.local}` : '';
    fail(`${repoId}: no local checkout${localHint} and no remote/ref to clone`);
  }

  const cachePath = join(cacheRoot, repoId);
  await cloneAtRef(repoId, repo.remote, repo.ref, cachePath);
  return { path: cachePath, mode: 'clone' };
}

// Shallow-clone a single pinned commit. Idempotent: re-clones into a fresh dir.
async function cloneAtRef(repoId, remote, ref, dest) {
  await rm(dest, { recursive: true, force: true });
  await mkdir(dest, { recursive: true });
  try {
    await run('git', ['init', '--quiet'], { cwd: dest });
    await run('git', ['remote', 'add', 'origin', remote], { cwd: dest });
    await run('git', ['fetch', '--quiet', '--depth', '1', 'origin', ref], { cwd: dest });
    await run('git', ['checkout', '--quiet', 'FETCH_HEAD'], { cwd: dest });
  } catch (error) {
    fail(`${repoId}: failed to clone ${remote} at ${ref}: ${error.message}`);
  }
  console.log(`Cloned ${repoId} at ${ref.slice(0, 12)} into ${relative(root, dest)}`);
}

function blobUrl(repo, repoRelPath) {
  return `${repo.remote}/blob/${repo.ref}/${repoRelPath.replace(/\\/g, '/')}`;
}

function rawUrl(repo, repoRelPath) {
  const base = repo.remote.replace('github.com', 'raw.githubusercontent.com');
  return `${base}/${repo.ref}/${repoRelPath.replace(/\\/g, '/')}`;
}

// Build a lookup from a repo-relative source path (e.g. "docs/api.md") to its
// destination slug, so intra-repo links can be rewritten to site routes.
function buildDestIndex(entries) {
  const index = new Map();
  for (const entry of entries) {
    index.set(normalize(entry.src), entry);
  }
  return index;
}

// Strip a leading YAML frontmatter block if the repo markdown happens to carry
// one, so we never emit two frontmatter blocks.
function stripFrontmatter(md) {
  if (!md.startsWith('---\n')) return md;
  const end = md.indexOf('\n---\n', 4);
  if (end === -1) return md;
  return md.slice(end + 5).replace(/^\n+/, '');
}

function firstH1(md) {
  const match = md.match(/^#\s+(.+?)\s*$/m);
  return match ? match[1].trim() : null;
}

// If the title comes from the manifest label, drop a duplicate leading H1 so the
// Starlight page title is not repeated immediately in the body.
function dropLeadingH1(md) {
  return md.replace(/^\s*#\s+.+?\s*(?:\r?\n|$)/, '');
}

// Strip a leading "> **Page type:** ..." metadata banner that the product repos
// carry under the H1. It is a repo-side navigation aid for contributors reading
// the docs on GitHub; on the rendered site it is noise (and can leak a stale
// "Status: draft" marker). Only a leading blockquote whose first line declares
// the Page type is removed; ordinary blockquotes are left intact. Runs after
// dropLeadingH1, so the banner is the leading content for manifest entries.
export function stripPageTypeBanner(md) {
  const lines = md.split('\n');
  let start = 0;
  while (start < lines.length && lines[start].trim() === '') start += 1;
  if (start >= lines.length || !/^>\s*\*\*Page type:\*\*/.test(lines[start])) {
    return md;
  }
  let end = start;
  while (end < lines.length && lines[end].startsWith('>')) end += 1;
  while (end < lines.length && lines[end].trim() === '') end += 1;
  // Everything before `start` is blank (the first non-blank line is the banner),
  // so dropping through `end` removes the banner and its surrounding blank lines.
  return lines.slice(end).join('\n');
}

// The site route for a destination slug, as an absolute path (used for the
// final segment / browser navigation). Trailing slash matches the site config.
function siteRoute(destSlug) {
  const slug = destSlug.endsWith('/index') ? destSlug.slice(0, -'/index'.length) : destSlug;
  return `/${slug}/`;
}

// Relative link from one page's dest slug to another's, so the built-link
// checker (which only validates relative and base-prefixed links) can verify
// the route resolves. Astro serves each page as <slug>/index.html, so relative
// links resolve against the page's own URL directory (the route, not the slug
// parent). An index page (slug ending /index) is served at <parent>/, so its
// URL directory is one level shallower than a normal page.
function relativeRoute(fromDest, toDest) {
  const fromDir = siteRoute(fromDest); // the page's own URL directory
  const target = siteRoute(toDest);
  let rel = posix.relative(fromDir, target);
  if (rel === '') return './';
  if (!rel.startsWith('.')) rel = `./${rel}`;
  // relative() drops the trailing slash; keep it for clean directory routes.
  if (!rel.endsWith('/')) rel = `${rel}/`;
  return rel;
}

// Markdown link matcher: [text](target). Skips image alt handled separately.
// Captures the leading "!" so images and links share one pass.
const LINK_RE = /(!?)\[([^\]]*)\]\(([^)\s]+)(\s+"[^"]*")?\)/g;

function isExternal(target) {
  return (
    target.startsWith('http://') ||
    target.startsWith('https://') ||
    target.startsWith('mailto:') ||
    target.startsWith('tel:') ||
    target.startsWith('//') ||
    target.startsWith('data:')
  );
}

function splitTarget(target) {
  const hashIndex = target.indexOf('#');
  if (hashIndex === -1) return [target, ''];
  return [target.slice(0, hashIndex), target.slice(hashIndex)];
}

// Rewrite repo-relative links. Intra-repo links that map to an allowlisted dest
// become site routes; any other repo-relative link becomes an absolute GitHub
// blob URL at the pinned ref so it never 404s. Local assets are collected for
// copying and rewritten to repo-relative output paths.
function rewriteLinks(md, ctx) {
  const { repo, entry, destIndex, sourceFileDir, repoRoot, assetsToCopy } = ctx;

  return md.replace(LINK_RE, (whole, bang, text, target) => {
    if (!target || target.startsWith('#') || isExternal(target)) {
      return whole;
    }

    const [path, fragment] = splitTarget(target);
    const [pathNoQuery] = path.split('?');

    // Resolve the link target to a repo-relative path.
    const absInRepo = resolve(sourceFileDir, pathNoQuery);
    const repoRelPath = normalize(relative(repoRoot, absInRepo));

    // Link escapes the repo (shouldn't happen): fall back to GitHub blob.
    if (repoRelPath.startsWith('..')) {
      warn(
        `${entry.src}: link target "${target}" resolves outside the repo; using GitHub fallback`,
      );
      return `${bang}[${text}](${blobUrl(repo, pathNoQuery.replace(/^(\.\.\/)+/, ''))}${fragment})`;
    }

    // Image / asset reference: copy it next to the output and link relatively.
    // Assets land under public/products/<repo>/_assets so they are served as
    // static files (content-collection files that are not .md/.mdx are not
    // served), and the page links to the absolute /products/... asset URL.
    if (bang === '!') {
      const assetSource = absInRepo;
      if (!existsSync(assetSource)) {
        warn(`${entry.src}: referenced asset "${target}" not found at ${repoRelPath}`);
        return `${bang}[${text}](${rawUrl(repo, repoRelPath)})`;
      }
      const assetName = repoRelPath.replace(/[/\\]/g, '__');
      const assetDest = resolve(root, 'public/products', repo.id, '_assets', assetName);
      assetsToCopy.push({ from: assetSource, to: assetDest });
      return `${bang}[${text}](/products/${repo.id}/_assets/${assetName})`;
    }

    // Intra-repo markdown link to an allowlisted page: rewrite to a site route.
    const destEntry = destIndex.get(repoRelPath);
    if (destEntry) {
      const rel = relativeRoute(entry.dest, destEntry.dest);
      return `${bang}[${text}](${rel}${fragment})`;
    }

    // Repo-relative link to something we do not publish (or that is missing):
    // point at the GitHub blob at the pinned ref so it never 404s.
    if (repoRelPath.endsWith('.md') && !existsSync(absInRepo)) {
      warn(`${entry.src}: link "${target}" points at missing file ${repoRelPath}`);
    }
    return `${bang}[${text}](${blobUrl(repo, repoRelPath)}${fragment})`;
  });
}

function frontmatterBlock(fields) {
  const fm = {
    title: fields.title,
    description: fields.description,
    status: 'current',
    owner: fields.owner,
    source_repos: [fields.owner],
    last_reviewed: today,
    doc_type: fields.doc_type,
    locale: 'en',
    standards_referenced: [],
    editUrl: fields.editUrl,
  };
  // YAML.stringify keeps the body deterministic and quotes where needed.
  return `---\n${YAML.stringify(fm).trimEnd()}\n---\n`;
}

// Derive a one-line description from the first non-empty prose paragraph when
// the manifest does not provide one.
function deriveDescription(md, fallback) {
  const lines = md.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line) continue;
    if (line.startsWith('#') || line.startsWith('>') || line.startsWith('```') || line.startsWith('|')) {
      continue;
    }
    // Strip markdown emphasis/link syntax for a clean description.
    const clean = line
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/[*_`]/g, '')
      .trim();
    if (clean.length >= 20) {
      return clean.length > 160 ? `${clean.slice(0, 157)}...` : clean;
    }
  }
  return fallback;
}

async function syncEntry(repoId, repo, entry, source, destIndex) {
  const sourceFile = resolve(source.path, entry.src);
  if (!existsSync(sourceFile)) {
    fail(`${repoId}: allowlisted source ${entry.src} not found in ${source.mode} source`);
  }

  const raw = await readFile(sourceFile, 'utf8');
  const stripped = stripFrontmatter(raw);

  const title = entry.label || firstH1(stripped);
  if (!title) {
    fail(`${repoId}: ${entry.src} has no label and no H1 to derive a title from`);
  }

  // Drop the leading H1 only when we are using the manifest label as the title,
  // to avoid a duplicate page heading.
  const bodyBase = stripPageTypeBanner(entry.label ? dropLeadingH1(stripped) : stripped);

  const outFile = resolve(docsDir, `${entry.dest}.mdx`);
  const assetsToCopy = [];
  const body = rewriteLinks(bodyBase, {
    repo: { ...repo, id: repoId },
    entry,
    destIndex,
    sourceFileDir: dirname(sourceFile),
    repoRoot: source.path,
    assetsToCopy,
    outFile,
  });

  const description = entry.description || deriveDescription(stripped, `${title} for ${repoId}.`);
  const fm = frontmatterBlock({
    title,
    description,
    owner: repoId,
    doc_type: entry.doc_type,
    editUrl: blobUrl({ ...repo }, entry.src),
  });

  await mkdir(dirname(outFile), { recursive: true });
  await writeFile(outFile, `${fm}\n${body.replace(/^\n+/, '').trimEnd()}\n`);

  for (const asset of assetsToCopy) {
    await mkdir(dirname(asset.to), { recursive: true });
    await cp(asset.from, asset.to);
  }

  return { outFile: relative(root, outFile), assets: assetsToCopy.length };
}

async function main() {
  const manifestPath = resolve(dataDir, 'repo-docs.yaml');
  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  if (!manifest || typeof manifest.repos !== 'object') {
    fail('repo-docs.yaml must contain a top-level `repos` map');
  }

  // Clean and recreate the output dir so removed allowlist entries don't linger.
  await rm(outputRoot, { recursive: true, force: true });
  await mkdir(outputRoot, { recursive: true });

  let pageCount = 0;
  let assetCount = 0;

  for (const [repoId, repo] of Object.entries(manifest.repos)) {
    if (!Array.isArray(repo.docs) || repo.docs.length === 0) {
      warn(`${repoId}: no docs entries in manifest; skipping`);
      continue;
    }
    const source = await resolveSource(repoId, repo);
    console.log(`Syncing ${repoId} from ${source.mode} source ${relative(root, source.path)}`);

    const destIndex = buildDestIndex(repo.docs);
    for (const entry of repo.docs) {
      const result = await syncEntry(repoId, repo, entry, source, destIndex);
      pageCount += 1;
      assetCount += result.assets;
    }
  }

  console.log(
    `Synced ${pageCount} product doc page(s)` +
      (assetCount ? `, ${assetCount} asset(s)` : '') +
      (warnings.length ? `, ${warnings.length} warning(s)` : '') +
      '.',
  );
}

// Run the pipeline only when invoked directly, so tests can import the pure
// helpers above without triggering a full clone-and-write run.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
