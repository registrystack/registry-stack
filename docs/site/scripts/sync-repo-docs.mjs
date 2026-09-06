// Build-time docs aggregation (Wave 3).
//
// Reads src/data/repo-docs.yaml, pulls the allowlisted markdown from each
// product repo (sibling checkout in dev, shallow clone at the pinned ref in
// CI), adapts it into Starlight pages, and writes them under
// src/content/docs/products/<repo>/. The output is a build artifact: it is
// gitignored and regenerated on every `npm run generate`.
//
// The repos stay GitHub-native plain Markdown. All Starlight adaptation
// (frontmatter derivation, link rewriting, asset copying) happens here so a
// developer editing a product repo never has to know Starlight exists. Synced
// pages remain .md files, so source text is never compiled as executable MDX.
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
import { createMarkdownProcessor } from '@astrojs/markdown-remark';
import { parseFragment } from 'parse5';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { unified } from 'unified';
import YAML from 'yaml';
import {
  applyDocsetRefs,
  filterRepoDocsForDocset,
  getDocset,
  loadDocsets,
  selectedDocsetId,
} from './docsets.mjs';
import { fetchRefWithRetry } from './git-fetch-retry.mjs';

const run = promisify(execFile);

const root = process.cwd();
const dataDir = resolve(root, 'src/data');
const docsDir = resolve(root, 'src/content/docs');
const outputRoot = resolve(docsDir, 'products');
const cacheRoot = resolve(root, '.repo-docs-cache');

export const GENERATED_PRODUCT_DOC_EXTENSION = '.md';

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
    await fetchRefWithRetry(ref, dest);
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

const STANDALONE_HTML_COMMENT_RE = /^ {0,3}<!--[^<>`]*-->[\t ]*$/u;
const syncedMarkdownParser = unified().use(remarkParse).use(remarkGfm);

function* markdownNodes(root) {
  const nodes = [root];
  while (nodes.length > 0) {
    const node = nodes.pop();
    yield node;
    if (node.children) {
      for (let index = node.children.length - 1; index >= 0; index -= 1) {
        nodes.push(node.children[index]);
      }
    }
  }
}

// Plain Markdown still permits raw HTML. Refuse HTML tags outside code so a
// source document cannot emit active markup into the built site. Parse the
// source using Markdown's own grammar so indented and fenced examples remain
// authorable. Complete standalone HTML comment lines remain inert source
// markers.
export function validateInertMarkdown(md, context = 'synced product Markdown') {
  const lines = md.split(/\r?\n/u);
  for (const node of markdownNodes(syncedMarkdownParser.parse(md))) {
    if (node.type !== 'html') continue;
    const line = node.position?.start.line ?? 1;
    const isStandaloneComment = node.position?.end.line === line
      && STANDALONE_HTML_COMMENT_RE.test(lines[line - 1]);
    if (isStandaloneComment) continue;
    throw new Error(
      `${context}: raw HTML is not allowed outside code examples (line ${line})`,
    );
  }
  return md;
}

const RENDER_BASE_URL = 'https://docs.registrystack.invalid/';
const SAFE_RENDERED_PROTOCOLS = new Set(['http:', 'https:', 'mailto:', 'tel:']);
const RENDERED_URL_ATTRIBUTES = new Set([
  'action',
  'formaction',
  'href',
  'poster',
  'src',
  'xlink:href',
]);

function renderedElements(node) {
  const elements = [];
  for (const child of node.childNodes ?? []) {
    if (child.tagName) elements.push(child);
    elements.push(...renderedElements(child));
  }
  if (node.content) elements.push(...renderedElements(node.content));
  return elements;
}

function renderedUrlIsSafe(value) {
  try {
    const url = new URL(value, RENDER_BASE_URL);
    return SAFE_RENDERED_PROTOCOLS.has(url.protocol);
  } catch {
    return false;
  }
}

// Markdown reference definitions, autolinks, and inline destinations follow
// different parsing rules. Render with Astro's Markdown processor after link
// rewriting, then inspect the decoded HTML attributes at the actual execution
// boundary. This catches character-reference and control-character scheme
// obfuscation without trying to reproduce the CommonMark destination grammar.
export async function validateRenderedMarkdownLinks(
  md,
  context = 'synced product Markdown',
  markdownProcessor,
) {
  const processor = markdownProcessor ?? await createSyncedMarkdownProcessor();
  const rendered = await processor.render(md);
  const fragment = parseFragment(rendered.code);

  for (const element of renderedElements(fragment)) {
    for (const attribute of element.attrs ?? []) {
      if (!RENDERED_URL_ATTRIBUTES.has(attribute.name)) continue;
      if (!renderedUrlIsSafe(attribute.value)) {
        throw new Error(
          `${context}: rendered Markdown contains an unsafe ${element.tagName} ${attribute.name} destination`,
        );
      }
    }
  }
  return md;
}

export async function createSyncedMarkdownProcessor() {
  return createMarkdownProcessor({
    remarkPlugins: [remarkGfm],
    syntaxHighlight: false,
  });
}

// Product sources keep their implementation-era name, while the public docs
// use the approved display name. Rewrite prose only. Technical identifiers in
// code spans and fences stay byte-for-byte unchanged, as do CCCEV and OOTS
// terms in which "Evidence" is part of a standards-defined name.
export function applyRepoDisplayName(md, repoId) {
  if (repoId !== 'registry-evidence') return md;

  const protectedTerms = [
    'Evidence Type',
    'Evidence Broker',
    'Evidence Provider',
    'Evidence Exchange',
    'Evidence Request',
    'Evidence Response',
    'Evidence Vocabulary',
  ];
  const placeholders = new Map(
    protectedTerms.map((term, index) => [`\u0000EVIDENCE_TERM_${index}\u0000`, term]),
  );

  let fence = null;
  return md
    .split('\n')
    .map((line) => {
      const fenceMatch = line.match(/^\s*(```+|~~~+)/);
      if (fenceMatch) {
        const marker = fenceMatch[1][0];
        fence = fence === marker ? null : marker;
        return line;
      }
      if (fence) return line;

      let displayLine = line
        .replace(/^### Evidence\s*$/, '### Assertion evidence')
        .replace(/^## Discover available Evidence\s*$/, '## Discover available Evidence Gateway definitions')
        .replace(/^## Request Evidence\s*$/, '## Request an assertion from Evidence Gateway');

      const segments = displayLine.split(/(`+[^`]*`+)/g);
      displayLine = segments
        .map((segment, index) => {
          if (index % 2 === 1) return segment;
          let prose = segment;
          const linkTargets = [];
          prose = prose.replace(/(!?\[[^\]]*\]\()([^)]*)(\))/g, (_whole, prefix, target, suffix) => {
            const placeholder = `\u0000EVIDENCE_LINK_TARGET_${linkTargets.length}\u0000`;
            linkTargets.push(target);
            return `${prefix}${placeholder}${suffix}`;
          });
          for (const [placeholder, term] of placeholders) {
            prose = prose.replaceAll(term, placeholder);
          }
          prose = prose.replace(/\bEvidence\b(?! Gateway\b)/g, 'Evidence Gateway');
          for (const [placeholder, term] of placeholders) {
            prose = prose.replaceAll(placeholder, term);
          }
          for (const [index, target] of linkTargets.entries()) {
            prose = prose.replaceAll(`\u0000EVIDENCE_LINK_TARGET_${index}\u0000`, target);
          }
          return prose;
        })
        .join('');
      return displayLine;
    })
    .join('\n');
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
export function rewriteLinks(md, ctx) {
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

export function validateStandardsReferenced(value, context, knownStandards) {
  if (value === undefined) {
    throw new Error(
      `${context}: standards_referenced is required; use [] when the page references no registered standards`,
    );
  }
  if (!Array.isArray(value)) {
    throw new Error(`${context}: standards_referenced must be a list`);
  }

  const seen = new Set();
  for (const id of value) {
    if (typeof id !== 'string' || id.trim() !== id || id === '') {
      throw new Error(`${context}: standards_referenced entries must be non-empty strings`);
    }
    if (!knownStandards.has(id)) {
      throw new Error(`${context}: standards_referenced id "${id}" is not in src/data/standards.yaml`);
    }
    if (seen.has(id)) {
      throw new Error(`${context}: standards_referenced id "${id}" is duplicated`);
    }
    seen.add(id);
  }
  return value;
}

export function validateLastReviewed(value, context) {
  if (value === 'unreviewed') return value;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error(
      `${context}: last_reviewed is required and must be "unreviewed" or a YYYY-MM-DD date`,
    );
  }
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new Error(`${context}: last_reviewed "${value}" is not a valid calendar date`);
  }
  return value;
}

function validateDocsetOverrides(entry, context, knownStandards, docsets) {
  const overrides = entry.docset_overrides ?? [];
  if (!Array.isArray(overrides)) {
    throw new Error(`${context}: docset_overrides must be a list`);
  }

  const docsetById = new Map(docsets.docsets.map((docset) => [docset.id, docset]));
  const seenDocsets = new Set();
  for (const [index, override] of overrides.entries()) {
    const overrideContext = `${context}: docset_overrides[${index}]`;
    if (!override || typeof override !== 'object' || Array.isArray(override)) {
      throw new Error(`${overrideContext} must be a map`);
    }
    const unknownKeys = Object.keys(override).filter(
      (key) => !['docsets', 'standards_referenced', 'last_reviewed'].includes(key),
    );
    if (unknownKeys.length > 0) {
      throw new Error(`${overrideContext} has unknown field "${unknownKeys[0]}"`);
    }
    if (!Array.isArray(override.docsets) || override.docsets.length === 0) {
      throw new Error(`${overrideContext}.docsets must be a non-empty list`);
    }
    validateStandardsReferenced(
      override.standards_referenced,
      overrideContext,
      knownStandards,
    );
    validateLastReviewed(override.last_reviewed, overrideContext);

    for (const docsetId of override.docsets) {
      if (typeof docsetId !== 'string' || docsetId.trim() !== docsetId || docsetId === '') {
        throw new Error(`${overrideContext}.docsets entries must be non-empty strings`);
      }
      const docset = docsetById.get(docsetId);
      if (!docset) {
        throw new Error(`${overrideContext} references unknown docset "${docsetId}"`);
      }
      const isVersionedDraftRecord =
        docset.status === 'draft' &&
        ['candidate', 'failed'].includes(docset.availability) &&
        /^v\d+\.\d+\.\d+$/.test(docset.id);
      if (
        docsetId === docsets.current ||
        (docset.status !== 'archived' && !isVersionedDraftRecord)
      ) {
        throw new Error(
          `${overrideContext} may reference archived docsets or versioned draft records only`,
        );
      }
      if (entry.exclude_docsets?.includes(docsetId)) {
        throw new Error(`${overrideContext} references excluded docset "${docsetId}"`);
      }
      if (seenDocsets.has(docsetId)) {
        throw new Error(`${context}: docset "${docsetId}" has more than one metadata override`);
      }
      seenDocsets.add(docsetId);
    }
  }

  const expectedDocsets = docsets.docsets.filter((docset) => {
    return docset.status === 'archived' && !entry.exclude_docsets?.includes(docset.id);
  });
  for (const docset of expectedDocsets) {
    if (!seenDocsets.has(docset.id)) {
      throw new Error(
        `${context}: missing complete metadata override for archived docset "${docset.id}"`,
      );
    }
  }
}

export function validateRepoDocsMetadata(manifest, knownStandards, docsets) {
  for (const [repoId, repo] of Object.entries(manifest.repos ?? {})) {
    if (!Array.isArray(repo.docs)) continue;
    for (const [index, entry] of repo.docs.entries()) {
      const source = entry?.src ?? `docs[${index}]`;
      const context = `${repoId}: ${source}`;
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new Error(`${context}: repo doc entry must be a map`);
      }
      validateStandardsReferenced(entry.standards_referenced, context, knownStandards);
      validateLastReviewed(entry.last_reviewed, context);
      validateDocsetOverrides(entry, context, knownStandards, docsets);
    }
  }
  return manifest;
}

// Historical metadata is frozen with the pinned source. Every applicable
// archived docset has a complete standards and review-status override.
export function applyDocsetMetadataOverrides(manifest, docset) {
  if (docset.status !== 'archived') return manifest;
  for (const repo of Object.values(manifest.repos ?? {})) {
    if (!Array.isArray(repo.docs)) continue;
    for (const entry of repo.docs) {
      if (entry.exclude_docsets?.includes(docset.id)) continue;
      const override = entry.docset_overrides?.find((candidate) => {
        return candidate.docsets.includes(docset.id);
      });
      if (!override) {
        throw new Error(`${entry.src}: missing metadata override for archived docset "${docset.id}"`);
      }
      entry.standards_referenced = [...override.standards_referenced];
      entry.last_reviewed = override.last_reviewed;
    }
  }
  return manifest;
}

export function frontmatterBlock(fields) {
  const lastReviewed = validateLastReviewed(fields.last_reviewed, 'generated frontmatter');
  if (!Array.isArray(fields.standards_referenced)) {
    throw new Error('generated frontmatter: standards_referenced must be a list');
  }
  const fm = {
    title: fields.title,
    description: fields.description,
    status: lastReviewed === 'unreviewed' ? 'draft' : 'current',
    owner: fields.owner,
    source_repos: [fields.owner],
    last_reviewed: lastReviewed,
    doc_type: fields.doc_type,
    locale: 'en',
    standards_referenced: fields.standards_referenced,
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

async function syncEntry(
  repoId,
  repo,
  entry,
  source,
  destIndex,
  knownStandards,
  markdownProcessor,
) {
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

  const outFile = resolve(docsDir, `${entry.dest}${GENERATED_PRODUCT_DOC_EXTENSION}`);
  const assetsToCopy = [];
  const body = applyRepoDisplayName(
    rewriteLinks(validateInertMarkdown(bodyBase, `${repoId}: ${entry.src}`), {
      repo: { ...repo, id: repoId },
      entry,
      destIndex,
      sourceFileDir: dirname(sourceFile),
      repoRoot: source.path,
      assetsToCopy,
      outFile,
    }),
    repoId,
  );
  await validateRenderedMarkdownLinks(body, `${repoId}: ${entry.src}`, markdownProcessor);

  const description = entry.description || deriveDescription(stripped, `${title} for ${repoId}.`);
  const standards_referenced = validateStandardsReferenced(
    entry.standards_referenced,
    `${repoId}: ${entry.src}`,
    knownStandards,
  );
  const last_reviewed = validateLastReviewed(entry.last_reviewed, `${repoId}: ${entry.src}`);
  const fm = frontmatterBlock({
    title,
    description,
    owner: repoId,
    doc_type: entry.doc_type,
    last_reviewed,
    standards_referenced,
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

async function loadKnownStandards() {
  const standardsPath = resolve(dataDir, 'standards.yaml');
  const standards = YAML.parse(await readFile(standardsPath, 'utf8'));
  if (!Array.isArray(standards)) {
    fail('standards.yaml must contain a top-level list');
  }
  for (const [index, standard] of standards.entries()) {
    if (!standard || typeof standard.id !== 'string' || standard.id === '') {
      fail(`standards.yaml entry ${index + 1} is missing id`);
    }
  }
  return new Set(standards.map((standard) => standard.id));
}

async function main() {
  const manifestPath = resolve(dataDir, 'repo-docs.yaml');
  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  if (!manifest || typeof manifest.repos !== 'object') {
    fail('repo-docs.yaml must contain a top-level `repos` map');
  }
  const knownStandards = await loadKnownStandards();
  const markdownProcessor = await createSyncedMarkdownProcessor();
  const docsets = await loadDocsets({ dataDir });
  validateRepoDocsMetadata(manifest, knownStandards, docsets);
  const docset = getDocset(docsets, selectedDocsetId(docsets));
  // Filter before applying docset refs: a repo whose docs are all excluded
  // from this docset (a product newer than the docset, like registry-evidence
  // in pre-Evidence archives) must not count as an active repo the docset is
  // required to pin.
  filterRepoDocsForDocset(manifest, docset);
  if (docset.id !== docsets.current) {
    applyDocsetRefs(manifest, docset);
    console.log(`Using archived docset ${docset.id} for product docs.`);
  }
  applyDocsetMetadataOverrides(manifest, docset);

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
      const result = await syncEntry(
        repoId,
        repo,
        entry,
        source,
        destIndex,
        knownStandards,
        markdownProcessor,
      );
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
