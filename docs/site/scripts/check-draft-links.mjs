#!/usr/bin/env node

// Validates the internal page links, in-page anchors, and static-asset
// references carried by pages marked `draft: true`.
//
// Starlight only includes a draft page's route in a production build when
// `import.meta.env.MODE !== 'production'` (see the `data.draft === false`
// filter in @astrojs/starlight/utils/routing/index.ts), so `npm run build`
// never emits HTML for a draft page and scripts/check-built-links.mjs, which
// walks the built `dist/` tree, never sees a draft page's links. This script
// parses the Markdown source directly instead, so a draft page's links are
// proven correct before the page is un-drafted and reaches the built check.
//
// Run after `npm run generate`, which materializes the synced product pages
// and generated example assets a draft page's links can target.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import GithubSlugger from 'github-slugger';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { unified } from 'unified';
import YAML from 'yaml';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const parser = unified().use(remarkParse).use(remarkGfm);
const DOCS_ORIGIN = 'https://docs.registrystack.invalid';

function* nodes(root) {
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    yield node;
    if (node.children) {
      for (let index = node.children.length - 1; index >= 0; index -= 1) {
        stack.push(node.children[index]);
      }
    }
  }
}

function textContent(node) {
  if (node.type === 'text' || node.type === 'inlineCode') return node.value;
  return (node.children ?? []).map(textContent).join('');
}

function frontmatter(text, file) {
  if (!text.startsWith('---\n')) {
    throw new Error(`${file} is missing YAML frontmatter`);
  }
  const end = text.indexOf('\n---\n', 4);
  if (end === -1) {
    throw new Error(`${file} has unterminated YAML frontmatter`);
  }
  return YAML.parse(text.slice(4, end));
}

function markdownFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...markdownFiles(path));
    else if (/\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found;
}

// A doc file's route is its path under the docs root with the extension
// dropped and a trailing `index` segment removed, matching Starlight's
// default (unconfigured) slug computation: tutorials/foo.mdx -> tutorials/foo,
// products/bar/index.md -> products/bar, index.mdx -> "" (the home page).
export function routeForDocPath(relPath) {
  const parts = relPath.replace(/\.(md|mdx)$/, '').split('/');
  if (parts.at(-1) === 'index') parts.pop();
  return parts.join('/');
}

export function headingSlugs(markdown) {
  const slugger = new GithubSlugger();
  const slugs = new Set();
  for (const node of nodes(parser.parse(markdown))) {
    if (node.type === 'heading') slugs.add(slugger.slug(textContent(node)));
  }
  return slugs;
}

export function extractLinks(markdown) {
  const links = [];
  for (const node of nodes(parser.parse(markdown))) {
    if (node.type === 'link' || node.type === 'image') links.push(node.url);
  }
  return links;
}

function isExternal(raw) {
  return /^(https?:|mailto:|tel:|data:)/.test(raw);
}

export function checkDraftLinks({
  docsDir = resolve(scriptDir, '../src/content/docs'),
  publicDir = resolve(scriptDir, '../public'),
} = {}) {
  const errors = [];
  let checked = 0;

  const routeInfo = new Map();
  for (const file of markdownFiles(docsDir)) {
    const rel = relative(docsDir, file);
    routeInfo.set(routeForDocPath(rel), { file, text: readFileSync(file, 'utf8') });
  }

  for (const [route, info] of routeInfo) {
    let data;
    try {
      data = frontmatter(info.text, info.file);
    } catch {
      continue; // scripts/check-doc-frontmatter.mjs is the authority on frontmatter shape.
    }
    if (data?.draft !== true) continue;

    const sourceLabel = relative(docsDir, info.file);
    for (const raw of extractLinks(info.text)) {
      checked += 1;
      if (raw === '' || isExternal(raw)) continue;

      if (raw.startsWith('#')) {
        const fragment = decodeURIComponent(raw.slice(1));
        if (!headingSlugs(info.text).has(fragment)) {
          errors.push(`${sourceLabel}: in-page link ${raw} has no matching heading`);
        }
        continue;
      }

      let url;
      try {
        url = new URL(raw, `${DOCS_ORIGIN}/${route}${route ? '/' : ''}`);
      } catch (error) {
        errors.push(`${sourceLabel}: ${raw}: ${error.message}`);
        continue;
      }
      if (url.origin !== DOCS_ORIGIN) {
        errors.push(`${sourceLabel}: ${raw}: resolves outside the docs site`);
        continue;
      }

      const targetPath = decodeURIComponent(url.pathname);
      const fragment = url.hash ? decodeURIComponent(url.hash.slice(1)) : undefined;

      if (extname(targetPath)) {
        const assetPath = join(publicDir, targetPath);
        if (!existsSync(assetPath)) {
          errors.push(`${sourceLabel}: ${raw}: no asset at public${targetPath}`);
        }
        continue;
      }

      const targetRoute = targetPath.replace(/^\/+/, '').replace(/\/+$/, '');
      const target = routeInfo.get(targetRoute);
      if (!target) {
        errors.push(`${sourceLabel}: ${raw}: no docs page for route "${targetRoute || '/'}"`);
        continue;
      }
      if (fragment && !headingSlugs(target.text).has(fragment)) {
        errors.push(
          `${sourceLabel}: ${raw}: ${relative(docsDir, target.file)} has no heading matching #${fragment}`,
        );
      }
    }
  }

  return { checked, errors };
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const result = checkDraftLinks();
  if (result.errors.length > 0) {
    console.error('Draft page link check failed:');
    for (const error of result.errors) {
      console.error(`- ${error}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`Verified ${result.checked} draft page links.`);
  }
}
