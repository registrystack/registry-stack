#!/usr/bin/env node

// Refuses root-absolute internal links in docs pages.
//
// The deployed site serves the released docset at the root and the Main
// docset under /dev/. A Markdown link or HTML href such as
// `/explanation/how-evidence-works/` is emitted unchanged, so on a /dev/ page
// it resolves to the released tree, not the Main one, and the assembled
// deploy's built link check fails whenever that page or anchor differs
// between Main and the release. A build of one docset alone serves it at `/`,
// so scripts/check-built-links.mjs cannot see the mistake before the deploy
// does. A relative link resolves inside whichever docset carries the page.
//
// Links are read from the parsed Markdown, so code spans and fenced code are
// not links. Frontmatter is out of scope. External URLs, protocol-relative
// `//` URLs, and fragment-only links pass.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { unified } from 'unified';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const parser = unified().use(remarkParse).use(remarkGfm);

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

function markdownFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...markdownFiles(path));
    else if (/\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found;
}

// Blanks a leading YAML frontmatter block, keeping its newlines so the line
// numbers of the body stay those of the file.
function withoutFrontmatter(text) {
  const match = text.match(/^---\n[\s\S]*?\n---\n/u);
  if (!match) return text;
  return match[0].replace(/[^\n]/gu, '') + text.slice(match[0].length);
}

function isRootAbsolute(target) {
  return target.startsWith('/') && !target.startsWith('//');
}

// The root-absolute link targets on a page, each with its 1-based line.
export function rootAbsoluteLinks(text) {
  const found = [];
  for (const node of nodes(parser.parse(withoutFrontmatter(text)))) {
    if (['link', 'image', 'definition'].includes(node.type)) {
      if (isRootAbsolute(node.url)) found.push({ line: node.position.start.line, target: node.url });
    } else if (node.type === 'html') {
      for (const match of node.value.matchAll(/\bhref=(?<quote>["'])(?<target>.*?)\k<quote>/gu)) {
        if (!isRootAbsolute(match.groups.target)) continue;
        const line = node.position.start.line + (node.value.slice(0, match.index).match(/\n/gu)?.length ?? 0);
        found.push({ line, target: match.groups.target });
      }
    }
  }
  return found.sort((a, b) => a.line - b.line);
}

export function checkRelativeLinks({ docsDir = resolve(scriptDir, '../src/content/docs') } = {}) {
  const errors = [];
  let checked = 0;
  for (const file of markdownFiles(docsDir).sort()) {
    checked += 1;
    const label = relative(docsDir, file);
    for (const { line, target } of rootAbsoluteLinks(readFileSync(file, 'utf8'))) {
      errors.push(
        `${label}:${line}: ${target} is root-absolute; use a relative link so it resolves inside the docset that serves the page`,
      );
    }
  }
  return { checked, errors };
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const result = checkRelativeLinks();
  if (result.errors.length > 0) {
    console.error('Relative link check failed:');
    for (const error of result.errors) {
      console.error(`- ${error}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`Verified relative internal links on ${result.checked} docs pages.`);
  }
}
