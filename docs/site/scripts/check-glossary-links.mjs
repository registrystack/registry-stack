#!/usr/bin/env node

// Holds the glossary to the pages that use it.
//
// A glossary term earns its entry by being linked from a page: a reader
// arrives at a definition from the sentence that needed it, never from the
// top of a long list. So every `<dt>` in reference/glossary.mdx carries an
// `id`, every `id` is linked from at least one other page under
// src/content/docs, and every link into the glossary points at an `id` that
// exists. A term no page links is deleted or linked; the check does not
// decide which.
//
// Links are matched as text (`glossary/#term` in a Markdown link or an HTML
// href), so a link inside a code span would count. None does today, and a
// term linked only from a code span would be a stranger kind of mistake.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

export const GLOSSARY_PAGE = 'reference/glossary.mdx';

function markdownFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...markdownFiles(path));
    else if (/\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found;
}

// The terms a glossary page defines: one entry per `<dt>`, with its `id` when
// it carries one.
export function glossaryTerms(text) {
  const terms = [];
  for (const match of text.matchAll(/<dt(?<attributes>[^>]*)>(?<term>[\s\S]*?)<\/dt>/gu)) {
    const id = match.groups.attributes.match(/\bid="(?<id>[^"]*)"/u)?.groups.id;
    terms.push({ term: match.groups.term.trim(), id });
  }
  return terms;
}

// The glossary anchors a page links: `glossary/#term` wherever it appears, and
// `#term` alone when the page is the glossary itself.
export function glossaryAnchors(text, { isGlossary = false } = {}) {
  const anchors = [];
  for (const match of text.matchAll(/glossary\/?#(?<id>[A-Za-z0-9_-]+)/gu)) {
    anchors.push(match.groups.id);
  }
  if (isGlossary) {
    for (const match of text.matchAll(/href="#(?<id>[A-Za-z0-9_-]+)"/gu)) {
      anchors.push(match.groups.id);
    }
  }
  return anchors;
}

export function checkGlossaryLinks({ docsDir = resolve(scriptDir, '../src/content/docs') } = {}) {
  const errors = [];
  const glossaryFile = join(docsDir, GLOSSARY_PAGE);
  const terms = glossaryTerms(readFileSync(glossaryFile, 'utf8'));

  const ids = new Set();
  for (const { term, id } of terms) {
    if (id === undefined || id === '') {
      errors.push(`${GLOSSARY_PAGE}: "${term}" has no id, so no page can link it`);
    } else if (ids.has(id)) {
      errors.push(`${GLOSSARY_PAGE}: id "${id}" is defined twice`);
    } else {
      ids.add(id);
    }
  }

  const linkedFrom = new Map([...ids].map((id) => [id, new Set()]));
  let links = 0;
  for (const file of markdownFiles(docsDir)) {
    const page = relative(docsDir, file);
    const isGlossary = page === GLOSSARY_PAGE;
    for (const id of glossaryAnchors(readFileSync(file, 'utf8'), { isGlossary })) {
      links += 1;
      if (!ids.has(id)) {
        errors.push(`${page}: links glossary term "${id}", which the glossary does not define`);
      } else if (!isGlossary) {
        linkedFrom.get(id).add(page);
      }
    }
  }

  for (const [id, pages] of linkedFrom) {
    if (pages.size === 0) {
      errors.push(`${GLOSSARY_PAGE}: "${id}" is linked from no page; link it or delete it`);
    }
  }

  return { terms: terms.length, links, errors };
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const result = checkGlossaryLinks();
  if (result.errors.length > 0) {
    console.error('Glossary link check failed:');
    for (const error of result.errors) {
      console.error(`- ${error}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`Verified ${result.terms} glossary terms against ${result.links} links.`);
  }
}
