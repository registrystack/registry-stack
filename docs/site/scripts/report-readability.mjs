#!/usr/bin/env node

// Report-only: prints plain-English measures for each page under
// src/content/docs, so writers can see where sentences run long. Never a gate;
// exits 0 whenever the pages can be read.
//
// Per page: sentences, sentences over the word ceiling, semicolons, and commas
// per sentence. Frontmatter, imports, MDX comments, JSX and HTML tags, fenced
// code and inline code are not prose and are not counted.
//
// Usage: node scripts/report-readability.mjs [--docs <dir>]

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

export const MAX_SENTENCE_WORDS = 25;

function markdownFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...markdownFiles(path));
    else if (/\.(md|mdx)$/.test(entry.name)) found.push(path);
  }
  return found.sort();
}

// The prose blocks of a page: one string per paragraph, list item, heading-free
// table cell row or HTML text run, with everything that is not prose removed.
export function proseBlocks(source) {
  const text = source
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '')
    .replace(/^(?:```|~~~)[^\n]*\n[\s\S]*?^(?:```|~~~)[ \t]*$/gm, '')
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/^(?:import|export)\s.*$/gm, '')
    .replace(/`[^`\n]*`/g, '')
    .replace(/<\/?[A-Za-z][^>]*>/g, ' ')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1')
    .replace(/<(https?:[^>\s]+)>/g, '')
    .replace(/https?:\/\/\S+/g, '');
  const blocks = [];
  let current = [];
  const flush = () => {
    if (current.length > 0) blocks.push(current.join(' ').replace(/\s+/g, ' ').trim());
    current = [];
  };
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || /^#{1,6}\s/.test(trimmed) || /^\|?\s*:?-{2,}/.test(trimmed)) {
      flush();
    } else if (trimmed.startsWith('|')) {
      flush();
      for (const cell of trimmed.split('|')) if (cell.trim() !== '') blocks.push(cell.trim());
    } else if (/^(?:[-*+]|\d+[.)])\s/.test(trimmed)) {
      flush();
      current.push(trimmed.replace(/^(?:[-*+]|\d+[.)])\s+/, ''));
    } else {
      current.push(trimmed.replace(/^>\s?/, ''));
    }
  }
  flush();
  return blocks.map((block) => block.replace(/[*_]{1,3}/g, '')).filter(Boolean);
}

const ABBREVIATIONS = /\b(?:e\.g|i\.e|etc|vs|cf|no)\.$/i;

// Splits a prose block at a full stop, question mark or exclamation mark that
// is followed by a space and a capital letter, or ends the block. A semicolon
// does not end a sentence.
export function sentences(block) {
  const found = [];
  let start = 0;
  for (const match of block.matchAll(/[.!?]+(?=\s+[A-Z"'(\[]|\s*$)/g)) {
    const end = match.index + match[0].length;
    const candidate = block.slice(start, end);
    if (ABBREVIATIONS.test(candidate)) continue;
    found.push(candidate.trim());
    start = end;
  }
  const rest = block.slice(start).trim();
  if (rest !== '') found.push(rest);
  return found.filter((sentence) => /[\p{L}\p{N}]/u.test(sentence));
}

export function wordCount(sentence) {
  return (sentence.match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu) ?? []).length;
}

export function measure(source, { maxWords = MAX_SENTENCE_WORDS } = {}) {
  const all = proseBlocks(source).flatMap(sentences);
  let long = 0;
  let semicolons = 0;
  let commas = 0;
  for (const sentence of all) {
    if (wordCount(sentence) > maxWords) long += 1;
    semicolons += (sentence.match(/;/g) ?? []).length;
    commas += (sentence.match(/,/g) ?? []).length;
  }
  return { sentences: all.length, long, semicolons, commas };
}

const perSentence = ({ sentences: count, commas }) => (count === 0 ? 0 : commas / count);

export function reportReadability({ docsDir = resolve(scriptDir, '../src/content/docs') } = {}) {
  const pages = markdownFiles(docsDir).map((file) => ({
    page: relative(docsDir, file),
    ...measure(readFileSync(file, 'utf8')),
  }));
  const total = pages.reduce(
    (sum, page) => ({
      sentences: sum.sentences + page.sentences,
      long: sum.long + page.long,
      semicolons: sum.semicolons + page.semicolons,
      commas: sum.commas + page.commas,
    }),
    { sentences: 0, long: 0, semicolons: 0, commas: 0 },
  );
  return { pages, total };
}

export function formatReport({ pages, total }) {
  const row = (name, m) =>
    `${String(m.sentences).padStart(9)} ${String(m.long).padStart(5)} ${String(m.semicolons).padStart(5)} ${perSentence(m).toFixed(2).padStart(9)}  ${name}`;
  const lines = [`sentences  >${MAX_SENTENCE_WORDS}w  semis  commas/s  page`];
  for (const page of pages) lines.push(row(page.page, page));
  lines.push('', row(`TOTAL (${pages.length} pages)`, total));
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const docsFlag = process.argv.indexOf('--docs');
  const docsDir = docsFlag === -1 ? undefined : resolve(process.argv[docsFlag + 1]);
  console.log(formatReport(reportReadability(docsDir ? { docsDir } : {})));
}
