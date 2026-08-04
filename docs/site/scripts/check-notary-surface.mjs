import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const defaultSiteRoot = resolve(import.meta.dirname, '..');

// Registry Notary is retired, and no adopter ever ran it, so a current page has
// nobody to orient: naming the product only to say it is gone leaves the reader
// carrying a name that means nothing to them. The record of the retirement
// lives on the history pages. Two things survive on the product surface.
//
// The identifier outlived the product. A frozen posture shape, a Relay startup
// validator, a manifest access kind, and a pinned image name all still spell
// `registry-notary`, and a page documenting one of those has to write it down.
// Written as code, the word is an identifier and not a product on offer.
const codeSpan = /`[^`]*`/gu;

// A specification's version table is that document's own history, held to the
// same rule as the changelog and the decision records. `blocks()` gives each
// table row separately, so this matches a row and never the prose around it.
const versionHistoryRow = /^\|\s*\d+\.\d+(?:\.\d+)?\s*\|\s*\d{4}-\d{2}-\d{2}\s*\|/u;

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await markdownFiles(path)));
    else if (entry.isFile() && entry.name.endsWith('.mdx')) paths.push(path);
  }
  return paths;
}

function frontmatter(source, path) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u);
  if (!match) throw new Error(`${path} has no frontmatter`);
  return {
    status: match[1].match(/^status:[ \t]*(\S.*)$/mu)?.[1]?.trim(),
    draft: /^draft:[ \t]*true[ \t]*$/mu.test(match[1]),
  };
}

// `status: draft` marks a page as under review; it does not hide it, so a
// reader still meets it. `status: historical` and `deprecated` are the marked
// past, and `draft: true` is unpublished.
function isProductSurface(status) {
  return status === 'current' || status === 'draft';
}

// History keeps the name: the changelog and the decision records are the record
// of what happened, not a description of what to run.
function isHistoryPage(siteRelative) {
  return (
    siteRelative.startsWith('src/content/docs/decisions/') ||
    /\/(?:changelog|release-notes)(?:\/index)?\.mdx$/u.test(siteRelative)
  );
}

// A table row or list item stands alone; ordinary prose is judged by paragraph,
// because a sentence is hard-wrapped across several lines.
function blocks(source) {
  const found = [];
  let start = 0;
  let text = '';
  const flush = () => {
    if (text.trim()) found.push({ text, start });
    text = '';
  };
  let offset = 0;
  for (const line of source.split('\n')) {
    const standalone = /^\s*(?:[|*-]|\d+\.)/u.test(line);
    if (!line.trim() || standalone) flush();
    if (line.trim()) {
      if (!text) start = offset;
      text += `${line}\n`;
      if (standalone) flush();
    }
    offset += line.length + 1;
  }
  flush();
  return found;
}

function lineNumber(source, index) {
  return source.slice(0, index).split('\n').length;
}

export async function findNotaryMentions(siteRoot = defaultSiteRoot) {
  const contentRoot = resolve(siteRoot, 'src/content/docs');
  const findings = [];
  for (const path of await markdownFiles(contentRoot)) {
    const source = await readFile(path, 'utf8');
    const metadata = frontmatter(source, path);
    const siteRelative = relative(siteRoot, path);
    if (
      !isProductSurface(metadata.status) ||
      metadata.draft ||
      siteRelative.startsWith('src/content/docs/products/') ||
      isHistoryPage(siteRelative)
    ) {
      continue;
    }
    for (const block of blocks(source)) {
      if (!/notary/iu.test(block.text)) continue;
      if (versionHistoryRow.test(block.text.trim())) continue;
      if (!/notary/iu.test(block.text.replace(codeSpan, ''))) continue;
      findings.push({
        path: siteRelative,
        line: lineNumber(source, block.start),
        excerpt: block.text.trim().split('\n')[0].slice(0, 90),
      });
    }
  }
  return findings.sort(
    (left, right) => left.path.localeCompare(right.path) || left.line - right.line,
  );
}

export async function checkNotarySurface(siteRoot = defaultSiteRoot) {
  const findings = await findNotaryMentions(siteRoot);
  if (findings.length === 0) return;
  throw new Error(
    [
      'Current documentation names Registry Notary, which no adopter can meet.',
      ...findings.map(({ path, line, excerpt }) => `${path}:${line}: ${excerpt}`),
      'Rewrite the page around Registry Relay, Evidence, and Registry Mint. Leave',
      'the retirement itself to the decision record and the changelog. Where a',
      'shipped schema, validator, or image name still spells the identifier,',
      'write it as code and say nothing about the product behind it.',
    ].join('\n'),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await checkNotarySurface();
  console.log('Notary surface check passed: no current page names Registry Notary.');
}
