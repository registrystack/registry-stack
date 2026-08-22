#!/usr/bin/env node

// Validates the {/* Evidence: ... */} anchors that carry every factual claim the
// documentation makes about the source repository: the paths they cite exist, the
// line references they carry are inside those files, and the symbols they name are
// present in at least one path the same anchor cites.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

// Prose words that carry a symbol shape but name a language, never an item in the
// repository. Keep this list minimal: an entry here is a symbol the checker can no
// longer catch when it goes stale.
export const PROSE_SYMBOL_ALLOWLIST = new Set([
  // "the JavaScript example", "the TypeScript declarations": language names.
  'JavaScript',
  'TypeScript',
]);

// Directories a repository-relative citation may start from.
const REPOSITORY_ROOTS = ['crates', 'products', 'release', 'docs', 'external', '\\.github'];
// Directories a continuation citation may start from, resolved against the crate or
// product root of the most recently cited path in the same anchor.
const CONTINUATION_ROOTS = ['src', 'tests', 'examples', 'benches', 'schemas', 'scripts'];
// Extensions that make a bare token a sibling filename rather than ordinary prose.
const SOURCE_EXTENSIONS = [
  'rs',
  'mjs',
  'md',
  'py',
  'sh',
  'rhai',
  'toml',
  'yaml',
  'yml',
  'jsonld',
  'json',
];
// Extensions read when a symbol has to be looked for inside a cited directory.
const TEXT_EXTENSIONS = new Set([
  ...SOURCE_EXTENSIONS,
  'js',
  'ts',
  'txt',
  'sql',
  'snap',
  'html',
  'css',
  'lock',
]);
const SKIPPED_DIRECTORIES = new Set(['target', 'node_modules', '.git', 'dist', '.astro']);
// Where a continuation with no full path before it is read from: the site the anchor
// itself lives in, whose own src/ tree the docs pages cite.
const DOCS_SITE_ROOT = 'docs/site';

const ANCHOR_PATTERN = /\{\/\*\s*Evidence:([\s\S]*?)\*\/\}/g;
const CITATION_PATTERN = new RegExp(
  [
    `(?<full>(?<![\\w/.-])(?:${REPOSITORY_ROOTS.join('|')})(?:/[A-Za-z0-9._-]+)+/?(?::\\d+(?:-\\d+)?)?)`,
    `(?<relative>(?<![\\w/.-])(?:${CONTINUATION_ROOTS.join('|')})(?:/[A-Za-z0-9._-]+)+/?(?::\\d+(?:-\\d+)?)?)`,
    `(?<sibling>(?<![\\w/.-])[A-Za-z0-9_-]+\\.(?:${SOURCE_EXTENSIONS.join('|')})(?![\\w/-])(?::\\d+(?:-\\d+)?)?)`,
    `(?<lines>(?<=[\\s(]):\\d+(?:-\\d+)?(?![\\w-]))`,
  ].join('|'),
  'g',
);
const LINE_SUFFIX = /^(?<path>.*?)(?::(?<start>\d+)(?:-(?<end>\d+))?)?$/;
const WORD_PATTERN = /[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_]*/g;
const SCREAMING_SNAKE_CASE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const SNAKE_CASE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const UPPER_CAMEL_CASE = /^(?:[A-Z][a-z0-9]+){2,}$/;
// A configuration or wire key: the internal capital is what holds it apart from prose.
const LOWER_CAMEL_CASE = /^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+$/;

export function extractAnchors(text) {
  const anchors = [];
  for (const match of text.matchAll(ANCHOR_PATTERN)) {
    const line = text.slice(0, match.index).split('\n').length;
    anchors.push({ line, body: match[1] });
  }
  return anchors;
}

function splitLineReference(token) {
  const groups = LINE_SUFFIX.exec(token)?.groups;
  if (!groups) {
    return { path: token };
  }
  const start = groups.start === undefined ? undefined : Number(groups.start);
  const end = groups.end === undefined ? start : Number(groups.end);
  // A sentence that ends on a path leaves its full stop inside the token.
  return { path: groups.path.replace(/\.+$/, ''), start, end };
}

// The crate, product, or top-level unit a continuation citation is resolved against.
function citationRoot(path) {
  const segments = path.split('/');
  return ['crates', 'products', 'docs', 'external'].includes(segments[0]) && segments.length > 1
    ? `${segments[0]}/${segments[1]}`
    : segments[0];
}

function joinPath(base, tail) {
  return base === '' ? tail : `${base}/${tail}`;
}

// Every citation carries the ordered candidate paths it may resolve to, and whether a
// candidate is a claim or a guess. A full repository path, a continuation anchored to
// one, and a continuation read against the docs site plainly name a repository path, so
// a miss is drift and is reported. A bare sibling filename is only a reading of the
// prose: when nothing resolves, it names a file the repository does not own (an
// adopter's configuration file, or a path inside a generated package) and is left alone.
export function parseAnchor(body, { siteRoot = DOCS_SITE_ROOT } = {}) {
  const citations = [];
  const strippedParts = [];
  let cursor = 0;
  let lastCitedPath;
  let previous;

  for (const match of body.matchAll(CITATION_PATTERN)) {
    const { full, relative: continuation, sibling, lines } = match.groups;
    strippedParts.push(body.slice(cursor, match.index), ' ');
    cursor = match.index + match[0].length;

    if (lines !== undefined) {
      if (!previous) {
        continue;
      }
      const { start, end } = splitLineReference(`_${lines}`);
      citations.push({ ...previous, form: 'lines', raw: lines, start, end });
      continue;
    }

    const token = full ?? continuation ?? sibling;
    const { path, start, end } = splitLineReference(token);
    const trimmed = path.replace(/\/$/, '');
    // A line suffix the anchor cut short, `:5-`, leaves its hyphen outside the token and
    // would otherwise read as the single line 5 rather than the range it was meant to be.
    const malformedLines = start !== undefined && body.startsWith('-', cursor);
    const parentOfLastCitedPath =
      lastCitedPath === undefined || dirname(lastCitedPath) === '.' ? '' : dirname(lastCitedPath);
    let citation;
    if (full !== undefined) {
      citation = { form: 'full', candidates: [trimmed], reportMissing: true };
    } else if (continuation !== undefined && lastCitedPath === undefined) {
      citation = {
        form: 'continuation',
        candidates: [joinPath(siteRoot, trimmed)],
        reportMissing: true,
      };
    } else if (continuation !== undefined) {
      citation = {
        form: 'continuation',
        candidates: [
          joinPath(citationRoot(lastCitedPath), trimmed),
          joinPath(parentOfLastCitedPath, trimmed),
        ],
        reportMissing: true,
      };
    } else if (lastCitedPath === undefined) {
      // A sibling filename with no path before it has nothing to sit beside.
      continue;
    } else {
      citation = {
        form: 'sibling',
        candidates: [
          joinPath(parentOfLastCitedPath, trimmed),
          joinPath(citationRoot(lastCitedPath), trimmed),
          joinPath(lastCitedPath, trimmed),
        ],
        reportMissing: false,
        basename: trimmed,
        // A bare filename may name a file the repository keeps at its root, Cargo.toml
        // or deny.toml, which sits beside no cited path at all. It is tried only after
        // the search inside the cited unit, so a nearer file always wins.
        rootCandidate: trimmed,
        searchRoot: citationRoot(lastCitedPath),
      };
    }

    citation.candidates = [...new Set(citation.candidates)];
    // What follows reads against the path cited last, whichever form carried it: a
    // continuation moves the anchor on just as a second full path does. A sibling is a
    // reading of the prose rather than a path claim, so it leaves the anchor where it is.
    if (citation.reportMissing) {
      lastCitedPath = citation.candidates[0];
    }
    previous = citation;
    citations.push({ ...citation, raw: token, start, end, malformedLines });
  }

  strippedParts.push(body.slice(cursor));
  return { citations, symbols: extractSymbols(strippedParts.join('')) };
}

// The four shapes that hold a name apart from the prose around it.
function carriesSymbolShape(candidate) {
  return (
    SCREAMING_SNAKE_CASE.test(candidate) ||
    SNAKE_CASE.test(candidate) ||
    UPPER_CAMEL_CASE.test(candidate) ||
    LOWER_CAMEL_CASE.test(candidate)
  );
}

export function extractSymbols(prose) {
  const symbols = [];
  const record = (candidate) => {
    if (PROSE_SYMBOL_ALLOWLIST.has(candidate)) {
      return;
    }
    if (!symbols.includes(candidate)) {
      symbols.push(candidate);
    }
  };

  for (const match of prose.matchAll(WORD_PATTERN)) {
    const token = match[0];
    const segments = token.split('::');
    const candidate = segments.at(-1);
    // Every segment of a qualified path names something the repository holds, so a typo
    // in the module, type, or enum that qualifies the name is drift too. Segments that
    // carry no symbol shape, `std` and `fs` in std::fs::read, name nothing to look for.
    for (const qualifier of segments.slice(0, -1)) {
      if (carriesSymbolShape(qualifier)) {
        record(qualifier);
      }
    }
    // An anchor spells a function reference with empty parentheses, so an identifier
    // written that way is a name whatever its case. Parentheses that carry anything,
    // "the check (see below)", are prose.
    const spelledAsCall = prose.startsWith('()', match.index + token.length);
    if (segments.length === 1 && !spelledAsCall && !carriesSymbolShape(candidate)) {
      continue;
    }
    record(candidate);
  }
  return symbols;
}

// A citation that climbs above the repository, by a `..` segment or by resolving outside
// the root, names nothing the documentation can cite, so it is refused before it is read.
function escapesRepository(repoRoot, path) {
  if (path.split('/').includes('..')) {
    return true;
  }
  const root = resolve(repoRoot);
  const absolute = resolve(root, path);
  return absolute !== root && !absolute.startsWith(`${root}${sep}`);
}

function entryKind(absolute) {
  try {
    return statSync(absolute).isDirectory() ? 'directory' : 'file';
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
      return 'missing';
    }
    throw error;
  }
}

function lineCount(text) {
  const lines = text.split('\n');
  return lines.at(-1) === '' ? lines.length - 1 : lines.length;
}

function filesUnder(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        files.push(...filesUnder(resolve(directory, entry.name)));
      }
      continue;
    }
    if (entry.isFile()) {
      files.push(resolve(directory, entry.name));
    }
  }
  return files;
}

function isTextFile(path) {
  return TEXT_EXTENSIONS.has(path.split('.').at(-1));
}

function wholeWordPattern(symbol) {
  const escaped = symbol.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])`);
}

function pluralLines(count) {
  return count === 1 ? '1 line' : `${count} lines`;
}

function mdxPages(directory) {
  const pages = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      pages.push(...mdxPages(path));
    } else if (entry.isFile() && entry.name.endsWith('.mdx')) {
      pages.push(path);
    }
  }
  return pages.sort();
}

export function checkEvidenceAnchors({
  repoRoot = resolve(scriptDir, '../../..'),
  docsRoot,
  strictLineRefs = false,
} = {}) {
  const contentRoot = docsRoot ?? resolve(repoRoot, 'docs/site/src/content/docs');
  const errors = [];
  const fileTexts = new Map();
  const directoryFiles = new Map();
  let anchors = 0;
  let paths = 0;
  let symbols = 0;
  let lineRefs = 0;

  const readText = (path) => {
    if (!fileTexts.has(path)) {
      fileTexts.set(path, readFileSync(resolve(repoRoot, path), 'utf8'));
    }
    return fileTexts.get(path);
  };

  const listFiles = (path) => {
    if (!directoryFiles.has(path)) {
      const absolute = resolve(repoRoot, path);
      directoryFiles.set(
        path,
        entryKind(absolute) === 'directory'
          ? filesUnder(absolute).map((file) => relative(repoRoot, file).replaceAll('\\', '/'))
          : [],
      );
    }
    return directoryFiles.get(path);
  };

  // A bare sibling filename may name a file that sits elsewhere in the crate or product
  // the anchor already named, so fall back to a single unambiguous match under it.
  const uniqueFileNamed = (root, basename) => {
    const matches = listFiles(root).filter((path) => path.endsWith(`/${basename}`));
    return matches.length === 1 ? matches[0] : undefined;
  };

  for (const page of mdxPages(contentRoot)) {
    const location = relative(contentRoot, page).replaceAll('\\', '/');
    for (const anchor of extractAnchors(readFileSync(page, 'utf8'))) {
      anchors += 1;
      const { citations, symbols: cited } = parseAnchor(anchor.body);
      const at = `${location}:${anchor.line}`;
      const citedFiles = [];
      const citedDirectories = [];
      let lastResolvedFile;

      for (const citation of citations) {
        const range =
          citation.start === undefined
            ? ''
            : `:${citation.start}${citation.end === citation.start ? '' : `-${citation.end}`}`;
        const escaping = citation.candidates.find((candidate) =>
          escapesRepository(repoRoot, candidate),
        );
        if (escaping !== undefined) {
          paths += 1;
          if (range !== '') {
            lineRefs += 1;
          }
          errors.push(`${at} cites ${escaping}${range}, which leaves the repository`);
          continue;
        }
        // A cut-short suffix parses as a line the anchor never meant, so it is reported
        // as the malformed reference it is rather than checked against the file.
        if (citation.malformedLines) {
          paths += 1;
          lineRefs += 1;
          errors.push(
            `${at} cites ${citation.raw}-, but a line reference names a line or a first and last line`,
          );
          continue;
        }
        const resolved =
          citation.candidates.find(
            (candidate) => entryKind(resolve(repoRoot, candidate)) !== 'missing',
          ) ??
          (citation.basename === undefined
            ? undefined
            : uniqueFileNamed(citation.searchRoot, citation.basename)) ??
          (citation.rootCandidate !== undefined &&
          entryKind(resolve(repoRoot, citation.rootCandidate)) !== 'missing'
            ? citation.rootCandidate
            : undefined) ??
          // A bare line reference that follows a filename the repository does not own
          // still belongs to the last file the anchor resolved.
          (citation.form === 'lines' ? lastResolvedFile : undefined);
        if (resolved === undefined && !citation.reportMissing) {
          continue;
        }
        paths += 1;
        if (range !== '') {
          lineRefs += 1;
        }
        if (resolved === undefined) {
          errors.push(`${at} cites ${citation.candidates[0]}${range}, which does not exist`);
          continue;
        }
        if (strictLineRefs && range !== '') {
          errors.push(
            `${at} cites ${resolved}${range}; line numbers drift silently, so name the symbol, test, constant, or key instead`,
          );
        }
        if (entryKind(resolve(repoRoot, resolved)) === 'directory') {
          if (range !== '') {
            errors.push(`${at} cites ${resolved}${range}, but that path is a directory`);
          }
          citedDirectories.push(resolved);
          continue;
        }
        citedFiles.push(resolved);
        lastResolvedFile = resolved;
        if (range === '') {
          continue;
        }
        const count = lineCount(readText(resolved));
        if (citation.start < 1 || citation.end < citation.start) {
          errors.push(
            `${at} cites ${resolved}${range}, but a line range starts at line 1 and ends at or after its start`,
          );
        } else if (citation.start > count || citation.end > count) {
          errors.push(
            `${at} cites ${resolved}${range}, but the file has ${pluralLines(count)}`,
          );
        }
      }

      if (citedFiles.length === 0 && citedDirectories.length === 0) {
        continue;
      }

      for (const symbol of cited) {
        symbols += 1;
        const pattern = wholeWordPattern(symbol);
        const found =
          citedFiles.some((path) => pattern.test(readText(path))) ||
          citedDirectories.some((directory) =>
            listFiles(directory)
              .filter((path) => isTextFile(path))
              .some((path) => pattern.test(readText(path))),
          );
        if (!found) {
          errors.push(`${at} cites ${symbol}, which no cited path contains`);
        }
      }
    }
  }

  return { anchors, paths, symbols, lineRefs, errors };
}

export function parseArguments(args) {
  if (args.length === 0) {
    return { strictLineRefs: false };
  }
  if (args.length === 1 && args[0] === '--strict-line-refs') {
    return { strictLineRefs: true };
  }
  throw new Error('usage: check-evidence-anchors.mjs [--strict-line-refs]');
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = checkEvidenceAnchors(options);
    const counts =
      `${result.anchors} anchors, ${result.paths} cited paths, and ${result.symbols} cited symbols checked; ` +
      `${result.lineRefs} line-range citations found`;
    if (result.errors.length > 0) {
      console.error(result.errors.join('\n'));
      console.error(`Evidence anchor check failed: ${counts}.`);
      process.exitCode = 1;
    } else {
      console.log(`Evidence anchor check passed: ${counts}.`);
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
