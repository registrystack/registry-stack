#!/usr/bin/env node

// Validates the {/* Evidence: ... */} anchors that carry every factual claim the
// documentation makes about the source repository: the paths they cite exist, the
// line references they carry are inside those files, and the symbols they name are
// present in at least one path the same anchor cites.

import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
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

// Directories a repository-relative citation may start from: every top-level directory the
// repository keeps, because a citation into one this list omits parses as no citation at
// all and leaves its anchor checked against nothing. The entries are regular expression
// source, so a dot-directory carries its escape.
export const REPOSITORY_ROOTS = [
  'crates',
  'products',
  'release',
  'docs',
  'docker',
  'editors',
  'external',
  'schemas',
  '\\.cargo',
  '\\.github',
];
// Directories a continuation citation may start from, resolved against the crate or
// product root of the most recently cited path in the same anchor.
const CONTINUATION_ROOTS = ['src', 'tests', 'examples', 'benches', 'schemas', 'scripts'];
// The roots both lists name: a crate or product keeps a schemas/ directory of its own and
// so does the repository. A citation that starts at one is read against the unit cited
// before it first and against the repository root last, so the nearer directory wins, the
// way it does for a bare filename that may name a file kept at the root.
const SHARED_ROOTS = new Set(REPOSITORY_ROOTS.filter((root) => CONTINUATION_ROOTS.includes(root)));
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
// Whether a path named a directory, which is what a bare child citation continues. A dot
// in the last segment is what says a path named a file, so an extensionless script reads
// as a directory. The reading is a syntactic one because nothing here opens the repository.
const NAMES_A_DIRECTORY = /(?:^|\/)[^./]+$/;
// A bare sibling that names a Rust source file is one the repository owns: an adopter of
// this stack writes configuration and scripts, never Rust, and a package the runtime
// generates carries none either. Every other extension a sibling may carry names a file the
// repository need not hold, so only this one turns a miss into drift.
const NAMES_RUST_SOURCE = /\.rs$/;
// A compact list of files that share a directory, `src/{api,startup}.rs`. It is read only
// where a path segment can start, so a brace group the prose itself writes, `{ claim,
// allowed }`, stays prose.
const BRACE_LIST = '\\{[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)+\\}';
// What follows a citation root: path segments, any of which may be a brace list carrying the
// suffix its entries share, then an optional trailing slash and line reference.
const PATH_BODY = `(?:/(?:[A-Za-z0-9._-]+|${BRACE_LIST}[A-Za-z0-9._-]*))+/?(?::\\d+(?:-\\d+)?)?`;
const CITATION_PATTERN = new RegExp(
  [
    `(?<full>(?<![\\w/.-])(?:${REPOSITORY_ROOTS.join('|')})${PATH_BODY})`,
    `(?<relative>(?<![\\w/.-])(?:${CONTINUATION_ROOTS.join('|')})${PATH_BODY})`,
    `(?<sibling>(?<![\\w/.-])[A-Za-z0-9_-]+\\.(?:${SOURCE_EXTENSIONS.join('|')})(?![\\w/-])(?::\\d+(?:-\\d+)?)?)`,
    `(?<child>(?<![\\w/.-])[A-Za-z0-9_-]+/(?![\\w/-]))`,
    `(?<lines>(?<=[\\s(]):\\d+(?:-\\d+)?(?![\\w-]))`,
  ].join('|'),
  'g',
);
const LINE_SUFFIX = /^(?<path>.*?)(?::(?<start>\d+)(?:-(?<end>\d+))?)?$/;
// What a line reference the citation pattern could not read leaves behind the token it
// follows: word characters or a hyphen, which a well-formed reference would have carried
// itself, optionally behind the colon that opens one. A colon the prose writes is followed
// by a space, and a reference the prose punctuates is followed by the punctuation, so
// neither leaves anything this reads.
const UNREAD_LINE_REFERENCE = /^:?[\w-][\w:-]*/;
const WORD_PATTERN = /[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_]*/g;
// A dotted configuration or wire key path, sources.*.authentication.kind. The word pass reads
// its segments one by one and keeps only the ones that carry a symbol shape, so this pattern is
// what puts the whole path back together before that decision is made.
const DOTTED_KEY_PATH = /(?<![\w./-])[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_*]+)+/g;
const SCREAMING_SNAKE_CASE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const SNAKE_CASE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const UPPER_CAMEL_CASE = /^(?:[A-Z][a-z0-9]+){2,}$/;
// The same name with an initialism run into it, OAuthErrorCode or HTTPRedirectHandler,
// whose capitals leave no [A-Z][a-z]+ boundary for the shape above to read. Two lower-case
// runs and one capital run of two or more are what hold it apart from the acronyms the
// prose is full of: OpenAPI, SQLite, OpenCRVS, and EdDSA carry one lower-case run each, and
// SDMX or JWKS carry none, so none of them is read as a name to look for.
const UPPER_CAMEL_CASE_WITH_INITIALISM =
  /^(?=[^a-z]*[a-z]+[^a-z]+[a-z])(?=[A-Za-z0-9]*[A-Z]{2})[A-Z][A-Za-z0-9]*$/;
// A configuration or wire key: the internal capital is what holds it apart from prose.
const LOWER_CAMEL_CASE = /^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+$/;
// An exact wire value spelled in capitals: ES256, RS256, CRS84. Uppercase letters and
// digits only, with at least two letters and at least one digit. The digit is what holds
// it apart from an acronym the prose spells in capitals, JSON or HTTP, and the second
// letter is what holds it apart from a product version word, V1 or V2. Both exclusions
// are deliberate: those words carry no drift a cited file could disprove, and checking
// them would report correct anchors.
const UPPER_CASE_WIRE_VALUE = /^(?=[A-Z0-9]*[0-9])(?=(?:[0-9]*[A-Z]){2})[A-Z0-9]+$/;

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

// One path per brace-list entry: `src/{api,startup}.rs` names two files, so a rename of
// either is drift, and a path with no brace list stands alone as it always did.
function expandBraceLists(path) {
  const match = /\{([A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)+)\}/.exec(path);
  if (!match) {
    return [path];
  }
  const before = path.slice(0, match.index);
  const after = path.slice(match.index + match[0].length);
  return match[1].split(',').flatMap((entry) => expandBraceLists(`${before}${entry}${after}`));
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
// A bare Rust filename is the one sibling that is a claim, because only this repository
// writes Rust into the stack, so a miss there is drift like any other.
/**
 * @typedef {object} Citation
 * @property {string} form which reading produced it, and so which fallbacks apply
 * @property {string[]} candidates the paths it may resolve to, tried in order
 * @property {boolean} reportMissing whether resolving nothing is drift or prose
 * @property {string} [raw] the token as the anchor spelled it
 * @property {number} [start] first line of a line reference
 * @property {number} [end] last line of a line reference
 * @property {string} [malformedLines] the part of a line reference the pattern could not read
 * @property {string} [basename] bare filename to search for when no candidate resolves
 * @property {string} [searchRoot] where that search runs, the empty string for the whole tree
 * @property {string} [rootCandidate] the same name as a file kept at the repository root
 */

export function parseAnchor(body, { siteRoot = DOCS_SITE_ROOT } = {}) {
  /** @type {Citation[]} */
  const citations = [];
  const strippedParts = [];
  let cursor = 0;
  let lastCitedPath;
  let previous;

  for (const match of body.matchAll(CITATION_PATTERN)) {
    const { full, relative: continuation, sibling, child, lines } = match.groups;
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

    const token = full ?? continuation ?? sibling ?? child;
    const { path, start, end } = splitLineReference(token);
    const trimmed = path.replace(/\/$/, '');
    // A line reference the anchor spelled wrong leaves the part the pattern could not read
    // outside the token: the hyphen of a range cut short in `:5-`, the word run into the
    // number in `:1foo`, the whole suffix in `:abc`. Each would otherwise be thrown away,
    // leaving the citation checked as the bare file or as a line the anchor never meant.
    const malformedLines = UNREAD_LINE_REFERENCE.exec(body.slice(cursor))?.[0];

    // A brace list stands for one citation per entry, so each file it names is resolved and
    // counted on its own, and each entry reads against the path the entry before it set.
    for (const cited of expandBraceLists(trimmed)) {
      const parentOfLastCitedPath =
        lastCitedPath === undefined || dirname(lastCitedPath) === '.' ? '' : dirname(lastCitedPath);
      // A path that starts at a shared root is read as a continuation, and carries the
      // repository reading of the same token as its last candidate.
      const shared = full !== undefined && SHARED_ROOTS.has(cited.split('/')[0]);
      /** @type {Citation} */
      let citation;
      if (full !== undefined && !shared) {
        citation = { form: 'full', candidates: [cited], reportMissing: true };
      } else if ((continuation !== undefined || shared) && lastCitedPath === undefined) {
        citation = {
          form: 'continuation',
          candidates: [joinPath(siteRoot, cited), ...(shared ? [cited] : [])],
          reportMissing: true,
        };
      } else if (continuation !== undefined || shared) {
        citation = {
          form: 'continuation',
          candidates: [
            joinPath(citationRoot(lastCitedPath), cited),
            joinPath(parentOfLastCitedPath, cited),
            ...(shared ? [cited] : []),
          ],
          reportMissing: true,
        };
      } else if (child !== undefined) {
        // A bare child names a directory inside the one cited before it, so a rename of
        // that directory is drift and is reported. After a filename there is no directory
        // to continue and the name is prose: `governed/` beside package.rs names a
        // directory the package writes, not one the repository holds.
        if (lastCitedPath === undefined || !NAMES_A_DIRECTORY.test(lastCitedPath)) {
          continue;
        }
        citation = {
          form: 'child',
          candidates: [joinPath(lastCitedPath, cited)],
          reportMissing: true,
        };
      } else if (lastCitedPath === undefined) {
        // A bare filename that opens an anchor has no path to sit beside, so the
        // repository itself is what it is read against: the file kept at the root, then a
        // single unambiguous file of that name anywhere in the tree. It stays a reading of
        // the prose for the same reason a sibling does, and the missing path before it is
        // one more reason: nothing at all says the repository owns the name.
        citation = {
          form: 'sibling',
          candidates: [cited],
          reportMissing: NAMES_RUST_SOURCE.test(cited),
          basename: cited,
          searchRoot: '',
        };
      } else {
        citation = {
          form: 'sibling',
          candidates: [
            joinPath(parentOfLastCitedPath, cited),
            joinPath(citationRoot(lastCitedPath), cited),
            joinPath(lastCitedPath, cited),
          ],
          reportMissing: NAMES_RUST_SOURCE.test(cited),
          basename: cited,
          // A bare filename may name a file the repository keeps at its root, Cargo.toml
          // or deny.toml, which sits beside no cited path at all. It is tried only after
          // the search inside the cited unit, so a nearer file always wins.
          rootCandidate: cited,
          searchRoot: citationRoot(lastCitedPath),
        };
      }

      citation.candidates = [...new Set(citation.candidates)];
      // What follows reads against the path cited last, whichever form carried it: a
      // continuation moves the anchor on just as a second full path does. A sibling names
      // no directory to read the next citation against, so it leaves the anchor where it
      // is whether or not the repository has to hold the file it names.
      if (citation.form !== 'sibling') {
        lastCitedPath = citation.candidates[0];
      }
      previous = citation;
      citations.push({ ...citation, raw: token, start, end, malformedLines });
    }
  }

  strippedParts.push(body.slice(cursor));
  return { citations, symbols: extractSymbols(strippedParts.join('')) };
}

// The shapes that hold a name apart from the prose around it.
function carriesSymbolShape(candidate) {
  return (
    SCREAMING_SNAKE_CASE.test(candidate) ||
    SNAKE_CASE.test(candidate) ||
    UPPER_CAMEL_CASE.test(candidate) ||
    UPPER_CAMEL_CASE_WITH_INITIALISM.test(candidate) ||
    LOWER_CAMEL_CASE.test(candidate) ||
    UPPER_CASE_WIRE_VALUE.test(candidate)
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

  // A dotted key path names one key per segment, and a segment such as the credentials of
  // evidence_data_request.transport_absences.credentials carries no shape of its own, so the
  // word pass below drops it and a typo there goes unreported. One segment already carrying a
  // symbol shape is what holds a key path apart from a domain name, id.registrystack.org, or a
  // version string, v0.9.0, whose segments name nothing to look for.
  for (const match of prose.matchAll(DOTTED_KEY_PATH)) {
    const segments = match[0].split('.');
    if (!segments.some(carriesSymbolShape)) {
      continue;
    }
    for (const segment of segments) {
      // A wildcard segment stands for any key rather than naming one.
      if (segment !== '*') {
        record(segment);
      }
    }
  }

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

// The path a read would really open. A path the repository does not hold has none, and
// stays the missing citation it already was rather than becoming an escape.
function realPath(absolute) {
  try {
    return realpathSync(absolute);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
      return undefined;
    }
    throw error;
  }
}

// A citation that climbs above the repository, by a `..` segment or by resolving outside
// the root, names nothing the documentation can cite, so it is refused before it is read.
function escapesRepository(repoRoot, path) {
  if (path.split('/').includes('..')) {
    return true;
  }
  const root = resolve(repoRoot);
  const absolute = resolve(root, path);
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) {
    return true;
  }
  // A symlink passes the check above and is then followed by both the stat and the read,
  // so the real path is what decides. The root is resolved too: a macOS temporary
  // directory is itself reached through a symlink, and an unresolved root would call
  // every path beneath it an escape.
  const realRoot = realPath(root);
  const realAbsolute = realPath(absolute);
  if (realRoot === undefined || realAbsolute === undefined) {
    return false;
  }
  return realAbsolute !== realRoot && !realAbsolute.startsWith(`${realRoot}${sep}`);
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
  // the anchor already named, so fall back to a single unambiguous match under it. The
  // root is the repository itself when the filename opened the anchor and named no unit
  // to search inside.
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
      const reportedBefore = errors.length;
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
        if (citation.malformedLines !== undefined) {
          paths += 1;
          lineRefs += 1;
          errors.push(
            `${at} cites ${citation.raw}${citation.malformedLines}, but a line reference names a line or a first and last line`,
          );
          continue;
        }
        let resolved = citation.candidates.find(
          (candidate) => entryKind(resolve(repoRoot, candidate)) !== 'missing',
        );
        if (resolved === undefined && citation.basename !== undefined) {
          resolved = uniqueFileNamed(citation.searchRoot, citation.basename);
        }
        // The file kept at the repository root is the last place a bare filename is looked
        // for, and the one resolution the escape check above cannot have seen, because the
        // root candidate is no member of the candidate list. A root file that a symlink
        // leads out of the checkout is refused here rather than read, and refusing it is
        // reported: it is the only thing that would have resolved.
        if (
          resolved === undefined &&
          citation.rootCandidate !== undefined &&
          entryKind(resolve(repoRoot, citation.rootCandidate)) !== 'missing'
        ) {
          if (escapesRepository(repoRoot, citation.rootCandidate)) {
            paths += 1;
            if (range !== '') {
              lineRefs += 1;
            }
            errors.push(
              `${at} cites ${citation.rootCandidate}${range}, which leaves the repository`,
            );
            continue;
          }
          resolved = citation.rootCandidate;
        }
        if (resolved === undefined && citation.form === 'lines') {
          // A bare line reference that follows a filename the repository does not own
          // still belongs to the last file the anchor resolved.
          resolved = lastResolvedFile;
        }
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
        // An anchor that resolves no path has nothing to read its symbols against, so
        // letting it pass would state a guarantee the check never made for it. An anchor
        // whose citations were reported already fails, and naming it twice names no
        // further drift.
        if (errors.length === reportedBefore) {
          errors.push(
            citations.length === 0
              ? `${at} cites no path in this repository, so nothing it claims was checked`
              : `${at} resolves none of the paths it cites, so nothing it claims was checked`,
          );
        }
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
