import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const defaultSiteRoot = resolve(import.meta.dirname, '..');
const sealedHistoryPages = new Set([
  'src/content/docs/changelog.md',
  'src/content/docs/changelog.mdx',
]);

// Surfaces a current page must not present as available. Draft, historical,
// and sealed history pages keep their record: the check reads only pages that
// claim to describe what ships today.
const removedSurfaces = [
  {
    // Relay V2 replaced the whole tool with relayctl rather than renaming a
    // command hierarchy, so a current page must not hand a reader a registryctl
    // command to run. Naming the tool is not the drift: a current page has to be
    // able to link the retirement decision record, define the retired term in the
    // glossary, and cite the V1 commands it is retiring. Only a runnable
    // invocation is drift, so this reads command position inside a fenced block.
    id: 'removed adopter tool command',
    within: 'fenced-code',
    pattern: /(?:^|[|&;][ \t]*)[ \t]*(?:[$%#>][ \t]*)?(?:sudo[ \t]+)?registryctl\b/gmu,
  },
  {
    // The same instruction written as prose. A cited command inside a sentence
    // ("`registryctl trust bundle sign` was Relay V1 tooling") is a citation and
    // stays; an imperative that tells a reader to run one is drift.
    id: 'removed adopter tool command',
    pattern: /\b(?:run|runs|execute|executes|invoke|invokes)[ \t]+`?registryctl[ \t]+[a-z][\w-]*/giu,
  },
  {
    id: 'removed initializer',
    pattern: /\bregistry-relay[ \t]+init\b/gu,
  },
  {
    id: 'removed live-test environment',
    pattern: /\bREGISTRY_STACK_LIVE_[A-Z0-9_]*\b/gu,
  },
  {
    id: 'removed Bruno surface',
    pattern: /\bbruno\b/giu,
  },
];

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) paths.push(...await markdownFiles(path));
    else if (entry.isFile() && /\.mdx?$/u.test(entry.name)) paths.push(path);
  }
  return paths;
}

function frontmatter(source, path) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u);
  if (!match) throw new Error(`${path} has no frontmatter`);
  const status = match[1].match(/^status:[ \t]*(\S.*)$/mu)?.[1]?.trim();
  const draft = /^draft:[ \t]*true[ \t]*$/mu.test(match[1]);
  return { status, draft };
}

function lineNumber(source, index) {
  return source.slice(0, index).split('\n').length;
}

// Blanks every character outside a fenced code block, keeping offsets and line
// breaks, so a surface scoped to `fenced-code` reads only runnable blocks and
// still reports the line it matched on. Fence delimiters themselves are blanked:
// a match must be on a command line, not on the ```sh that opens one.
function fencedCodeOnly(source) {
  let open = null;
  return source
    .split('\n')
    .map((line) => {
      const blank = ' '.repeat(line.length);
      const fence = line.match(/^[ \t]*(`{3,}|~{3,})/u)?.[1];
      if (fence && (open === null || fence[0] === open)) {
        open = open === null ? fence[0] : null;
        return blank;
      }
      return open === null ? blank : line;
    })
    .join('\n');
}

function isSealedHistoryPage(siteRelative) {
  return (
    sealedHistoryPages.has(siteRelative) ||
    /\/(?:changelog|release-notes)(?:\/index)?\.mdx?$/u.test(siteRelative)
  );
}

export async function findRemovedSurfaces(siteRoot = defaultSiteRoot) {
  const contentRoot = resolve(siteRoot, 'src/content/docs');
  const findings = [];
  for (const path of await markdownFiles(contentRoot)) {
    const source = await readFile(path, 'utf8');
    const metadata = frontmatter(source, path);
    const siteRelative = relative(siteRoot, path);
    if (
      metadata.status !== 'current' ||
      metadata.draft ||
      isSealedHistoryPage(siteRelative)
    ) {
      continue;
    }
    const fencedCode = fencedCodeOnly(source);
    for (const surface of removedSurfaces) {
      const searched = surface.within === 'fenced-code' ? fencedCode : source;
      for (const match of searched.matchAll(surface.pattern)) {
        findings.push({
          path: siteRelative,
          line: lineNumber(source, match.index),
          surface: surface.id,
          match: match[0].trim(),
        });
      }
    }
  }
  return findings.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.line - right.line ||
      left.match.localeCompare(right.match),
  );
}

export async function checkCurrentDocCutover(siteRoot = defaultSiteRoot) {
  const findings = await findRemovedSurfaces(siteRoot);
  if (findings.length === 0) return;
  const details = findings.map(
    ({ path, line, surface, match }) =>
      `${path}:${line}: ${surface}: ${JSON.stringify(match)}`,
  );
  throw new Error(
    [
      'Removed pre-1.0 surfaces remain in current documentation.',
      ...details,
      'Remove prescriptive historical command mappings from current documentation.',
    ].join('\n'),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await checkCurrentDocCutover();
  console.log('Current documentation prescribes no retired adopter-tool command.');
}
