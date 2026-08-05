import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const defaultSiteRoot = resolve(import.meta.dirname, '..');
const sealedHistoryPages = new Set([
  'src/content/docs/changelog.mdx',
]);

const removedSurfaces = [
  {
    id: 'removed top-level command',
    pattern:
      /\bregistryctl[ \t]+(?:add|start|stop|restart|status|open|smoke|logs|preflight|capabilities|compare|promote|migrate|bundle|anchor|authoring|project)\b/gu,
  },
  {
    id: 'removed initializer',
    pattern: /\b(?:registryctl[ \t]+init[ \t]+(?:--from\b|relay\b)|registry-relay[ \t]+init\b)/gu,
  },
  {
    id: 'removed live test',
    pattern: /\bregistryctl[ \t]+test\b[^\n]*[ \t]--live\b/gu,
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
    else if (entry.isFile() && entry.name.endsWith('.mdx')) paths.push(path);
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

function isSealedHistoryPage(siteRelative) {
  return (
    sealedHistoryPages.has(siteRelative) ||
    /\/(?:changelog|release-notes)(?:\/index)?\.mdx$/u.test(siteRelative)
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
    for (const surface of removedSurfaces) {
      for (const match of source.matchAll(surface.pattern)) {
        findings.push({
          path: siteRelative,
          line: lineNumber(source, match.index),
          surface: surface.id,
          match: match[0],
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
  console.log('Current documentation uses only the Registryctl 1.0 command hierarchy.');
}
