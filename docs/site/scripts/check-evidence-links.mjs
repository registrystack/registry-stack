#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

const SAME_REPOSITORY = 'https://github.com/registrystack/registry-stack';
const SEMVER_TAG =
  /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const FULL_COMMIT = /^[0-9a-f]{40}$/;

function parseYamlScalar(value, location) {
  const trimmed = value.trim();
  if (trimmed.startsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`${location} has an invalid quoted URL: ${error.message}`);
    }
  }
  if (trimmed.startsWith("'")) {
    if (!trimmed.endsWith("'")) {
      throw new Error(`${location} has an unterminated quoted URL`);
    }
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (trimmed === '|' || trimmed === '>') {
    throw new Error(`${location} must use a single-line URL scalar`);
  }
  return trimmed;
}

export function extractEvidenceUrlsFromYaml(text, kind) {
  const urls = [];
  let inEvidenceBlock = false;

  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (kind === 'contracts' && /^  source_of_truth:\s*$/.test(line)) {
      inEvidenceBlock = true;
      continue;
    }
    if (kind === 'standards' && /^  evidence_docs:\s*$/.test(line)) {
      inEvidenceBlock = true;
      continue;
    }
    if (!inEvidenceBlock) {
      continue;
    }
    if (/^  \S/.test(line)) {
      inEvidenceBlock = false;
      continue;
    }

    const indentation = kind === 'contracts' ? 4 : 6;
    const match = new RegExp(`^ {${indentation}}url:\\s*(.+?)\\s*$`).exec(line);
    if (match) {
      urls.push(parseYamlScalar(match[1], `${kind}.yaml:${index + 1}`));
    }
  }

  return urls;
}

function generatedEvidenceUrls(data, kind) {
  if (!Array.isArray(data)) {
    throw new Error(`generated/${kind}.json must contain a top-level list`);
  }
  if (kind === 'contracts') {
    return data.map((entry, index) => {
      const url = entry?.source_of_truth?.url;
      if (typeof url !== 'string' || url.length === 0) {
        throw new Error(`generated/contracts.json entry ${index + 1} has no source URL`);
      }
      return url;
    });
  }
  return data.flatMap((entry, entryIndex) => {
    if (!Array.isArray(entry?.evidence_docs)) {
      throw new Error(`generated/standards.json entry ${entryIndex + 1} has no evidence_docs`);
    }
    return entry.evidence_docs.map((evidence, evidenceIndex) => {
      if (typeof evidence?.url !== 'string' || evidence.url.length === 0) {
        throw new Error(
          `generated/standards.json entry ${entryIndex + 1} evidence ${evidenceIndex + 1} has no URL`,
        );
      }
      return evidence.url;
    });
  });
}

function readEvidenceUrls(dataDir) {
  const urls = [];
  for (const kind of ['contracts', 'standards']) {
    const yamlUrls = extractEvidenceUrlsFromYaml(
      readFileSync(resolve(dataDir, `${kind}.yaml`), 'utf8'),
      kind,
    );
    const generatedUrls = generatedEvidenceUrls(
      JSON.parse(readFileSync(resolve(dataDir, 'generated', `${kind}.json`), 'utf8')),
      kind,
    );
    if (JSON.stringify(yamlUrls) !== JSON.stringify(generatedUrls)) {
      throw new Error(
        `${kind}.yaml evidence URLs differ from generated/${kind}.json; run npm run generate`,
      );
    }
    urls.push(...yamlUrls.map((url, index) => ({ location: `${kind}[${index + 1}]`, url })));
  }
  return urls;
}

function gitObjectExists(repoRoot, object, gitCommand) {
  return (
    spawnSync(gitCommand, ['cat-file', '-e', object], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, GIT_NO_LAZY_FETCH: '1' },
      stdio: 'pipe',
    }).status === 0
  );
}

function safePathParts(parts) {
  try {
    return parts.map((part) => decodeURIComponent(part));
  } catch {
    return [];
  }
}

function validRepositoryPath(parts) {
  return (
    parts.length > 0 &&
    parts.every(
      (part) =>
        part.length > 0 &&
        part !== '.' &&
        part !== '..' &&
        !part.includes('/') &&
        !part.includes('\\') &&
        !part.includes('\0'),
    )
  );
}

function checkRepositoryEvidence(repoRoot, rawUrl, gitCommand) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return 'must be a root-relative docs URL or an absolute Registry Stack GitHub URL';
  }

  if (`${url.origin}${url.pathname}`.startsWith(`${SAME_REPOSITORY}/`) === false) {
    return 'external evidence URLs are not locally verifiable';
  }
  if (url.search || url.hash || url.username || url.password || url.port) {
    return 'repository evidence URLs must not contain credentials, ports, queries, or fragments';
  }

  const parts = safePathParts(url.pathname.split('/').filter(Boolean));
  if (
    parts.length < 5 ||
    parts[0] !== 'registrystack' ||
    parts[1] !== 'registry-stack' ||
    !['blob', 'tree'].includes(parts[2])
  ) {
    return 'must use a Registry Stack /blob/<ref>/<path> or /tree/<ref>/<path> URL';
  }

  const ref = parts[3];
  const repositoryPath = parts.slice(4);
  if (!validRepositoryPath(repositoryPath)) {
    return 'contains an invalid or missing repository path';
  }

  let commitish;
  if (SEMVER_TAG.test(ref)) {
    commitish = `refs/tags/${ref}`;
  } else if (FULL_COMMIT.test(ref)) {
    commitish = ref;
  } else {
    return `uses ${ref}, but evidence refs must be semver tags or full 40-character commits`;
  }

  if (!gitObjectExists(repoRoot, `${commitish}^{commit}`, gitCommand)) {
    return `references missing Git commit or tag ${ref}`;
  }
  const path = repositoryPath.join('/');
  if (!gitObjectExists(repoRoot, `${commitish}^{commit}:${path}`, gitCommand)) {
    return `references missing path ${path} at ${ref}`;
  }
  return undefined;
}

function currentDocsCandidates(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl, 'https://docs.registrystack.invalid');
  } catch {
    return [];
  }
  if (url.origin !== 'https://docs.registrystack.invalid' || !rawUrl.startsWith('/')) {
    return [];
  }
  const parts = safePathParts(url.pathname.split('/').filter(Boolean));
  if (!validRepositoryPath(parts)) {
    return [];
  }
  const route = posix.join(...parts);
  return [
    `docs/site/src/content/docs/${route}.mdx`,
    `docs/site/src/content/docs/${route}.md`,
    `docs/site/src/content/docs/${route}/index.mdx`,
    `docs/site/src/content/docs/${route}/index.md`,
  ];
}

function checkCurrentDocsEvidence(repoRoot, sourceRef, rawUrl, gitCommand) {
  const candidates = currentDocsCandidates(rawUrl);
  if (candidates.length === 0) {
    return 'contains an invalid current-docs route';
  }
  if (!gitObjectExists(repoRoot, `${sourceRef}^{commit}`, gitCommand)) {
    return `cannot resolve release source ${sourceRef}`;
  }
  if (
    !candidates.some((path) =>
      gitObjectExists(repoRoot, `${sourceRef}^{commit}:${path}`, gitCommand),
    )
  ) {
    return `does not resolve to a documentation page at release source ${sourceRef}`;
  }
  return undefined;
}

export function checkEvidenceLinks({
  repoRoot = resolve(scriptDir, '../../..'),
  dataDir = resolve(scriptDir, '../src/data'),
  sourceRef = 'HEAD',
  gitCommand = 'git',
} = {}) {
  const errors = [];
  let evidence;
  try {
    evidence = readEvidenceUrls(dataDir);
  } catch (error) {
    return { checked: 0, errors: [error.message] };
  }

  for (const item of evidence) {
    const error = item.url.startsWith('/')
      ? checkCurrentDocsEvidence(repoRoot, sourceRef, item.url, gitCommand)
      : checkRepositoryEvidence(repoRoot, item.url, gitCommand);
    if (error) {
      errors.push(`${item.location}: ${item.url}: ${error}`);
    }
  }
  return { checked: evidence.length, errors };
}

function sourceRefArgument(args) {
  if (args.length === 0) {
    return 'HEAD';
  }
  if (args.length === 2 && args[0] === '--source-ref' && args[1]) {
    return args[1];
  }
  throw new Error('usage: check-evidence-links.mjs [--source-ref <tag-or-commit>]');
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    const result = checkEvidenceLinks({ sourceRef: sourceRefArgument(process.argv.slice(2)) });
    if (result.errors.length > 0) {
      console.error('Evidence link check failed:');
      for (const error of result.errors) {
        console.error(`- ${error}`);
      }
      process.exitCode = 1;
    } else {
      console.log(`Verified ${result.checked} evidence links using local Git objects.`);
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
