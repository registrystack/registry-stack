#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

const SAME_REPOSITORY = 'https://github.com/registrystack/registry-stack';
const SEMVER_TAG =
  /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const FULL_COMMIT = /^[0-9a-f]{40}$/;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const STRICT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

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
    const yamlText = readFileSync(resolve(dataDir, `${kind}.yaml`), 'utf8');
    const yamlUrls = extractEvidenceUrlsFromYaml(yamlText, kind);
    const generatedData = JSON.parse(
      readFileSync(resolve(dataDir, 'generated', `${kind}.json`), 'utf8'),
    );
    const generatedUrls = generatedEvidenceUrls(generatedData, kind);
    if (JSON.stringify(yamlUrls) !== JSON.stringify(generatedUrls)) {
      throw new Error(
        `${kind}.yaml evidence URLs differ from generated/${kind}.json; run npm run generate`,
      );
    }
    if (kind === 'contracts') {
      const yamlData = YAML.parse(yamlText) ?? [];
      if (!Array.isArray(yamlData) || !Array.isArray(generatedData)) {
        throw new Error('contracts evidence data must contain a top-level list');
      }
      const yamlStatuses = yamlData.map((entry) => entry?.status);
      const generatedStatuses = generatedData.map((entry) => entry?.status);
      if (JSON.stringify(yamlStatuses) !== JSON.stringify(generatedStatuses)) {
        throw new Error(
          'contracts.yaml statuses differ from generated/contracts.json; run npm run generate',
        );
      }
      for (const [index, status] of yamlStatuses.entries()) {
        if (!['current-source', 'pinned-generated-snapshot'].includes(status)) {
          throw new Error(`contracts.yaml entry ${index + 1} has invalid status ${status}`);
        }
      }
      urls.push(
        ...yamlUrls.map((url, index) => ({
          location: `${kind}[${index + 1}]`,
          url,
          currentSource: yamlStatuses[index] === 'current-source',
        })),
      );
    } else {
      urls.push(...yamlUrls.map((url, index) => ({ location: `${kind}[${index + 1}]`, url })));
    }
  }
  return urls;
}

function gitCommandSucceeds(repoRoot, args, gitCommand) {
  return (
    spawnSync(gitCommand, args, {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, GIT_NO_LAZY_FETCH: '1' },
      stdio: 'pipe',
    }).status === 0
  );
}

function gitObjectExists(repoRoot, object, gitCommand) {
  return gitCommandSucceeds(repoRoot, ['cat-file', '-e', object], gitCommand);
}

function gitCommitIsAncestor(repoRoot, ancestor, descendant, gitCommand) {
  return gitCommandSucceeds(
    repoRoot,
    ['merge-base', '--is-ancestor', `${ancestor}^{commit}`, `${descendant}^{commit}`],
    gitCommand,
  );
}

function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

export function currentReleaseCandidateTag(manifestDir) {
  const candidates = readdirSync(manifestDir)
    .filter((name) => /^registry-stack-.+[.]yaml$/.test(name))
    .sort()
    .map((name) => {
      const manifest = YAML.parse(readFileSync(resolve(manifestDir, name), 'utf8'));
      const stack = manifest?.stack;
      if (!stack || typeof stack !== 'object') {
        throw new Error(`${name} must contain a stack object`);
      }
      const releaseId = stack.release;
      if (typeof releaseId !== 'string' || !RELEASE_ID.test(releaseId)) {
        throw new Error(`${name} has an invalid stack.release`);
      }
      if (name !== `registry-stack-${releaseId}.yaml`) {
        throw new Error(`${name} does not match stack.release ${releaseId}`);
      }
      const version = stack.version;
      const match = typeof version === 'string' ? STRICT_VERSION.exec(version) : null;
      if (!match) {
        throw new Error(`${name} has an invalid stack.version`);
      }
      if (stack.source_repo !== 'registrystack/registry-stack') {
        throw new Error(`${name} has an invalid stack.source_repo`);
      }
      if (stack.source_tag !== `v${version}`) {
        throw new Error(`${name} stack.source_tag must be v${version}`);
      }
      return { name, version, parts: match.slice(1).map(Number) };
    });
  if (candidates.length === 0) {
    throw new Error(`no Registry Stack release manifests found in ${manifestDir}`);
  }
  candidates.sort((left, right) => compareVersions(left.parts, right.parts));
  const current = candidates.at(-1);
  const previous = candidates.at(-2);
  if (previous && compareVersions(previous.parts, current.parts) === 0) {
    throw new Error(
      `version ${current.version} has multiple release manifests: ${previous.name}, ${current.name}`,
    );
  }
  return `v${current.version}`;
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

function checkRepositoryEvidence(
  repoRoot,
  rawUrl,
  gitCommand,
  { candidateTag, sourceRef, currentSource = false } = {},
) {
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
    if (ref !== candidateTag || !gitObjectExists(repoRoot, `${sourceRef}^{commit}`, gitCommand)) {
      return `references missing Git commit or tag ${ref}`;
    }
    commitish = sourceRef;
  }
  const path = repositoryPath.join('/');
  if (!gitObjectExists(repoRoot, `${commitish}^{commit}:${path}`, gitCommand)) {
    return `references missing path ${path} at ${ref}`;
  }
  if (currentSource) {
    if (!gitObjectExists(repoRoot, `${sourceRef}^{commit}`, gitCommand)) {
      return `cannot resolve selected current source ${sourceRef}`;
    }
    if (!gitCommitIsAncestor(repoRoot, commitish, sourceRef, gitCommand)) {
      return `references ${ref}, which is not reachable from selected current source ${sourceRef}`;
    }
    if (!gitObjectExists(repoRoot, `${sourceRef}^{commit}:${path}`, gitCommand)) {
      return `references path ${path}, which is absent from selected current source ${sourceRef}`;
    }
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
  candidateTag,
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
      : checkRepositoryEvidence(repoRoot, item.url, gitCommand, {
          candidateTag,
          sourceRef,
          currentSource: item.currentSource,
        });
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
    const repoRoot = resolve(scriptDir, '../../..');
    const sourceRef = sourceRefArgument(process.argv.slice(2));
    const candidateTag = currentReleaseCandidateTag(resolve(repoRoot, 'release/manifests'));
    const result = checkEvidenceLinks({ repoRoot, sourceRef, candidateTag });
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
