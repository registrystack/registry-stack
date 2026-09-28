import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { test } from 'node:test';

// Current operator docs carry no exact release pins (#1441): an install or download target names
// `<tag>` and points at the latest release, and exact pins live only inside archived docsets,
// which are built from their own tags and never read from this tree. A historical sentence such as
// "starting with v0.33.0" is not an install or download target and is never flagged.

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');
const contentRoot = resolve(siteRoot, 'src/content/docs');

const RELEASE = String.raw`v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?`;

// Each rule names an install or download target that a pinned release version would freeze.
const TARGET_RULES = [
  {
    id: 'container-image-tag',
    pattern: new RegExp(String.raw`ghcr\.io/registrystack/[a-z0-9-]+:${RELEASE}\b`, 'g'),
  },
  {
    id: 'release-asset-download',
    pattern: new RegExp(
      String.raw`github\.com/registrystack/registry-stack/releases/(?:download|tag)/${RELEASE}\b`,
      'g',
    ),
  },
  {
    id: 'installer-version-variable',
    pattern: new RegExp(String.raw`\b[A-Z][A-Z0-9_]*_VERSION=["']?${RELEASE}\b`, 'g'),
  },
  {
    id: 'package-install-version',
    pattern: new RegExp(
      String.raw`(?:\bregistry-[a-z0-9-]+(?:\[[a-z0-9,-]+\])?==|@registrystack/[a-z0-9-]+@)${RELEASE}\b`,
      'g',
    ),
  },
  {
    // The versioned assets release/scripts/release_candidate.py publishes: platform binaries and
    // client packages, installers, the SBOM, the security evidence and the docs archive.
    id: 'release-asset-name',
    pattern: new RegExp(
      String.raw`\b[a-z][a-z0-9-]*-v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)[0-9.]*)?`
        + String.raw`(?:-(?:linux|macos)-[a-z0-9]+|-install\.sh|-security-evidence\.tar\.gz|\.sbom\.spdx\.json|\.tar\.gz)`,
      'g',
    ),
  },
  {
    // The client packages the same inventory publishes under the bare package version: npm
    // tarballs such as registrystack-client-<version>.tgz and Python wheels.
    id: 'client-package-file',
    pattern: /\b[a-z][a-z0-9_-]*-\d+\.\d+\.\d+[0-9A-Za-z._-]*\.(?:tgz|whl)\b/g,
  },
];

// On an operator page, a repository link frozen at a release tag is an install or verification
// target too: operators follow it to the installer, the verification procedure, or the deployment
// files they copy. Reference and explanation pages may cite an artifact as it stood at a release.
const REPOSITORY_AT_TAG_RULE = {
  id: 'repository-link-at-release-tag',
  pattern: new RegExp(
    String.raw`(?:github\.com/registrystack/registry-stack/(?:blob|tree|raw)/|raw\.githubusercontent\.com/registrystack/registry-stack/)${RELEASE}/`,
    'g',
  ),
};

const OPERATOR_PAGE_PREFIXES = ['operate/', 'tutorials/', 'start/', 'configure/', 'verify/'];
const OPERATOR_PAGES = new Set([
  'reference/environment-variables.mdx',
  'reference/relayctl.mdx',
]);

// Dated records are historical by nature. Generated pages (products/ from repo-docs.yaml sources,
// reference/cli/ from the Clap trees) are published current pages, so `npm test` scans what
// `npm run generate` wrote there under the target rules.
const EXCLUDED_PREFIXES = ['decisions/'];
const GENERATED_PREFIXES = ['products/', 'reference/cli/'];
const EXCLUDED_PAGES = new Set(['changelog.mdx']);

// Repository files outside the docs site that are held to the same policy.
const EXTRA_OPERATOR_DOCS = ['docker/README.md'];

// Mentions that match a target rule on purpose: a past release named as history, or an example
// version that illustrates a naming scheme. Keep this narrow: every entry needs a reason, and an
// entry that no longer matches fails the suite.
const HISTORICAL_ALLOWLIST = [
  {
    file: 'docs/site/src/content/docs/products/registry-evidence/index.md',
    match: 'evidence-v1.2.0-linux-amd64',
    reason: 'products/evidence/README.md illustrates `<bin>-<tag>-<os>-<arch>` with a fictional v1.2.0',
  },
];

function listContentPages(dir = contentRoot) {
  const pages = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      pages.push(...listContentPages(path));
    } else if (/\.mdx?$/.test(entry.name)) {
      pages.push(relative(contentRoot, path).replaceAll('\\', '/'));
    }
  }
  return pages.sort();
}

function isOperatorPage(page) {
  if (GENERATED_PREFIXES.some((prefix) => page.startsWith(prefix))) return false;
  return OPERATOR_PAGE_PREFIXES.some((prefix) => page.startsWith(prefix)) || OPERATOR_PAGES.has(page);
}

function isCurrentPage(page) {
  return !EXCLUDED_PREFIXES.some((prefix) => page.startsWith(prefix)) && !EXCLUDED_PAGES.has(page);
}

export function findReleasePins(text, { operator }) {
  const rules = operator ? [...TARGET_RULES, REPOSITORY_AT_TAG_RULE] : TARGET_RULES;
  const findings = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const rule of rules) {
      for (const match of line.matchAll(rule.pattern)) {
        findings.push({ line: index + 1, rule: rule.id, match: match[0] });
      }
    }
  });
  return findings;
}

function currentDocuments() {
  const pages = listContentPages()
    .filter(isCurrentPage)
    .map((page) => ({
      file: `docs/site/src/content/docs/${page}`,
      text: readFileSync(resolve(contentRoot, page), 'utf8'),
      operator: isOperatorPage(page),
    }));
  const extras = EXTRA_OPERATOR_DOCS.map((file) => ({
    file,
    text: readFileSync(resolve(repoRoot, file), 'utf8'),
    operator: true,
  }));
  return [...pages, ...extras];
}

test('each release-pin rule flags its install or download target', () => {
  const flagged = (text, operator = false) =>
    findReleasePins(text, { operator }).map((finding) => finding.rule);

  assert.deepEqual(flagged('image `ghcr.io/registrystack/relay:v0.26.1`'), ['container-image-tag']);
  assert.deepEqual(flagged('ghcr.io/registrystack/casework:0.30.0-rc.1'), ['container-image-tag']);
  assert.deepEqual(
    flagged('https://github.com/registrystack/registry-stack/releases/download/v0.26.1/relay-install.sh'),
    ['release-asset-download'],
  );
  assert.deepEqual(flagged('CASEWORK_VERSION=v0.30.0 bash'), ['installer-version-variable']);
  assert.deepEqual(flagged('pip install "registry-stack-client==0.26.1"'), ['package-install-version']);
  assert.deepEqual(flagged('npm install @registrystack/client@0.26.1'), ['package-install-version']);
  for (const asset of [
    'relayctl-v0.26.1-linux-amd64',
    'relayctl-v0.33.0-macos-arm64.tar.gz',
    'relay-v0.35.0-install.sh',
    'breg-v0.35.0-rc.1-install.sh',
    'relay-client-node-v0.35.0-linux-arm64.tgz',
    'registry-stack-v0.35.0.sbom.spdx.json',
    'registry-stack-v0.35.0-security-evidence.tar.gz',
    'registry-docs-v0.35.0.tar.gz',
  ]) {
    assert.deepEqual(flagged(`take ${asset}`), ['release-asset-name'], asset);
  }
  for (const asset of [
    'registrystack-client-0.26.1.tgz',
    'registrystack-client-linux-x64-gnu-0.26.1.tgz',
    'registrystack-discovery-client-0.35.0-rc.1.tgz',
    'registry_stack_client-0.26.1-cp310-abi3-manylinux_2_28_x86_64.whl',
    'registry_relay_client-0.35.0-cp310-abi3-macosx_11_0_arm64.whl',
  ]) {
    assert.deepEqual(flagged(`take ${asset}`), ['client-package-file'], asset);
  }

  const verify = 'https://github.com/registrystack/registry-stack/blob/v0.26.1/release/VERIFY.md';
  assert.deepEqual(flagged(verify, true), ['repository-link-at-release-tag']);
  assert.deepEqual(flagged(verify, false), []);
});

test('release-pin rules leave tags, latest releases and history alone', () => {
  for (const text of [
    'The container image is `ghcr.io/registrystack/relay:<tag>`.',
    'curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/relay-install.sh | bash',
    'https://github.com/registrystack/registry-stack/blob/main/release/VERIFY.md',
    'Starting with v0.33.0, `relayctl-<tag>-macos-arm64.tar.gz` contains the macOS executable.',
    'curl -fsSLO https://github.com/registrystack/registry-stack/releases/latest/download/relay-install.sh',
    'The package ships from Registry Stack v0.26.1, so install a v0.26.1 or later release.',
    'python -m pip install "registry-stack-client==${version}"',
    'CASEWORK_VERSION=<tag> bash',
    'pip install ./registry_stack_client-<version>-cp310-abi3-<platform>.whl',
    'listener.bind: 127.0.0.1:8080',
  ]) {
    assert.deepEqual(findReleasePins(text, { operator: true }), [], text);
  }
});

test('current docs carry no exact release pin as an install or download target', () => {
  const documents = currentDocuments();
  assert.ok(
    documents.some((document) => document.file.endsWith('/operate/index.mdx') && document.operator),
    'the operator landing page must be in scope',
  );
  for (const prefix of GENERATED_PREFIXES) {
    assert.ok(
      documents.some((document) => document.file.startsWith(`docs/site/src/content/docs/${prefix}`)),
      `generated ${prefix} pages must be in scope; run npm run generate first`,
    );
  }

  const usedAllowlist = new Set();
  const violations = [];
  for (const document of documents) {
    for (const finding of findReleasePins(document.text, { operator: document.operator })) {
      const allowed = HISTORICAL_ALLOWLIST.findIndex(
        (entry) => entry.file === document.file && entry.match === finding.match,
      );
      if (allowed === -1) {
        violations.push(`${document.file}:${finding.line}: ${finding.rule}: ${finding.match}`);
      } else {
        usedAllowlist.add(allowed);
      }
    }
  }

  assert.deepEqual(
    violations,
    [],
    'Current docs must name `<tag>` and point at https://github.com/registrystack/registry-stack/releases/latest '
      + 'instead of pinning an exact release; pins belong only in archived docsets.',
  );
  const stale = HISTORICAL_ALLOWLIST.filter((_, index) => !usedAllowlist.has(index));
  assert.deepEqual(stale, [], 'remove allowlist entries that no longer match');
});
