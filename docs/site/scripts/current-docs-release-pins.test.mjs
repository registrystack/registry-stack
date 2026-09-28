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

// A release tag: `vX.Y.Z` (a prerelease suffix included), or one of the tag forms the stack used
// before semantic versions, such as registry-stack-beta-5-2026-06-24 or beta-2026-06-12.
const LEGACY_RELEASE = String.raw`(?:legacy/[a-z-]+/)?(?:registry-stack-)?(?:beta-\d+(?:\.\d+)?(?:-\d{4}-\d{2}-\d{2})?|beta-\d{4}-\d{2}-\d{2}|technical-preview-\d{4}-\d{2}-\d{2})`;
const RELEASE = String.raw`(?:v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?|${LEGACY_RELEASE})`;

// Each rule names an install or download target that a pinned release version would freeze.
const TARGET_RULES = [
  {
    id: 'container-image-tag',
    pattern: new RegExp(String.raw`ghcr\.io/registrystack/[a-z0-9-]+:${RELEASE}\b`, 'g'),
  },
  {
    id: 'release-asset-download',
    pattern: new RegExp(
      String.raw`github\.com/registrystack/registry-stack/(?:releases/(?:download|tag)/${RELEASE}\b|archive/(?:refs/tags/)?${RELEASE}\.(?:tar\.gz|zip)\b)`,
      'g',
    ),
  },
  {
    // A source checkout at a release tag: `git clone --branch <tag>`, `git checkout <tag>`, and the
    // like. Write the reader's release as `<tag>`.
    id: 'git-checkout-at-release',
    pattern: new RegExp(
      String.raw`\bgit\s+(?:(?:-[Cc]\s+\S+|--[a-z-]+(?:=\S+)?|-[a-zA-Z])\s+)*(?:clone\b[^\n\`]*?\s(?:--branch|-b)[= ]|checkout\s+(?:-[-a-z]+\s+)*(?:tags/)?|switch\s+(?:-[-a-z]+\s+)*(?:--detach|-d)\s+(?:-[-a-z]+\s+)*|fetch\b[^\n\`]*?\stag\s+)${RELEASE}\b`,
      'g',
    ),
  },
  {
    // `gh release download [<tag>]` takes the latest release when the tag is left out.
    id: 'github-cli-release-download',
    pattern: new RegExp(String.raw`\bgh\s+(?:-[-a-zA-Z]+(?:[= ]\S+)?\s+)*release\s+(?:download|view)\s+(?:-[-a-zA-Z]+(?:[= ]\S+)?\s+)*${RELEASE}\b`, 'g'),
  },
  {
    id: 'installer-version-variable',
    // Also a shell default such as RELAY_VERSION=${RELAY_VERSION:-v0.35.0}.
    pattern: new RegExp(
      String.raw`\b[A-Z][A-Z0-9_]*_VERSION=["']?(?:\$\{[A-Z0-9_]+:?[-=])?${RELEASE}\b`,
      'g',
    ),
  },
  {
    id: 'package-install-version',
    pattern: new RegExp(
      String.raw`(?:\bregistry-[a-z0-9-]+(?:\[[a-z0-9,-]+\])?==|@registrystack/[a-z0-9-]+@)${RELEASE}\b`,
      'g',
    ),
  },
  {
    // The versioned assets release/scripts/release_candidate.py and .github/workflows/release.yml
    // publish: platform binaries and client packages, installers, the SBOM, the security evidence,
    // the docs archive, and the release manifest, checksum signature and provenance files.
    id: 'release-asset-name',
    pattern: new RegExp(
      String.raw`\b[a-z][a-z0-9-]*-v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)[0-9.]*)?`
        + String.raw`(?:-(?:linux|macos)-[a-z0-9]+|-install\.sh|-security-evidence\.tar\.gz|\.sbom\.spdx\.json|\.tar\.gz`
        + String.raw`|-release-manifest\.json|-SHA256SUMS(?:\.sigstore\.json|\.intoto\.jsonl)?)`,
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
// version that illustrates a naming scheme. Keep this narrow: every entry needs a reason, covers
// exactly one occurrence in its file, and fails the suite once it no longer matches.
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

// A page whose frontmatter doc_type is how-to or tutorial is an operator page wherever it lives:
// generated product pages carry the doc_type repo-docs.yaml declares, and hand-written pages such
// as security/hardening-checklist.mdx declare their own.
const OPERATOR_DOC_TYPES = new Set(['how-to', 'tutorial']);

function frontmatterDocType(text) {
  const frontmatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  return frontmatter?.[1].match(/^doc_type:\s*(\S+)\s*$/m)?.[1];
}

function isOperatorPage(page, text) {
  if (page.startsWith('reference/cli/')) return false;
  if (OPERATOR_DOC_TYPES.has(frontmatterDocType(text))) return true;
  if (page.startsWith('products/')) return false;
  return OPERATOR_PAGE_PREFIXES.some((prefix) => page.startsWith(prefix)) || OPERATOR_PAGES.has(page);
}

function isCurrentPage(page) {
  return !EXCLUDED_PREFIXES.some((prefix) => page.startsWith(prefix)) && !EXCLUDED_PAGES.has(page);
}

// A fenced code block holds what the reader runs or copies, never history, so any exact release in
// one is a pin whatever command carries it. The targeted rules above also cover inline prose.
const RELEASE_IN_CODE_BLOCK_RULE = {
  id: 'release-in-code-block',
  pattern: new RegExp(String.raw`(?<![\w.-])(?:v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?|${LEGACY_RELEASE})(?![\w-])`, 'g'),
};

export function findReleasePins(text, { operator }) {
  const rules = operator ? [...TARGET_RULES, REPOSITORY_AT_TAG_RULE] : TARGET_RULES;
  const findings = [];
  const lines = text.split(/\r?\n/);
  let fence = null;
  lines.forEach((line, index) => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker && fence === null) {
      fence = marker[1];
      return;
    }
    if (fence !== null && line.trim().startsWith(fence) && line.trim().replace(/[`~]/g, '') === '') {
      fence = null;
      return;
    }
    const lineFindings = [];
    for (const rule of rules) {
      for (const match of line.matchAll(rule.pattern)) {
        lineFindings.push({ line: index + 1, rule: rule.id, match: match[0] });
      }
    }
    if (fence !== null && lineFindings.length === 0) {
      for (const match of line.matchAll(RELEASE_IN_CODE_BLOCK_RULE.pattern)) {
        lineFindings.push({ line: index + 1, rule: RELEASE_IN_CODE_BLOCK_RULE.id, match: match[0] });
      }
    }
    findings.push(...lineFindings);
  });
  return findings;
}

// Each allowlist entry absorbs one occurrence of its match in its file; any further occurrence,
// such as a real download instruction reusing an allowlisted example, is a violation.
export function checkDocuments(documents, allowlist) {
  const remaining = allowlist.map(() => 1);
  const violations = [];
  for (const document of documents) {
    for (const finding of findReleasePins(document.text, { operator: document.operator })) {
      const allowed = allowlist.findIndex(
        (entry, index) =>
          remaining[index] > 0 && entry.file === document.file && entry.match === finding.match,
      );
      if (allowed === -1) {
        violations.push(`${document.file}:${finding.line}: ${finding.rule}: ${finding.match}`);
      } else {
        remaining[allowed] -= 1;
      }
    }
  }
  const stale = allowlist.filter((_, index) => remaining[index] > 0);
  return { violations, stale };
}

function currentDocuments() {
  const pages = listContentPages()
    .filter(isCurrentPage)
    .map((page) => {
      const text = readFileSync(resolve(contentRoot, page), 'utf8');
      return { file: `docs/site/src/content/docs/${page}`, text, operator: isOperatorPage(page, text) };
    });
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
  for (const archive of [
    'https://github.com/registrystack/registry-stack/archive/refs/tags/v0.35.0.tar.gz',
    'https://github.com/registrystack/registry-stack/archive/v0.35.0-rc.1.zip',
  ]) {
    assert.deepEqual(flagged(archive), ['release-asset-download'], archive);
  }
  for (const legacy of ['beta-5', 'beta-2026-06-12', 'registry-stack-beta-5.1-2026-06-24']) {
    assert.deepEqual(
      flagged(`https://github.com/registrystack/registry-stack/releases/download/${legacy}/relay`),
      ['release-asset-download'],
      legacy,
    );
    assert.deepEqual(flagged(`ghcr.io/registrystack/relay:${legacy}`), ['container-image-tag'], legacy);
    assert.deepEqual(
      flagged(`https://github.com/registrystack/registry-stack/blob/${legacy}/release/VERIFY.md`, true),
      ['repository-link-at-release-tag'],
      legacy,
    );
  }
  assert.deepEqual(
    flagged(
      'https://github.com/registrystack/registry-stack/tree/legacy/registry-lab/registry-stack-beta-5-2026-06-24/lab/',
      true,
    ),
    ['repository-link-at-release-tag'],
  );
  for (const checkout of [
    'git clone --branch v0.35.0 https://github.com/registrystack/registry-stack.git',
    'git clone --depth 1 -b v0.35.0 https://github.com/registrystack/registry-stack.git',
    'git checkout v0.35.0',
    'git checkout tags/v0.35.0-rc.1',
    'git checkout --detach v0.35.0',
    'git checkout -q --detach v0.35.0',
    'git switch --quiet --detach v0.35.0',
    'git -C /srv/registry checkout v0.35.0',
    'git -c advice.detachedHead=false checkout v0.35.0',
    'git switch --detach v0.35.0',
    'git fetch origin tag v0.35.0',
  ]) {
    assert.deepEqual(flagged(checkout), ['git-checkout-at-release'], checkout);
  }
  for (const download of [
    'gh release download v0.35.0 -R registrystack/registry-stack',
    'gh release download --repo registrystack/registry-stack v0.35.0',
    'gh -R registrystack/registry-stack release download v0.35.0',
  ]) {
    assert.deepEqual(flagged(download), ['github-cli-release-download'], download);
  }
  assert.deepEqual(flagged('CASEWORK_VERSION=v0.30.0 bash'), ['installer-version-variable']);
  assert.deepEqual(
    flagged('RELAY_VERSION=${RELAY_VERSION:-v0.35.0} bash relay-install.sh'),
    ['installer-version-variable'],
  );
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
    'registry-stack-v0.35.0-release-manifest.json',
    'registry-stack-v0.35.0-SHA256SUMS',
    'registry-stack-v0.35.0-SHA256SUMS.sigstore.json',
    'registry-stack-v0.35.0-SHA256SUMS.intoto.jsonl',
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

test('any exact release inside a fenced code block is a pin', () => {
  const block = (body, fence = '```') => `Run:\n\n${fence}sh\n${body}\n${fence}\n\nStarting with v0.33.0, prose is history.`;
  const rules = (text) => findReleasePins(text, { operator: false }).map((finding) => finding.rule);

  assert.deepEqual(rules(block('some-new-tool fetch --release v0.35.0')), ['release-in-code-block']);
  assert.deepEqual(rules(block('deploy --version beta-5')), ['release-in-code-block']);
  assert.deepEqual(rules(block('echo v0.35.0-rc.1', '~~~')), ['release-in-code-block']);
  // A targeted rule reports the line once, not twice.
  assert.deepEqual(rules(block('docker pull ghcr.io/registrystack/relay:v0.35.0')), ['container-image-tag']);
  // Tags, versions without the release prefix, and prose outside the block stay clean.
  assert.deepEqual(rules(block('relay --version\nrelay 0.35.0\ngit checkout <tag>')), []);
  assert.deepEqual(rules(block('bind: 127.0.0.1:8080\nopenapi: 3.1.0')), []);
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
    'git clone --branch <tag> https://github.com/registrystack/registry-stack.git',
    'git checkout main',
    'gh release download -R registrystack/registry-stack --pattern "relay-*"',
    'gh release download <tag> -R registrystack/registry-stack',
    'The archived [Beta 5 documentation](/v/beta-5/) keeps its own pins.',
    'https://github.com/registrystack/registry-stack/archive/refs/heads/main.zip',
    'pip install ./registry_stack_client-<version>-cp310-abi3-<platform>.whl',
    'listener.bind: 127.0.0.1:8080',
  ]) {
    assert.deepEqual(findReleasePins(text, { operator: true }), [], text);
  }
});

// A page that asks the reader for a release tag must say where to find it.
const TAG_PLACEHOLDER_TARGET =
  /releases\/download\/<|ghcr\.io\/registrystack\/[a-z0-9-]+:<|registry-stack\/(?:blob|tree|raw)\/<|_VERSION=<|gh release download <|--branch <|git checkout <|git switch [^\n`]*<[a-z-]*tag>/;
const LATEST_RELEASE_POINTER = 'github.com/registrystack/registry-stack/releases/latest';

export function missingLatestPointer(documents) {
  return documents
    .filter((document) => TAG_PLACEHOLDER_TARGET.test(document.text))
    .filter((document) => !document.text.includes(LATEST_RELEASE_POINTER))
    .map((document) => document.file);
}

test('a page that asks for a release tag points at the latest release', () => {
  const placeholder = 'curl -fsSL https://github.com/registrystack/registry-stack/releases/download/<tag>/relay-install.sh';
  assert.deepEqual(missingLatestPointer([{ file: 'a', text: placeholder }]), ['a']);
  assert.deepEqual(
    missingLatestPointer([{ file: 'a', text: `${placeholder}\nSee https://${LATEST_RELEASE_POINTER}.` }]),
    [],
  );
  assert.deepEqual(missingLatestPointer([{ file: 'a', text: 'No install target.' }]), []);
  assert.deepEqual(missingLatestPointer(currentDocuments()), []);
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

  const { violations, stale } = checkDocuments(documents, HISTORICAL_ALLOWLIST);
  assert.deepEqual(
    violations,
    [],
    'Current docs must name `<tag>` and point at https://github.com/registrystack/registry-stack/releases/latest '
      + 'instead of pinning an exact release; pins belong only in archived docsets.',
  );
  assert.deepEqual(stale, [], 'remove allowlist entries that no longer match');
});

test('an allowlist entry absorbs one occurrence and no more', () => {
  const file = 'docs/site/src/content/docs/products/example/index.md';
  const entry = { file, match: 'evidence-v1.2.0-linux-amd64', reason: 'naming example' };
  const once = 'named `<bin>-<tag>-<os>-<arch>` (for example `evidence-v1.2.0-linux-amd64`)';
  const twice = `${once}\ncurl -fsSLO .../evidence-v1.2.0-linux-amd64`;

  assert.deepEqual(checkDocuments([{ file, text: once, operator: false }], [entry]), {
    violations: [],
    stale: [],
  });
  assert.deepEqual(checkDocuments([{ file, text: twice, operator: false }], [entry]), {
    violations: [`${file}:2: release-asset-name: evidence-v1.2.0-linux-amd64`],
    stale: [],
  });
  assert.deepEqual(checkDocuments([{ file, text: 'no pins here', operator: false }], [entry]), {
    violations: [],
    stale: [entry],
  });
});

test('generated product how-to and tutorial pages are operator pages', () => {
  const page = (docType) => `---\ntitle: Example\ndoc_type: ${docType}\n---\n\nBody.\n`;
  assert.equal(isOperatorPage('products/registry-manifest/validate-and-render.md', page('how-to')), true);
  assert.equal(isOperatorPage('products/registry-evidence/tutorial.md', page('tutorial')), true);
  assert.equal(isOperatorPage('products/registry-evidence/index.md', page('explanation')), false);
  assert.equal(isOperatorPage('products/registry-evidence/authoring-form.md', page('reference')), false);
  assert.equal(isOperatorPage('reference/cli/relay.mdx', page('how-to')), false);
  assert.equal(isOperatorPage('operate/index.mdx', 'no frontmatter'), true);
  assert.equal(isOperatorPage('security/hardening-checklist.mdx', page('how-to')), true);
  assert.equal(isOperatorPage('security/support-window.mdx', page('reference')), false);
});
