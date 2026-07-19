import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { checkEvidenceLinks, extractEvidenceUrlsFromYaml } from './check-evidence-links.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, '../../..');

function git(root, ...args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
}

function createRepository(t) {
  const root = mkdtempSync(join(tmpdir(), 'registry-evidence-links-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(resolve(root, 'docs/site/src/content/docs/explanation'), { recursive: true });
  mkdirSync(resolve(root, 'source/tree'), { recursive: true });
  writeFileSync(resolve(root, 'docs/site/src/content/docs/explanation/current.mdx'), '# Current\n');
  writeFileSync(resolve(root, 'source/file.md'), '# Source\n');
  writeFileSync(resolve(root, 'source/tree/item.txt'), 'evidence\n');
  git(root, 'init', '--quiet');
  git(root, 'config', 'user.email', 'tests@example.invalid');
  git(root, 'config', 'user.name', 'Evidence Tests');
  git(root, 'add', '.');
  git(root, 'commit', '--quiet', '-m', 'test evidence');
  git(root, 'tag', 'v1.2.3');
  return { root, commit: git(root, 'rev-parse', 'HEAD') };
}

function writeEvidenceData(root, { contractUrls, standardUrls, officialUrl } = {}) {
  const dataDir = resolve(root, 'docs/site/src/data');
  mkdirSync(resolve(dataDir, 'generated'), { recursive: true });
  const contracts = (contractUrls ?? []).map((url, index) => ({
    id: `contract-${index}`,
    source_of_truth: { label: `Contract ${index}`, url },
  }));
  const standards = [
    {
      id: 'standard',
      official_url: officialUrl ?? 'https://standards.example.invalid/main',
      evidence_docs: (standardUrls ?? []).map((url, index) => ({
        label: `Evidence ${index}`,
        url,
      })),
    },
  ];
  const contractsYaml = contracts
    .map(
      (entry) =>
        `- id: ${entry.id}\n  source_of_truth:\n    label: ${entry.source_of_truth.label}\n    url: ${entry.source_of_truth.url}\n`,
    )
    .join('');
  const standardsYaml = [
    '- id: standard',
    `  official_url: ${standards[0].official_url}`,
    '  evidence_docs:',
    ...standards[0].evidence_docs.flatMap((entry) => [
      `    - label: ${entry.label}`,
      `      url: ${entry.url}`,
    ]),
    '',
  ].join('\n');
  writeFileSync(resolve(dataDir, 'contracts.yaml'), contractsYaml);
  writeFileSync(resolve(dataDir, 'standards.yaml'), standardsYaml);
  writeFileSync(resolve(dataDir, 'generated/contracts.json'), `${JSON.stringify(contracts)}\n`);
  writeFileSync(resolve(dataDir, 'generated/standards.json'), `${JSON.stringify(standards)}\n`);
  return dataDir;
}

test('accepts semver tags, full commits, and root-relative current docs', (t) => {
  const { root, commit } = createRepository(t);
  const dataDir = writeEvidenceData(root, {
    contractUrls: [
      'https://github.com/registrystack/registry-stack/blob/v1.2.3/source/file.md',
    ],
    standardUrls: [
      `https://github.com/registrystack/registry-stack/tree/${commit}/source/tree`,
      '/explanation/current/',
    ],
    officialUrl: 'https://standards.example.invalid/unverified/current',
  });

  assert.deepEqual(checkEvidenceLinks({ repoRoot: root, dataDir, sourceRef: commit }), {
    checked: 3,
    errors: [],
  });
});

test('rejects branches, short commits, missing refs, and missing paths', async (t) => {
  const { root, commit } = createRepository(t);
  const cases = [
    {
      name: 'branch',
      url: 'https://github.com/registrystack/registry-stack/blob/main/source/file.md',
      expected: /semver tags or full 40-character commits/,
    },
    {
      name: 'short commit',
      url: `https://github.com/registrystack/registry-stack/blob/${commit.slice(0, 8)}/source/file.md`,
      expected: /semver tags or full 40-character commits/,
    },
    {
      name: 'missing tag',
      url: 'https://github.com/registrystack/registry-stack/blob/v9.9.9/source/file.md',
      expected: /missing Git commit or tag/,
    },
    {
      name: 'missing path',
      url: 'https://github.com/registrystack/registry-stack/blob/v1.2.3/source/missing.md',
      expected: /missing path/,
    },
  ];

  for (const item of cases) {
    await t.test(item.name, () => {
      const dataDir = writeEvidenceData(root, { contractUrls: [item.url] });
      const result = checkEvidenceLinks({ repoRoot: root, dataDir, sourceRef: commit });
      assert.equal(result.checked, 1);
      assert.equal(result.errors.length, 1);
      assert.match(result.errors[0], item.expected);
    });
  }
});

test('rejects foreign evidence hosts but excludes official_url from the check', (t) => {
  const { root, commit } = createRepository(t);
  const dataDir = writeEvidenceData(root, {
    contractUrls: ['https://evidence.example.invalid/blob/v1.2.3/source/file.md'],
    officialUrl: 'https://github.com/registrystack/registry-stack/blob/main/source/missing.md',
  });

  const result = checkEvidenceLinks({ repoRoot: root, dataDir, sourceRef: commit });
  assert.equal(result.checked, 1);
  assert.match(result.errors[0], /external evidence URLs are not locally verifiable/);
});

test('rejects a missing current-docs route at the selected source', (t) => {
  const { root, commit } = createRepository(t);
  const dataDir = writeEvidenceData(root, { standardUrls: ['/explanation/missing/'] });
  const result = checkEvidenceLinks({ repoRoot: root, dataDir, sourceRef: commit });
  assert.match(result.errors[0], /does not resolve to a documentation page/);
});

test('rejects generated evidence data that is stale', (t) => {
  const { root, commit } = createRepository(t);
  const dataDir = writeEvidenceData(root, {
    contractUrls: [
      'https://github.com/registrystack/registry-stack/blob/v1.2.3/source/file.md',
    ],
  });
  writeFileSync(resolve(dataDir, 'generated/contracts.json'), '[]\n');

  const result = checkEvidenceLinks({ repoRoot: root, dataDir, sourceRef: commit });
  assert.equal(result.checked, 0);
  assert.match(result.errors[0], /run npm run generate/);
});

test('extracts only policy-owned YAML fields', () => {
  const standards = `- id: test
  official_url: https://example.invalid/main
  evidence_docs:
    - label: source
      url: 'https://github.com/registrystack/registry-stack/blob/v1.2.3/source/file.md'
  notes: current
`;
  assert.deepEqual(extractEvidenceUrlsFromYaml(standards, 'standards'), [
    'https://github.com/registrystack/registry-stack/blob/v1.2.3/source/file.md',
  ]);
});

test('release verification uses the resolved tag target without installing the docs tree', () => {
  const workflow = readFileSync(resolve(repositoryRoot, '.github/workflows/release.yml'), 'utf8');
  assert.match(
    workflow,
    /npm run check:evidence-links --\s+--source-ref "\$\{\{ steps\.release\.outputs\.tag_target \}\}"/,
  );
  assert.doesNotMatch(workflow, /npm ci/);
});
