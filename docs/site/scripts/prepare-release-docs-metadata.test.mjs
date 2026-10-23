import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { prepareReleaseDocsMetadata } from './prepare-release-docs-metadata.mjs';

const docsetsSource = `# Publication selectors stay unchanged.
current: latest
released: v0.26.1
docsets:
  - id: latest
    status: current
    products:
      registry-stack: { version: main source (unreleased), ref: HEAD }
      registry-evidence: { version: main source (unreleased), ref: HEAD }
      registry-coordinator: { version: main source (unreleased), ref: HEAD }
  # This comment and the historical scalar styles survive preparation.
  - id: v0.26.1
    status: archived
    availability: released
    description: 'A historical release.'
    products:
      registry-stack: { version: v0.26.1, ref: old-source }
`;
const repoDocsSource = `# Do not invent a human review.
repos:
  registry-evidence:
    docs:
      - src: products/evidence/README.md
        standards_referenced: [openapi, sd-jwt-vc]
        last_reviewed: 2026-09-01
        docset_overrides:
          # Prior semantics intentionally differ from current source.
          - docsets: [v0.26.1]
            standards_referenced: [openapi]
            last_reviewed: unreviewed
        description: 'Preserve this quote style.'
      - src: products/evidence/NEW.md
        standards_referenced: []
        last_reviewed: unreviewed
      - src: products/evidence/EXCLUDED.md
        exclude_docsets: [v0.29.0]
        standards_referenced: [openapi]
        last_reviewed: unreviewed
`;

const releaseArtifactsSource = `applies_from: v0.29.0
products:
  registry-stack: registry-docs
  registry-evidence: evidence
  registry-coordinator: coordinator
`;

async function fixture(t, {
  external = {}, manifestVersion = '0.29.0', releaseId = 'beta-41', sourceRef,
  artifacts = { 'registry-docs': '0.29.0', evidence: '0.29.0' }, distribution,
} = {}) {
  const root = await mkdtemp(resolve(tmpdir(), 'prepare-docs-metadata-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const siteRoot = resolve(root, 'docs/site');
  await mkdir(resolve(siteRoot, 'src/data'), { recursive: true });
  await mkdir(resolve(root, 'release/manifests'), { recursive: true });
  await writeFile(resolve(root, `release/manifests/registry-stack-${releaseId}.yaml`), YAML.stringify({
    stack: {
      release: releaseId, version: manifestVersion, source_tag: 'v0.29.0',
      ...(sourceRef ? { source_ref: sourceRef } : {}),
    },
    artifacts, external,
  }));
  if (distribution) {
    await mkdir(resolve(root, 'release/distributions'), { recursive: true });
    await writeFile(
      resolve(root, 'release/distributions/v0.29.0.json'),
      JSON.stringify(distribution),
    );
  }
  await writeFile(resolve(siteRoot, 'src/data/docset-release-artifacts.yaml'), releaseArtifactsSource);
  await writeFile(resolve(siteRoot, 'src/data/docsets.yaml'), docsetsSource);
  await writeFile(resolve(siteRoot, 'src/data/repo-docs.yaml'), repoDocsSource);
  const read = async (name) => readFile(resolve(siteRoot, `src/data/${name}.yaml`), 'utf8');
  const write = async (name, value) => writeFile(resolve(siteRoot, `src/data/${name}.yaml`), value);
  const prepare = (options = {}) => prepareReleaseDocsMetadata({
    siteRoot, version: '0.29.0', releaseId, date: '2026-09-10', ...options,
  });
  return { root, read, write, prepare };
}

test('prepares a future candidate from current product metadata and explicit external refs', async (t) => {
  const { prepare, read } = await fixture(t, { external: { crosswalk: { ref: 'a'.repeat(40) } } });
  assert.deepEqual(await prepare(), {
    docsetId: 'v0.29.0', changedPaths: ['docs/site/src/data/docsets.yaml', 'docs/site/src/data/repo-docs.yaml'],
  });
  const docsets = YAML.parse(await read('docsets'));
  assert.equal(docsets.current, 'latest');
  assert.equal(docsets.released, 'v0.26.1');
  const candidate = docsets.docsets.find((entry) => entry.id === 'v0.29.0');
  assert.equal(candidate.availability, 'candidate');
  assert.equal(candidate.published_at, '2026-09-10');
  assert.deepEqual(candidate.products['registry-evidence'], { version: 'v0.29.0', ref: 'v0.29.0' });
  assert.deepEqual(candidate.products.crosswalk, { version: 'a'.repeat(40), ref: 'a'.repeat(40) });
  const docs = YAML.parse(await read('repo-docs')).repos['registry-evidence'].docs;
  assert.deepEqual(docs[0].docset_overrides[1], {
    docsets: ['v0.29.0'], standards_referenced: ['openapi', 'sd-jwt-vc'], last_reviewed: '2026-09-01',
  });
  assert.deepEqual(docs[1].docset_overrides[0], {
    docsets: ['v0.29.0'], standards_referenced: [], last_reviewed: 'unreviewed',
  });
  assert.equal(docs[2].docset_overrides, undefined);
});

test('labels a product the manifest does not ship as main source at the docset ref', async (t) => {
  const { prepare, read } = await fixture(t);
  await prepare();
  const candidate = YAML.parse(await read('docsets')).docsets.find((entry) => entry.id === 'v0.29.0');
  assert.deepEqual(candidate.products, {
    'registry-stack': { version: 'v0.29.0', ref: 'v0.29.0' },
    'registry-evidence': { version: 'v0.29.0', ref: 'v0.29.0' },
    'registry-coordinator': { version: 'main source (unreleased)', ref: 'v0.29.0' },
  });
});

test('pins an unshipped product to the manifest source ref when one is recorded', async (t) => {
  const sourceRef = 'c'.repeat(40);
  const { prepare, read } = await fixture(t, { sourceRef });
  await prepare();
  const candidate = YAML.parse(await read('docsets')).docsets.find((entry) => entry.id === 'v0.29.0');
  assert.deepEqual(candidate.products['registry-coordinator'], {
    version: 'main source (unreleased)', ref: sourceRef,
  });
  assert.deepEqual(candidate.products['registry-evidence'], { version: 'v0.29.0', ref: sourceRef });
});

test('pins selected Discovery docs to the original independent release tag and version', async (t) => {
  const distribution = {
    schema_version: 'registry-stack.distribution-selection.v1',
    stack_version: '0.29.0',
    components: [{ unit: 'discovery', version: '1.4.2', policy: 'exact' }],
  };
  const { prepare, read, write } = await fixture(t, {
    artifacts: { 'registry-docs': '0.29.0', evidence: '0.29.0', discovery: '1.4.2', discoveryctl: '1.4.2' },
    distribution,
  });
  await write('docsets', docsetsSource.replace(
    '      registry-coordinator: { version: main source (unreleased), ref: HEAD }',
    '      registry-coordinator: { version: main source (unreleased), ref: HEAD }\n' +
      '      registry-discovery: { version: main source (unreleased), ref: HEAD }',
  ));
  await write('docset-release-artifacts', `${releaseArtifactsSource}  registry-discovery: discovery\n`);

  await prepare();

  const candidate = YAML.parse(await read('docsets')).docsets.find((entry) => entry.id === 'v0.29.0');
  assert.deepEqual(candidate.products['registry-discovery'], {
    version: 'v1.4.2',
    ref: 'discovery/v1.4.2',
  });
  assert.deepEqual(candidate.products['registry-evidence'], {
    version: 'v0.29.0',
    ref: 'v0.29.0',
  });
});

test('refuses a distribution selection for a different Stack version', async (t) => {
  const selection = {
    schema_version: 'registry-stack.distribution-selection.v1',
    stack_version: '0.28.0',
    components: [{ unit: 'discovery', version: '1.4.2', policy: 'exact' }],
  };
  const { prepare } = await fixture(t, { distribution: selection });
  await assert.rejects(prepare(), /distribution selection stack_version must match/);
});

test('refuses a distribution selection policy other than exact', async (t) => {
  const selection = {
    schema_version: 'registry-stack.distribution-selection.v1',
    stack_version: '0.29.0',
    components: [{ unit: 'discovery', version: '1.4.2', policy: 'compatible-patch' }],
  };
  const { prepare } = await fixture(t, { distribution: selection });
  await assert.rejects(prepare(), /distribution selection Discovery policy must be exact/);
});

test('refuses symlinked and non-regular distribution selections', async (t) => {
  const symlinkFixture = await fixture(t);
  const symlinkPath = resolve(
    symlinkFixture.root,
    'release/distributions/v0.29.0.json',
  );
  const symlinkTarget = resolve(symlinkFixture.root, 'selection.json');
  await mkdir(resolve(symlinkFixture.root, 'release/distributions'), { recursive: true });
  await writeFile(symlinkTarget, '{}');
  await symlink(symlinkTarget, symlinkPath);
  await assert.rejects(symlinkFixture.prepare(), /distribution selection must be a regular file/);

  const danglingFixture = await fixture(t);
  const danglingPath = resolve(
    danglingFixture.root,
    'release/distributions/v0.29.0.json',
  );
  await mkdir(resolve(danglingFixture.root, 'release/distributions'), { recursive: true });
  await symlink(resolve(danglingFixture.root, 'missing-selection.json'), danglingPath);
  await assert.rejects(danglingFixture.prepare(), /distribution selection must be a regular file/);

  const directoryFixture = await fixture(t);
  await mkdir(resolve(
    directoryFixture.root,
    'release/distributions/v0.29.0.json',
  ), { recursive: true });
  await assert.rejects(directoryFixture.prepare(), /distribution selection must be a regular file/);
});

test('refuses a current product that names no release artifact', async (t) => {
  const { prepare, read, write } = await fixture(t);
  await write('docset-release-artifacts', releaseArtifactsSource.replace('  registry-coordinator: coordinator\n', ''));
  await assert.rejects(prepare(), /registry-coordinator names no release artifact in docset-release-artifacts\.yaml/);
  assert.equal(await read('docsets'), docsetsSource);
});

test('preserves original YAML bytes and historical semantic records with idempotent reruns', async (t) => {
  const { prepare, read } = await fixture(t);
  await prepare();
  const docsetsAfter = await read('docsets');
  const repoAfter = await read('repo-docs');
  // Removing only the inserted fragments reconstructs the complete old input.
  assert.equal(docsetsAfter.replace(/  - id: v0\.29\.0\n[\s\S]*?(?=  # This comment)/, ''), docsetsSource);
  assert.equal(repoAfter.replace(/          - docsets: \[ v0\.29\.0 \]\n            standards_referenced: \[ openapi, sd-jwt-vc \]\n            last_reviewed: 2026-09-01\n/, '')
    .replace(/        docset_overrides:\n          - docsets: \[ v0\.29\.0 \]\n            standards_referenced: \[\]\n            last_reviewed: unreviewed\n/, ''), repoDocsSource);
  assert.deepEqual(await prepare(), { docsetId: 'v0.29.0', changedPaths: [] });
  assert.equal(await read('docsets'), docsetsAfter);
  assert.equal(await read('repo-docs'), repoAfter);
});

test('checks metadata without writing and refuses identity/date conflicts before writes', async (t) => {
  const { prepare, read } = await fixture(t);
  assert.equal((await prepare({ write: false })).changedPaths.length, 2);
  assert.equal(await read('docsets'), docsetsSource);
  assert.equal(await read('repo-docs'), repoDocsSource);
  await assert.rejects(prepare({ date: '2026-02-30' }), /valid.*calendar date/);
  await assert.rejects(prepare({ version: 'v0.29.0' }), /unprefixed/);
  await assert.rejects(prepare({ releaseId: '../beta-41' }), /release identifier/);
  await prepare();
  const before = await read('docsets');
  await assert.rejects(prepare({ date: '2026-09-11' }), /conflicting existing candidate/);
  assert.equal(await read('docsets'), before);
});

test('refuses conflicting existing snapshots without adding a candidate or modifying history', async (t) => {
  const { prepare, read, write } = await fixture(t);
  await write('repo-docs', repoDocsSource.replace('docsets: [v0.26.1]', 'docsets: [v0.26.1, v0.29.0]'));
  const before = await read('repo-docs');
  await assert.rejects(prepare(), /conflicting metadata snapshot/);
  assert.equal(await read('docsets'), docsetsSource);
  assert.equal(await read('repo-docs'), before);
});

test('refuses a mismatched or missing selected manifest', async (t) => {
  const { prepare } = await fixture(t, { manifestVersion: '0.28.0' });
  await assert.rejects(prepare(), /selected manifest must match/);
  await assert.rejects(prepare({ releaseId: 'beta-42' }), /ENOENT/);
});

test('allows an exact frozen rerun but refuses missing or changed frozen metadata', async (t) => {
  const { prepare, read, write } = await fixture(t);
  await write('archive-lock', 'archives:\n  v0.29.0: { bundle_sha256: frozen }\n');
  await assert.rejects(prepare(), /cannot modify metadata for frozen archive/);
  assert.equal(await read('docsets'), docsetsSource);
  await write('archive-lock', 'archives: {}\n');
  await prepare();
  await write('archive-lock', 'archives:\n  v0.29.0: { bundle_sha256: frozen }\n');
  assert.deepEqual((await prepare()).changedPaths, []);
  await write('repo-docs', (await read('repo-docs')).replace('last_reviewed: 2026-09-01', 'last_reviewed: 2026-09-02'));
  await assert.rejects(prepare(), /conflicting metadata snapshot/);
});

test('accepts the release tool ID grammar and rejects unsafe or overlong IDs', async (t) => {
  const { prepare, read } = await fixture(t, { releaseId: 'Beta_41' });
  assert.equal((await prepare()).changedPaths.length, 2);
  assert.match(await read('docsets'), /Beta_41 candidate/);
  for (const releaseId of ['', '.beta', '../beta', 'beta/41', 'a'.repeat(65)]) {
    await assert.rejects(prepare({ releaseId }), /release identifier/);
  }
});
