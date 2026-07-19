import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import test from 'node:test';
import YAML from 'yaml';

const docsRoot = process.cwd();
const repoRoot = resolve(docsRoot, '../..');

const stableIds = new Set([
  'openapi-publication',
  'rfc9457-problem-contract',
  'rfc9727-api-catalog',
  'dcat-metadata',
  'bregdcat-ap-metadata',
  'json-ld-metadata',
  'shacl-metadata',
  'json-schema-metadata',
  'odrl-metadata',
  'link-free-ogc-records-metadata',
  'csv-source-input',
  'xlsx-source-input',
  'json-aggregate-output',
]);

const experimentalIds = new Set([
  'live-ogc-api-records',
  'ogc-api-features',
  'ogc-api-edr',
  'sp-dci-sync',
  'standards-cel-mapping',
  'sdmx-json-aggregate-output',
  'csv-aggregate-output',
  'attribute-release',
  'parquet-source-input',
]);

async function readRepo(path) {
  return readFile(resolve(repoRoot, path), 'utf8');
}

async function loadRoster() {
  return YAML.parse(await readFile(resolve(docsRoot, 'src/data/relay-support.yaml'), 'utf8'));
}

test('Relay 1.0 roster pins the approved stable and experimental surfaces', async () => {
  const roster = await loadRoster();
  const ids = roster.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length, 'roster ids must be unique');
  assert.deepEqual(
    new Set(roster.filter((entry) => entry.stability_tier === 'stable').map((entry) => entry.id)),
    stableIds,
  );
  assert.deepEqual(
    new Set(
      roster.filter((entry) => entry.stability_tier === 'experimental').map((entry) => entry.id),
    ),
    experimentalIds,
  );

  for (const entry of roster) {
    assert.equal(entry.decision_date, '2026-07-19', `${entry.id} decision date`);
    assert.equal(
      entry.decision_reference,
      'https://github.com/registrystack/registry-stack/issues/305',
      `${entry.id} decision reference`,
    );
    assert.ok(entry.evidence, `${entry.id} evidence reference`);
    if (entry.stability_tier === 'stable') {
      assert.notEqual(entry.support_owner, 'none', `${entry.id} needs a support owner`);
      assert.equal(entry.feature_frozen, false, `${entry.id} must not be frozen`);
      assert.equal(entry.canonical_release, true, `${entry.id} must be in the release contract`);
    } else {
      assert.equal(entry.support_owner, 'none', `${entry.id} has no approved support owner`);
      assert.equal(entry.feature_frozen, true, `${entry.id} must be feature-frozen`);
      assert.equal(entry.canonical_release, false, `${entry.id} must remain outside 1.0`);
    }
  }
});

test('generated Relay roster is byte-for-byte current', async () => {
  const source = await loadRoster();
  const generated = await readFile(
    resolve(docsRoot, 'src/data/generated/relay-support.json'),
    'utf8',
  );
  assert.equal(generated, `${JSON.stringify(source, null, 2)}\n`);
});

test('included unstable OpenAPI formats publish machine-readable selectors', async () => {
  const roster = await loadRoster();
  const includedUnstable = roster.filter((entry) => entry.openapi_policy === 'included_unstable');
  assert.deepEqual(
    new Map(includedUnstable.map((entry) => [entry.id, entry.openapi_selectors])),
    new Map([
      [
        'sdmx-json-aggregate-output',
        {
          format_tokens: ['sdmx-json'],
          media_types: ['application/vnd.sdmx.data+json;version=2.1'],
        },
      ],
      [
        'csv-aggregate-output',
        { format_tokens: ['csv'], media_types: ['text/csv'] },
      ],
    ]),
  );
  for (const entry of includedUnstable) {
    assert.equal(entry.category, 'aggregate_output', `${entry.id} selector category`);
  }
});

test('canonical Relay release, local image, and OpenAPI use the same feature set', async () => {
  const roster = await loadRoster();
  const canonicalFeatures = new Set(
    roster
      .filter((entry) => entry.canonical_release)
      .flatMap((entry) => entry.cargo_features),
  );
  assert.deepEqual(canonicalFeatures, new Set(), 'the approved 1.0 Relay feature list is empty');

  const cargoToml = await readRepo('crates/registry-relay/Cargo.toml');
  const declaredFeatures = new Set(
    [...cargoToml.matchAll(/^([a-z][a-z0-9-]*)\s*=\s*\[/gm)].map((match) => match[1]),
  );
  for (const feature of roster.flatMap((entry) => entry.cargo_features)) {
    assert.ok(declaredFeatures.has(feature), `experimental source feature ${feature} must remain`);
  }

  const dockerfile = await readRepo('crates/registry-relay/Dockerfile');
  assert.match(
    dockerfile,
    /^ARG REGISTRY_RELAY_FEATURES=""$/m,
    'the local production image must default to the canonical empty feature set',
  );

  const workflowPath = process.env.RELAY_RELEASE_WORKFLOW_PATH ?? '.github/workflows/release.yml';
  const workflow = isAbsolute(workflowPath)
    ? await readFile(workflowPath, 'utf8')
    : await readRepo(workflowPath);
  const workflowRelayFeatures = new Set(
    [...workflow.matchAll(/--features\s+([^\s'"]+)/g)]
      .flatMap((match) => match[1].split(','))
      .filter((feature) => feature.startsWith('registry-relay/'))
      .map((feature) => feature.slice('registry-relay/'.length)),
  );
  assert.deepEqual(
    workflowRelayFeatures,
    canonicalFeatures,
    'the release workflow Relay features must match the canonical 1.0 roster',
  );

  const openapi = JSON.parse(
    await readRepo('crates/registry-relay/openapi/registry-relay.openapi.json'),
  );
  const exposure = JSON.parse(
    await readRepo('crates/registry-relay/security/exposure-manifest.json'),
  );
  const experimentalFeatures = new Set(
    roster
      .filter((entry) => entry.stability_tier === 'experimental')
      .flatMap((entry) => entry.cargo_features),
  );
  for (const endpoint of exposure.endpoints.filter(
    (entry) => entry.feature && experimentalFeatures.has(entry.feature),
  )) {
    assert.equal(endpoint.stability, 'experimental', `${endpoint.method} ${endpoint.path} tier`);
    assert.equal(
      openapi.paths[endpoint.path],
      undefined,
      `${endpoint.path} must not appear in the pinned canonical OpenAPI`,
    );
  }
  assert.ok(
    openapi.paths['/metadata/ogc/records'],
    'stable link-free OGC Records metadata must remain in the pinned OpenAPI',
  );

  const justfile = await readRepo('crates/registry-relay/justfile');
  assert.match(justfile, /^\s*cargo test --all-features$/m, 'all-feature tests must remain enabled');
});

test('Relay documentation distinguishes source decoders from aggregate output', async () => {
  const readme = await readRepo('crates/registry-relay/README.md');
  assert.match(readme, /CSV, XLSX, and Parquet are source decoders/);
  assert.match(readme, /Aggregate output supports JSON,\s+CSV, and SDMX-JSON/);
  assert.match(readme, /Experimental surfaces are outside the 1\.0 compatibility promise/);
});
