import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
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
  'attribute-release',
  'crosswalk-runtime',
]);

const experimentalIds = new Set([
  'live-ogc-api-records',
  'ogc-api-features',
  'ogc-api-edr',
  'sp-dci-sync',
  'standards-cel-mapping',
  'sdmx-json-aggregate-output',
  'csv-aggregate-output',
  'parquet-source-input',
]);

const issue487Ids = new Set(['attribute-release', 'crosswalk-runtime']);

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
    const issue487 = issue487Ids.has(entry.id);
    assert.equal(
      entry.decision_date,
      issue487 ? '2026-07-25' : '2026-07-19',
      `${entry.id} decision date`,
    );
    assert.equal(
      entry.decision_reference,
      `https://github.com/registrystack/registry-stack/issues/${issue487 ? '487' : '305'}`,
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

test('Relay V1 local image and OpenAPI use the same feature set', async () => {
  const roster = await loadRoster();
  const canonicalFeatures = new Set(
    roster
      .filter((entry) => entry.canonical_release)
      .flatMap((entry) => entry.cargo_features),
  );
  assert.deepEqual(
    canonicalFeatures,
    new Set(['attribute-release', 'crosswalk-runtime']),
    'the approved 1.0 Relay feature list must be exact',
  );
  const canonicalProfile = (
    await readRepo('crates/registry-relay/canonical-release-features.txt')
  ).trim();
  assert.deepEqual(
    new Set(canonicalProfile.split(',')),
    canonicalFeatures,
    'the canonical release profile must match the approved 1.0 roster',
  );

  const cargoToml = await readRepo('crates/registry-relay/Cargo.toml');
  const cargoFeatureSection = cargoToml.match(/\[features\]\n([\s\S]*?)\n\[/)?.[1];
  assert.ok(cargoFeatureSection, 'Relay Cargo.toml must declare a features table');
  const declaredFeatures = new Set(
    [...cargoFeatureSection.matchAll(/^([a-z][a-z0-9-]*)\s*=\s*\[/gm)].map(
      (match) => match[1],
    ),
  );
  for (const feature of roster.flatMap((entry) => entry.cargo_features)) {
    assert.ok(declaredFeatures.has(feature), `rostered source feature ${feature} must remain`);
  }
  assert.deepEqual(
    new Set(roster.flatMap((entry) => entry.cargo_features)),
    new Set([...declaredFeatures].filter((feature) => feature !== 'default')),
    'every Relay Cargo feature must have one support-roster decision',
  );
  assert.match(
    cargoToml,
    /^default = \["attribute-release"\]$/m,
    'the developer default must enable stable attribute release',
  );

  const dockerfile = await readRepo('crates/registry-relay/Dockerfile');
  const dockerProfile = dockerfile.match(/^ARG REGISTRY_RELAY_FEATURES="([^"]+)"$/m)?.[1];
  assert.equal(
    dockerProfile,
    canonicalProfile,
    'the local production image must default to the canonical feature set',
  );

  const openapiContract = await readRepo(
    'crates/registry-relay/scripts/check-openapi-contract.sh',
  );
  assert.match(
    openapiContract,
    /RELEASE_FEATURES=.*canonical-release-features\.txt/,
    'the OpenAPI contract must read the canonical Relay feature profile',
  );
  assert.match(
    openapiContract,
    /--no-default-features --features "\$RELEASE_FEATURES"/,
    'the OpenAPI contract must select the canonical Relay feature profile exactly',
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
  assert.ok(
    openapi.paths['/v1/attribute-releases'],
    'stable attribute release discovery must appear in the pinned OpenAPI',
  );
  assert.ok(
    openapi.paths['/v1/attribute-releases/{profile_id}/versions/{version}/resolve'],
    'stable attribute release resolution must appear in the pinned OpenAPI',
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
