import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

import {
  diagnosticCatalogs,
  generateDiagnosticReferences,
  validateDiagnosticReference,
} from './generate-diagnostic-references.mjs';

const productOwnedDocsSlugFamilies = new Set([
  'bundle_verification',
  'notary_activation',
  'relay_activation',
  'relay_process_startup',
]);

const entry = (catalog, family, owner, product, code) => ({
  family,
  code,
  owner,
  product,
  phase: 'static_phase',
  safe_meaning: 'Static catalog meaning without runtime values.',
  rule: 'registry.reference.static_rule',
  safe_remediation: 'Correct the reviewed static input and retry.',
  field_address_pattern: null,
  evidence_scope: 'static catalog metadata',
  secret_sensitive_value_policy: 'no_runtime_values',
  docs_anchor: `/reference/diagnostics/${catalog}/#${product}--${
    productOwnedDocsSlugFamilies.has(family) ? 'static-test' : code
  }`,
  lifecycle: 'unreleased',
  introduced_in: null,
  stability: 'pre1_stable_code',
  evidence_limitation: 'This reference does not inspect runtime values.',
});

function fixtureReferences() {
  return {
    authoring: {
      schema_version: diagnosticCatalogs.authoring.schemaVersion,
      entries: [
        entry(
          'authoring',
          'authoring_validation',
          'registryctl',
          'registryctl',
          'registryctl.authoring.test',
        ),
      ],
    },
    fixture: {
      schema_version: diagnosticCatalogs.fixture.schemaVersion,
      entries: [
        entry(
          'fixture',
          'fixture_execution',
          'registryctl',
          'registryctl_relay_offline_harness',
          'fixture.test',
        ),
      ],
    },
    operator: {
      schema_version: diagnosticCatalogs.operator.schemaVersion,
      entries: [
        entry(
          'operator',
          'bundle_verification',
          'registry_platform_ops',
          'registry_platform_ops',
          'rejected_test',
        ),
        entry(
          'operator',
          'relay_activation',
          'registry_relay',
          'registry_relay',
          'relay.activation.test',
        ),
      ],
      omissions: [],
    },
  };
}

function fixtureExecutor(references, { divergent = false } = {}) {
  const calls = new Map();
  return async (_repoRoot, args) => {
    const catalog = args[args.indexOf('--catalog') + 1];
    const count = (calls.get(catalog) ?? 0) + 1;
    calls.set(catalog, count);
    const output = JSON.stringify(references[catalog], null, 2);
    return `${output}${divergent && count === 2 ? ' ' : ''}\n`;
  };
}

test('publishes opaque, byte-identical internal and public artifacts after two exact CLI runs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-diagnostic-reference-'));
  try {
    const references = fixtureReferences();
    const repoRoot = join(root, 'repo');
    await generateDiagnosticReferences(root, repoRoot, fixtureExecutor(references));
    for (const contract of Object.values(diagnosticCatalogs)) {
      const internal = await readFile(resolve(root, contract.internal), 'utf8');
      assert.equal(
        internal,
        await readFile(resolve(root, contract.public), 'utf8'),
      );
      assert.equal(
        internal,
        await readFile(resolve(repoRoot, contract.fixture), 'utf8'),
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects nondeterminism before publishing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-diagnostic-reference-'));
  try {
    await assert.rejects(
      generateDiagnosticReferences(
        root,
        '/unused',
        fixtureExecutor(fixtureReferences(), { divergent: true }),
      ),
      /not byte deterministic/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects unknown, reordered, duplicate, stale-lifecycle, unsafe, and wrong-owner entries', () => {
  const unknown = fixtureReferences().authoring;
  unknown.entries[0].unexpected = true;
  assert.throws(() => validateDiagnosticReference('authoring', unknown), /exactly/);

  const reordered = fixtureReferences().operator;
  reordered.entries.reverse();
  assert.throws(() => validateDiagnosticReference('operator', reordered), /not ordered/);

  const duplicate = fixtureReferences().operator;
  duplicate.entries.push({ ...duplicate.entries[1] });
  assert.throws(() => validateDiagnosticReference('operator', duplicate), /duplicate/);

  const stale = fixtureReferences().fixture;
  stale.entries[0].introduced_in = '0.13.0';
  assert.throws(() => validateDiagnosticReference('fixture', stale), /introduced_in: null/);

  const unsafe = fixtureReferences().authoring;
  unsafe.entries[0].safe_meaning = 'COUNTRY_SECRET_SENTINEL';
  assert.throws(() => validateDiagnosticReference('authoring', unsafe), /runtime or secret/);

  const owner = fixtureReferences().operator;
  owner.entries[0].owner = 'registry_relay';
  assert.throws(() => validateDiagnosticReference('operator', owner), /product-owner/);

  const policy = fixtureReferences().operator;
  policy.entries[0].secret_sensitive_value_policy = 'print_received_value';
  assert.throws(() => validateDiagnosticReference('operator', policy), /not closed/);

  const stability = fixtureReferences().operator;
  stability.entries[0].stability = 'experimental';
  assert.throws(() => validateDiagnosticReference('operator', stability), /not supported/);

  const omission = fixtureReferences().operator;
  omission.omissions.push({
    family: 'relay_process_startup',
    product: 'registry_relay',
    reason: 'temporary_gap',
    evidence: 'A static catalog gap.',
    required_action: 'Publish complete product-owned metadata.',
  });
  assert.throws(() => validateDiagnosticReference('operator', omission), /reason is not supported/);
});
