import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';

const siteRoot = resolve(import.meta.dirname, '..');
const advancedRoot = resolve(
  siteRoot,
  'src/content/docs/operate/advanced',
);

const taskPages = [
  'rotate-credentials-and-trust.mdx',
  'compare-and-reapprove-source-change.mdx',
  'refresh-and-recover-materialization.mdx',
  'recover-upgrade-migrate-and-rollback.mdx',
  'inspect-and-diagnose.mdx',
  'operate-script-workers.mdx',
];

async function readPage(name) {
  return readFile(resolve(advancedRoot, name), 'utf8');
}

async function readSitePage(path) {
  return readFile(resolve(siteRoot, 'src/content/docs', path), 'utf8');
}

test('advanced operator pages are goal-oriented and include recovery evidence', async () => {
  const requiredSections = [
    '## Prerequisites',
    '## Ownership and trust boundary',
    '## Expected evidence',
    '## What this proves',
    '## Roll back or recover',
    '## Escalate',
    '## Next',
  ];

  for (const pageName of taskPages) {
    const source = await readPage(pageName);
    assert.match(source, /^status: current$/m, pageName);
    assert.match(source, /^doc_type: how-to$/m, pageName);
    for (const section of requiredSections) {
      assert.ok(source.includes(section), `${pageName} is missing ${section}`);
    }
    assert.match(source, /does not prove|do not prove/i, pageName);
  }
});

test('advanced operations cover every FC3-E recoverable operator task', async () => {
  const source = (
    await Promise.all(['index.mdx', ...taskPages].map(readPage))
  ).join('\n');

  for (const expected of [
    /source credential/i,
    /caller key/i,
    /signing key/i,
    /certificate/i,
    /trust anchor/i,
    /verified baseline/i,
    /reapprove/i,
    /source product or version label/i,
    /without widening/i,
    /refresh/i,
    /serving_last_good/,
    /retention/i,
    /back up/i,
    /restore/i,
    /restart/i,
    /upgrade/i,
    /pre-1\.0 cutover/i,
    /roll back/i,
    /redacted posture/i,
    /audit/i,
    /healthz/,
    /ready/,
    /openapi\.json/i,
    /source denial/i,
    /policy denial/i,
    /ambiguity/i,
    /stale materialization/i,
    /bundle rejection/i,
    /capability.*mismatch/i,
    /bounded Script worker/i,
    /protocol\.fhir\.parse_searchset/,
    /protocol\.dci\.search/,
  ]) {
    assert.match(source, expected);
  }
});

test('diagnosis uses generated references and stable code vocabulary', async () => {
  const source = await readPage('inspect-and-diagnose.mdx');

  for (const link of [
    '../../../reference/diagnostics/operator/',
    '../../../reference/diagnostics/fixture/',
    '../../../reference/diagnostics/authoring/',
    '../../../reference/errors/',
  ]) {
    assert.ok(source.includes(`](${link})`), `missing stable link ${link}`);
  }

  for (const code of [
    'relay.consultation.activation.source_credentials_unavailable',
    'notary.relay.credentials_rejected',
    'pdp.purpose_not_permitted',
    'pdp.evidence_stale',
    'source.cardinality_violation',
    'rejected_signature',
    'rejected_binding',
    'rejected_validation',
    'rejected_rollback',
    'relay.consultation.activation.unsupported_plan',
    'notary.relay.profile_mismatch',
    'registry.admin.capability.not_supported',
  ]) {
    assert.ok(source.includes(`\`${code}\``), `missing stable code ${code}`);
  }

  assert.match(
    source,
    /registryctl tooling diagnostics --catalog operator --format json/,
  );
  assert.match(
    source,
    /registryctl tooling diagnostics --catalog fixture --format json/,
  );
  assert.match(
    source,
    /registryctl tooling diagnostics --catalog authoring --format json/,
  );
});

test('advanced operations preserve product activation and confidentiality boundaries', async () => {
  const source = (
    await Promise.all(['index.mdx', ...taskPages].map(readPage))
  ).join('\n');

  assert.match(source, /separate (?:product )?bundles/i);
  assert.match(source, /not atomic project activation/i);
  assert.match(source, /admit (?:caller )?traffic only after both product/i);
  assert.match(source, /do not use personal data|with synthetic identifiers/i);

  for (const superseded of [
    /activate Relay and Notary as one/i,
    /root manifest binds compatible Relay and Notary/i,
    /atomic project activation coordinator/i,
    /live country (?:proof|success|interoperability)/i,
  ]) {
    assert.doesNotMatch(source, superseded);
  }
});

test('bundle verification separates stateless closure from product rollback eligibility', async () => {
  const source = await readPage('rotate-credentials-and-trust.mdx');

  assert.match(
    source,
    /ROTATED_TRUST=operator-inputs\/rotated-relay-consultation-trust[\s\S]*?SIGNED_PRODUCT_BUNDLE=operator-inputs\/signed-relay-consultation-next[\s\S]*?registryctl trust bundle sign[\s\S]*?--anchor "\$ROTATED_TRUST\/anchor\.json"[\s\S]*?--against "\$CURRENT_APPROVED_SET"[\s\S]*?PRODUCT_TRUST_ANCHOR="\$ROTATED_TRUST\/anchor\.json"[\s\S]*?registryctl trust bundle verify[\s\S]*?--bundle-dir "\$SIGNED_PRODUCT_BUNDLE"[\s\S]*?--anchor "\$PRODUCT_TRUST_ANCHOR"/,
  );
  assert.match(
    source,
    /registryctl trust approved-set assemble[\s\S]*?--from "\$CURRENT_APPROVED_SET"[\s\S]*?--relay-consultation "\$SIGNED_PRODUCT_BUNDLE"/,
  );
  assert.match(
    source,
    /does not read product anti-rollback state or establish local rollback eligibility/,
  );
  for (const [product, stateVariable] of [
    ['registry-relay', 'RELAY_ROLLBACK_STATE'],
    ['registry-notary', 'NOTARY_ROLLBACK_STATE'],
  ]) {
    assert.match(
      source,
      new RegExp(
        `${product} config verify-bundle[\\s\\S]*?` +
          '--bundle-dir "\\$SIGNED_PRODUCT_BUNDLE"[\\s\\S]*?' +
          '--anchor-path "\\$PRODUCT_TRUST_ANCHOR"[\\s\\S]*?' +
          `--state-path "\\$${stateVariable}"`,
      ),
    );
  }
  assert.match(source, /require accepted state to exist/);
  assert.match(source, /without persisting an acceptance/);
  assert.doesNotMatch(
    source,
    /(?:registryctl )?[Bb]undle verification proves[\s\S]{0,100}anti-rollback eligibility/,
  );
});

test('materialization refresh uses one supported table path and rejects reload-all', async () => {
  const source = await readPage('refresh-and-recover-materialization.mdx');

  assert.match(
    source,
    /\/admin\/v1\/datasets\/<dataset-id>\/tables\/<table-id>\/reload/,
  );
  assert.match(
    source,
    /Do not use `\/admin\/v1\/reload` for a deployment that contains any audited SnapshotExact plan/,
  );
  assert.match(
    source,
    /rejects the complete reload-all request with `ingest\.materialization_failed`/,
  );
  assert.match(source, /refreshes no resource/);
  assert.match(source, /There is no atomic multi-materialization admin refresh/);
  assert.doesNotMatch(
    source,
    /http:\/\/127\.0\.0\.1:8081\/admin\/v1\/reload(?:\s|$)/,
  );
  assert.doesNotMatch(
    source,
    /Reload-all prepares every resource before publishing any resource/,
  );
});

test('advanced operations contain no secret material or unsafe copy-paste values', async () => {
  const source = (
    await Promise.all(['index.mdx', ...taskPages].map(readPage))
  ).join('\n');

  for (const secretMaterial of [
    /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/,
    /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
    /\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*["']?(?!<)[A-Za-z0-9/+_-]{16,}/i,
    /REGISTRY_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY)=/,
  ]) {
    assert.doesNotMatch(source, secretMaterial);
  }

  assert.doesNotMatch(source, /curl[^\n]*\s-[^-]*d\s+.*(?:secret|token|password)/i);
});

test('materialization recovery documents the exact fail-closed and recovery boundaries', async () => {
  const refresh = await readPage('refresh-and-recover-materialization.mdx');
  const backup = await readSitePage('operate/backup-and-restore.mdx');
  const retention = await readSitePage(
    'operate/retention-and-persistent-state.mdx',
  );
  const source = [refresh, backup, retention].join('\n');

  assert.match(refresh, /any audited SnapshotExact plan/i);
  assert.match(refresh, /rejects the complete reload-all request/i);
  assert.match(refresh, /table-specific endpoint/i);
  assert.match(refresh, /ordinary reads retain their previous ready table/i);
  assert.match(refresh, /global `\/ready` can remain `200`/i);
  assert.match(refresh, /execution-time SnapshotExact freshness/i);

  assert.match(source, /`retain_generations`[^.]*from `1` through `16`/i);
  assert.match(
    source,
    /not an admin-selectable list of\s+arbitrary rollback targets/i,
  );
  assert.match(backup, /one coordinated recovery point/i);
  assert.match(
    backup,
    /source inputs, the Relay ingest cache, and the Relay\s+consultation database/i,
  );
  assert.match(source, /database active pointer and\s+history/i);
  assert.match(
    source,
    /exact active generation and restricted content\s+digest/i,
  );
  assert.match(backup, /A list of unrelated artifact hashes is not evidence/i);
});

test('backup and update use only the generated 1.0 deployment lifecycle', async () => {
  const backup = await readSitePage('operate/backup-and-restore.mdx');
  const update = await readSitePage('operate/upgrade-and-rollback.mdx');
  const source = [backup, update].join('\n');

  assert.doesNotMatch(
    source,
    /\bregistryctl\s+(?:start|stop|smoke|init|add)\b/i,
  );
  assert.match(backup, /Keep Registryctl out of backup automation/i);
  assert.match(backup, /`relay-public-state`/);
  assert.match(backup, /`consultation-state`/);
  assert.match(backup, /operator owns those controls and the recovery decision/i);
  assert.match(update, /fresh, verified generated package/i);
  assert.match(update, /`generated\/RUNBOOK\.md`/);
  assert.match(update, /`generated\.previous\/`/);
  assert.match(update, /rollback is unsupported/i);
  assert.match(update, /Do not configure an automated rollback/i);
  assert.doesNotMatch(source, /registry-runtime-stage-secrets/);

  const orderedStagers = new RegExp(
    [
      'registry-relay-public-stage-secrets',
      'registry-relay-consultation-stage-secrets',
      'registry-notary-stage-secrets',
      'registry-postgresql-stage-secrets',
      "'verify_state'",
    ].join('[\\s\\S]*'),
  );
  for (const page of [backup, update]) {
    assert.match(page, orderedStagers);
    for (const stager of [
      'registry-relay-public-stage-secrets',
      'registry-relay-consultation-stage-secrets',
      'registry-notary-stage-secrets',
      'registry-postgresql-stage-secrets',
    ]) {
      assert.match(page, new RegExp(`run --rm --no-deps ${stager}`));
    }
    assert.match(page, /generated\/compose\.empty\.env/);
    assert.match(page, /generated\/compose\.yaml/);
    assert.match(page, /'verify_state'/);
    assert.match(page, /\n\s+down\n/);
    assert.match(page, /\n\s+up --detach --wait --wait-timeout 120/);
  }
});

test('advanced recovery preserves the generated-package acceptance boundary', async () => {
  const recovery = await readPage(
    'recover-upgrade-migrate-and-rollback.mdx',
  );

  assert.match(recovery, /fresh candidate/i);
  assert.match(recovery, /generated\/RUNBOOK\.md/);
  assert.match(recovery, /`relay-public-state`/);
  assert.match(recovery, /`consultation-state`/);
  assert.match(recovery, /rollback\s+is unsupported/i);
  assert.match(recovery, /Do not configure an automated rollback/i);
  assert.doesNotMatch(
    recovery,
    /registry-relay consultation bootstrap-state|registry-notary[^.\n]*state install/i,
  );
  assert.doesNotMatch(recovery, /Use rollback after target traffic/i);
});
