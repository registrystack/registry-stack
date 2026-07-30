import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { extractFencedBlocks } from './registryctl-tutorial.mjs';

const siteRoot = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(siteRoot, relativePath), 'utf8');
}

function fence(markdown, heading, language, occurrence = 1) {
  const match = extractFencedBlocks(markdown).find(
    (block) =>
      block.heading === heading &&
      block.language === language &&
      block.occurrence === occurrence,
  );
  assert.ok(match, `missing ${heading} ${language} fence ${occurrence}`);
  return match.content;
}

const firstInstallation = [
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml config --no-interpolate --no-env-resolution --quiet',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-runtime-stage-secrets',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-postgres-bootstrap',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-public-prepare-state',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-consultation-prepare-state',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-notary-prepare-state',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-public-initialize',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-relay-consultation-initialize',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml -f generated/compose.initialize.yaml run --rm registry-notary-initialize',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml up --detach --wait --wait-timeout 120',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml ps',
].join('\n');

const ordinaryStartAndStop = [
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml config --no-interpolate --no-env-resolution --quiet',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-runtime-stage-secrets',
  "docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-relay-public 'product-action' 'relay-public' 'verify_state'",
  "docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-relay-consultation 'product-action' 'relay-consultation' 'verify_state'",
  "docker compose --env-file generated/compose.empty.env -f generated/compose.yaml run --rm --no-deps registry-notary 'product-action' 'verify_state'",
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml up --detach --wait --wait-timeout 120',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml ps',
  'docker compose --env-file generated/compose.empty.env -f generated/compose.yaml down',
].join('\n');

test('public OAuth and Rhai journey applies a generated docs asset to a fresh HTTP starter', () => {
  const gate = read('scripts/check-registryctl-tutorials.sh');
  const oauth = read('src/content/docs/tutorials/configure-project-script-adapter.mdx');
  const opencrvs = read('src/content/docs/tutorials/verify-opencrvs-claims.mdx');
  const overlay = read('public/examples/registryctl/opencrvs-events-api-overlay-v1.sh');

  for (const page of [oauth, opencrvs]) {
    assert.match(page, /registryctl init .* --template http/);
    assert.match(page, /rm -r integrations\/person-record/);
    assert.match(page, /opencrvs-events-api-overlay-v1\.sh/);
  }
  assert.match(gate, /init "\$OPENCRVS_PROJECT" --template http/);
  assert.match(gate, /rm -r "\$OPENCRVS_PROJECT\/integrations\/person-record"/);
  assert.match(gate, /sh "\$OPENCRVS_OVERLAY"/);
  assert.match(gate, /check --explain/);
  assert.match(gate, /registry\.project\.explanation\.v1/);
  assert.doesNotMatch(gate, /OPENCRVS_FIXTURE|cp -R/);
  assert.match(overlay, /fixtures\/oauth-expiry\.yaml/);
  assert.match(overlay, /fixtures\/source-timeout\.yaml/);
  assert.match(overlay, /adapter\.rhai/);
});

test('optional public-source continuation has exact offline and opt-in live gates', () => {
  const page = read('src/content/docs/tutorials/author-registry-project.mdx');
  const gate = read('scripts/check-registryctl-public-source-live.sh');
  const overlay = read('public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh');

  assert.match(page, /registryctl init public-json-live-demo --template http/);
  assert.match(page, /jsonplaceholder-todo-live-overlay-v1\.sh/);
  assert.match(page, /registryctl test --environment local/);
  assert.match(page, /registryctl check --environment public-demo --explain/);
  assert.match(page, /registryctl dev --environment public-demo smoke/);
  assert.match(page, /registryctl dev --environment public-demo-missing smoke/);
  assert.match(page, /rm -r public-json-live-demo/);
  assert.match(page, /authoritative project-contract evidence/);
  assert.match(page, /outside Registry Stack's\ntrust boundary/);
  assert.match(page, /not an institutional registry/);

  assert.match(gate, /REGISTRYCTL_PUBLIC_SOURCE_LIVE/);
  assert.match(gate, /REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR/);
  assert.match(gate, /https:\/\/jsonplaceholder\.typicode\.com\/todos\/4/);
  assert.match(gate, /https:\/\/jsonplaceholder\.typicode\.com\/todos\/999999/);
  assert.match(gate, /expected 200/);
  assert.match(gate, /expected 404/);
  assert.match(gate, /--environment "\$environment" smoke/);

  assert.match(overlay, /source_mode: operator_bound/);
  assert.match(overlay, /origin: https:\/\/jsonplaceholder\.typicode\.com/);
  assert.match(overlay, /auth: \{ type: none \}/);
  assert.match(overlay, /default_fixture: completed-todo/);
  assert.match(overlay, /default_fixture: no-todo/);
  assert.doesNotMatch(overlay, /credential:/);
});

test('Compose command blocks exactly reproduce the generated runbook sequence', () => {
  const page = read('src/content/docs/operate/single-node-compose-behind-proxy.mdx');
  assert.equal(fence(page, 'Initialize each product once', 'sh', 2), firstInstallation);
  assert.equal(fence(page, 'Run the package standalone', 'sh'), ordinaryStartAndStop);
});

test('Compose include remains operator-owned and outside package verification', () => {
  const page = read('src/content/docs/operate/single-node-compose-behind-proxy.mdx');
  assert.match(page, /Registryctl verifies only the generated package/);
  assert.match(page, /operator owns the include graph/);
  assert.match(
    page,
    /docker compose --env-file \.\/registry-stack\/generated\/compose\.empty\.env -f \.\/compose\.yaml config --no-interpolate --no-env-resolution --quiet/,
  );
  assert.doesNotMatch(page, /docker compose -f \.\/compose\.yaml config/);
  assert.doesNotMatch(page, /--parent-compose|package_and_parent|parent-scoped verification/);
  assert.doesNotMatch(page, /Metrics use|metrics ports|operator-override|Registryctl-certified/);
});

test('initial approval bridge covers every lane before approved-set assembly', () => {
  const page = read('src/content/docs/operate/approve-initial-baseline.mdx');
  for (const lane of ['relay-public', 'relay-consultation', 'notary']) {
    assert.match(page, new RegExp(`--lane ${lane}`));
    assert.match(page, new RegExp(`signing-inputs/${lane}`));
    assert.match(page, new RegExp(`${lane}-anchor\\.json`));
    assert.match(page, new RegExp(`${lane}-bundle`));
  }
  assert.match(page, /registryctl trust approved-set assemble/);
  assert.match(page, /--output-file operator-handoff\/approved-set\.v1\.json/);
  assert.match(page, /registryctl deploy verify --package operator-handoff\/registry-stack/);
  assert.match(page, /registryctl trust anchor rotate/);
  assert.match(page, /--current-anchor "\$CURRENT_ANCHOR"/);
  assert.match(page, /--against "\$CURRENT_APPROVED_SET"/);
  assert.match(page, /registryctl trust bundle verify/);
  assert.match(page, /registryctl trust approved-set assemble \\\n  --from "\$CURRENT_APPROVED_SET"/);
  assert.match(page, /--approved-set operator-handoff\/approved-set\.v2\.json/);
  assert.match(page, /registryctl deploy verify --package operator-handoff\/registry-stack\.v2/);
});
