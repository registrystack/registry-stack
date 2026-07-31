import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import {
  closeSync,
  constants,
  cpSync,
  fstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import { extractFencedBlocks } from './registryctl-tutorial.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const starterRoot = resolve(
  siteRoot,
  '../../crates/registryctl/assets/project-starters/bounded-http',
);

function read(relativePath) {
  return readFileSync(resolve(siteRoot, relativePath), 'utf8');
}

function exactLines(source) {
  return new Set(source.split(/\r?\n/));
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

function temporaryStarter(t) {
  const root = mkdtempSync(join(tmpdir(), 'registryctl-docs-overlay-'));
  const project = resolve(root, 'project');
  cpSync(starterRoot, project, { recursive: true });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return project;
}

function runScriptFile(scriptPath, cwd) {
  return spawnSync('/bin/sh', ['-eu', scriptPath], {
    cwd,
    encoding: 'utf8',
  });
}

function runShellSnippet(script, cwd, env = {}) {
  return spawnSync('/bin/sh', ['-eu'], {
    cwd,
    encoding: 'utf8',
    input: script,
    env: { ...process.env, ...env },
  });
}

function pathMode(path, flags = constants.O_RDONLY) {
  const descriptor = openSync(path, flags);
  try {
    return fstatSync(descriptor).mode & 0o777;
  } finally {
    closeSync(descriptor);
  }
}

function readRegularUtf8WithMode(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    const stats = fstatSync(descriptor);
    assert.ok(stats.isFile(), `${path} must be a regular file`);
    return {
      mode: stats.mode & 0o777,
      content: readFileSync(descriptor, 'utf8'),
    };
  } finally {
    closeSync(descriptor);
  }
}

function assertPathMissing(path) {
  assert.throws(() => readFileSync(path), /ENOENT/);
}

function assertOverlayChecksum(relativePath) {
  const overlayPath = resolve(siteRoot, relativePath);
  const checksum = readFileSync(`${overlayPath}.sha256`, 'ascii').trimEnd();
  const expected = createHash('sha256').update(readFileSync(overlayPath)).digest('hex');
  assert.equal(checksum, `${expected}  ${basename(overlayPath)}`);
}

const compose =
  'docker compose --project-name "$REGISTRY_STACK_COMPOSE_PROJECT" --env-file generated/compose.empty.env -f generated/compose.yaml';
const actions = `${compose} -f generated/compose.initialize.yaml`;
const servingStages = [
  'registry-relay-public-stage-secrets',
  'registry-relay-consultation-stage-secrets',
  'registry-notary-stage-secrets',
  'registry-postgresql-stage-secrets',
].map((service) => `${compose} run --rm --no-deps ${service}`);
const stateVerifiers = [
  'registry-relay-public-verify-state',
  'registry-relay-consultation-verify-state',
  'registry-notary-verify-state',
].map((service) => `${actions} run --rm --no-deps ${service}`);

const firstInstallation = [
  `${actions} config --no-interpolate --no-env-resolution --quiet`,
  `${actions} run --rm --no-deps registry-relay-consultation-actions-stage-secrets`,
  `${actions} run --rm --no-deps registry-notary-actions-stage-secrets`,
  `${actions} run --rm --no-deps registry-postgresql-actions-stage-secrets`,
  `${actions} run --rm registry-postgres-bootstrap`,
  `${actions} run --rm registry-relay-public-prepare-state`,
  `${actions} run --rm registry-relay-consultation-prepare-state`,
  `${actions} run --rm registry-notary-prepare-state`,
  `${actions} run --rm registry-relay-public-initialize`,
  `${actions} run --rm registry-relay-consultation-initialize`,
  `${actions} run --rm registry-notary-initialize`,
  ...stateVerifiers,
  ...servingStages,
  `${compose} up --detach --wait --wait-timeout 120`,
  `${compose} ps`,
].join('\n');

const ordinaryStartAndStop = [
  `${compose} config --no-interpolate --no-env-resolution --quiet`,
  ...stateVerifiers,
  ...servingStages,
  `${compose} up --detach --wait --wait-timeout 120`,
  `${compose} ps`,
  `${compose} down`,
].join('\n');

const productUpdate = [
  `${actions} run --rm --no-deps registry-relay-public-preview-state`,
  `${actions} run --rm --no-deps registry-relay-consultation-preview-state`,
  `${actions} run --rm --no-deps registry-notary-preview-state`,
  `${compose} stop`,
  `${actions} run --rm --no-deps registry-relay-public-accept-state`,
  `${actions} run --rm --no-deps registry-relay-consultation-accept-state`,
  `${actions} run --rm --no-deps registry-notary-accept-state`,
  ...stateVerifiers,
  ...servingStages,
  `${compose} up --detach --wait --wait-timeout 120`,
  ...stateVerifiers,
  `${compose} ps`,
].join('\n');

test('public OAuth and Rhai journey applies a generated docs asset to a fresh HTTP starter', (t) => {
  const gate = read('scripts/check-registryctl-tutorials.sh');
  const oauth = read('src/content/docs/tutorials/configure-project-script-adapter.mdx');
  const opencrvs = read('src/content/docs/tutorials/verify-opencrvs-claims.mdx');
  const overlay = read('public/examples/registryctl/opencrvs-events-api-overlay-v1.sh');

  for (const page of [oauth, opencrvs]) {
    const pageLines = exactLines(page);
    assert.match(page, /registryctl init .* --template http/);
    assert.match(page, /opencrvs-events-api-overlay-v1\.sh/);
    assert.equal(
      pageLines.has(
        '  OVERLAY_URL="https://docs.registrystack.org/v/$REGISTRYCTL_VERSION/examples/registryctl/$OVERLAY"',
      ),
      true,
    );
    assert.match(page, /curl -fsS "\$OVERLAY_URL\.sha256" -o "\$OVERLAY\.sha256"/);
    assert.match(page, /hmac\.compare_digest\(actual, expected\)/);
    assert.doesNotMatch(page, /rm -r integrations\/person-record/);
  }
  assert.match(gate, /init "\$OPENCRVS_PROJECT" --template http/);
  assert.match(gate, /sh "\$OPENCRVS_OVERLAY"/);
  assert.match(gate, /verify_overlay_asset "\$OPENCRVS_OVERLAY"/);
  assert.match(gate, /check --explain/);
  assert.match(gate, /registry\.project\.explanation\.v1/);
  assert.doesNotMatch(gate, /OPENCRVS_FIXTURE|cp -R|rm -r "\$OPENCRVS_PROJECT\/integrations/);
  assert.match(overlay, /fixtures\/oauth-expiry\.yaml/);
  assert.match(overlay, /fixtures\/source-timeout\.yaml/);
  assert.match(overlay, /adapter\.rhai/);
  assert.match(overlay, /HTTP starter closure does not match this release/);
  assert.match(overlay, /rm -r integrations\/person-record/);
  assertOverlayChecksum('public/examples/registryctl/opencrvs-events-api-overlay-v1.sh');

  const project = temporaryStarter(t);
  const result = runScriptFile(
    resolve(siteRoot, 'public/examples/registryctl/opencrvs-events-api-overlay-v1.sh'),
    project,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Applied the synthetic OpenCRVS Events API-shaped OAuth and Rhai overlay/);
  assertPathMissing(resolve(project, 'integrations/person-record'));
  assert.doesNotThrow(() =>
    readFileSync(resolve(project, 'integrations/birth-event-search/integration.yaml'), 'utf8'),
  );
});

test('optional public-source continuation has exact offline and opt-in live gates', (t) => {
  const page = read('src/content/docs/tutorials/author-registry-project.mdx');
  const gate = read('scripts/check-registryctl-public-source-live.sh');
  const overlay = read('public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh');
  const pageLines = exactLines(page);
  const gateLines = exactLines(gate);
  const overlayLines = exactLines(overlay);

  assert.match(page, /registryctl init public-json-live-demo --template http/);
  assert.match(page, /jsonplaceholder-todo-live-overlay-v1\.sh/);
  assert.equal(
    pageLines.has(
      '  OVERLAY_URL="https://docs.registrystack.org/v/$REGISTRYCTL_VERSION/examples/registryctl/$OVERLAY"',
    ),
    true,
  );
  assert.match(page, /curl -fsS "\$OVERLAY_URL\.sha256" -o "\$OVERLAY\.sha256"/);
  assert.match(page, /hmac\.compare_digest\(actual, expected\)/);
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
  assert.match(gate, /REGISTRYCTL_RELEASED_DOCS_ROOT/);
  assert.match(
    gate,
    /RELEASED_DOCS_ROOT\/examples\/registryctl\/jsonplaceholder-todo-live-overlay-v1\.sh/,
  );
  assert.equal(gateLines.has('  https://jsonplaceholder.typicode.com/todos/4)'), true);
  assert.equal(gateLines.has('  https://jsonplaceholder.typicode.com/todos/999999)'), true);
  assert.match(gate, /expected 200/);
  assert.match(gate, /expected 404/);
  assert.match(gate, /--environment "\$environment" smoke/);
  assert.doesNotMatch(gate, /rm -r "\$PROJECT\/integrations\/person-record"/);

  assert.match(overlay, /source_mode: operator_bound/);
  assert.equal(overlayLines.has('      origin: https://jsonplaceholder.typicode.com'), true);
  assert.match(overlay, /auth: \{ type: none \}/);
  assert.match(overlay, /default_fixture: completed-todo/);
  assert.match(overlay, /default_fixture: no-todo/);
  assert.doesNotMatch(overlay, /credential:/);
  assert.match(overlay, /HTTP starter closure does not match this release/);
  assertOverlayChecksum('public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh');

  const project = temporaryStarter(t);
  const result = runScriptFile(
    resolve(siteRoot, 'public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh'),
    project,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotThrow(() =>
    readFileSync(resolve(project, 'integrations/public-todo/integration.yaml'), 'utf8'),
  );
});

test('public overlays reject a changed starter before mutation', (t) => {
  const project = temporaryStarter(t);
  const readme = resolve(project, 'README.md');
  writeFileSync(readme, `${readFileSync(readme, 'utf8')}\nchanged by operator\n`);
  const result = runScriptFile(
    resolve(siteRoot, 'public/examples/registryctl/opencrvs-events-api-overlay-v1.sh'),
    project,
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /HTTP starter closure does not match this release: changed=README\.md/);
  assert.doesNotThrow(() =>
    readFileSync(resolve(project, 'integrations/person-record/integration.yaml'), 'utf8'),
  );
  assertPathMissing(resolve(project, 'integrations/birth-event-search'));
});

test('Compose command blocks exactly reproduce the generated runbook sequence', () => {
  const page = read('src/content/docs/operate/single-node-compose-behind-proxy.mdx');
  assert.equal(fence(page, 'Initialize each product once', 'sh', 2), firstInstallation);
  assert.equal(fence(page, 'Run the package standalone', 'sh'), ordinaryStartAndStop);
  assert.doesNotMatch(page, /registry-runtime-stage-secrets/);
});

test('product update executes preview, stop, accept, exact verify, then start', (t) => {
  const page = read('src/content/docs/operate/upgrade-and-rollback.mdx');
  const commands = fence(
    page,
    'Preview, accept, verify, and start the candidate',
    'sh',
  );
  assert.equal(commands, productUpdate);

  const root = mkdtempSync(join(tmpdir(), 'registryctl-update-order-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const docker = resolve(root, 'docker');
  const state = resolve(root, 'state');
  const events = resolve(root, 'events');
  writeFileSync(state, 'running\n');
  writeFileSync(
    docker,
    [
      '#!/bin/sh',
      'set -eu',
      'last=',
      'for argument do last=$argument; done',
      'case "$*" in',
      '  *-preview-state)',
      '    test "$(cat "$DX_UPDATE_STATE")" = running',
      '    printf "preview:%s\\n" "$last" >>"$DX_UPDATE_EVENTS"',
      '    ;;',
      '  *" stop")',
      '    test "$(grep -c "^preview:" "$DX_UPDATE_EVENTS")" -eq 3',
      '    printf "stopped\\n" >"$DX_UPDATE_STATE"',
      '    printf "stop\\n" >>"$DX_UPDATE_EVENTS"',
      '    ;;',
      '  *-accept-state)',
      '    test "$(cat "$DX_UPDATE_STATE")" = stopped',
      '    test "$(grep -c "^preview:" "$DX_UPDATE_EVENTS")" -eq 3',
      '    printf "accept:%s\\n" "$last" >>"$DX_UPDATE_EVENTS"',
      '    ;;',
      '  *-verify-state)',
      '    test "$(grep -c "^accept:" "$DX_UPDATE_EVENTS")" -eq 3',
      '    if test "$(cat "$DX_UPDATE_STATE")" = stopped; then',
      '      printf "verify-before:%s\\n" "$last" >>"$DX_UPDATE_EVENTS"',
      '    else',
      '      test "$(cat "$DX_UPDATE_STATE")" = running',
      '      test "$(grep -c "^start$" "$DX_UPDATE_EVENTS")" -eq 1',
      '      printf "verify-after:%s\\n" "$last" >>"$DX_UPDATE_EVENTS"',
      '    fi',
      '    ;;',
      '  *-stage-secrets)',
      '    test "$(cat "$DX_UPDATE_STATE")" = stopped',
      '    test "$(grep -c "^verify-before:" "$DX_UPDATE_EVENTS")" -eq 3',
      '    printf "stage:%s\\n" "$last" >>"$DX_UPDATE_EVENTS"',
      '    ;;',
      '  *" up --detach --wait --wait-timeout 120")',
      '    test "$(grep -c "^stage:" "$DX_UPDATE_EVENTS")" -eq 4',
      '    printf "start\\n" >>"$DX_UPDATE_EVENTS"',
      '    printf "running\\n" >"$DX_UPDATE_STATE"',
      '    ;;',
      '  *" ps")',
      '    test "$(grep -c "^verify-after:" "$DX_UPDATE_EVENTS")" -eq 3',
      '    printf "ps\\n" >>"$DX_UPDATE_EVENTS"',
      '    ;;',
      '  *)',
      '    printf "unexpected docker command: %s\\n" "$*" >&2',
      '    exit 32',
      '    ;;',
      'esac',
      '',
    ].join('\n'),
    { mode: 0o755 },
  );

  const result = runShellSnippet(commands, root, {
    DX_UPDATE_EVENTS: events,
    DX_UPDATE_STATE: state,
    PATH: `${root}:${process.env.PATH}`,
    REGISTRY_STACK_COMPOSE_PROJECT: 'registry-test-package',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    readFileSync(events, 'utf8'),
    [
      'preview:registry-relay-public-preview-state',
      'preview:registry-relay-consultation-preview-state',
      'preview:registry-notary-preview-state',
      'stop',
      'accept:registry-relay-public-accept-state',
      'accept:registry-relay-consultation-accept-state',
      'accept:registry-notary-accept-state',
      'verify-before:registry-relay-public-verify-state',
      'verify-before:registry-relay-consultation-verify-state',
      'verify-before:registry-notary-verify-state',
      'stage:registry-relay-public-stage-secrets',
      'stage:registry-relay-consultation-stage-secrets',
      'stage:registry-notary-stage-secrets',
      'stage:registry-postgresql-stage-secrets',
      'start',
      'verify-after:registry-relay-public-verify-state',
      'verify-after:registry-relay-consultation-verify-state',
      'verify-after:registry-notary-verify-state',
      'ps',
      '',
    ].join('\n'),
  );
  assert.equal(readFileSync(state, 'utf8'), 'running\n');
});

test('transferred package acceptance uses external closure and operator-file checks', () => {
  const page = read('src/content/docs/operate/single-node-compose-behind-proxy.mdx');
  const verifyBlock = fence(page, 'Verify the generated package', 'sh');

  assert.match(page, /generated\/\n    compose\.empty\.env[\s\S]*operator-files\.v1\.json/);
  assert.match(page, /generated\/\n    compose\.empty\.env[\s\S]*postgresql-server\.env/);
  assert.match(page, /exact environment keys copied from the signed/);
  assert.match(page, /Registryctl never\s+creates production values/);
  assert.match(page, /compact Notary-to-Relay workload JWT/);
  assert.match(page, /Product startup and preparation remain the semantic validation boundary/);
  assert.match(
    verifyBlock,
    /^TRANSFER_CLOSURE_SHA256="<independently-recorded-generated-closure-sha256>"$/m,
  );
  assert.match(
    verifyBlock,
    /--expected-closure-sha256 "\$TRANSFER_CLOSURE_SHA256" \\\n  --check-operator-files/,
  );
  assert.match(page, /Do not derive it from files in that package/);
  assert.match(page, /not sufficient for transfer\s+acceptance/);
  assert.ok(
    page.indexOf('--check-operator-files') < page.indexOf('## Initialize each product once'),
  );
});

test('Compose include remains operator-owned and outside package verification', () => {
  const page = read('src/content/docs/operate/single-node-compose-behind-proxy.mdx');
  assert.match(page, /Registryctl verifies only the generated package/);
  assert.match(page, /operator owns the include graph/);
  assert.match(page, /```sh\ncd \.\.\nregistryctl deploy verify --package \.\/registry-stack/);
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
    assert.match(page, new RegExp(`build/local/signing-inputs/${lane}`));
    assert.match(page, new RegExp(`${lane}-anchor\\.json`));
    assert.match(page, new RegExp(`${lane}-bundle`));
    assert.match(page, new RegExp(`evaluation-keys/${lane}\\.public\\.jwk`));
    assert.match(page, new RegExp(`file:evaluation-keys/${lane}\\.private\\.jwk`));
  }
  assert.doesNotMatch(page, /build\/production|--environment production/);
  assert.match(page, /registryctl trust approved-set assemble/);
  assert.match(page, /--environment local/);
  assert.match(page, /--output-file operator-handoff\/approved-set\.v1\.json/);
  assert.match(page, /registryctl deploy verify --package operator-handoff\/registry-stack/);
  assert.match(page, /requires OpenSSL with Ed25519 support and Python 3/);
  assert.match(
    page,
    /--package operator-handoff\/registry-stack \\\n  --expected-closure-sha256 "\$GENERATED_CLOSURE_SHA256"/,
  );
  assert.match(page, /does not accept it for\s+initialization/);
  assert.match(page, /registryctl trust anchor rotate/);
  assert.match(page, /--current-anchor "\$CURRENT_ANCHOR"/);
  assert.match(page, /--rotate-anchor relay-consultation/);
  assert.match(
    page,
    /--next-public-key evaluation-keys\/relay-consultation\.public\.jwk[\s\S]*--next-public-key operator-inputs\/relay-consultation-next\.public\.jwk/,
  );
  assert.match(page, /--against "\$CURRENT_APPROVED_SET"/);
  assert.match(page, /registryctl trust bundle verify/);
  assert.match(page, /registryctl trust approved-set assemble \\\n  --from "\$CURRENT_APPROVED_SET"/);
  assert.match(page, /--approved-set operator-handoff\/approved-set\.v2\.json/);
  assert.match(page, /registryctl deploy verify --package operator-handoff\/registry-stack\.v2/);
  assert.match(page, /required preview, stop, audited acceptance, exact\s+verification/);
});

test('HTTP tutorial hands initial builds to baseline approval before deployment', () => {
  const page = read('src/content/docs/tutorials/author-registry-project.mdx');
  const approval = '../../operate/approve-initial-baseline/';
  const deployment = '../../operate/single-node-compose-behind-proxy/';
  assert.match(page, /Next: registryctl trust anchor create --help/);
  assert.ok(page.includes(`](${approval})`));
  assert.ok(page.includes(`](${deployment})`));
  assert.ok(page.indexOf(`](${approval})`) < page.indexOf(`](${deployment})`));
});

test('evaluation-only lane key procedure emits distinct owner-only Ed25519 JWK pairs', (t) => {
  const page = read('src/content/docs/operate/approve-initial-baseline.mdx');
  const script = fence(page, 'Generate evaluation-only lane keys', 'sh');
  const root = mkdtempSync(join(tmpdir(), 'registryctl-evaluation-keys-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const result = runShellSnippet(script, root);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    pathMode(resolve(root, 'evaluation-keys'), constants.O_RDONLY | constants.O_DIRECTORY),
    0o700,
  );

  const publicMembers = new Set();
  for (const lane of ['relay-public', 'relay-consultation', 'notary']) {
    const privatePath = resolve(root, `evaluation-keys/${lane}.private.jwk`);
    const publicPath = resolve(root, `evaluation-keys/${lane}.public.jwk`);
    const privateFile = readRegularUtf8WithMode(privatePath);
    const publicFile = readRegularUtf8WithMode(publicPath);
    assert.equal(privateFile.mode, 0o600);
    assert.equal(publicFile.mode, 0o600);

    const privateJwk = JSON.parse(privateFile.content);
    const publicJwk = JSON.parse(publicFile.content);
    assert.deepEqual(publicJwk, {
      crv: 'Ed25519',
      kty: 'OKP',
      x: privateJwk.x,
    });
    assert.equal(typeof privateJwk.d, 'string');
    assert.equal(privateJwk.d.length, 43);
    assert.equal(privateJwk.x.length, 43);
    publicMembers.add(privateJwk.x);

    const payload = Buffer.from(`registryctl-${lane}`, 'utf8');
    const signature = sign(null, payload, createPrivateKey({ key: privateJwk, format: 'jwk' }));
    assert.equal(
      verify(null, payload, createPublicKey({ key: publicJwk, format: 'jwk' }), signature),
      true,
    );
    assertPathMissing(resolve(root, `evaluation-keys/${lane}.private.der`));
    assertPathMissing(resolve(root, `evaluation-keys/${lane}.public.der`));
  }
  assert.equal(publicMembers.size, 3);
});
