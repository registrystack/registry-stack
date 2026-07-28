import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';

import { parse } from 'yaml';

import {
  HTTP_STATUS_PREFIX,
  assertHttpStatus,
  assertJsonSubset,
  assertOutputContainsLines,
  assertTutorialLayout,
  extractFencedBlocks,
  rebindProjectImages,
  redactOutput,
  replaceLiteralOnce,
  setRelayMinGroupSize,
} from './registryctl-tutorial.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');
let registryctlBinary;
let registryctlBinaryDirectory;

after(() => {
  if (registryctlBinaryDirectory !== undefined) {
    rmSync(registryctlBinaryDirectory, { recursive: true, force: true });
  }
});

function exactRegistryctlBinary() {
  if (registryctlBinary !== undefined) return registryctlBinary;
  if (process.env.REGISTRYCTL_BIN !== undefined) {
    registryctlBinary = process.env.REGISTRYCTL_BIN;
    return registryctlBinary;
  }

  const buildEvents = execFileSync(
    'cargo',
    [
      'build',
      '--locked',
      '--quiet',
      '-p',
      'registryctl',
      '--bin',
      'registryctl',
      '--message-format=json',
    ],
    { cwd: repoRoot, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  )
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const artifact = buildEvents.findLast(
    (event) =>
      event.reason === 'compiler-artifact' &&
      event.target?.name === 'registryctl' &&
      event.executable,
  );
  assert.ok(artifact, 'cargo did not identify the exact registryctl executable');
  registryctlBinaryDirectory = mkdtempSync(join(tmpdir(), 'registryctl-docs-binary-'));
  registryctlBinary = join(
    registryctlBinaryDirectory,
    process.platform === 'win32' ? 'registryctl.exe' : 'registryctl',
  );
  copyFileSync(artifact.executable, registryctlBinary);
  chmodSync(registryctlBinary, 0o700);
  return registryctlBinary;
}

function registryctl(args) {
  return execFileSync(exactRegistryctlBinary(), args, {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
}

test('extracts shell fences with headings, occurrences, and multiline commands intact', () => {
  const markdown = `## Start

\`\`\`sh
registryctl start
\`\`\`

\`\`\`text
PASS ready
\`\`\`

## Query

  \`\`\`sh
  curl -sS \\
    http://127.0.0.1:4242/ready
  \`\`\`
`;
  const blocks = extractFencedBlocks(markdown);

  assert.deepEqual(
    blocks.map(({ heading, language, occurrence }) => ({ heading, language, occurrence })),
    [
      { heading: 'Start', language: 'sh', occurrence: 1 },
      { heading: 'Start', language: 'text', occurrence: 1 },
      { heading: 'Query', language: 'sh', occurrence: 1 },
    ],
  );
  assert.equal(blocks[2].content, 'curl -sS \\\n  http://127.0.0.1:4242/ready');
});

test('layout and documented-output assertions fail on drift', () => {
  const markdown = '## One\n\n```sh\none\n```\n\n## Two\n\n```sh\ntwo\n```\n';
  assertTutorialLayout(markdown, ['One', 'Two']);
  assert.throws(() => assertTutorialLayout(markdown, ['Two', 'One']), /layout changed/);
  assertOutputContainsLines('PASS one\nPASS two\n', 'PASS one\nPASS two');
  assert.throws(
    () => assertOutputContainsLines('PASS one\n', 'PASS one\nPASS two'),
    /PASS two/,
  );
});

test('asserts instrumented HTTP status and JSON subsets without depending on array order', () => {
  const output = `HTTP/1.1 200 OK\r
content-type: application/json\r
\r
{"observations":[{"district":"south","count":2},{"district":"north","count":2}]}
${HTTP_STATUS_PREFIX}200
source-under-test images rebound
`;
  assertHttpStatus(output, 200);
  assertJsonSubset(output, {
    observations: [
      { district: 'north', count: 2 },
      { district: 'south', count: 2 },
    ],
  });
  assert.throws(() => assertHttpStatus(output, 403), /expected HTTP 403/);
  assert.throws(() => assertJsonSubset(output, { observations: [] }), /must be empty/);
});

test('rebinds generated project images without changing ports', () => {
  const directory = mkdtempSync(join(tmpdir(), 'registryctl-project-'));
  try {
    writeFileSync(
      join(directory, 'compose.yaml'),
      'services:\n  registry-relay:\n    image: relay:old\n    ports: ["4242:8080"]\n  registry-relay-consultation:\n    image: relay:old\n  registry-relay-consultation-bootstrap:\n    image: relay:old\n  registry-notary:\n    image: notary:old\n',
    );
    writeFileSync(
      join(directory, 'registryctl.yaml'),
      'runtime:\n  relay_image: relay:old\n  notary_image: notary:old\n',
    );

    rebindProjectImages(directory, 'relay:source', 'notary:source');

    const compose = parse(readFileSync(join(directory, 'compose.yaml'), 'utf8'));
    const manifest = parse(readFileSync(join(directory, 'registryctl.yaml'), 'utf8'));
    assert.equal(compose.services['registry-relay'].image, 'relay:source');
    assert.equal(compose.services['registry-relay-consultation'].image, 'relay:source');
    assert.equal(compose.services['registry-relay-consultation-bootstrap'].image, 'relay:source');
    assert.equal(compose.services['registry-notary'].image, 'notary:source');
    assert.deepEqual(compose.services['registry-relay'].ports, ['4242:8080']);
    assert.equal(manifest.runtime.relay_image, 'relay:source');
    assert.equal(manifest.runtime.notary_image, 'notary:source');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('edits Relay policy YAML by stable identifiers', () => {
  const directory = mkdtempSync(join(tmpdir(), 'registryctl-config-'));
  const relayPath = join(directory, 'relay.yaml');
  try {
    writeFileSync(
      relayPath,
      'datasets:\n  - id: benefits\n    aggregates:\n      - id: by_district\n        disclosure_control:\n          min_group_size: 2\n',
    );
    setRelayMinGroupSize(relayPath, 'benefits', 'by_district', 3);

    assert.equal(
      parse(readFileSync(relayPath, 'utf8')).datasets[0].aggregates[0].disclosure_control
        .min_group_size,
      3,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('derives one documented command substitution and rejects ambiguous replacements', () => {
  assert.equal(replaceLiteralOnce('purpose: tutorial', 'tutorial', 'casework'), 'purpose: casework');
  assert.throws(() => replaceLiteralOnce('tutorial tutorial', 'tutorial', 'casework'), /found 2/);
});

test('redacts generated env values and credential headers before output is printed', () => {
  const redacted = redactOutput(
    'token=secret-value-123\nAuthorization: Bearer visible-token\nx-api-key: visible-key\n',
    'ROW_READER_RAW=secret-value-123\n',
  );
  assert.equal(redacted.includes('secret-value-123'), false);
  assert.equal(redacted.includes('visible-token'), false);
  assert.equal(redacted.includes('visible-key'), false);
  assert.match(redacted, /REDACTED:ROW_READER_RAW/);
});

test('canonical first API tutorial keeps doctor and smoke evidence value-free', () => {
  const tutorial = readFileSync(
    new URL(
      '../src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx',
      import.meta.url,
    ),
    'utf8',
  );
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');

  assert.match(tutorial, /authored project can be compiled/);
  assert.match(tutorial, /workbook passes[\s\S]*strict validation/);
  assert.match(tutorial, /generated result matches the authored inputs/);
  assert.match(tutorial, /listener is loopback-only/);
  assert.match(tutorial, /It does not contain raw keys or[\s\S]*workbook rows/);
  assert.doesNotMatch(tutorial, /relay\.startup\.config_validation_rejected|min_cell_size/);
  assert.doesNotMatch(script, /set-relay-min-group-size|min_cell_size/);
});

test('source tutorial gate validates canonical authoring without rewriting release images', () => {
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');

  assert.match(script, /cat "\$BLOCKS\/02\.sh"/);
  assert.match(script, /source "\$BLOCKS\/03\.sh"/);
  assert.match(script, /registryctl preflight --project-dir \. --environment local/);
  assert.match(script, /registryctl build --project-dir \. --environment local/);
  assert.match(script, /exact runtime sequence is release-gated from the sealed candidate payload/);
  assert.doesNotMatch(script, /docker build|rebind-project|REGISTRYCTL_RELAY_STAGING_IMAGE/);
});

test('source tutorial gate does not stand in for the first-claim or runtime gates', () => {
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');

  assert.match(script, /does not execute the release installer[\s\S]*or local runtime/);
  assert.doesNotMatch(
    script,
    /run_notary_tutorial|active-registration-exists|population-record-exists/,
  );
});

test('HTTP authoring tutorial output stays synchronized with the current starter', () => {
  const directory = mkdtempSync(join(tmpdir(), 'registryctl-http-trace-'));
  const projectDirectory = join(directory, 'registry-project');
  try {
    registryctl(['init', '--from', 'http', '--project-dir', projectDirectory]);
    assert.match(
      readFileSync(
        join(
          projectDirectory,
          'integrations/person-record/fixtures/active.yaml',
        ),
        'utf8',
      ),
      /^request:$/m,
      'the exact executable must embed the governed-request starter',
    );
    const actual = registryctl(
      [
        'test',
        '--project-dir',
        projectDirectory,
        '--integration',
        'person-record',
        '--fixture',
        'active-person',
        '--trace',
      ],
    ).trimEnd();
    const tutorial = readFileSync(
      resolve(siteRoot, 'src/content/docs/tutorials/author-registry-project.mdx'),
      'utf8',
    );
    const documented = extractFencedBlocks(tutorial).find(
      (block) => block.heading === 'Trace one fixture offline' && block.language === 'text',
    );
    assert.ok(documented, 'tutorial trace output block is missing');
    assert.equal(documented.content, actual);

    assert.match(actual, /^PASS: 9\/9 fixtures passed$/m);
    assert.deepEqual(
      actual
        .split('\n')
        .filter((line) => line.startsWith('  PASS person-record.'))
        .map((line) => line.trim().slice('PASS person-record.'.length)),
      [
        'active-person',
        'active-person::derived/request_to_consultation_binding',
        'active-person::derived/request_authority',
        'active-person::derived/status_rejection',
        'active-person::derived/malformed_decode',
        'active-person::derived/byte_ceiling',
        'active-person::derived/timeout',
        'active-person::derived/authorization_before_source',
        'active-person::derived/output_minimization',
      ],
    );

    const built = registryctl(
      [
        'build',
        '--project-dir',
        projectDirectory,
        '--environment',
        'local',
      ],
    ).trimEnd();
    const documentedBuild = extractFencedBlocks(tutorial).find(
      (block) => block.heading === 'Build unsigned product inputs' && block.language === 'text',
    );
    assert.ok(documentedBuild, 'tutorial build output block is missing');
    assertOutputContainsLines(built, documentedBuild.content.split('\n').slice(1).join('\n'));
    assert.match(built, /^  Output: \.registry-stack\/build\/local$/m);
    assert.match(tutorial, /An artifact action of `regenerate` is lifecycle metadata/);

    const trustedLocal = registryctl(
      [
        'check',
        '--project-dir',
        projectDirectory,
        '--environment',
        'local',
        '--explain',
        '--show-authored-values',
      ],
    ).trimEnd();
    const documentedTrustedLocal = extractFencedBlocks(tutorial).find(
      (block) =>
        block.heading === 'Review the generated plan' &&
        block.language === 'text' &&
        block.content.startsWith('WARNING: trusted-local authored values follow.'),
    );
    assert.ok(documentedTrustedLocal, 'trusted-local safety output block is missing');
    assertOutputContainsLines(trustedLocal, documentedTrustedLocal.content);

    const checkHelp = registryctl(['check', '--help']);
    assert.match(
      checkHelp,
      /--show-authored-values[\s\S]*Show directly authored non-secret values for trusted-local terminal review/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('release-form claim tutorial keeps the live no-match result bounded', () => {
  const tutorial = readFileSync(
    new URL('../src/content/docs/tutorials/verify-claim-registry-api.mdx', import.meta.url),
    'utf8',
  );
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');

  assert.match(tutorial, /project-record-exists/);
  assert.match(tutorial, /"claim_id": "project-record-exists"[\s\S]*?"value": false/);
  assert.match(tutorial, /bounded[\s\S]*no\s+match/);
  assert.match(tutorial, /"value": "pw_999"/);
  for (const broaderNegative of [
    'global nonexistence',
    'fraud',
    'ineligibility',
    'legal negative',
  ]) {
    assert.match(tutorial, new RegExp(broaderNegative.replace(' ', '\\s+')));
  }
  assert.doesNotMatch(
    tutorial,
    /population-record-exists|person-registration-accepted|active-registration-exists|active-or-pending-registration-exists/,
  );
  assert.doesNotMatch(script, /project-record-exists/);
});

test('release-form claim tutorial continues the canonical v0.15.2 project live', () => {
  const tutorial = readFileSync(
    new URL('../src/content/docs/tutorials/verify-claim-registry-api.mdx', import.meta.url),
    'utf8',
  );

  assert.match(tutorial, /^status: current$/m);
  assert.match(tutorial, /registryctl 0\.15\.2 with its matching image lock/i);
  assert.match(tutorial, /Continue from[\s\S]*`my-first-api`/);
  assert.match(tutorial, /registryctl add notary/);
  assert.match(tutorial, /\.registry-stack\/runtime\/local\/secrets\/local\.env/);
  assert.match(tutorial, /http:\/\/127\.0\.0\.1:4255\/v1\/evaluations/);
  assert.match(tutorial, /HTTP 403/);
  assert.match(tutorial, /REGISTRYCTL_LOCAL_NOTARY_UNDER_SCOPED_TOKEN_RAW/);
  assert.match(tutorial, /REGISTRYCTL_LOCAL_NOTARY_CALLER_TOKEN_RAW/);
  assert.match(tutorial, /evidence:projects:read/);
  assert.match(tutorial, /public-works-case-management/);
  assert.match(tutorial, /project-status-accepted/);
  assert.match(tutorial, /PASS: 6\/6 fixtures passed/);
  assert.match(tutorial, /"value": "pw_001"/);
  assert.match(tutorial, /"value": "PW-002"/);
  assert.match(tutorial, /"value": "pw_999"/);
  assert.match(tutorial, /registryctl restart/);
  assert.match(tutorial, /registryctl stop/);
  assert.match(tutorial, /You\s+do not edit `?\.registry-stack\//);
  assert.doesNotMatch(
    tutorial,
    /registryctl init --from snapshot|Main checkout|git clone|git switch|git rev-parse|cargo build|registryctl build|manifest_source_ref|tag_target/,
  );
});

test('live claim tutorial restarts after an authored status-policy change', () => {
  const tutorial = readFileSync(
    new URL('../src/content/docs/tutorials/verify-claim-registry-api.mdx', import.meta.url),
    'utf8',
  );
  const plannedHeading = tutorial.indexOf('## Evaluate the planned project');
  const initialResult = tutorial.indexOf('"value": false', plannedHeading);
  const authoredEdit = tutorial.indexOf(
    'project.matched && (project.status == "active" || project.status == "planned")',
    initialResult,
  );
  const restart = tutorial.indexOf('registryctl restart', authoredEdit);
  const changedResult = tutorial.indexOf('"value": true', restart);
  const cleanup = tutorial.indexOf('registryctl stop', changedResult);

  assert.ok(initialResult > plannedHeading, 'initial planned-project result is missing');
  assert.ok(authoredEdit > initialResult, 'authored policy edit must follow the initial result');
  assert.ok(restart > authoredEdit, 'restart must follow the authored policy edit');
  assert.ok(changedResult > restart, 'changed live result must follow restart');
  assert.ok(cleanup > changedResult, 'cleanup must follow the changed live result');
});

test('current-source bootstrap stays executable and outside adopter release-form pages', () => {
  const bootstrap = readFileSync(
    new URL('../src/content/docs/start/test-current-source-revision.mdx', import.meta.url),
    'utf8',
  );
  const authoring = readFileSync(
    new URL('../src/content/docs/tutorials/author-registry-project.mdx', import.meta.url),
    'utf8',
  );
  const notary = readFileSync(
    new URL('../src/content/docs/tutorials/verify-claim-registry-api.mdx', import.meta.url),
    'utf8',
  );
  const reference = readFileSync(
    new URL('../src/content/docs/reference/registryctl.mdx', import.meta.url),
    'utf8',
  );

  assert.match(bootstrap, /^status: current$/m);
  assert.match(bootstrap, /^doc_type: how-to$/m);
  assert.match(bootstrap, /git switch --detach "\$SOURCE_REF"/);
  assert.match(bootstrap, /cargo build --locked -p registryctl/);
  assert.match(bootstrap, /npm run test:tutorial:registryctl/);
  assert.match(bootstrap, /npm run check:tutorial:registryctl/);
  assert.match(bootstrap, /temporary source-test lock/);
  assert.match(bootstrap, /generation-only image sentinels/);
  assert.match(bootstrap, /does not retain or publish the[\s\S]*lock as a reusable artifact/);
  assert.match(bootstrap, /\.manifest_source_ref == \$source_ref/);
  assert.match(bootstrap, /\.tag_target == \$source_ref/);
  assert.match(bootstrap, /export REGISTRYCTL_IMAGE_LOCK="\$LOCK_PATH"/);
  assert.match(
    bootstrap,
    /not a release, release candidate, signed artifact set, production image, country[\s\S]*acceptance result, or interoperability result/,
  );

  for (const page of [authoring, reference, notary]) {
    assert.doesNotMatch(page, /test-current-source-revision/);
    assert.doesNotMatch(page, /git switch --detach|cargo build --locked/);
  }
});
