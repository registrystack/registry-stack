import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import {
  assertFenceEquals,
  assertFenceFileEquals,
  assertFenceInFile,
  assertJsonSubset,
  assertOutputContainsLines,
  assertProjectReports,
  assertTutorialLayout,
  extractFencedBlocks,
  parseJsonOutput,
  replaceFencePair,
  writeFence,
  writeEvidenceManifest,
} from './registryctl-tutorial.mjs';

const siteRoot = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(siteRoot, relativePath), 'utf8');
}

test('extracts shell fences with headings, occurrences, and multiline commands intact', () => {
  const markdown = `## Start

\`\`\`sh
registryctl test
\`\`\`

\`\`\`text
Fixtures: 25.
\`\`\`

## Review

  \`\`\`sh
  registryctl check \\
    --explain
  \`\`\`
`;
  const blocks = extractFencedBlocks(markdown);

  assert.deepEqual(
    blocks.map(({ heading, language, occurrence }) => ({ heading, language, occurrence })),
    [
      { heading: 'Start', language: 'sh', occurrence: 1 },
      { heading: 'Start', language: 'text', occurrence: 1 },
      { heading: 'Review', language: 'sh', occurrence: 1 },
    ],
  );
  assert.equal(blocks[2].content, 'registryctl check \\\n  --explain');
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

test('synchronizes fenced examples with executable output and maintained files', () => {
  const markdown = '## Output\n\n```text\nCreated in my-registry.\n```\n\n```yaml\nvalue: exact\n```\n';
  assertFenceEquals(
    'Created in /tmp/reader/my-registry.\n',
    markdown,
    'Output',
    'text',
    1,
    [['/tmp/reader/my-registry', 'my-registry']],
  );
  assertFenceFileEquals(markdown, 'Output', 'yaml', 1, 'value: exact\n');
  assertFenceInFile(markdown, 'Output', 'yaml', 1, 'before\nvalue: exact\nafter\n');
  assert.throws(
    () => assertFenceFileEquals(markdown, 'Output', 'yaml', 1, 'value: drifted\n'),
    /differs/,
  );
});

test('writes one selected fenced procedure as an owner-only executable input', (t) => {
  const root = mkdtempSync(resolve(tmpdir(), 'registryctl-tutorial-fence-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const markdown = resolve(root, 'guide.md');
  const output = resolve(root, 'procedure.sh');
  const source = '## Procedure\n\n```sh\nregistryctl test --environment local\n```\n';
  writeFileSync(markdown, source);

  writeFence(markdown, 'Procedure', 'sh', 1, output);

  assert.equal(readFileSync(output, 'utf8'), 'registryctl test --environment local\n');
  assert.equal(statSync(output).mode & 0o777, 0o600);
});

test('replaces one exact fenced source fragment with its paired replacement', () => {
  const markdown = `## Change

\`\`\`yaml
status: active
\`\`\`

\`\`\`yaml
status: planned
\`\`\`
`;

  assert.equal(
    replaceFencePair(
      markdown,
      'Change',
      'yaml',
      1,
      'Change',
      'yaml',
      2,
      'before\nstatus: active\nafter\n',
    ),
    'before\nstatus: planned\nafter\n',
  );
});

test('rejects a fence-pair replacement when the source is absent or repeated', () => {
  const markdown = `## Change

\`\`\`yaml
status: active
\`\`\`

\`\`\`yaml
status: planned
\`\`\`
`;
  const replace = (target) =>
    replaceFencePair(
      markdown,
      'Change',
      'yaml',
      1,
      'Change',
      'yaml',
      2,
      target,
    );

  assert.throws(() => replace('status: missing\n'), /found 0/);
  assert.throws(
    () => replace('status: active\nstatus: active\n'),
    /found 2/,
  );
});

test('parses one strict JSON document and asserts subsets without array-order coupling', () => {
  const output = JSON.stringify({
    schema_version: 'registryctl.project_command.v1',
    observations: [
      { district: 'south', count: 2 },
      { district: 'north', count: 2 },
    ],
  });
  assert.equal(parseJsonOutput(output).schema_version, 'registryctl.project_command.v1');
  assertJsonSubset(output, {
    observations: [
      { district: 'north', count: 2 },
      { district: 'south', count: 2 },
    ],
  });
  assert.throws(() => parseJsonOutput(`log line\n${output}`), /not one strict JSON document/);
});

test('accepts matching test, check, and build reports with derived security evidence', () => {
  const fixture = {
    integration: 'person-record',
    fixture: 'match::derived/authorization_before_source',
    expected_error: 'authorization.denied',
    source_access: false,
    passed: true,
  };
  const minimization = {
    integration: 'person-record',
    fixture: 'match::derived/output_minimization',
    passed: true,
  };
  const common = {
    schema_version: 'registryctl.project_command.v1',
    project: 'fictional-registry',
    environment: 'local',
    fixtures: [fixture, minimization],
  };
  const testReport = JSON.stringify({ ...common, status: 'passed' });
  const checkReport = JSON.stringify({ ...common, status: 'valid' });
  const buildReport = JSON.stringify({
    schema_version: 'registryctl.reviewed_project_build_report.v1',
    build: { ...common, status: 'built' },
    affected_lanes: ['relay-public', 'relay-consultation', 'notary'],
  });

  assert.doesNotThrow(() =>
    assertProjectReports(testReport, checkReport, buildReport, 'fictional-registry'),
  );
  assert.throws(
    () =>
      assertProjectReports(
        testReport,
        checkReport,
        JSON.stringify({
          schema_version: 'registryctl.reviewed_project_build_report.v1',
          build: { ...common, status: 'built' },
          affected_lanes: ['relay-consultation', 'notary'],
        }),
        'fictional-registry',
      ),
    /relay-public/,
  );
});

test('accepts snapshot reports with explicit minimized outputs and claims', () => {
  const authorization = {
    integration: 'project-record-snapshot',
    fixture: 'match::derived/authorization_before_source',
    expected_error: 'authorization.denied',
    source_access: false,
    passed: true,
  };
  const snapshot = {
    integration: 'project-record-snapshot',
    fixture: 'match',
    outcome: 'match',
    outputs: ['status'],
    claims: ['project-record-exists', 'project-status-accepted'],
    passed: true,
  };
  const common = {
    schema_version: 'registryctl.project_command.v1',
    project: 'fictional-public-works-registry',
    environment: 'local',
    fixtures: [snapshot, authorization],
  };
  const testReport = JSON.stringify({ ...common, status: 'passed' });
  const checkReport = JSON.stringify({ ...common, status: 'valid' });
  const buildReport = JSON.stringify({
    schema_version: 'registryctl.reviewed_project_build_report.v1',
    build: { ...common, status: 'built' },
    affected_lanes: ['relay-public', 'relay-consultation', 'notary'],
  });

  assert.doesNotThrow(() =>
    assertProjectReports(
      testReport,
      checkReport,
      buildReport,
      'fictional-public-works-registry',
      'snapshot',
    ),
  );

  const extraOutput = {
    ...snapshot,
    outputs: ['status', 'project_id'],
  };
  const reportWithExtraOutput = JSON.stringify({
    ...common,
    status: 'passed',
    fixtures: [extraOutput, authorization],
  });
  const checkWithExtraOutput = JSON.stringify({
    ...common,
    status: 'valid',
    fixtures: [extraOutput, authorization],
  });
  assert.throws(
    () =>
      assertProjectReports(
        reportWithExtraOutput,
        checkWithExtraOutput,
        JSON.stringify({
          schema_version: 'registryctl.reviewed_project_build_report.v1',
          build: {
            ...common,
            status: 'built',
            fixtures: [extraOutput, authorization],
          },
          affected_lanes: ['relay-public', 'relay-consultation', 'notary'],
        }),
        'fictional-public-works-registry',
        'snapshot',
      ),
    /outputs must be exactly/,
  );
});

test('evidence manifest keeps three journeys and records retained HTTP and OAuth projects', (t) => {
  const root = mkdtempSync(resolve(tmpdir(), 'registryctl-tutorial-manifest-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const reports = resolve(root, 'reports');
  const retainedHttp = resolve(root, 'reader-http-project');
  const retainedOauth = resolve(root, 'reader-opencrvs-project');

  writeEvidenceManifest(reports, 'sealed', '1.0.0', retainedHttp, retainedOauth);
  const manifest = JSON.parse(readFileSync(resolve(reports, 'manifest.json'), 'utf8'));

  assert.equal(manifest.mode, 'sealed');
  assert.deepEqual(
    manifest.projects.map((project) => project.id),
    ['http', 'spreadsheet', 'opencrvs-events-api'],
  );
  assert.equal(manifest.retained_project, retainedHttp);
  assert.equal(manifest.retained_oauth_project, retainedOauth);
  assert.ok(
    manifest.projects
      .find((project) => project.id === 'spreadsheet')
      .reports.includes('spreadsheet-evidence/dev-smoke.txt'),
  );
  assert.ok(
    manifest.projects
      .find((project) => project.id === 'spreadsheet')
      .reports.includes('spreadsheet-evidence/records-denied.json'),
  );
  assert.ok(
    manifest.projects
      .find((project) => project.id === 'spreadsheet')
      .reports.includes('spreadsheet-evidence/records-request.json'),
  );
  assert.ok(
    manifest.projects
      .find((project) => project.id === 'spreadsheet')
      .reports.includes('spreadsheet-evidence/evidence-request.json'),
  );
});

test('reader gate executes the evidence change and limits development runtime to sealed mode', () => {
  const script = read('scripts/check-registryctl-tutorials.sh');
  const spreadsheet = extractFencedBlocks(
    read('src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx'),
  );
  const spreadsheetFence = (heading, language, occurrence) =>
    spreadsheet.some(
      (block) =>
        block.heading === heading &&
        block.language === language &&
        block.occurrence === occurrence,
    );

  assert.match(script, /init "\$HTTP_PROJECT" --template http >"\$REPORT_ROOT\/http\/init\.txt"/);
  assert.match(script, /init "\$SPREADSHEET_PROJECT" --template spreadsheet/);
  assert.match(script, /init "\$OPENCRVS_PROJECT" --template http/);
  assert.match(script, /sh "\$OPENCRVS_OVERLAY"/);
  assert.match(script, /-C "\$project_directory" test --format json/);
  assert.match(script, /-C "\$project_directory" check --format json/);
  assert.match(script, /-C "\$project_directory" build --format json/);
  assert.match(script, /opencrvs-events-api/);
  assert.match(script, /jsonplaceholder-todo-live-overlay-v1\.sh/);
  assert.match(script, /test --environment local/);
  assert.match(script, /check \\\n\t--environment public-demo --explain/);
  assert.match(script, /public-demo-missing/);
  assert.match(script, /public-todo/);
  assert.match(script, /todo-verification/);
  assert.match(script, /assert-fence-file-equals/);
  assert.match(script, /assert-fence-equals/);
  assert.match(script, /replace-fence-pair/);
  assert.match(script, /'Test the starter' \\\n\t\ttext \\\n\t\t1/);
  assert.match(script, /'Inspect the contract you own' \\\n\t\ttext \\\n\t\t1/);
  assert.ok(spreadsheetFence('Test the starter', 'text', 1));
  assert.ok(spreadsheetFence('Inspect the contract you own', 'text', 1));
  assert.ok(spreadsheetFence('Build the review inputs', 'text', 1));
  assert.match(script, /Spreadsheet evidence-change reader journey: PASS/);
  assert.match(script, /if \[\[ "\$RUNNER_MODE" == "sealed" \]\]; then/);
  assert.match(script, /dev --detach/);
  assert.match(script, /records-denied\.curl/);
  assert.match(script, /records-request\.curl/);
  assert.match(script, /anonymous records request returned HTTP/);
  assert.match(script, /auth\.missing_credential/);
  assert.match(script, /assert-json-subset "\$EVIDENCE_REPORT\/records-request\.json"/);
  assert.match(script, /assert-json-subset "\$EVIDENCE_REPORT\/evidence-request\.json"/);
  assert.match(script, /assert-json-subset "\$EVIDENCE_BODY"/);
  assert.match(script, /"value":"PW-002"/);
  assert.match(script, /north-01/);
  assert.match(script, /'planned'/);
  assert.match(script, /dev smoke/);
  assert.match(script, /dev down/);
  assert.match(script, /--environment local/);
  assert.doesNotMatch(script, /APPROVAL_TUTORIAL|Initial local approval|trust anchor|trust bundle|approved-set/);
  assert.doesNotMatch(script, /deploy generate/);
  assert.match(script, /oauth2_bearer_no_expiry/);
  assert.match(script, /REGISTRYCTL_BIN must be an absolute installed-binary path/);
  assert.match(script, /REGISTRYCTL_TUTORIAL_EVIDENCE_DIR/);
  assert.match(script, /REGISTRYCTL_TUTORIAL_PROJECT_DIR/);
  assert.match(script, /REGISTRYCTL_TUTORIAL_OAUTH_PROJECT_DIR/);
  assert.match(script, /REGISTRYCTL_RELEASED_DOCS_ROOT/);
  assert.match(script, /RELEASED_DOCS_ROOT\/tutorials\/author-registry-project\.md/);
  assert.match(script, /RELEASED_DOCS_ROOT\/tutorials\/publish-spreadsheet-secured-registry-api\.md/);
  assert.match(script, /RELEASED_DOCS_ROOT\/tutorials\/verify-claim-registry-api\.md/);
  assert.match(script, /RELEASED_DOCS_ROOT\/configure\/oauth-client-credentials\.md/);
  assert.match(script, /RELEASED_DOCS_ROOT\/examples\/registryctl\/opencrvs-events-api-overlay-v1\.sh/);
  assert.match(script, /RELEASED_DOCS_ROOT\/examples\/registryctl\/jsonplaceholder-todo-live-overlay-v1\.sh/);
  assert.match(script, /OPENCRVS_PROJECT="\$\{RETAINED_OAUTH_PROJECT:-\$WORK_ROOT\/opencrvs-reader\}"/);
  assert.match(script, /HTTP_PROJECT="\$\{RETAINED_PROJECT:-\$WORK_ROOT\/http-reader\}"/);
  assert.match(script, /SPREADSHEET_PROJECT="\$WORK_ROOT\/spreadsheet-reader"/);
  assert.match(script, /EVIDENCE_PROJECT="\$SPREADSHEET_PROJECT"/);
  assert.match(script, /"\$RETAINED_OAUTH_PROJECT"/);
  assert.match(script, /disposable runtime runs only with an explicitly installed sealed binary/);
  assert.doesNotMatch(
    script,
    /OPENCRVS_FIXTURE|cp -R|registryctl preflight|init --from|docker build|fake image|v0\.15\.2/,
  );
  assert.doesNotMatch(script, /registryctl 1\.0 reader journeys/);
});

test('current reader pages keep public starters and current command roots', () => {
  const pages = [
    read('src/content/docs/tutorials/author-registry-project.mdx'),
    read('src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx'),
    read('src/content/docs/tutorials/configure-project-script-adapter.mdx'),
    read('src/content/docs/tutorials/verify-opencrvs-claims.mdx'),
  ];
  const currentText = pages.join('\n');

  assert.match(currentText, /tag="v<major>\.<minor>\.<patch>"/);
  assert.match(currentText, /registryctl-\$\{tag\}-install\.sh/);
  assert.match(currentText, /release\/VERIFY\.md/);
  assert.match(currentText, /quick installation path trusts GitHub and TLS/);
  assert.match(currentText, /--template http/);
  assert.match(currentText, /--template spreadsheet/);
  assert.match(currentText, /registryctl dev smoke/);
  assert.match(currentText, /registryctl check/);
  assert.match(currentText, /registryctl build/);
  assert.doesNotMatch(
    currentText,
    /registryctl (?:preflight|start|stop|restart|smoke|add notary)|init --from|test --live|Bruno/,
  );
  assert.doesNotMatch(currentText, /TODO:|Evidence:/);
});

test('OAuth guidance distinguishes expiring and strict no-expiry profiles', () => {
  const oauth = read('src/content/docs/configure/oauth-client-credentials.mdx');
  const adapter = read('src/content/docs/tutorials/configure-project-script-adapter.mdx');

  assert.match(oauth, /request: form/);
  assert.match(oauth, /request: json/);
  assert.match(oauth, /response_profile: oauth2_bearer/);
  assert.match(oauth, /response_profile: oauth2_bearer_no_expiry/);
  assert.match(oauth, /`access_token` must be non-empty and bounded/);
  assert.match(oauth, /`token_type` must be exactly `Bearer`/);
  assert.match(oauth, /`expires_in` must be an integer/);
  assert.match(oauth, /caching is disabled/);
  assert.match(oauth, /private source origin and token endpoint/);
  assert.match(oauth, /secret references/);
  assert.match(adapter, /file: adapter\.rhai/);
});

test('OpenCRVS remains a synthetic case study, not a template or conformance claim', () => {
  const tutorial = read('src/content/docs/tutorials/verify-opencrvs-claims.mdx');
  const cutover = read('src/content/docs/start/pre-1.0-cutover.mdx');

  assert.match(tutorial, /^status: current$/m);
  assert.match(tutorial, /does not ship an OpenCRVS template/);
  assert.match(tutorial, /synthetic/i);
  assert.match(tutorial, /does not establish compatibility/i);
  assert.match(tutorial, /country configuration/i);
  assert.match(tutorial, /POST \/api\/events\/events\/search/);
  assert.match(tutorial, /birth-event-search/);
  assert.match(tutorial, /birth-event-match/);
  assert.match(tutorial, /birth-event-found/);
  assert.match(tutorial, /birth-event-registered/);
  assert.doesNotMatch(tutorial, /--template opencrvs|init --from opencrvs/);
  assert.match(cutover, /public 1\.0 starters are `http` and `spreadsheet`/);
  assert.match(cutover, /OAuth-backed Rhai is an adaptation of an HTTP project/);
  assert.match(cutover, /OpenCRVS material is a synthetic example.*not a template/);
});
