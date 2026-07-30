import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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

test('reader gate uses 1.0 commands and leaves runtime evidence to the release workflow', () => {
  const script = read('scripts/check-registryctl-tutorials.sh');

  assert.match(script, /init "\$HTTP_PROJECT" --template http >"\$REPORT_ROOT\/http\/init\.txt"/);
  assert.match(script, /-C "\$project_directory" test --format json/);
  assert.match(script, /-C "\$project_directory" check --format json/);
  assert.match(script, /-C "\$project_directory" build --format json/);
  assert.match(script, /opencrvs-events-api/);
  assert.match(script, /assert-fence-file-equals/);
  assert.match(script, /assert-fence-equals/);
  assert.match(script, /oauth2_bearer_no_expiry/);
  assert.match(script, /REGISTRYCTL_BIN must be an absolute installed-binary path/);
  assert.match(script, /REGISTRYCTL_TUTORIAL_EVIDENCE_DIR/);
  assert.match(script, /REGISTRYCTL_TUTORIAL_PROJECT_DIR/);
  assert.match(script, /exact runtime sequence is release-gated from the sealed candidate payload/);
  assert.doesNotMatch(script, /registryctl preflight|init --from|docker build|fake image|v0\.15\.2/);
});

test('current reader pages use only the two public templates and current command roots', () => {
  const pages = [
    read('src/content/docs/tutorials/author-registry-project.mdx'),
    read('src/content/docs/tutorials/configure-project-script-adapter.mdx'),
    read('src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx'),
    read('src/content/docs/tutorials/use-your-spreadsheet.mdx'),
    read('src/content/docs/tutorials/verify-claim-registry-api.mdx'),
    read('src/content/docs/tutorials/deploy-standalone-with-own-data.mdx'),
    read('src/content/docs/reference/registryctl.mdx'),
  ];
  const currentText = pages.join('\n');

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
});
