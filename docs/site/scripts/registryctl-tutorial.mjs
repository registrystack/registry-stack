import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function normalizedLines(value) {
  return value.replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n');
}

export function extractFencedBlocks(markdown) {
  const lines = normalizedLines(markdown);
  const blocks = [];
  const occurrences = new Map();
  let heading = null;
  let fence = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];

    if (fence === null) {
      const headingMatch = /^##\s+(.+?)\s*$/.exec(line);
      if (headingMatch) {
        heading = headingMatch[1];
        continue;
      }

      const fenceMatch = /^(\s*)```([A-Za-z0-9_-]+)\s*$/.exec(line);
      if (fenceMatch && heading !== null) {
        fence = {
          heading,
          language: fenceMatch[2],
          indent: fenceMatch[1],
          line: index + 1,
          lines: [],
        };
      }
      continue;
    }

    if (line.trim() === '```') {
      while (fence.lines.at(0) === '') fence.lines.shift();
      while (fence.lines.at(-1) === '') fence.lines.pop();
      const key = `${fence.heading}\u0000${fence.language}`;
      const occurrence = (occurrences.get(key) ?? 0) + 1;
      occurrences.set(key, occurrence);
      blocks.push({
        heading: fence.heading,
        language: fence.language,
        occurrence,
        line: fence.line,
        content: fence.lines.join('\n'),
      });
      fence = null;
      continue;
    }

    fence.lines.push(line.startsWith(fence.indent) ? line.slice(fence.indent.length) : line);
  }

  invariant(
    fence === null,
    `unterminated ${fence?.language ?? ''} fence under ${fence?.heading ?? 'unknown heading'}`,
  );
  return blocks;
}

export function shellBlocks(markdown) {
  return extractFencedBlocks(markdown).filter((block) => block.language === 'sh');
}

export function assertTutorialLayout(markdown, expectedHeadings) {
  const actualHeadings = shellBlocks(markdown).map((block) => block.heading);
  invariant(
    JSON.stringify(actualHeadings) === JSON.stringify(expectedHeadings),
    `shell block layout changed\nexpected: ${JSON.stringify(expectedHeadings)}\nactual:   ${JSON.stringify(actualHeadings)}`,
  );
}

function findFence(markdown, heading, language, occurrence) {
  const block = extractFencedBlocks(markdown).find(
    (candidate) =>
      candidate.heading === heading &&
      candidate.language === language &&
      candidate.occurrence === occurrence,
  );
  invariant(block, `missing ${language} fence ${occurrence} under "${heading}"`);
  return block;
}

export function writeShellBlocks(markdownPath, outputDirectory) {
  const blocks = shellBlocks(readFileSync(markdownPath, 'utf8'));
  mkdirSync(outputDirectory, { recursive: true });
  blocks.forEach((block, index) => {
    const path = resolve(outputDirectory, `${String(index + 1).padStart(2, '0')}.sh`);
    writeFileSync(path, `${block.content}\n`, { encoding: 'utf8', mode: 0o600 });
    chmodSync(path, 0o600);
  });
  writeFileSync(
    resolve(outputDirectory, 'manifest.json'),
    `${JSON.stringify(
      blocks.map(({ heading, occurrence, line }) => ({ heading, occurrence, line })),
      null,
      2,
    )}\n`,
    'utf8',
  );
  return blocks;
}

export function writeFence(
  markdownPath,
  heading,
  language,
  occurrence,
  outputPath,
) {
  const block = findFence(
    readFileSync(markdownPath, 'utf8'),
    heading,
    language,
    occurrence,
  );
  writeFileSync(outputPath, `${block.content}\n`, { encoding: 'utf8', mode: 0o600 });
  chmodSync(outputPath, 0o600);
}

export function assertOutputContainsLines(output, expected, label = 'command output') {
  const missing = normalizedLines(expected).filter((line) => line !== '' && !output.includes(line));
  invariant(missing.length === 0, `${label} is missing documented lines:\n${missing.join('\n')}`);
}

export function assertOutputContains(output, values, label = 'command output') {
  const missing = values.filter((value) => !output.includes(value));
  invariant(missing.length === 0, `${label} is missing expected values: ${missing.join(', ')}`);
}

export function assertOutputExcludes(output, values, label = 'command output') {
  const present = values.filter((value) => output.includes(value));
  invariant(present.length === 0, `${label} exposes forbidden values: ${present.join(', ')}`);
}

export function assertFenceEquals(
  output,
  markdown,
  heading,
  language,
  occurrence,
  replacements = [],
) {
  let actual = output.trim();
  for (const [from, to] of replacements) {
    invariant(from !== '', 'fence replacement source must not be empty');
    actual = actual.replaceAll(from, to);
  }
  const expected = findFence(markdown, heading, language, occurrence).content;
  invariant(
    actual === expected,
    `${heading} ${language} fence ${occurrence} differs from executable output`,
  );
}

export function assertFenceFileEquals(markdown, heading, language, occurrence, source) {
  const expected = source.trim();
  const actual = findFence(markdown, heading, language, occurrence).content;
  invariant(
    actual === expected,
    `${heading} ${language} fence ${occurrence} differs from its maintained source file`,
  );
}

export function assertFenceInFile(markdown, heading, language, occurrence, source) {
  const fragment = findFence(markdown, heading, language, occurrence).content;
  invariant(
    source.includes(fragment),
    `${heading} ${language} fence ${occurrence} is not an exact maintained-source fragment`,
  );
}

export function parseJsonOutput(output) {
  const value = output.trim();
  invariant(value !== '', 'command output is empty');
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`command output is not one strict JSON document: ${error.message}`);
  }
}

function subsetMismatch(actual, expected, path = '$') {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return `${path} must be an array`;
    if (expected.length === 0 && actual.length !== 0) return `${path} must be empty`;
    for (const expectedEntry of expected) {
      const matched = actual.some(
        (actualEntry) => subsetMismatch(actualEntry, expectedEntry, path) === null,
      );
      if (!matched) {
        return `${path} is missing expected array entry ${JSON.stringify(expectedEntry)}`;
      }
    }
    return null;
  }

  if (expected !== null && typeof expected === 'object') {
    if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) {
      return `${path} must be an object`;
    }
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (!(key in actual)) return `${path}.${key} is missing`;
      const mismatch = subsetMismatch(actual[key], expectedValue, `${path}.${key}`);
      if (mismatch !== null) return mismatch;
    }
    return null;
  }

  return Object.is(actual, expected)
    ? null
    : `${path} expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
}

export function assertJsonSubset(output, expected) {
  const mismatch = subsetMismatch(parseJsonOutput(output), expected);
  invariant(mismatch === null, mismatch);
}

function fixtureIds(report) {
  invariant(Array.isArray(report.fixtures), 'report fixtures must be an array');
  return report.fixtures.map((fixture) => fixture.fixture);
}

export function assertProjectReports(testOutput, checkOutput, buildOutput, expectedProject = null) {
  const testReport = parseJsonOutput(testOutput);
  const checkReport = parseJsonOutput(checkOutput);
  const buildEnvelope = parseJsonOutput(buildOutput);
  const buildReport = buildEnvelope.build;
  const project = expectedProject ?? testReport.project;

  invariant(testReport.schema_version === 'registryctl.project_command.v1', 'unexpected test schema');
  invariant(checkReport.schema_version === 'registryctl.project_command.v1', 'unexpected check schema');
  invariant(
    buildEnvelope.schema_version === 'registryctl.reviewed_project_build_report.v1',
    'unexpected build schema',
  );
  invariant(buildReport?.schema_version === 'registryctl.project_command.v1', 'unexpected nested build schema');
  invariant(testReport.status === 'passed', `test status is ${testReport.status}`);
  invariant(checkReport.status === 'valid', `check status is ${checkReport.status}`);
  invariant(buildReport.status === 'built', `build status is ${buildReport.status}`);

  for (const report of [testReport, checkReport, buildReport]) {
    invariant(report.project === project, `expected project ${project}, got ${report.project}`);
    invariant(report.environment === 'local', `expected local environment, got ${report.environment}`);
    invariant(report.fixtures.length > 0, 'project report has no fixtures');
    invariant(report.fixtures.every((fixture) => fixture.passed === true), 'a fixture did not pass');
  }

  const expectedFixtureIds = fixtureIds(testReport);
  invariant(
    JSON.stringify(fixtureIds(checkReport)) === JSON.stringify(expectedFixtureIds),
    'check fixture set differs from test',
  );
  invariant(
    JSON.stringify(fixtureIds(buildReport)) === JSON.stringify(expectedFixtureIds),
    'build fixture set differs from test',
  );

  const authorizationCheck = testReport.fixtures.find((fixture) =>
    fixture.fixture.endsWith('::derived/authorization_before_source'),
  );
  invariant(authorizationCheck, 'authorization-before-source fixture is missing');
  invariant(
    authorizationCheck.expected_error === 'authorization.denied' &&
      authorizationCheck.source_access === false,
    'authorization-before-source fixture does not prove zero source access',
  );

  const minimizationCheck = testReport.fixtures.find((fixture) =>
    fixture.fixture.endsWith('::derived/output_minimization'),
  );
  invariant(minimizationCheck?.passed === true, 'output-minimization fixture is missing or failed');

  const affectedLanes = buildEnvelope.affected_lanes;
  invariant(Array.isArray(affectedLanes), 'build affected_lanes must be an array');
  for (const lane of ['relay-public', 'relay-consultation', 'notary']) {
    invariant(affectedLanes.includes(lane), `build does not include ${lane}`);
  }
}

export function writeEvidenceManifest(
  directory,
  mode,
  registryctlVersion,
  retainedProject = null,
  retainedOauthProject = null,
) {
  mkdirSync(directory, { recursive: true });
  const manifest = {
    schema_version: 'registryctl.tutorial_reader_journeys.v1',
    status: 'passed',
    mode,
    registryctl_version: registryctlVersion,
    projects: [
      {
        id: 'http',
        source: 'embedded-http-template',
        reports: [
          'http/init.txt',
          'http/test.txt',
          'http/trace.txt',
          'http/build.txt',
          'http/test.json',
          'http/check.json',
          'http/build.json',
        ],
      },
      {
        id: 'opencrvs-events-api',
        source: 'public-docs-overlay-v1',
        covers: ['oauth-client-credentials', 'bounded-http', 'rhai', 'opencrvs-shaped-search'],
        reports: ['opencrvs/test.json', 'opencrvs/check.json', 'opencrvs/build.json'],
      },
      {
        id: 'initial-local-approval',
        source: 'maintained-http-template',
        covers: ['independent-lane-keys', 'anchors', 'bundles', 'approved-set'],
        reports: [
          'initial-approval/relay-public-verify.txt',
          'initial-approval/relay-consultation-verify.txt',
          'initial-approval/notary-verify.txt',
          'initial-approval/approved-set.txt',
        ],
      },
    ],
    release_boundary:
      'Installer, release lock, doctor, and disposable development runtime evidence are separate.',
    retained_project: retainedProject || null,
    retained_oauth_project: retainedOauthProject || null,
  };
  writeFileSync(
    resolve(directory, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
    'utf8',
  );
}

function read(path) {
  return readFileSync(path, 'utf8');
}

async function main([command, ...args]) {
  switch (command) {
    case 'extract-shell': {
      invariant(args.length === 2, 'usage: extract-shell <tutorial> <output-directory>');
      writeShellBlocks(args[0], args[1]);
      return;
    }
    case 'extract-fence': {
      invariant(
        args.length === 5,
        'usage: extract-fence <tutorial> <heading> <language> <occurrence> <output-file>',
      );
      writeFence(args[0], args[1], args[2], Number(args[3]), args[4]);
      return;
    }
    case 'assert-layout': {
      invariant(args.length === 2, 'usage: assert-layout <tutorial> <expected-headings-json>');
      assertTutorialLayout(read(args[0]), JSON.parse(args[1]));
      return;
    }
    case 'assert-contains': {
      invariant(args.length >= 2, 'usage: assert-contains <output> <value>...');
      assertOutputContains(read(args[0]), args.slice(1));
      return;
    }
    case 'assert-not-contains': {
      invariant(args.length >= 2, 'usage: assert-not-contains <output> <value>...');
      assertOutputExcludes(read(args[0]), args.slice(1));
      return;
    }
    case 'assert-fence-equals': {
      invariant(
        args.length === 5 || args.length === 7,
        'usage: assert-fence-equals <output> <tutorial> <heading> <language> <occurrence> [replace-from replace-to]',
      );
      const replacements = args.length === 7 ? [[args[5], args[6]]] : [];
      assertFenceEquals(
        read(args[0]),
        read(args[1]),
        args[2],
        args[3],
        Number(args[4]),
        replacements,
      );
      return;
    }
    case 'assert-fence-file-equals': {
      invariant(
        args.length === 5,
        'usage: assert-fence-file-equals <tutorial> <heading> <language> <occurrence> <source-file>',
      );
      assertFenceFileEquals(read(args[0]), args[1], args[2], Number(args[3]), read(args[4]));
      return;
    }
    case 'assert-fence-in-file': {
      invariant(
        args.length === 5,
        'usage: assert-fence-in-file <tutorial> <heading> <language> <occurrence> <source-file>',
      );
      assertFenceInFile(read(args[0]), args[1], args[2], Number(args[3]), read(args[4]));
      return;
    }
    case 'assert-json-subset': {
      invariant(args.length === 2, 'usage: assert-json-subset <output> <expected-json>');
      assertJsonSubset(read(args[0]), JSON.parse(args[1]));
      return;
    }
    case 'assert-project-reports': {
      invariant(
        args.length === 3 || args.length === 4,
        'usage: assert-project-reports <test-json> <check-json> <build-json> [project-id]',
      );
      assertProjectReports(read(args[0]), read(args[1]), read(args[2]), args[3] ?? null);
      return;
    }
    case 'write-evidence-manifest': {
      invariant(
        args.length >= 3 && args.length <= 5,
        'usage: write-evidence-manifest <directory> <source|sealed> <registryctl-version> [retained-project] [retained-oauth-project]',
      );
      invariant(args[1] === 'source' || args[1] === 'sealed', 'invalid evidence mode');
      writeEvidenceManifest(args[0], args[1], args[2], args[3] ?? null, args[4] ?? null);
      return;
    }
    default:
      throw new Error(`unknown command: ${command ?? ''}`);
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`registryctl tutorial helper: ${error.message}\n`);
    process.exitCode = 1;
  }
}
