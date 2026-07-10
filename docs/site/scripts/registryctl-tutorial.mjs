import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseDocument } from 'yaml';

export const HTTP_STATUS_PREFIX = '__REGISTRYCTL_TUTORIAL_HTTP_STATUS__:';

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

  invariant(fence === null, `unterminated ${fence?.language ?? ''} fence under ${fence?.heading ?? 'unknown heading'}`);
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
    `${JSON.stringify(blocks.map(({ heading, occurrence, line }) => ({ heading, occurrence, line })), null, 2)}\n`,
    'utf8',
  );
  return blocks;
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

export function assertHttpStatus(output, expectedStatus) {
  const pattern = new RegExp(`${HTTP_STATUS_PREFIX}(\\d{3})`, 'g');
  const statuses = [...output.matchAll(pattern)].map((match) => Number(match[1]));
  invariant(statuses.length === 1, `expected one recorded HTTP status, found ${statuses.length}`);
  invariant(
    statuses[0] === Number(expectedStatus),
    `expected HTTP ${expectedStatus}, received HTTP ${statuses[0]}`,
  );
}

function withoutHttpStatusMarkers(output) {
  const escapedPrefix = HTTP_STATUS_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return output
    .replace(new RegExp(`\\n?${escapedPrefix}\\d{3}\\r?\\n?`, 'g'), '\n')
    .replaceAll('\r', '');
}

export function parseJsonOutput(output) {
  const value = withoutHttpStatusMarkers(output);
  const starts = [];
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === '{' || value[index] === '[') starts.push(index);
  }
  for (const start of starts) {
    try {
      return JSON.parse(value.slice(start).trim());
    } catch {
      // Try the next JSON-looking boundary. HTTP headers can precede the body.
    }
  }
  throw new Error('command output does not contain a complete JSON value');
}

function subsetMismatch(actual, expected, path = '$') {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return `${path} must be an array`;
    if (expected.length === 0 && actual.length !== 0) return `${path} must be empty`;
    for (const expectedEntry of expected) {
      const matched = actual.some((actualEntry) => subsetMismatch(actualEntry, expectedEntry, path) === null);
      if (!matched) return `${path} is missing expected array entry ${JSON.stringify(expectedEntry)}`;
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

export function assertProblem(output, expectedStatus, expectedCode) {
  assertHttpStatus(output, expectedStatus);
  assertJsonSubset(output, { status: Number(expectedStatus), code: expectedCode });
}

function readYamlDocument(path) {
  const document = parseDocument(readFileSync(path, 'utf8'));
  invariant(document.errors.length === 0, `failed to parse ${path}: ${document.errors.join('; ')}`);
  return document;
}

function writeYamlDocument(path, document) {
  writeFileSync(path, document.toString(), 'utf8');
}

export function rebindProjectImages(projectDirectory, relayImage, notaryImage) {
  const composePath = resolve(projectDirectory, 'compose.yaml');
  const manifestPath = resolve(projectDirectory, 'registryctl.yaml');
  const compose = readYamlDocument(composePath);
  const composeValue = compose.toJS();
  const hasRelay = composeValue?.services?.['registry-relay'] !== undefined;
  const hasNotary = composeValue?.services?.['registry-notary'] !== undefined;
  invariant(hasRelay || hasNotary, `${composePath} has no Registry Stack product services`);

  if (hasRelay) compose.setIn(['services', 'registry-relay', 'image'], relayImage);
  if (hasNotary) compose.setIn(['services', 'registry-notary', 'image'], notaryImage);
  writeYamlDocument(composePath, compose);

  const manifest = readYamlDocument(manifestPath);
  if (hasRelay) manifest.setIn(['runtime', 'relay_image'], relayImage);
  if (hasNotary) manifest.setIn(['runtime', 'notary_image'], notaryImage);
  writeYamlDocument(manifestPath, manifest);
}

export function setRelayMinGroupSize(configPath, datasetId, aggregateId, value) {
  const document = readYamlDocument(configPath);
  const config = document.toJS();
  const datasetIndex = config?.datasets?.findIndex((dataset) => dataset.id === datasetId) ?? -1;
  invariant(datasetIndex >= 0, `dataset ${datasetId} not found in ${configPath}`);
  const aggregateIndex =
    config.datasets[datasetIndex]?.aggregates?.findIndex((aggregate) => aggregate.id === aggregateId) ?? -1;
  invariant(aggregateIndex >= 0, `aggregate ${aggregateId} not found in dataset ${datasetId}`);
  const path = [
    'datasets',
    datasetIndex,
    'aggregates',
    aggregateIndex,
    'disclosure_control',
    'min_group_size',
  ];
  invariant(typeof document.getIn(path) === 'number', `${aggregateId} has no numeric min_group_size`);
  document.setIn(path, Number(value));
  writeYamlDocument(configPath, document);
}

export function setNotaryAllowedPurposes(configPath, claimId, bindingId, purposes) {
  const document = readYamlDocument(configPath);
  const config = document.toJS();
  const claimIndex = config?.evidence?.claims?.findIndex((claim) => claim.id === claimId) ?? -1;
  invariant(claimIndex >= 0, `claim ${claimId} not found in ${configPath}`);
  invariant(
    config.evidence.claims[claimIndex]?.source_bindings?.[bindingId] !== undefined,
    `source binding ${bindingId} not found for claim ${claimId}`,
  );
  document.setIn(
    ['evidence', 'claims', claimIndex, 'source_bindings', bindingId, 'matching', 'allowed_purposes'],
    purposes,
  );
  writeYamlDocument(configPath, document);
}

export function replaceLiteralOnce(value, from, to) {
  const occurrences = value.split(from).length - 1;
  invariant(occurrences === 1, `expected one occurrence of ${JSON.stringify(from)}, found ${occurrences}`);
  return value.replace(from, to);
}

export function redactOutput(output, envFile = '') {
  const secrets = [];
  if (envFile !== '') {
    for (const line of normalizedLines(envFile)) {
      if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
      const separator = line.indexOf('=');
      if (separator < 1) continue;
      const key = line.slice(0, separator).trim();
      let value = line.slice(separator + 1).trim();
      if (
        value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'")))
      ) {
        value = value.slice(1, -1);
      }
      if (value.length >= 8) secrets.push({ key, value });
    }
  }

  let redacted = output;
  for (const { key, value } of secrets.toSorted((left, right) => right.value.length - left.value.length)) {
    redacted = redacted.split(value).join(`[REDACTED:${key}]`);
  }
  return redacted
    .replace(/(Authorization:\s*Bearer\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(x-api-key:\s*)[^\s]+/gi, '$1[REDACTED]');
}

export async function assertPortsFree(ports) {
  const servers = [];
  try {
    for (const port of ports) {
      const server = createServer();
      await new Promise((resolveListen, rejectListen) => {
        server.once('error', rejectListen);
        server.listen({ host: '127.0.0.1', port, exclusive: true }, resolveListen);
      });
      servers.push(server);
    }
  } catch (error) {
    throw new Error(`documented tutorial ports are not free: ${error.message}`);
  } finally {
    await Promise.all(
      servers.map(
        (server) =>
          new Promise((resolveClose) => {
            server.close(resolveClose);
          }),
      ),
    );
  }
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
    case 'assert-layout': {
      invariant(args.length === 2, 'usage: assert-layout <tutorial> <expected-headings-json>');
      assertTutorialLayout(read(args[0]), JSON.parse(args[1]));
      return;
    }
    case 'assert-fence-lines': {
      invariant(
        args.length === 5,
        'usage: assert-fence-lines <output> <tutorial> <heading> <language> <occurrence>',
      );
      const expected = findFence(read(args[1]), args[2], args[3], Number(args[4])).content;
      assertOutputContainsLines(read(args[0]), expected, args[2]);
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
    case 'assert-http': {
      invariant(args.length === 2, 'usage: assert-http <output> <status>');
      assertHttpStatus(read(args[0]), Number(args[1]));
      return;
    }
    case 'assert-problem': {
      invariant(args.length === 3, 'usage: assert-problem <output> <status> <code>');
      assertProblem(read(args[0]), Number(args[1]), args[2]);
      return;
    }
    case 'assert-json-subset': {
      invariant(args.length === 2, 'usage: assert-json-subset <output> <expected-json>');
      assertJsonSubset(read(args[0]), JSON.parse(args[1]));
      return;
    }
    case 'rebind-project': {
      invariant(
        args.length === 3,
        'usage: rebind-project <project-directory> <relay-image> <notary-image>',
      );
      rebindProjectImages(args[0], args[1], args[2]);
      return;
    }
    case 'set-relay-min-group-size': {
      invariant(
        args.length === 4,
        'usage: set-relay-min-group-size <config> <dataset-id> <aggregate-id> <value>',
      );
      setRelayMinGroupSize(args[0], args[1], args[2], Number(args[3]));
      return;
    }
    case 'set-notary-purposes': {
      invariant(
        args.length === 4,
        'usage: set-notary-purposes <config> <claim-id> <binding-id> <purposes-json>',
      );
      setNotaryAllowedPurposes(args[0], args[1], args[2], JSON.parse(args[3]));
      return;
    }
    case 'replace-once': {
      invariant(args.length === 4, 'usage: replace-once <input> <from> <to> <output>');
      writeFileSync(args[3], replaceLiteralOnce(read(args[0]), args[1], args[2]), 'utf8');
      return;
    }
    case 'sanitize': {
      invariant(args.length === 1 || args.length === 2, 'usage: sanitize <output> [env-file]');
      const envFile = args[1] === undefined ? '' : read(args[1]);
      process.stdout.write(redactOutput(read(args[0]), envFile));
      return;
    }
    case 'assert-ports-free': {
      invariant(args.length > 0, 'usage: assert-ports-free <port>...');
      await assertPortsFree(args.map(Number));
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
