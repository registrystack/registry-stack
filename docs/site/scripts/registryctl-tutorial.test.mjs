import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

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
      'services:\n  registry-relay:\n    image: relay:old\n    ports: ["4242:8080"]\n  registry-notary:\n    image: notary:old\n',
    );
    writeFileSync(
      join(directory, 'registryctl.yaml'),
      'runtime:\n  relay_image: relay:old\n  notary_image: notary:old\n',
    );

    rebindProjectImages(directory, 'relay:source', 'notary:source');

    const compose = parse(readFileSync(join(directory, 'compose.yaml'), 'utf8'));
    const manifest = parse(readFileSync(join(directory, 'registryctl.yaml'), 'utf8'));
    assert.equal(compose.services['registry-relay'].image, 'relay:source');
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

test('source tutorial image staging includes the dedicated Relay Rhai worker', () => {
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');
  const worker = 'registry-relay-rhai-worker';

  assert.match(script, new RegExp(`\\$LINUX_TARGET/release/${worker}`));
  assert.match(script, new RegExp(`dist/image-bin/${worker}`));
  assert.match(script, new RegExp(`chmod 0755[\\s\\S]*dist/image-bin/${worker}`));
});

test('source tutorial image staging includes the dedicated Notary CEL worker', () => {
  const script = readFileSync(new URL('./check-registryctl-tutorials.sh', import.meta.url), 'utf8');
  const worker = 'registry-notary-cel-worker';

  assert.match(script, new RegExp(`--bin ${worker}`));
  assert.match(script, new RegExp(`\\$LINUX_TARGET/release/${worker}`));
  assert.match(script, new RegExp(`dist/image-bin/${worker}`));
  assert.match(script, new RegExp(`chmod 0755[\\s\\S]*dist/image-bin/${worker}`));
});
