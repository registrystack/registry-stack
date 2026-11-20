import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const page = readFileSync(
  resolve(here, '../src/content/docs/security/evidence.mdx'),
  'utf8',
);
const replaySection = page.match(
  /^## Replay protection\n(?<body>[\s\S]*?)(?=^## )/m,
)?.groups?.body;

assert.ok(replaySection, 'The Registry Evidence security model must contain the replay protection section');
const prose = replaySection.replace(/\s+/g, ' ');

test('Evidence replay protection distinguishes credential replay from operation receipts', () => {
  assert.match(
    prose,
    /Registry Evidence holds no credential or presentation replay state/,
  );
  assert.match(
    prose,
    /Replay prevention for one-time credentials belongs to the surrounding protocol or issuer that creates and validates a one-time challenge/,
  );
  assert.match(prose, /Other products may retain operation receipts or replay recovery state under their own contracts/);
  assert.doesNotMatch(prose, /No maintained Registry Stack resource server holds a replay table/);
  assert.doesNotMatch(replaySection, /^\| Registry /m);
});

test('Evidence replay protection does not turn validation into credential consumption', () => {
  assert.match(
    prose,
    /Registry Evidence does not claim replay prevention or single-use enforcement/,
  );
  assert.match(
    prose,
    /signature[s]?, expiry, audience, nonce equality, and other request bindings/,
  );
  assert.match(prose, /Nonce equality is not nonce consumption/);
  assert.doesNotMatch(prose, /Evidence (prevents|enforces|blocks) (replay|single-use|reuse)/i);
  assert.doesNotMatch(replaySection, /\bRedis\b|\bPostgreSQL\b|batch-child/i);
});

test('Evidence replay protection is product behaviour, not a normative requirement', () => {
  assert.doesNotMatch(replaySection, /\bMUST\b|\bSHALL\b|\bMAY\b|REQ-SEC/);
});
