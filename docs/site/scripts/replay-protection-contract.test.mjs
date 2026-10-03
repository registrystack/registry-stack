import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const spec = readFileSync(
  resolve(here, '../src/content/docs/spec/rs-sec-g.mdx'),
  'utf8',
);
const replaySection = spec.match(
  /^## 7[.] Replay-protection authority\n(?<body>[\s\S]*?)(?=^## 8[.] )/m,
)?.groups?.body;

assert.ok(replaySection, 'RS-SEC-G must contain the replay-protection authority section');
const prose = replaySection.replace(/\s+/g, ' ');

test('RS-SEC-G distinguishes Evidence credential replay from operation receipts', () => {
  assert.match(
    prose,
    /Evidence Gateway holds no credential or presentation replay state/,
  );
  assert.match(
    prose,
    /Replay prevention for one-time credentials belongs to the surrounding protocol or issuer that creates and validates a one-time challenge/,
  );
  assert.match(prose, /Other products may retain operation receipts or replay recovery state under their own contracts/);
  assert.doesNotMatch(prose, /No maintained Registry Stack resource server holds a replay table/);
  assert.doesNotMatch(replaySection, /^\| Registry /m);
});

test('RS-SEC-G does not turn validation into credential consumption', () => {
  assert.match(
    prose,
    /A service that holds no replay state MUST NOT claim replay prevention or single-use enforcement/,
  );
  assert.match(
    prose,
    /signature[s]?, expiry, audience, nonce equality, and other request bindings/,
  );
  assert.doesNotMatch(replaySection, /\bRedis\b|\bPostgreSQL\b|batch-child/i);
});
