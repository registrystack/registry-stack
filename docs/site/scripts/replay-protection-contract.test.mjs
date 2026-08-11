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

// Prose wraps at the source margin, so sentence-level assertions read a
// whitespace-normalized copy. Table rows and links are checked against the raw
// section, where the exact shape is the thing being guarded.
const prose = replaySection.replace(/\s+/g, ' ');

test('RS-SEC-G keeps the exact product replay matrix', () => {
  const productRows = replaySection.match(/^\| Registry \w+ \|.*$/gm) ?? [];
  assert.equal(productRows.length, 1, 'expected one replay-contract row per product');

  assert.match(
    replaySection,
    /\| Registry Mint \| Single use of a client assertion identifier at the token endpoint[.] \|[\s\S]*?verified against the named client's registered keys[\s\S]*?\| The assertion's own expiry, bounded by the configured maximum assertion lifetime,/,
  );
});

// A compiled Relay operation is a read, so Relay owns no replay decision and the
// page must not imply that its pagination cursor is a single-use token.
test('RS-SEC-G states that Registry Relay holds no replay state', () => {
  assert.doesNotMatch(replaySection, /^\| Registry Relay \|/m);
  assert.match(prose, /Registry Relay holds no replay state/);
  assert.match(
    prose,
    /A cursor is bound request context, not a single-use token, and a deployment MUST NOT present it as one/,
  );
});

// Evidence has no replay subsystem, and the page must not imply that the echoed
// request nonce is one.
test('RS-SEC-G states that Evidence Gateway holds no replay state', () => {
  assert.match(prose, /Evidence Gateway holds no replay state at all/);
  assert.match(prose, /never stored, uniqueness-checked, or exposed/);
  assert.match(
    prose,
    /A service that holds no replay state MUST NOT be presented as providing replay, single-use, or freshness protection/,
  );
});

// Replay authority stays product-owned. Nothing in the maintained stack keeps a
// replay decision in shared storage, so the page must not acquire one.
test('RS-SEC-G keeps replay authority product-owned and isolated', () => {
  assert.match(
    prose,
    /Registry Mint's client-assertion cache is the only replay authority this stack holds/,
  );
  assert.match(
    prose,
    /No maintained service persists a replay decision across restart, and none keeps replay correctness state in a database/,
  );
  assert.doesNotMatch(replaySection, /\bRedis\b/i);
  // V1 vocabulary the cutover removed from this section. Relay held replay state
  // in PostgreSQL and keyed it on a consultation batch child; V2 holds none, so
  // either name reappearing here is drift rather than a new claim.
  assert.doesNotMatch(replaySection, /\bPostgreSQL\b/i);
  assert.doesNotMatch(replaySection, /batch-child/i);
});

// In-process single use is not a cross-instance guarantee, and the page must
// not let a reader read it as one.
test('RS-SEC-G bounds in-process single-use enforcement', () => {
  assert.match(prose, /MUST fail closed when the cache is saturated rather than evict a live entry/);
  assert.match(
    prose,
    /deployment that runs more than one instance MUST NOT claim single use across those instances/,
  );
});

test('RS-SEC-G links retention and Relay recovery', () => {
  assert.match(replaySection, /\[retention and persistent-state reference\]\(\.\.\/\.\.\/operate\/retention-and-persistent-state\/\)/);
  // Relay V2 retired the standalone backup-and-restore page. The recovery steps
  // it carried now live on the Relay operations page, which is where this
  // section has to send an operator.
  assert.match(replaySection, /\]\(\.\.\/\.\.\/operate\/relay\/\)/);
  assert.doesNotMatch(replaySection, /operate\/backup-and-restore/);
});
