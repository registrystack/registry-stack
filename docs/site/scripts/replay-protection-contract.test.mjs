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

test('RS-SEC-G keeps the exact product replay matrix', () => {
  const productRows = replaySection.match(/^\| Registry (?:Relay|Mint) \|.*$/gm) ?? [];
  assert.equal(productRows.length, 2, 'expected one replay-contract row per product');

  assert.match(
    replaySection,
    /\| Registry Relay \| Batch-child idempotent consultation execution[.] \|[\s\S]*?child identity[\s\S]*?exact canonical request[\s\S]*?\| `15 minutes` from reservation or terminal publication[.] \|/,
  );
  assert.match(
    replaySection,
    /\| Registry Mint \| Single use of a client assertion identifier at the token endpoint[.] \|[\s\S]*?verified against the named client's registered keys[\s\S]*?\| The assertion's own expiry, bounded by the configured maximum assertion lifetime,/,
  );
});

// Evidence has no replay subsystem, and the page must not imply that the echoed
// request nonce is one.
test('RS-SEC-G states that Evidence holds no replay state', () => {
  assert.match(replaySection, /Evidence holds no replay state at all/);
  assert.match(replaySection, /never stored, uniqueness-checked, or exposed/);
});

test('RS-SEC-G keeps replay authority product-owned and isolated', () => {
  assert.match(replaySection, /production or multi-instance deployment MUST keep replay correctness state in\nthe PostgreSQL state owned by the product/);
  assert.match(replaySection, /Replicas of one product authority MUST share only that authority's product state/);
  assert.match(replaySection, /Separate product authorities MUST NOT share replay state/);
  assert.match(
    replaySection,
    /Two products MUST NOT share replay tables, schemas, database roles,\nmigrations, or correctness transactions/,
  );
  assert.match(replaySection, /MUST NOT turn these boundaries into a shared correctness-state abstraction/);
  assert.doesNotMatch(replaySection, /\bRedis\b/i);
});

// In-process single use is not a cross-instance guarantee, and the page must
// not let a reader read it as one.
test('RS-SEC-G bounds in-process single-use enforcement', () => {
  assert.match(replaySection, /MUST fail closed when\nthe cache is saturated rather than evict a live entry/);
  assert.match(
    replaySection,
    /deployment that runs more than one instance MUST NOT\nclaim single use across those instances/,
  );
});

test('RS-SEC-G links retention and recovery and requires fail-closed recovery', () => {
  assert.match(replaySection, /\[retention and persistent-state reference\]\(\.\.\/\.\.\/operate\/retention-and-persistent-state\/\)/);
  assert.match(replaySection, /\[backup and restore procedure\]\(\.\.\/\.\.\/operate\/backup-and-restore\/\)/);
  assert.match(replaySection, /database-unavailable, read-only, timed-out, or transaction-uncertain result MUST fail closed/);
  assert.match(replaySection, /potentially stale recovery point MUST remain offline until the product-specific recovery rules/);
  assert.match(replaySection, /Expiry alone MUST NOT be treated as repair/);
});
