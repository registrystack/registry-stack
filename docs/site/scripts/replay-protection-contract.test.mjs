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
  /^## 8[.] Replay-protection authority\n(?<body>[\s\S]*?)(?=^## 9[.] )/m,
)?.groups?.body;

assert.ok(replaySection, 'RS-SEC-G must contain the replay-protection authority section');

test('RS-SEC-G keeps the exact product replay matrix', () => {
  const productRows = replaySection.match(/^\| Registry (?:Relay|Notary) \|.*$/gm) ?? [];
  assert.equal(productRows.length, 2, 'expected one replay-contract row per product');

  assert.match(
    replaySection,
    /\| Registry Relay \| Batch-child idempotent consultation execution[.] \|[\s\S]*?child identity[\s\S]*?exact canonical request[\s\S]*?\| `15 minutes` from reservation or terminal publication[.] \|/,
  );
  assert.match(
    replaySection,
    /\| Registry Notary \| Scoped, domain-separated protocol one-time and completion domains,[\s\S]*?Product-specific scope and identifier hashes[\s\S]*?\| The product-specific absolute expiry or bounded retention for the domain,/,
  );
});

test('RS-SEC-G keeps replay authority product-owned and isolated', () => {
  assert.match(replaySection, /production or multi-instance deployment MUST keep replay correctness state in\nthe PostgreSQL state owned by the product/);
  assert.match(replaySection, /Replicas of one product authority MUST share only that authority's product state/);
  assert.match(replaySection, /Separate federation authorities MUST NOT share replay state/);
  assert.match(
    replaySection,
    /Registry Relay and Registry Notary MUST NOT share replay tables, schemas, database roles,\nmigrations, or correctness transactions/,
  );
  assert.match(replaySection, /MUST NOT turn these boundaries into a shared correctness-state abstraction/);
  assert.doesNotMatch(replaySection, /\bRedis\b/i);
});

test('RS-SEC-G links retention and recovery and requires fail-closed recovery', () => {
  assert.match(replaySection, /\[retention and persistent-state reference\]\(\.\.\/\.\.\/operate\/retention-and-persistent-state\/\)/);
  assert.match(replaySection, /\[backup and restore procedure\]\(\.\.\/\.\.\/operate\/backup-and-restore\/\)/);
  assert.match(replaySection, /database-unavailable, read-only, timed-out, or transaction-uncertain result MUST fail closed/);
  assert.match(replaySection, /potentially stale recovery point MUST remain offline until the product-specific recovery rules/);
  assert.match(replaySection, /Expiry alone MUST NOT be treated as repair/);
});
