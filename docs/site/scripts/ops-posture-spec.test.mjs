import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import YAML from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, '..');
const repositoryRoot = resolve(siteRoot, '../..');
const specPath = resolve(siteRoot, 'src/content/docs/spec/rs-op-posture.mdx');
const relayCrate = resolve(repositoryRoot, 'crates/registry-relay-v2/src');
const relayHttpContract = resolve(
  repositoryRoot,
  'crates/registry-relay-http-contract/src/lib.rs',
);

const page = readFileSync(specPath, 'utf8');
const serverSource = readFileSync(resolve(relayCrate, 'server.rs'), 'utf8');
const httpContractSource = readFileSync(relayHttpContract, 'utf8');
const mainSource = readFileSync(resolve(relayCrate, 'main.rs'), 'utf8');
const contractSource = readFileSync(resolve(relayCrate, 'contract.rs'), 'utf8');
const startupSource = readFileSync(resolve(relayCrate, 'startup.rs'), 'utf8');

function frontmatter(text) {
  const end = text.indexOf('\n---\n', 4);
  assert.notEqual(end, -1, 'expected complete YAML frontmatter');
  return YAML.parse(text.slice(4, end));
}

test('RS-OP-POSTURE has a stable formal-specification identifier', () => {
  const data = frontmatter(page);

  assert.equal(data.doc_id, 'RS-OP-POSTURE');
  assert.equal(data.doc_type, 'specification');
  assert.equal(data.category, 'normative');
  assert.equal(data.evidence, 'verified');
  assert.deepEqual(data.layer, ['operations']);
});

test('RS-OP-POSTURE retires the admin posture requirements without reusing identifiers', () => {
  assert.match(
    page,
    /REQ-OP-POSTURE-001 through REQ-OP-POSTURE-011 are retired in full and MUST NOT be reused/,
  );

  const defined = [...page.matchAll(/^REQ-OP-POSTURE-(\d+):/gm)].map((match) =>
    Number(match[1]),
  );
  assert.ok(defined.length > 0, 'expected the specification to define requirements');
  for (const identifier of defined) {
    assert.ok(
      identifier >= 101,
      `REQ-OP-POSTURE-${String(identifier).padStart(3, '0')} reuses a retired identifier`,
    );
  }
});

test('RS-OP-POSTURE states the operational probe inventory the runtime serves', () => {
  assert.match(httpContractSource, /pub const HEALTH: &str = "\/health";/);
  assert.match(httpContractSource, /pub const READY: &str = "\/ready";/);
  assert.match(serverSource, /\.route\(routes::HEALTH, get\(crate::api::health\)\)/);
  assert.match(serverSource, /\.route\(routes::READY, get\(crate::api::ready\)\)/);
  assert.doesNotMatch(serverSource, /\.route\("\/admin/);
  assert.doesNotMatch(serverSource, /\.route\("\/metrics/);

  assert.match(page, /`GET \/health`/);
  assert.match(page, /`GET \/ready`/);
  assert.match(page, /\{"status":"ok"\}/);
  assert.match(page, /\{"status":"ready"\}/);
  assert.match(page, /MUST NOT expose an administrative route, a posture route, a metrics route/);
  assert.match(page, /`service\.not_ready`/);
});

test('RS-OP-POSTURE composes readiness exactly as the runtime does', () => {
  assert.match(serverSource, /audit_ready && source_ready && issuer_ready/);

  assert.match(page, /audit readiness, source readiness, and\s+issuer readiness all hold/);
  assert.match(page, /MUST NOT begin serving in an unready state/);
  assert.match(page, /snapshot source MUST be confirmed unchanged/);
});

test('RS-OP-POSTURE states the audit sink as a serving precondition', () => {
  assert.match(page, /`audit\.unavailable`/);
  assert.match(page, /MUST NOT degrade to serving without audit/);
});

test('RS-OP-POSTURE states the runtime bounds the contract enforces', () => {
  const bounds = [
    /request_timeout_milliseconds > ([\d_]+)/,
    /concurrent_queries > ([\d_]+)/,
    /maximum_age_seconds > ([\d_]+)/,
    /burst > ([\d_]+)/,
  ];

  for (const pattern of bounds) {
    const match = contractSource.match(pattern);
    assert.ok(match, `expected ${pattern} in the runtime contract`);
    const bound = match[1].replaceAll('_', '');
    assert.ok(
      page.includes(bound),
      `RS-OP-POSTURE does not state the ${bound} bound the runtime enforces`,
    );
  }

  assert.match(page, /MUST NOT\s+silently clamp an out-of-range value/);
});

test('RS-OP-POSTURE states the URI bound and the quota vocabulary', () => {
  const uriBound = serverSource.match(/MAXIMUM_URI_BYTES: usize = (\d+) \* 1024/);
  assert.ok(uriBound, 'expected a URI byte bound in the server');
  assert.ok(page.includes(String(Number(uriBound[1]) * 1024)));

  assert.match(page, /`internal\.uri_too_long`/);
  assert.match(page, /`consultation\.rate_limited`/);
  assert.match(page, /`aggregate-data\.rate_limited`/);
  assert.match(page, /MUST NOT rely on quotas as a\s+per-caller/);
});

test('RS-OP-POSTURE states the closed operational log level set', () => {
  const levels = new Set(
    [...mainSource.matchAll(/"registry_relay_v2=(\w+)"/g)].map((match) => match[1]),
  );
  assert.deepEqual([...levels].sort(), ['debug', 'error', 'info', 'off', 'trace', 'warn']);

  for (const level of levels) {
    assert.ok(page.includes(`\`${level}\``), `RS-OP-POSTURE omits the \`${level}\` log level`);
  }
  assert.match(page, /An unrecognized value MUST be treated as `info`/);
  assert.match(page, /Relay-owned log targets only/);
});

test('RS-OP-POSTURE states the shipped healthcheck defaults', () => {
  const url = mainSource.match(/DEFAULT_HEALTHCHECK_URL: &str = "([^"]+)"/);
  assert.ok(url, 'expected a default healthcheck URL');
  assert.ok(page.includes(url[1]), 'RS-OP-POSTURE does not state the default healthcheck URL');
  assert.ok(url[1].endsWith('/health'), 'the shipped healthcheck probes liveness');

  const timeout = startupSource.match(/HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs\((\d+)\)/);
  const bodyBytes = startupSource.match(/MAXIMUM_HEALTH_BODY_BYTES: usize = (\d+)/);
  assert.ok(timeout && bodyBytes, 'expected healthcheck bounds in startup');
  assert.ok(page.includes(`${timeout[1]} seconds`));
  assert.ok(page.includes(`${bodyBytes[1]} response bytes`));
});

test('RS-OP-POSTURE states the defaults startup applies', () => {
  const cursorAge = startupSource.match(
    /DEFAULT_CURSOR_MAXIMUM_AGE: Duration = Duration::from_secs\((\d+)\)/,
  );
  const shutdownGrace = startupSource.match(
    /DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs\((\d+)\)/,
  );
  assert.ok(cursorAge && shutdownGrace, 'expected startup defaults');
  assert.ok(page.includes(`${cursorAge[1]} seconds`));
  assert.ok(page.includes(`${shutdownGrace[1]} seconds`));

  assert.match(startupSource, /The package is the governed trust root\. Verify it before opening/);
  assert.match(page, /MUST verify the sealed package before it opens an issuer, audit,\s+source/);
});

test('RS-OP-POSTURE links no retired route', () => {
  for (const route of [
    '/reference/apis/registry-relay/',
    '/reference/registryctl/',
    '/reference/diagnostics/',
    '/operate/backup-and-restore/',
    '/spec/rs-pr-registryctl/',
  ]) {
    assert.ok(!page.includes(route), `RS-OP-POSTURE links the retired route ${route}`);
  }
});
