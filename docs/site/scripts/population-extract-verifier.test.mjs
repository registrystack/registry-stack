import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  assetHref,
  formatIssuedAt,
  historyPath,
  lookupQuery,
  lookupRecord,
  normalizePublicReference,
  sha256Hex,
} from '../src/lib/population-extract/verify-client.mjs';
import { loadIssuedSpecimens } from '../src/lib/population-extract/verification-data.mjs';
import { normalizeReference } from '../../../products/render/examples/specimen-verification/reference.mjs';

const REFERENCE = 'TEST-ABCD-0123-4567-89AB-CDEF';
const PDF = Buffer.from('%PDF-1.7\nSynthetic Population extract\n%%EOF\n');
const DIGEST = `sha256:${createHash('sha256').update(PDF).digest('hex')}`;
const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBnzCCAUWgAwIBAgIUGSkZVSD93tTafMYk9zXkW+9N+VcwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwaUmVnaXN0cnkgQWRhcHRlciBUZXN0IFJvb3QwHhcNMjYxMDMw
MDQ1NDIwWhcNMzYxMDI3MDQ1NDIwWjAlMSMwIQYDVQQDDBpSZWdpc3RyeSBBZGFw
dGVyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIDV7zIjqChx
97aw2DaQUGi02tuThFuNl5IKP4RFr+5lxRclqsvlNfhU0Y4JnNLDuxdToqXgVKz6
DnA2hpkMqZyjUzBRMB0GA1UdDgQWBBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAfBgNV
HSMEGDAWgBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAPBgNVHRMBAf8EBTADAQH/MAoG
CCqGSM49BAMCA0gAMEUCIQDE6ceiEQLBfR3wcAbPoXkClwMWZCs+QRHpi9asKR6w
GwIgG/WsmuvsVVNeDynYVj92+B5SNtyVRK2+p3eo97VtmF0=
-----END CERTIFICATE-----
`;

async function makeIssuedDirectory(t) {
  const root = await mkdtemp(join(tmpdir(), 'population-extract-public-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function addRecord(root, options = {}) {
  const directoryName = options.directoryName ?? REFERENCE;
  const directory = join(root, directoryName);
  await mkdir(directory, { recursive: true });
  const receipt = {
    reference: REFERENCE,
    issuedAt: '2026-11-24T09:30:00.000Z',
    signedFileDigest: DIGEST,
    ...options.receipt,
  };
  await writeFile(join(directory, 'document.pdf'), options.pdf ?? PDF);
  await writeFile(join(directory, 'test-root.pem'), options.rootPem ?? TEST_CERTIFICATE);
  await writeFile(join(directory, 'receipt.json'), `${JSON.stringify(receipt)}\n`);
  if (options.extraFile) await writeFile(join(directory, options.extraFile), 'unexpected\n');
  return directory;
}

test('loads an exact public record after hashing its reviewed PDF', async (t) => {
  const root = await makeIssuedDirectory(t);
  await addRecord(root);

  assert.deepEqual(await loadIssuedSpecimens(root), [{
    reference: REFERENCE,
    issuedAt: '2026-11-24T09:30:00.000Z',
    signedFileDigest: DIGEST,
  }]);
});

test('an absent or empty issued directory fails the build', async (t) => {
  const root = await makeIssuedDirectory(t);
  await assert.rejects(loadIssuedSpecimens(join(root, 'not-created')), /directory is missing/i);
  await assert.rejects(loadIssuedSpecimens(root), /at least one record/i);
});

for (const [name, change, message] of [
  ['mismatched PDF digest', { receipt: { signedFileDigest: `sha256:${'0'.repeat(64)}` } }, /digest does not match/i],
  ['extra receipt field', { receipt: { personName: 'must not be published' } }, /exactly reference, issuedAt, signedFileDigest/i],
  ['directory and receipt mismatch', { directoryName: 'TEST-0000-0000-0000-0000-0000' }, /directory name must equal receipt reference/i],
  ['malformed issuedAt', { receipt: { issuedAt: 'not-a-time' } }, /issuedAt/i],
  ['unexpected public file', { extraFile: 'notes.txt' }, /exactly document\.pdf, receipt\.json, test-root\.pem/i],
]) {
  test(`refuses a public fixture with ${name}`, async (t) => {
    const root = await makeIssuedDirectory(t);
    await addRecord(root, change);
    await assert.rejects(loadIssuedSpecimens(root), message);
  });
}

test('refuses malformed receipt JSON without publishing a partial record', async (t) => {
  const root = await makeIssuedDirectory(t);
  const directory = await addRecord(root);
  await writeFile(join(directory, 'receipt.json'), '{bad json');
  await assert.rejects(loadIssuedSpecimens(root), /receipt\.json is not valid JSON/i);
});

for (const [name, rootPem] of [
  ['a private key', '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'],
  ['more than one certificate', `${TEST_CERTIFICATE}${TEST_CERTIFICATE}`],
  ['invalid certificate bytes', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'],
]) {
  test(`refuses test-root.pem containing ${name}`, async (t) => {
    const root = await makeIssuedDirectory(t);
    await addRecord(root, { rootPem });
    await assert.rejects(loadIssuedSpecimens(root), /public CERTIFICATE/i);
  });
}

test('browser reference normalisation stays aligned with the issuer', () => {
  for (const input of [
    REFERENCE,
    REFERENCE.toLowerCase(),
    'test abcd 0123 4567 89ab cdef',
    'TESTABCD0123456789ABCDEF',
    'TEST-ABCD-0123',
    '../TEST-ABCD-0123-4567-89AB-CDEF',
    '',
    null,
  ]) {
    assert.equal(normalizePublicReference(input), normalizeReference(input));
  }
});

test('static lookup distinguishes manual, malformed, unknown and found states', () => {
  const records = [{ reference: REFERENCE, issuedAt: '2026-11-24T09:30:00.000Z', signedFileDigest: DIGEST }];
  assert.deepEqual(lookupRecord(records, null), { kind: 'manual' });
  assert.deepEqual(lookupRecord(records, 'not-a-reference'), { kind: 'malformed' });
  assert.deepEqual(lookupRecord(records, 'TEST-0000-0000-0000-0000-0000'), {
    kind: 'unknown',
    reference: 'TEST-0000-0000-0000-0000-0000',
  });
  assert.deepEqual(lookupRecord(records, REFERENCE.toLowerCase()), { kind: 'found', record: records[0] });
  assert.deepEqual(lookupQuery(records, `?ref=${REFERENCE}&ref=${REFERENCE}`), { kind: 'malformed' });
});

test('public asset links preserve root and development prefixes', () => {
  const pdf = assetHref(REFERENCE, 'document.pdf');
  const root = assetHref(REFERENCE, 'test-root.pem');
  assert.equal(new URL(pdf, 'https://docs.example/examples/population-extract/verify/').pathname,
    `/examples/population-extract/issued/${REFERENCE}/document.pdf`);
  assert.equal(new URL(root, 'https://docs.example/dev/examples/population-extract/verify/').pathname,
    `/dev/examples/population-extract/issued/${REFERENCE}/test-root.pem`);
});

test('history keeps canonical references and drops arbitrary malformed input', () => {
  const href = 'https://docs.example/dev/examples/population-extract/verify/?view=test';
  assert.equal(
    historyPath(href, REFERENCE.toLowerCase()),
    `/dev/examples/population-extract/verify/?view=test&ref=${REFERENCE}`,
  );
  assert.equal(
    historyPath(`${href}&ref=${REFERENCE}`, '<script>private input</script>'),
    '/dev/examples/population-extract/verify/?view=test',
  );
});

test('browser SHA-256 comparison uses the exact selected bytes', async () => {
  assert.equal(await sha256Hex(PDF), DIGEST.slice('sha256:'.length));
  assert.notEqual(await sha256Hex(Buffer.from('different')), DIGEST.slice('sha256:'.length));
});

test('shows the receipt date and time in UTC across a day boundary', () => {
  assert.match(formatIssuedAt('2026-11-25T01:15:22+07:00'), /^24 November 2026.*18:15:22$/);
});

test('Astro route is prefix-aware and contains no telemetry or external assets', async () => {
  const route = await readFile(
    new URL('../src/pages/examples/population-extract/verify.astro', import.meta.url),
    'utf8',
  );
  assert.match(route, /import\.meta\.env\.BASE_URL/);
  assert.match(route, /https:\/\/docs\.registrystack\.org\/dev\/examples\/population-extract\/verify\//);
  assert.match(route, /name="robots" content="noindex,follow"/);
  assert.match(route, /style-src 'self' 'unsafe-inline'/);
  assert.doesNotMatch(route, /frame-ancestors/);
  assert.match(route, /data-records=\{JSON\.stringify\(records\)\}/);
  assert.match(route, /src\/lib\/population-extract|lib\/population-extract\/verify-client\.mjs/);
  assert.equal([...route.matchAll(/<a\b/g)].length, [...route.matchAll(/data-astro-prefetch="false"/g)].length);
  assert.doesNotMatch(route, /umami|mautic|google-analytics|googletagmanager|plausible|segment\.com/i);
  assert.doesNotMatch(route, /<script[^>]+src=["']https?:/i);
  assert.doesNotMatch(route, /<link[^>]+href=["']https?:/i);
});
