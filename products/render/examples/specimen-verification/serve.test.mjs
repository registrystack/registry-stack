import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { normalizeReference } from './reference.mjs';
import { createVerificationServer, parseArguments } from './serve.mjs';

const REFERENCE = 'TEST-ABCD-0123-4567-89AB-CDEF';
const PDF = Buffer.from('%PDF-1.7\nsynthetic population extract\n%%EOF\n');
const DIGEST = `sha256:${createHash('sha256').update(PDF).digest('hex')}`;

async function makeRegistry(t) {
  const root = await mkdtemp(join(tmpdir(), 'render-specimen-verification-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function addSpecimen(root, reference = REFERENCE, overrides = {}) {
  const directory = join(root, reference);
  await mkdir(directory, { recursive: true });
  const receipt = {
    reference,
    issuedAt: '2026-11-24T09:30:00Z',
    signedFileDigest: DIGEST,
    ...overrides,
  };
  await writeFile(join(directory, 'receipt.json'), `${JSON.stringify(receipt)}\n`);
  await writeFile(join(directory, 'document.pdf'), PDF);
  await writeFile(join(directory, 'test-root.pem'), 'TEST ROOT, NOT FOR PRODUCTION\n');
}

async function withServer(t, registry) {
  const server = await createVerificationServer({ registry });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

async function startCli(t, registry) {
  const script = fileURLToPath(new URL('./serve.mjs', import.meta.url));
  const child = spawn(process.execPath, [script, '--registry', registry, '--port', '0'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  let timer;
  let ready;
  try {
    ready = await Promise.race([
      new Promise((resolve, reject) => {
        child.stdout.on('data', () => {
          const newline = stdout.indexOf('\n');
          if (newline !== -1) resolve(stdout.slice(0, newline));
        });
        child.once('error', reject);
        child.once('exit', (code) => reject(new Error(`server exited ${code}: ${stderr}`)));
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('server did not become ready')), 3000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await once(child, 'exit');
    }
  });
  return { child, ready, stdout: () => stdout, stderr: () => stderr };
}

test('shared references normalize case, spaces, and hyphens', () => {
  assert.equal(normalizeReference(' test abcd 0123-4567 89ab cdef '), REFERENCE);
  assert.equal(normalizeReference('TESTABCD0123456789ABCDEF'), REFERENCE);
  assert.equal(normalizeReference('TEST-ABCD-0123'), null);
  assert.equal(normalizeReference('../TEST-ABCD-0123-4567-89AB-CDEF'), null);
});

test('CLI arguments default to loopback and reject wildcard or public binding', () => {
  assert.deepEqual(parseArguments(['--registry', '/tmp/specimens']), {
    registry: '/tmp/specimens',
    host: '127.0.0.1',
    port: 4371,
  });
  assert.deepEqual(
    parseArguments(['--registry', '/tmp/specimens', '--host', '192.168.20.8', '--port', '0']),
    { registry: '/tmp/specimens', host: '192.168.20.8', port: 0 },
  );
  for (const host of ['0.0.0.0', '8.8.8.8', '::', 'example.org']) {
    assert.throws(
      () => parseArguments(['--registry', '/tmp/specimens', '--host', host]),
      /private LAN IPv4|loopback/,
    );
  }
});

test('CLI port zero prints the actual ready URL once and emits no request log', async (t) => {
  const root = await makeRegistry(t);
  const cli = await startCli(t, root);
  assert.match(cli.ready, /^http:\/\/127\.0\.0\.1:\d+\/verify$/);

  const response = await fetch(cli.ready);
  assert.equal(response.status, 200);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(cli.stdout().trim().split('\n'), [cli.ready]);
  assert.equal(cli.stderr(), '');
});

test('manual verification page is accessible and privacy-bounded', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify`);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /<h1>Verify a population register extract<\/h1>/);
  assert.match(body, /Synthetic Population Office/);
  assert.match(body, /code printed beside the QR/);
  assert.match(body, /<h2 id="check-title">Check a reference<\/h2>/);
  assert.match(body, /<form[^>]+method="get"[^>]+action="\/verify"/);
  assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.doesNotMatch(body, /google-analytics|googletagmanager|plausible\.io|matomo|segment\.com/i);
});

test('a found reference returns registry metadata and a locally verified digest', async (t) => {
  const root = await makeRegistry(t);
  await addSpecimen(root);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify?ref=test%20abcd-0123%204567-89ab-cdef`);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /<h2[^>]*>Reference found<\/h2>/);
  assert.ok(body.indexOf('Reference found') < body.indexOf('Check another reference'));
  assert.match(body, /<h2 id="check-title">Check another reference<\/h2>/);
  assert.doesNotMatch(body, /class="status"/);
  assert.match(body, /Population register extract/);
  assert.match(body, /Synthetic Population Office/);
  assert.match(body, /recorded this test extract on/);
  assert.match(body, /<time datetime="2026-11-24T09:30:00\.000Z">24 November 2026[^<]*09:30 UTC<\/time>/);
  assert.match(body, new RegExp(DIGEST));
  assert.match(body, /stored PDF matches the receipt digest/i);
  assert.match(body, /Compare the original PDF using this SHA-256/);
  assert.match(body, /data-expected-digest="[0-9a-f]{64}"/);
  assert.doesNotMatch(body, /download=/i);
});

test('an unknown well-formed reference is a distinct 404 result', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify?ref=TEST-0000-0000-0000-0000-0000`);
  const body = await response.text();

  assert.equal(response.status, 404);
  assert.match(body, /<h2[^>]*>Unknown reference<\/h2>/);
  assert.doesNotMatch(body, /Reference found/);
});

test('a malformed scanner value is a distinct 400 result', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify?ref=not-a-reference`);
  const body = await response.text();

  assert.equal(response.status, 400);
  assert.match(body, /<h2[^>]*>Could not read reference<\/h2>/);
  assert.match(body, /five groups of four hexadecimal characters/);
});

test('receipt files must contain exactly the three allowlisted fields', async (t) => {
  const root = await makeRegistry(t);
  await addSpecimen(root, REFERENCE, { personName: 'must not be read' });
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify?ref=${REFERENCE}`);
  const body = await response.text();

  assert.equal(response.status, 500);
  assert.match(body, /<h2[^>]*>Verification error<\/h2>/);
  assert.doesNotMatch(body, /must not be read/);
});

test('a PDF digest mismatch fails closed as a verification error', async (t) => {
  const root = await makeRegistry(t);
  await addSpecimen(root, REFERENCE, { signedFileDigest: `sha256:${'0'.repeat(64)}` });
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify?ref=${REFERENCE}`);
  const body = await response.text();

  assert.equal(response.status, 500);
  assert.match(body, /<h2[^>]*>Verification error<\/h2>/);
  assert.match(body, /stored specimen did not match its receipt/i);
  assert.doesNotMatch(body, new RegExp(`sha256:${'0'.repeat(64)}`));
});

test('registry artifacts are never served directly', async (t) => {
  const root = await makeRegistry(t);
  await addSpecimen(root);
  const origin = await withServer(t, root);
  for (const path of [
    `/${REFERENCE}/receipt.json`,
    `/${REFERENCE}/document.pdf`,
    `/${REFERENCE}/test-root.pem`,
    '/document.pdf',
  ]) {
    const response = await fetch(`${origin}${path}`);
    assert.equal(response.status, 404, path);
    assert.equal(await response.text(), 'Not found\n');
  }
});

test('the browser helper compares locally and contains no upload request', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/assets/verify.js`);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /crypto\.subtle\.digest\('SHA-256'/);
  assert.match(body, /window\.isSecureContext/);
  assert.match(body, /latestSelection/);
  assert.match(body, /mine !== latestSelection/);
  assert.doesNotMatch(body, /fetch\(|XMLHttpRequest|sendBeacon|WebSocket/);
});

test('an invalid HTTP request target gets a clean 400 response', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const { port } = new URL(origin);
  const socket = connect(Number(port), '127.0.0.1');
  socket.setEncoding('utf8');
  let response = '';
  socket.on('data', (chunk) => { response += chunk; });
  await once(socket, 'connect');
  socket.end('GET http://[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n');
  await once(socket, 'close');

  assert.match(response, /^HTTP\/1\.1 400 /);
  assert.match(response, /Bad request/);
});

test('non-GET methods are refused without reading the registry', async (t) => {
  const root = await makeRegistry(t);
  const origin = await withServer(t, root);
  const response = await fetch(`${origin}/verify`, { method: 'POST', body: REFERENCE });

  assert.equal(response.status, 405);
  assert.equal(response.headers.get('allow'), 'GET, HEAD');
});
