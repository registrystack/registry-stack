// SPDX-License-Identifier: Apache-2.0
// Process and transport fixtures for synthetic native payment acceptance.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { closeSync, openSync } from 'node:fs';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { basename, join } from 'node:path';

export const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
export const hash = (value) => createHash('sha256').update(value).digest('hex');

export async function privateFile(path, value) {
  await writeFile(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2), { mode: 0o600 });
  await chmod(path, 0o600);
}

export async function secret(path) {
  const value = (await readFile(path, 'utf8')).trim();
  assert(value && value.length <= 65536, 'private fixture value must be bounded');
  return value;
}

// Keep dirty-tree provenance private. The known Git base plus this binary patch
// reconstructs tracked content; per-file hashes also cover the executed harness.
export async function sourceSnapshot(repository, directory) {
  const git = (...args) => command('git', ['--no-optional-locks', '-C', repository, ...args], { json: false });
  assert.equal(git('ls-files', '--others', '--exclude-standard').trim(), '', 'stage new source files before native acceptance');
  const patch = git('diff', '--binary', 'HEAD');
  await privateFile(join(directory, 'source.patch'), patch);
  const files = [];
  for (const path of git('ls-files', '-z').split('\0').filter(Boolean)) {
    try { files.push({ path, sha256: hash(await readFile(join(repository, path))) }); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      files.push({ path, deleted: true });
    }
  }
  const snapshot = { scope: 'source content at run time; binary build provenance is separately attested',
    head: git('rev-parse', 'HEAD').trim(), status: git('status', '--porcelain'), patchSha256: hash(patch), files };
  await privateFile(join(directory, 'source-snapshot.json'), snapshot);
  return snapshot;
}

export function command(binary, args, { env = process.env, input, json = true } = {}) {
  const result = spawnSync(binary, args, { env, input, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 120000 });
  // Never repeat stderr or argv: tools may include configured credentials in errors.
  if (result.status !== 0) {
    const codes = new Set();
    function visit(value) {
      if (!value || typeof value !== 'object') return;
      if (typeof value.code === 'string' && /^[a-z][a-z0-9_.-]{1,100}$/.test(value.code)) codes.add(value.code);
      for (const child of Object.values(value)) visit(child);
    }
    try { visit(JSON.parse(result.stdout)); } catch { codes.add('fixture.non-json-command-failure'); }
    throw new Error(`${basename(binary)} failed (${result.status ?? result.error?.code ?? result.signal}): ${[...codes].join(', ')}`);
  }
  return json ? JSON.parse(result.stdout) : result.stdout;
}

export function start(binary, args, logPath, env = process.env) {
  const descriptor = openSync(logPath, 'w', 0o600);
  const child = spawn(binary, args, { env, stdio: ['ignore', descriptor, descriptor] });
  closeSync(descriptor);
  const exited = new Promise((resolve, reject) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', () => reject(new Error('native fixture process could not start')));
  });
  return {
    child, exited,
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      let timer;
      const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), 15000); });
      const result = await Promise.race([exited, timeout]);
      clearTimeout(timer);
      assert(result, 'native fixture process did not stop within its shutdown budget');
    },
  };
}

function numericLoopbackHttp(value, message) {
  let url;
  try { url = new URL(value); } catch { assert.fail(message); }
  assert(url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)
    && !url.username && !url.password, message);
  return url;
}

export function loopback(origin) {
  const message = 'native payment acceptance requires a numeric loopback HTTP origin';
  const url = numericLoopbackHttp(origin, message);
  assert(!url.search && !url.hash && url.pathname === '/', message);
  return url.origin;
}

export async function exchange(method, url, { token, body, key, expected = [200] } = {}) {
  const requestUrl = numericLoopbackHttp(url,
    'native payment acceptance requires a numeric loopback HTTP request without user information').href;
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (key) headers['Idempotency-Key'] = key;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(requestUrl, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'manual', signal: AbortSignal.timeout(20000) });
  const bytes = await response.arrayBuffer();
  assert(bytes.byteLength <= 1048576, 'native response exceeded its fixture bound');
  const value = bytes.byteLength ? JSON.parse(Buffer.from(bytes).toString()) : null;
  const code = typeof value?.code === 'string' && /^[a-z][a-z0-9_.-]{1,100}$/.test(value.code) ? ` (${value.code})` : '';
  assert(expected.includes(response.status), `native ${method} ${new URL(requestUrl).pathname} returned HTTP ${response.status}${code}`);
  return { status: response.status, body: value };
}

export async function ready(url, processHandle, expected = [200, 401]) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    assert(processHandle.child.exitCode === null && processHandle.child.signalCode === null,
      'native service exited before readiness; inspect its private log');
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(300), redirect: 'manual' });
      if (expected.includes(response.status)) return;
    } catch (error) {
      if (!['TypeError', 'TimeoutError'].includes(error.name)) throw error;
    }
    await sleep(100);
  }
  throw new Error('native service did not become ready within its startup budget');
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

export async function unusedPort() {
  const server = http.createServer();
  const url = await listen(server);
  await new Promise((resolve) => server.close(resolve));
  return Number(new URL(url).port);
}

export async function authorization(secretsRoot) {
  const issuer = 'https://payment-acceptance.example.test';
  const signer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const client = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwks = { keys: [{ ...signer.publicKey.export({ format: 'jwk' }), kid: 'native-issuer', alg: 'ES256', use: 'sig' }] };
  const clientJwk = { ...client.privateKey.export({ format: 'jwk' }), kid: 'native-coordinator', alg: 'ES256', use: 'sig' };
  await privateFile(`${secretsRoot}/jwks`, jwks);
  await privateFile(`${secretsRoot}/coordinator-payments-jwk`, clientJwk);
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  function token(subject, audience, scope, clientId = 'coordinator-payments') {
    const now = Math.floor(Date.now() / 1000);
    const payload = `${b64({ alg: 'ES256', kid: 'native-issuer', typ: 'at+jwt' })}.${b64({
      iss: issuer, sub: subject, client_id: clientId, aud: audience, scope, iat: now, nbf: now, exp: now + 3600, jti: randomUUID(),
    })}`;
    return `${payload}.${sign('sha256', Buffer.from(payload), { key: signer.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  }
  const used = new Set();
  let grants = 0;
  const server = http.createServer(async (request, response) => {
    try {
      assert(request.method === 'POST' && request.url === '/token');
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; assert(size <= 16384); chunks.push(chunk); }
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      assert.equal(form.get('grant_type'), 'client_credentials');
      assert.equal(form.get('client_assertion_type'), 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      assert.equal(form.get('resource'), 'urn:registry:payment-adapter');
      assert.equal(form.get('scope'), 'payments:collect');
      const parts = form.get('client_assertion').split('.'); assert.equal(parts.length, 3);
      const header = JSON.parse(Buffer.from(parts[0], 'base64url')); assert.equal(header.alg, 'ES256');
      assert(verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), { key: client.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url')));
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
      assert.equal(claims.iss, 'coordinator-payments'); assert.equal(claims.sub, 'coordinator-payments');
      assert.equal(claims.aud, issuer);
      const now = Math.floor(Date.now() / 1000);
      assert(claims.exp > now && claims.exp <= now + 600 && typeof claims.jti === 'string' && !used.has(claims.jti));
      used.add(claims.jti); grants += 1;
      response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ token_type: 'Bearer', expires_in: 3600,
        access_token: token('payment-coordinator', 'urn:registry:payment-adapter', 'payments:collect') }));
    } catch {
      response.writeHead(401, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ error: 'invalid_client' }));
    }
  });
  const origin = await listen(server);
  return { issuer, origin, token, jwks, get grants() { return grants; },
    async close() { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } };
}

export async function relay(origin) {
  origin = loopback(origin);
  const records = []; const drops = new Set();
  let failRead = false; let corruptAmount = false;
  const server = http.createServer(async (request, response) => {
    try {
      assert(request.url.startsWith('/') && !request.url.startsWith('//'));
      const chunks = []; let length = 0;
      for await (const chunk of request) { length += chunk.length; assert(length <= 1048576); chunks.push(chunk); }
      const body = Buffer.concat(chunks);
      if (failRead && request.method === 'GET' && request.url.startsWith('/v1/records/')) {
        failRead = false; response.writeHead(503); response.end(); return;
      }
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) => !['host', 'connection', 'content-length'].includes(name)));
      const upstream = await fetch(origin + request.url, { method: request.method, headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : body, redirect: 'manual', signal: AbortSignal.timeout(15000) });
      let raw = Buffer.from(await upstream.arrayBuffer()); assert(raw.length <= 1048576);
      if (request.method === 'POST') records.push({ path: request.url.split('?')[0], key: request.headers['idempotency-key'] ?? null,
        bodyHash: hash(body), tenant: request.headers['x-platform-tenantid'] ?? null,
        biller: request.headers['x-billerid'] ?? null, status: upstream.status });
      const path = request.url.split('?')[0];
      if (request.method === 'POST' && upstream.ok && drops.delete(path)) {
        if (path.startsWith('/v1/actions/')) failRead = true;
        request.socket.destroy(); return;
      }
      if (corruptAmount && request.method === 'GET' && path.startsWith('/transferRequests/') && upstream.ok) {
        const value = JSON.parse(raw); value.amount = 25.51; raw = Buffer.from(JSON.stringify(value));
      }
      const returned = Object.fromEntries([...upstream.headers].filter(([name]) => !['connection', 'transfer-encoding', 'content-length'].includes(name)));
      response.writeHead(upstream.status, { ...returned, 'Content-Length': raw.length }); response.end(raw);
    } catch {
      if (!response.headersSent) response.writeHead(502);
      response.end();
    }
  });
  const url = await listen(server);
  return { url, records, drop(path) { drops.add(path); }, corrupt(value) { corruptAmount = value; },
    async close() { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } };
}
