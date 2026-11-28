import test from 'node:test'
import assert from 'node:assert/strict'
import { RegistryError, Transport, allPages, type Operation } from '../core.ts'

const read: Operation = { method: 'GET', path: '/v1/items', responses: {
  200: [{ mediaType: 'application/json', mode: 'json', validate: value =>
    typeof value === 'object' && value !== null && Object.hasOwn(value, 'items') }],
} }
const write: Operation = { ...read, method: 'POST', keyed: true, mutating: true, requestMediaType: 'application/json' }
const ok = () => Response.json({ items: [] })
const baseUrl = 'https://example.org/prefix'

test('base URL, path values, tokens and controlled request headers', async () => {
  for (const bad of ['http://example.org', 'http://127.0.0.1.example.com', 'http://127.0.0.1.nip.io:8080',
    'https://user@example.org', 'https://example.org?', 'https://example.org#', 'file:///tmp', baseUrl + '//child']) {
    assert.throws(() => new Transport({ baseUrl: bad, token: () => '' }))
  }
  for (const good of ['http://localhost', 'http://127.0.0.1', 'http://127.1', 'http://[::1]']) {
    new Transport({ baseUrl: good, token: () => '' })
  }
  let token = 0
  const client = new Transport({ baseUrl, token: async () => String(++token), fetch: async (url, init) => {
    assert.equal(String(url), baseUrl + '/v1/items')
    assert.equal(init?.redirect, 'manual')
    assert.equal(init?.credentials, 'omit')
    const headers = new Headers(init?.headers)
    assert.equal(headers.get('authorization'), 'Bearer ' + token)
    assert.equal(headers.get('cookie'), null)
    assert.equal(headers.get('idempotency-key'), init?.method === 'POST' ? 'original' : null)
    return ok()
  } })
  const headers = { Authorization: 'ignored', Cookie: 'ignored', 'Idempotency-Key': 'ignored' }
  await client.call(read, { headers })
  await client.call(write, { headers, idempotencyKey: 'original' })
  assert.equal(token, 2)
  for (const id of ['..', NaN, Infinity, -1]) {
    await assert.rejects(client.call({ ...read, path: '/v1/{id}' }, { path: { id } }), TypeError)
  }
})

const invalid = /^TypeError: Invalid registry base URL$/u
const tokenOverHttp = /^TypeError: A client with a token needs an https base URL, or a loopback host\.$/u

test('plain http reaches loopback, and a private or single-label host only without a token and with allowInsecureHttp', () => {
  let asked = 0
  const token = () => { asked++; return 'fixture' }
  const privateHosts = ['http://10.0.0.5', 'http://10.1', 'http://172.16.0.1', 'http://172.31.255.254',
    'http://192.168.1.20:8080', 'http://[fc00::1]', 'http://[fd12:3456::1]', 'http://registry', 'http://breg:8080/prefix']
  const publicHosts = ['http://example.org', 'http://registry.example.org', 'http://8.8.8.8', 'http://172.32.0.1',
    'http://172.15.255.255', 'http://192.169.0.1', 'http://169.255.0.1', 'http://11.0.0.1', 'http://[2001:db8::1]',
    'http://[fec0::1]', 'http://[::ffff:10.0.0.1]', 'http://registry.', 'http://4294967295',
    'http://breg.internal', 'http://localhost.example']
  for (const baseUrl of privateHosts) {
    assert.throws(() => new Transport({ baseUrl, token }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl }), invalid, baseUrl)
    // The option admits plain http beyond loopback only for a client with no token to send.
    assert.throws(() => new Transport({ baseUrl, token, allowInsecureHttp: true }), tokenOverHttp, baseUrl)
    new Transport({ baseUrl, allowInsecureHttp: true })
  }
  for (const baseUrl of publicHosts) {
    assert.throws(() => new Transport({ baseUrl, token }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl, token, allowInsecureHttp: true }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl, allowInsecureHttp: true }), invalid, baseUrl)
  }
  assert.equal(asked, 0)
})

test('a token over plain http is refused at construction for a container name, and loopback still works', () => {
  let asked = 0
  const token = () => { asked++; return 'fixture' }
  assert.throws(() => new Transport({ baseUrl: 'http://breg:8080', token, allowInsecureHttp: true }), tokenOverHttp)
  new Transport({ baseUrl: 'http://breg:8080', allowInsecureHttp: true })
  for (const baseUrl of ['http://127.0.0.1:8080', 'http://localhost:8080', 'http://127.5.6.7', 'http://[::1]:8080']) {
    new Transport({ baseUrl, token })
  }
  new Transport({ baseUrl: 'https://breg.example.org', token })
  assert.equal(asked, 0)
})

test('link-local addresses are refused over plain http in every mode', () => {
  const token = () => 'fixture'
  // A metadata literal is refused first, so it gets the invalid-base message even with a token.
  for (const baseUrl of ['http://169.254.169.254', 'http://[::ffff:a9fe:a9fe]']) {
    for (const options of [{}, { allowInsecureHttp: true }, { token }, { token, allowInsecureHttp: true }]) {
      assert.throws(() => new Transport({ baseUrl, ...options }), invalid, baseUrl)
    }
  }
  for (const baseUrl of ['http://169.254.10.1', 'http://[fe80::1]', 'http://[febf:ffff::1]/registry']) {
    for (const options of [{}, { allowInsecureHttp: true }]) assert.throws(() => new Transport({ baseUrl, ...options }), invalid, baseUrl)
    for (const options of [{ token }, { token, allowInsecureHttp: true }]) assert.throws(() => new Transport({ baseUrl, ...options }), tokenOverHttp, baseUrl)
  }
})

test('a metadata or always-denied literal is refused under https too, with or without a token', () => {
  const token = () => 'fixture'
  const denied = ['https://169.254.169.254', 'https://169.254.169.254/latest', 'https://100.100.100.200', 'https://[fd00:ec2::254]',
    'https://0.0.0.0', 'https://0.1.2.3:8443', 'https://224.0.0.1', 'https://239.255.255.255', 'https://[ff02::1]',
    // The same addresses spelled as IPv6: mapped, NAT64 and IPv4-compatible forms, and the unspecified address.
    'https://[::ffff:a9fe:a9fe]', 'https://[::ffff:169.254.169.254]', 'https://[::ffff:6464:64c8]', 'https://[::ffff:100.100.100.200]',
    'https://[::ffff:0:0]', 'https://[::ffff:e000:1]', 'https://[::]', 'https://[64:ff9b::a9fe:a9fe]', 'https://[64:ff9b::6464:64c8]',
    'https://[::a9fe:a9fe]', 'https://[::6464:64c8]', 'https://[::e000:1]']
  for (const baseUrl of denied) {
    assert.throws(() => new Transport({ baseUrl }), invalid, baseUrl)
    assert.throws(() => new Transport({ baseUrl, token }), invalid, baseUrl)
  }
  // Only those literals: a neighbouring address and an ordinary https host are admitted.
  for (const baseUrl of ['https://169.254.169.253', 'https://100.100.100.201', 'https://[fd00:ec2::255]', 'https://240.0.0.1', 'https://registry.example.org',
    'https://[::ffff:a9fe:a9fd]', 'https://[64:ff9b::a9fe:a9fd]', 'https://[::1]', 'https://[2001:db8::1]']) {
    new Transport({ baseUrl, token })
  }
})

test('allowInsecureHttp admits IPv6 unique-local literals exactly like IPv4 private ranges, for a client with no token', () => {
  const token = () => 'fixture'
  const admitted = ['http://10.0.0.5', 'http://192.168.1.20', 'http://[fc00::1]', 'http://[fdff:ffff::1]:8080']
  for (const baseUrl of admitted) {
    assert.throws(() => new Transport({ baseUrl, token }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl, token, allowInsecureHttp: true }), tokenOverHttp, baseUrl)
    new Transport({ baseUrl, allowInsecureHttp: true })
  }
  // Just outside fc00::/7.
  for (const baseUrl of ['http://[fbff:ffff::1]', 'http://[fe00::1]', 'http://[fe7f::1]', 'http://[fec0::1]']) {
    assert.throws(() => new Transport({ baseUrl, allowInsecureHttp: true }), invalid, baseUrl)
  }
})

test('allowInsecureHttp admits only single-label names, never a name with a dot', () => {
  for (const baseUrl of ['http://breg', 'http://breg:8080', 'http://registry-db/prefix']) {
    new Transport({ baseUrl, allowInsecureHttp: true })
  }
  const token = () => 'fixture'
  for (const baseUrl of ['http://breg.internal', 'http://localhost.example', 'http://breg.svc.cluster.local:8080',
    'http://registry.local', 'http://localhost.', 'http://breg.']) {
    assert.throws(() => new Transport({ baseUrl, token }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl, token, allowInsecureHttp: true }), tokenOverHttp, baseUrl)
    assert.throws(() => new Transport({ baseUrl, allowInsecureHttp: true }), invalid, baseUrl)
  }
})

test('an IPv4-mapped loopback is not loopback: plain http to it is refused in every mode', () => {
  const token = () => 'fixture'
  for (const baseUrl of ['http://[::ffff:127.0.0.1]', 'http://[::ffff:7f00:1]']) {
    assert.throws(() => new Transport({ baseUrl }), invalid, baseUrl)
    assert.throws(() => new Transport({ baseUrl, allowInsecureHttp: true }), invalid, baseUrl)
    assert.throws(() => new Transport({ baseUrl, token }), tokenOverHttp, baseUrl)
  }
  new Transport({ baseUrl: 'https://[::ffff:7f00:1]', token })
})

test('the token rule reads the options once, so a getter cannot answer the check and the copy differently', async () => {
  let reads = 0
  let sent: string | null = 'unset'
  const fetch: typeof globalThis.fetch = async (_url, init) => { sent = new Headers(init?.headers).get('authorization'); return ok() }
  const options = { baseUrl: 'http://breg:8080', allowInsecureHttp: true, fetch, get token() { return ++reads === 1 ? undefined : () => 'secret' } }
  // Either the construction is refused, or the client has no token and sends none.
  try {
    await new Transport(options as never).call(read)
  } catch (error) {
    assert.match(String(error), /needs an https base URL/u)
  }
  assert.notEqual(sent, 'Bearer secret')
})

test('a base with dot segments, or one the URL parser refuses, is refused with the fixed message', () => {
  for (const baseUrl of ['https://example.org/registry/../other', 'https://example.org/registry/./v1',
    'https://example.org/registry/%2e%2e/other', 'https://example.org/registry/%2E/v1', 'https://example.org/a/.%2e',
    'https://example.org/a/%2e.', 'https://example.org/registry/..']) {
    assert.throws(() => new Transport({ baseUrl, token: () => '' }), /^TypeError: Invalid registry base URL$/u, baseUrl)
  }
  for (const baseUrl of ['https://example.org:99999', 'https://[::1', 'https://exa%zzmple.org']) {
    assert.throws(() => new Transport({ baseUrl, token: () => '' }), (error: unknown) => {
      assert.ok(error instanceof TypeError)
      assert.equal(error.message, 'Invalid registry base URL')
      assert.equal(Object.hasOwn(error, 'input'), false)
      assert.equal(error.cause, undefined)
      return true
    }, baseUrl)
  }
  new Transport({ baseUrl: 'https://example.org/registry.v1/..data', token: () => '' })
})

test('dispatch determines uncertainty for mutations', async () => {
  const cases = [
    [() => new Response(null, { status: 500 }), 'status'],
    [() => new Response(null, { status: 503 }), 'status'],
    [() => Response.error(), 'status'],
    [() => Response.json({}), 'schema'],
    [() => new Response('{', { headers: { 'Content-Type': 'application/json' } }), 'schema'],
    [() => new Response(Uint8Array.of(255), { headers: { 'Content-Type': 'application/json' } }), 'schema'],
    [() => Response.json({ items: [9007199254740992] }), 'unsafe-integer'],
    [() => new Response('bad media'), 'media'],
    [() => new Response('x'.repeat(1024)), 'too-large'],
    [() => { throw new Error('transport fixture') }, 'network'],
  ] as const
  for (const [fetch, reason] of cases) {
    const client = new Transport({ baseUrl, token: () => 'fixture', fetch: async () => fetch(), maxResponseBytes: 128 })
    await assert.rejects(client.call(write), { reason, outcomeUnknown: true })
  }
  let sent = false
  const client = new Transport({ baseUrl, token: () => { throw new Error('token fixture') }, fetch: async () => {
    sent = true
    return ok()
  } })
  await assert.rejects(client.call(write), { reason: 'token', outcomeUnknown: false })
  assert.equal(sent, false)
})

test('correlates declared problems and keeps reflected credentials out of serialized errors', async () => {
  const token = 'synthetic-authorization-fixture'
  const operation: Operation = { ...write, messaging: true, problemValidators: { 429: () => true } }
  const body = { title: 'Busy', detail: 'Try later', status: 429, code: 'rate-limit.exceeded',
    type: 'https://id.registrystack.org/problems/registry-messaging/rate-limit/exceeded', traceId: '1'.repeat(32) }
  function call(problem: object, trace = body.traceId, retryAfter = '13', status = 429) {
    return new Transport({ baseUrl, token: () => token, fetch: async () => new Response(JSON.stringify(problem), {
      status, headers: { 'Content-Type': 'application/problem+json',
        traceparent: '00-' + trace + '-' + '2'.repeat(16) + '-01', 'Retry-After': retryAfter },
    }) }).call(operation)
  }
  await assert.rejects(call(body), { kind: 'refused', code: body.code, retryAfterSeconds: 13, outcomeUnknown: false })
  await assert.rejects(call(body, body.traceId, '86401'), { kind: 'refused', retryAfterSeconds: undefined })
  await assert.rejects(call({ ...body, status: 400 }), { kind: 'unexpected', code: undefined, outcomeUnknown: false })
  await assert.rejects(call({ ...body, type: 'https://example.org/other' }), { kind: 'unexpected' })
  await assert.rejects(call(body, '3'.repeat(32)), { kind: 'unexpected', retryAfterSeconds: undefined })
  await assert.rejects(call({ ...body, status: 400 }, body.traceId, '13', 400), { kind: 'unexpected', code: undefined })
  await assert.rejects(call({ ...body, detail: 'Bearer ' + token, [token]: token }), (error: unknown) => {
    assert.ok(error instanceof RegistryError)
    assert.equal(JSON.stringify(error).includes(token), false)
    assert.equal(Object.hasOwn(error, 'raw'), false)
    assert.equal(error.problem, undefined)
    assert.ok(new TextDecoder().decode(error.raw).includes(token))
    return true
  })
})

test('deadline and caller cancellation distinguish preparation from dispatch', async () => {
  const client = new Transport({ baseUrl, timeoutMs: 10,
    token: () => new Promise(() => {}), fetch: async () => { throw new Error('must not fetch') } })
  await assert.rejects(client.call(write), { reason: 'timeout', outcomeUnknown: false })
  const caller = new AbortController()
  const streaming = new Transport({ baseUrl, token: () => 'token', fetch: async () => {
    setTimeout(() => caller.abort(), 5)
    return new Response(new ReadableStream({}), { headers: { 'Content-Type': 'application/json' } })
  } })
  await assert.rejects(streaming.call(write, { signal: caller.signal }), { reason: 'aborted', status: 200, outcomeUnknown: true })
})

test('pagination bounds distinct cursors and rejects a repeated cursor', async () => {
  assert.deepEqual(await allPages(async () => ({ items: [1], nextCursor: '' })), [1])
  let calls = 0
  await assert.rejects(allPages(async () => ({ items: [++calls], nextCursor: String(calls) }), 2), RangeError)
  assert.equal(calls, 2)
  await assert.rejects(allPages(async () => ({ items: [], nextCursor: 'repeat' })), /repeated/iu)
})
