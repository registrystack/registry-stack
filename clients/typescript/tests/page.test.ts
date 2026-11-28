import test from 'node:test'
import { make } from './helpers.ts'
import assert from 'node:assert/strict'
import { RegistryError, Transport, describeError, registryClientHeader, type Operation } from '../core.ts'
import * as browser from '../browser.ts'
import { Client as Minimal } from '../generated/breg-minimal.ts'
import { Client as Documents } from '../generated/documents.ts'
import { Client as Casework } from '../generated/casework.ts'
import { Client as Coordinator } from '../generated/coordinator.ts'

const baseUrl = 'https://registry.example.org'
const read: Operation = { method: 'GET', path: '/v1/items', responses: {
  200: [{ mediaType: 'application/json', mode: 'json' }],
} }
const write: Operation = { ...read, method: 'POST', keyed: true, mutating: true, requestMediaType: 'application/json',
  problemValidators: { default: () => true } }
const meta = { datasetIdentifier: 'directory', recordTypeIdentifier: 'contact', registryIdentifier: 'local-directory' }

interface Seen { authorization: string | null; credentials: unknown; page: string | null }
function recording(answer: () => Response = () => Response.json({})) {
  const seen: Seen[] = []
  const fetch: typeof globalThis.fetch = async (_url, init) => {
    const headers = new Headers(init?.headers)
    seen.push({ authorization: headers.get('authorization'), credentials: init?.credentials,
      page: headers.get('Registry-Client') })
    return answer()
  }
  return { seen, fetch }
}

test('the Registry-Client header is one exported constant, also exported for browsers', () => {
  assert.deepEqual(registryClientHeader, { name: 'Registry-Client', value: 'page' })
  assert.equal(browser.registryClientHeader, registryClientHeader)
})

test('without a token the client sends no Authorization and same-origin cookies', async () => {
  const { seen, fetch } = recording()
  const transport = new Transport({ baseUrl, fetch })
  await transport.call(read)
  await transport.call(write, { body: {}, headers: { 'registry-client': 'other', Authorization: 'Bearer x' } })
  assert.deepEqual(seen, [
    { authorization: null, credentials: 'same-origin', page: 'page' },
    { authorization: null, credentials: 'same-origin', page: 'page' },
  ])
})

test('with a token the client sends the bearer, omits cookies and does not send the page header', async () => {
  const { seen, fetch } = recording()
  await new Transport({ baseUrl, token: () => 'fixture', fetch }).call(read)
  await new Transport({ baseUrl, token: () => undefined, fetch }).call(read)
  assert.deepEqual(seen, [
    { authorization: 'Bearer fixture', credentials: 'omit', page: null },
    { authorization: null, credentials: 'omit', page: null },
  ])
})

test('a generated client needs no token in page mode', async () => {
  const { seen, fetch } = recording(() => Response.json({ items: [], meta, pageInfo: { nextCursor: null } }))
  const client: Minimal = make(Minimal, { baseUrl, fetch })
  await client.records_contact_listPage()
  assert.deepEqual(seen, [{ authorization: null, credentials: 'same-origin', page: 'page' }])
})

function problemAnswer(status: number, code: string, problemStatus = status) {
  return new Response(JSON.stringify({ title: 'Problem', status: problemStatus, code }),
    { status, headers: { 'content-type': 'application/problem+json' } })
}

const sessionType = 'https://id.registrystack.org/problems/registry-platform/session/'
interface SessionShape { header?: string | null; type?: string | null; problemStatus?: number; contentType?: string }
/** The session service's own answer: the marker header, the session problem type, the code and status. */
function sessionAnswer(kind: 'expired' | 'unavailable', shape: SessionShape = {}) {
  const status = kind === 'expired' ? 401 : 503
  const headers: Record<string, string> = { 'content-type': shape.contentType ?? 'application/problem+json' }
  if (shape.header !== null) headers['registry-session-answer'] = shape.header ?? '1'
  const type = shape.type === undefined ? sessionType + kind : shape.type
  return new Response(JSON.stringify({ title: 'Session', status: shape.problemStatus ?? status,
    code: 'session.' + kind, ...(type === null ? {} : { type }) }), { status, headers })
}

function withLocation<T>(origin: string, run: () => Promise<T>): Promise<T> {
  const before = Object.getOwnPropertyDescriptor(globalThis, 'location')
  Object.defineProperty(globalThis, 'location', { value: { origin }, configurable: true })
  return run().finally(() => {
    if (before) Object.defineProperty(globalThis, 'location', before)
    else delete (globalThis as { location?: unknown }).location
  })
}

test('the session 401 expires sign-in without a product problem validator', async () => {
  const { fetch } = recording(() => sessionAnswer('expired'))
  await assert.rejects(new Transport({ baseUrl, fetch }).call(read), (error: unknown) => {
    assert.ok(error instanceof RegistryError)
    assert.deepEqual([error.kind, error.reason, error.status, error.outcomeUnknown], ['refused', 'sign-in-expired', 401, false])
    assert.equal(error.product, undefined)
    assert.equal(describeError(error), 'Your sign-in has ended, so sign in again.')
    return true
  })
})

test('a product answer carrying a session code is a product answer, in page and server mode', async () => {
  const lookalikes: Array<(kind: 'expired' | 'unavailable') => SessionShape> = [
    () => ({ header: null }), () => ({ header: '0' }), () => ({ header: 'yes' }),
    () => ({ type: null }),
    () => ({ type: 'https://example.invalid/problems/session/expired' }),
    kind => ({ type: sessionType + (kind === 'expired' ? 'unavailable' : 'expired') }),
    kind => ({ type: sessionType + kind + '/' }),
    kind => ({ problemStatus: kind === 'expired' ? 403 : 500 }),
  ]
  for (const shape of lookalikes) {
    await assert.rejects(new Transport({ baseUrl, fetch: recording(() => sessionAnswer('expired', shape('expired'))).fetch }).call(write),
      { kind: 'refused', reason: 'configuration', status: 401, outcomeUnknown: false })
    await assert.rejects(new Transport({ baseUrl, fetch: recording(() => sessionAnswer('unavailable', shape('unavailable'))).fetch }).call(write),
      { kind: 'unreachable', reason: 'status', status: 503, outcomeUnknown: true })
  }
})

test('the session type and header never classify an answer in server mode', async () => {
  const token = () => 'fixture'
  await assert.rejects(new Transport({ baseUrl, token, fetch: recording(() => sessionAnswer('expired')).fetch }).call(write),
    (error: unknown) => {
      assert.ok(error instanceof RegistryError)
      assert.deepEqual([error.reason, error.status, error.outcomeUnknown], ['status', 401, false])
      return true
    })
  await assert.rejects(new Transport({ baseUrl, token, fetch: recording(() => sessionAnswer('unavailable')).fetch }).call(write),
    { kind: 'unreachable', reason: 'status', status: 503, outcomeUnknown: true })
})

test('a session answer read as plain JSON is a configuration failure, not an expiry', async () => {
  const { fetch } = recording(() => sessionAnswer('expired', { contentType: 'application/json' }))
  await assert.rejects(new Transport({ baseUrl, fetch }).call(write),
    { kind: 'refused', reason: 'configuration', status: 401 })
})

test('a page 401 with an unsafe integer is still a configuration failure, other statuses are not', async () => {
  const body = '{"status":401,"code":"x","big":9007199254740993}'
  const answer = (status: number) => () => new Response(body.replace('401', String(status)),
    { status, headers: { 'content-type': 'application/problem+json' } })
  await assert.rejects(new Transport({ baseUrl, fetch: recording(answer(401)).fetch }).call(write),
    { reason: 'configuration', status: 401 })
  await assert.rejects(new Transport({ baseUrl, fetch: recording(answer(409)).fetch }).call(write),
    { reason: 'unsafe-integer', status: 409 })
})

test('a product 401 keeps its validated problem and identifies the module', async () => {
  const { fetch } = recording(() => new Response(JSON.stringify({
    status: 401, code: 'authentication.refused', title: 'Authentication refused',
    detail: 'The bearer credential is missing, invalid, or expired. Sign in again.',
    traceId: '0123456789abcdef0123456789abcdef',
    type: 'https://id.registrystack.org/problems/registry-casework/authentication/refused',
  }), { status: 401, headers: { 'content-type': 'application/problem+json' } }))
  await assert.rejects(make(Casework, { baseUrl, fetch }).call('describeCasework', {
    headers: { 'registry-casework-profile': 'fixture' },
  }), (error: unknown) => {
    assert.ok(error instanceof RegistryError)
    assert.deepEqual([error.kind, error.reason, error.outcomeUnknown, error.problem?.code],
      ['refused', 'configuration', false, 'authentication.refused'])
    assert.match(error.message, /casework service refused this page's session/u)
    assert.equal(error.product, 'casework')
    assert.equal(describeError(error), 'You are signed in, but this page is not available to your account.')
    assert.equal(describeError(error, {
      clientSentences: { 'client.page-access-refused': 'Access to this page is restricted.' },
    }), 'Access to this page is restricted.')
    assert.ok(!/casework|configuration/iu.test(describeError(error)))
    return true
  })
  await assert.rejects(new Transport({ baseUrl, fetch, token: () => 'fixture' }).call(write),
    { kind: 'refused', reason: 'status', outcomeUnknown: false, code: 'authentication.refused' })
})

test('bare, HTML, malformed and mismatched 401 answers are configuration failures', async () => {
  for (const answer of [
    () => new Response(null, { status: 401 }),
    () => new Response('<html>', { status: 401, headers: { 'content-type': 'text/html' } }),
    () => new Response('{', { status: 401, headers: { 'content-type': 'application/problem+json' } }),
    () => problemAnswer(401, 'session.expired', 403),
  ]) {
    await assert.rejects(new Transport({ baseUrl, fetch: recording(answer).fetch }).call(write),
      { kind: 'refused', reason: 'configuration', status: 401, outcomeUnknown: false })
  }
})

test('a 401 too large to inspect cannot expire sign-in', async () => {
  const { fetch } = recording(() => sessionAnswer('expired'))
  await assert.rejects(new Transport({ baseUrl, fetch, maxResponseBytes: 32 }).call(write),
    (error: unknown) => {
      assert.ok(error instanceof RegistryError)
      assert.deepEqual([error.reason, error.status, error.outcomeUnknown, error.product], ['too-large', 401, false, 'registry'])
      assert.equal(describeError(error), 'The registry sent an answer that could not be read.')
      return true
    })
})

const octets: Operation = { method: 'PUT', path: '/v1/blob', keyed: true, mutating: true,
  requestMediaType: 'application/octet-stream', problemValidators: { default: () => true },
  responses: { 200: [{ mediaType: 'application/octet-stream', mode: 'binary' }] } }
const downloadOperation: Operation = { method: 'GET', path: '/v1/blob',
  responses: { 200: [{ mediaType: 'application/octet-stream', mode: 'binary' }] } }

test('a page 401 or 503 on a byte transfer is capped by the client default without a per-call cap', async () => {
  for (const [kind, operation, options] of [
    ['expired', octets, { body: Uint8Array.of(1) }],
    ['unavailable', octets, { body: Uint8Array.of(1) }],
    ['expired', downloadOperation, {}],
  ] as const) {
    const { fetch } = recording(() => sessionAnswer(kind))
    await assert.rejects(new Transport({ baseUrl, fetch, maxResponseBytes: 32 }).call(operation, options),
      { reason: 'too-large', status: kind === 'expired' ? 401 : 503 })
    // The same answer under a roomy default is read and classified.
    const roomy = await new Transport({ baseUrl, fetch }).call(operation, options).catch((caught: unknown) => caught)
    assert.ok(roomy instanceof RegistryError)
    assert.equal(roomy.reason, kind === 'expired' ? 'sign-in-expired' : 'status')
  }
})

test('a small per-call cap does not hide a real session expiry', async () => {
  const { fetch } = recording(() => sessionAnswer('expired'))
  await assert.rejects(new Transport({ baseUrl, fetch }).call(write, { body: {}, maxResponseBytes: 16 }),
    { reason: 'sign-in-expired' })
  await assert.rejects(new Transport({ baseUrl, fetch }).call(octets, { body: Uint8Array.of(1), maxResponseBytes: 16 }),
    { reason: 'sign-in-expired' })
  // A call cap above a small client default is honoured for the session answer too.
  await assert.rejects(new Transport({ baseUrl, fetch, maxResponseBytes: 32 }).call(octets,
    { body: Uint8Array.of(1), maxResponseBytes: 4096 }), { reason: 'sign-in-expired' })
})

test('page mode refuses an absolute base on another origin before anything is sent', async () => {
  let requests = 0
  const fetch: typeof globalThis.fetch = async () => { requests++; return Response.json({}) }
  await withLocation('https://app.example.org', async () => {
    await assert.rejects(new Transport({ baseUrl, fetch }).call(read), (error: unknown) => {
      assert.ok(error instanceof TypeError)
      assert.ok(!(error instanceof RegistryError))
      return true
    })
    assert.equal(requests, 0)
    await new Transport({ baseUrl: 'https://app.example.org', fetch }).call(read)
    await new Transport({ baseUrl: '/registry', fetch }).call(read)
    assert.equal(requests, 2)
    // A server entry names its own base and is unaffected.
    await new Transport({ baseUrl, token: () => 'fixture', fetch }).call(read)
    assert.equal(requests, 3)
  })
  // With no page origin there is nothing to compare, so a server runtime is unaffected.
  await new Transport({ baseUrl, fetch }).call(read)
  assert.equal(requests, 4)
})

test('page mode compares the whole origin: the same host on another port or scheme is refused', async () => {
  let requests = 0
  const fetch: typeof globalThis.fetch = async () => { requests++; return Response.json({}) }
  await withLocation('http://localhost:8080', async () => {
    for (const other of ['http://localhost:5173', 'https://localhost:8080']) {
      await assert.rejects(async () => new Transport({ baseUrl: other, fetch }).call(read),
        (error: unknown) => error instanceof TypeError && !(error instanceof RegistryError), other)
    }
    assert.equal(requests, 0)
    await new Transport({ baseUrl: 'http://localhost:8080', fetch }).call(read)
    assert.equal(requests, 1)
  })
})

test('only the page session 503 has a known outcome', async () => {
  for (const [code, status, token, unknown] of [
    ['session.unavailable', 503, undefined, false],
    ['session.unavailable', 500, undefined, true],
    ['product.unavailable', 503, undefined, true],
    ['session.unavailable', 503, () => 'fixture', true],
  ] as const) {
    const { fetch } = recording(() => code === 'session.unavailable' && status === 503
      ? sessionAnswer('unavailable') : problemAnswer(503, code, status))
    await assert.rejects(new Transport({ baseUrl, fetch, token }).call(write),
      { kind: 'unreachable', reason: 'status', status: 503, outcomeUnknown: unknown })
  }
})

test('a bare page 403 still means not allowed', async () => {
  const { fetch } = recording(() => new Response(null, { status: 403 }))
  await assert.rejects(new Transport({ baseUrl, fetch }).call(write), (error: unknown) => {
    assert.ok(error instanceof RegistryError)
    assert.equal(describeError(error), 'You are not allowed to do this.')
    return true
  })
})

test('with a token a 401 keeps its status reason', async () => {
  const { fetch } = recording(() => new Response('Unauthorized', { status: 401 }))
  await assert.rejects(new Transport({ baseUrl, token: () => 'fixture', fetch }).call(write, { body: {} }),
    { kind: 'unexpected', reason: 'status', status: 401, outcomeUnknown: false })
})

test('a 412 is stale in both modes and keeps its kind', async () => {
  const problem = () => new Response(JSON.stringify({ status: 412, title: 'Precondition Failed', code: 'precondition.failed' }),
    { status: 412, headers: { 'Content-Type': 'application/problem+json' } })
  for (const token of [undefined, () => 'fixture']) {
    const validated = recording(problem)
    const error = await new Transport({ baseUrl, token, fetch: validated.fetch }).call(write, { body: {} })
      .catch((caught: unknown) => caught)
    assert.ok(error instanceof RegistryError)
    assert.deepEqual([error.kind, error.reason, error.outcomeUnknown, error.code], ['refused', 'stale', false, 'precondition.failed'])
    assert.equal(describeError(error), 'The item changed since it was loaded, so reload it and try again.')
    const bare = recording(() => new Response(null, { status: 412 }))
    await assert.rejects(new Transport({ baseUrl, token, fetch: bare.fetch }).call(read),
      { kind: 'unexpected', reason: 'stale', status: 412 })
  }
})

test('a signed operation omits cookies and keeps a 401 as a signature refusal in page mode', async () => {
  const { seen, fetch } = recording(() => new Response(null, { status: 401 }))
  const coordinator = make(Coordinator, { baseUrl, fetch })
  const headers = { 'webhook-id': '00000000-0000-4000-8000-000000000001', 'webhook-timestamp': '1', 'webhook-signature': 'v1,x' }
  await assert.rejects(coordinator.call('admitEvent', { path: { workflow: 'w', trigger: 't' }, headers, body: Uint8Array.of(123, 125) }),
    { reason: 'status', status: 401 })
  assert.deepEqual(seen, [{ authorization: null, credentials: 'omit', page: 'page' }])
})

test('every call takes a signal, including page helpers, Actions and byte transfers', async () => {
  const aborted = AbortSignal.abort()
  let requests = 0
  const fetch: typeof globalThis.fetch = async () => { requests++; return Response.json({}) }
  const minimal = make(Minimal, { baseUrl, fetch })
  const documents = make(Documents, { baseUrl, fetch })
  const preconditions = { contactId: { ifMatch: '"1"' } }
  const input = { contactId: '00000000-0000-4000-8000-000000000001', email: 'alice@example.org' }
  const calls: Array<() => Promise<unknown>> = [
    () => minimal.records_contact_listPage({ signal: aborted }),
    () => minimal.call('records.contact.list', { signal: aborted }),
    () => minimal.invoke('update-contact-email', input, { preconditions, signal: aborted }),
    () => minimal.targetConditions('update-contact-email', { contactId: input.contactId }, { signal: aborted }),
    () => documents.call('downloadDocumentVersion', { path: { documentId: 'd', versionId: 'v' }, signal: aborted }),
    () => documents.call('uploadDocumentContent', { path: { uploadId: 'u' }, body: Uint8Array.of(1),
      contentType: 'application/pdf', signal: aborted }),
  ]
  for (const call of calls) await assert.rejects(call(), { name: 'RegistryError', reason: 'aborted' })
  assert.equal(requests, 0)
})
