import test from 'node:test'
import { make } from './helpers.ts'
import assert from 'node:assert/strict'
import {
  RegistryError, Transport, clientFallbackSentence, clientSentences, describeError, pages, type Operation,
} from '../core.ts'
import { actionInputs, Client as FacilityClient } from '../generated/breg-facility.ts'
import { readFileSync } from 'node:fs'

const read: Operation = { method: 'GET', path: '/v1/items', responses: {
  200: [{ mediaType: 'application/json', mode: 'json' }],
} }

function withLocation<T>(origin: string | undefined, run: () => Promise<T> | T): Promise<T> {
  const before = Object.getOwnPropertyDescriptor(globalThis, 'location')
  if (origin !== undefined) Object.defineProperty(globalThis, 'location', { value: { origin }, configurable: true })
  return Promise.resolve().then(run).finally(() => {
    if (before) Object.defineProperty(globalThis, 'location', before)
    else delete (globalThis as { location?: unknown }).location
  })
}

test('a path base resolves against the page origin and keeps the transport rule', async () => {
  await withLocation('https://app.example.org', async () => {
    let seen = ''
    const transport = new Transport({ baseUrl: '/registry', token: () => '', fetch: async url => {
      seen = String(url)
      return Response.json({})
    } })
    await transport.call(read)
    assert.equal(seen, 'https://app.example.org/registry/v1/items')
  })
  await withLocation('http://localhost:5173', async () => {
    new Transport({ baseUrl: '/registry', token: () => '' })
  })
  await withLocation('http://app.example.org', async () => {
    assert.throws(() => new Transport({ baseUrl: '/registry', token: () => '' }), /needs an https base URL/u)
    assert.throws(() => new Transport({ baseUrl: '/registry', token: () => '', allowInsecureHttp: true }),
      /needs an https base URL/u)
    assert.throws(() => new Transport({ baseUrl: '/registry', allowInsecureHttp: true }), /Invalid registry base URL/u)
  })
  await withLocation('http://portal:5173', async () => {
    assert.throws(() => new Transport({ baseUrl: '/registry', token: () => '' }), /needs an https base URL/u)
    assert.throws(() => new Transport({ baseUrl: '/registry', token: () => '', allowInsecureHttp: true }), /needs an https base URL/u)
    new Transport({ baseUrl: '/registry', allowInsecureHttp: true })
  })
  await withLocation('https://app.example.org', async () => {
    for (const bad of ['//evil.example.org', '/registry?x=1', '/registry#x', '/a b', '/\\evil.example.org',
      '/registry/../other', '/registry/%2e%2e/other', '/registry/./v1']) {
      assert.throws(() => new Transport({ baseUrl: bad, token: () => '' }), /Invalid registry base URL/u)
    }
  })
})

test('a path base is refused where there is no page origin', async () => {
  await withLocation(undefined, async () => {
    assert.equal((globalThis as { location?: unknown }).location, undefined)
    assert.throws(() => new Transport({ baseUrl: '/registry', token: () => '' }), /Invalid registry base URL/u)
  })
})

const trace = '1'.repeat(32)
const failure = (info: Partial<ConstructorParameters<typeof RegistryError>[0]>) =>
  new RegistryError({ kind: 'refused', reason: 'status', outcomeUnknown: false, ...info })

const oneSentence = /^[A-Z][^.?!]*\.$/u
const write: Operation = { method: 'POST', path: '/v1/items', mutating: true, keyed: true,
  requestMediaType: 'application/json', problemValidators: { default: () => true },
  responses: { 200: [{ mediaType: 'application/json', mode: 'json', validate: value =>
    typeof value === 'object' && value !== null && Object.hasOwn(value, 'id') }] } }
const writeThrough = (fetch: typeof globalThis.fetch) =>
  new Transport({ baseUrl: 'https://registry.example.org', token: () => 'synthetic-token', fetch })
const problem = (status: number, body: object) => new Response(JSON.stringify({ status, title: 'Problem', ...body }),
  { status, headers: { 'Content-Type': 'application/problem+json' } })

test('describeError never repeats product problem detail', () => {
  const email = 'alice@example.org'
  const error = failure({ status: 409, problem: { code: 'idempotency.key-reused', traceId: trace,
    detail: 'The key ' + email + ' is in use. Trace ' + trace + '.' } })
  const sentence = describeError(error)
  assert.match(sentence, /conflicts/u)
  for (const value of [email, trace, 'in use', 'Trace']) assert.ok(!sentence.includes(value))
})

test('describeError shows a fixed sentence for a code the client raised itself and never its detail', () => {
  const detail = 'Served reason: ' + trace + ' for alice@example.org.'
  const own = (code: string) => failure({ status: 409, raisedByClient: true, problem: { code, detail } })
  for (const [code, sentence] of [
    ['client.file-type', clientSentences['client.file-type']!],
    ['client.command-unavailable', clientSentences['client.command-unavailable']!],
    ['client.never-heard-of-it', clientFallbackSentence],
  ] as const) {
    const shown = describeError(own(code))
    assert.equal(shown, sentence)
    assert.match(shown, oneSentence)
    for (const value of [trace, 'alice', 'Served']) assert.ok(!shown.includes(value))
  }
  // A programme replaces a sentence in the one table, and `detail` stays on the error.
  assert.equal(describeError(own('client.file-type'), { clientSentences: { 'client.file-type': 'Choisissez un PDF.' } }),
    'Choisissez un PDF.')
  // An empty replacement never reaches the screen.
  assert.equal(describeError(own('client.file-type'), { clientSentences: { 'client.file-type': '' } }), clientSentences['client.file-type'])
  assert.equal(describeError(own('client.other'), { clientSentences: Object.create({ 'client.other': 'Inherited.' }) }),
    clientFallbackSentence)
  assert.equal(own('client.file-type').detail, detail)
})

test('a client. code that arrived on the wire is a product failure, never client text', async () => {
  const wire = failure({ status: 409, problem: { code: 'client.file-type', detail: 'synthetic upstream copy' } })
  assert.match(describeError(wire), /conflicts/u)
  const throughTransport = await writeThrough(async () => problem(500, { code: 'client.file-type', detail: 'synthetic upstream copy' }))
    .call(write, { body: {} }).catch((caught: unknown) => caught)
  assert.ok(throughTransport instanceof RegistryError)
  assert.match(describeError(throughTransport), /may or may not have been made/u)
  assert.ok(!describeError(throughTransport).includes('synthetic'))
})

test('describeError uses only the caller-supplied label for a refused guard', () => {
  const guard = failure({ status: 412, problem: { code: 'action.guard_failed', guardReason: 'case-closed',
    detail: 'Free text from the answer.', traceId: trace } })
  assert.equal(describeError(guard), 'The action is not possible in the current state.')
  assert.equal(describeError(guard, { guardLabels: { 'case-closed': 'Only open cases can be closed.' } }),
    'Only open cases can be closed.')
  assert.equal(describeError(guard, { clientSentences: { 'availability.guard-not-satisfied': 'Ask your supervisor.' } }),
    'Ask your supervisor.')
  assert.equal(describeError(guard, { guardLabels: { 'other-guard': 'Other.' } }),
    'The action is not possible in the current state.')
  assert.equal(describeError(guard, { guardLabels: Object.create({ 'case-closed': 'Inherited.' }) }),
    'The action is not possible in the current state.')
})

test('describeError says an uncertain write may have been made when a 5xx problem arrived', async () => {
  const error = await writeThrough(async () => problem(500, { code: 'runtime.failure', detail: 'The runtime failed.' }))
    .call(write, { body: {} }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.outcomeUnknown, true)
  assert.equal(error.detail, 'The runtime failed.')
  assert.equal(describeError(error), 'The change may or may not have been made, so check before trying again.')
})

test('describeError says an uncertain write may have been made when the caller aborts after a 2xx', async () => {
  const caller = new AbortController()
  const error = await writeThrough(async () => {
    setTimeout(() => caller.abort(), 5)
    return new Response(new ReadableStream({}), { headers: { 'Content-Type': 'application/json' } })
  }).call(write, { body: {}, signal: caller.signal }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.deepEqual([error.reason, error.status, error.outcomeUnknown], ['aborted', 200, true])
  assert.match(describeError(error), /may or may not have been made/u)
})

test('describeError says an uncertain write may have been made when a 2xx answer fails its schema', async () => {
  const error = await writeThrough(async () => Response.json({ unexpected: true }))
    .call(write, { body: {} }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.deepEqual([error.reason, error.status, error.outcomeUnknown], ['schema', 200, true])
  assert.match(describeError(error), /may or may not have been made/u)
})

test('describeError says a request that was never built was not sent', async () => {
  let sent = 0
  const transport = writeThrough(async () => { sent++; return Response.json({ id: 1 }) })
  const error = await transport.call(write, { body: { value: 1n } }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.reason, 'input')
  assert.equal(sent, 0)
  assert.equal(describeError(error), 'The request could not be built from the given values.')
})

test('describeError has one fixed sentence per failure class', () => {
  const secret = 'bearer-secret-value'
  const cases: Array<[RegistryError, RegExp]> = [
    [failure({ kind: 'unreachable', reason: 'network' }), /did not answer/u],
    [failure({ kind: 'unreachable', reason: 'token' }), /credentials could not be obtained/u],
    [failure({ kind: 'unreachable', reason: 'timeout' }), /too long/u],
    [failure({ kind: 'unreachable', reason: 'aborted' }), /cancelled/u],
    [failure({ kind: 'unreachable', reason: 'network', outcomeUnknown: true }), /may or may not/u],
    [failure({ kind: 'unreachable', reason: 'timeout', outcomeUnknown: true }), /may or may not/u],
    [failure({ kind: 'unreachable', reason: 'status', status: 503 }), /failed to complete/u],
    [failure({ kind: 'unreachable', reason: 'status', status: 503, problem: { detail: secret } }), /failed to complete/u],
    [failure({ status: 401 }), /refused your credentials/u],
    [failure({ status: 403 }), /not allowed/u],
    [failure({ status: 404 }), /not found/u],
    [failure({ status: 409 }), /conflicts/u],
    [failure({ status: 409, problem: { code: 'action.guard_failed', detail: secret } }), /not possible/u],
    [failure({ status: 428 }), /conflicts/u],
    [failure({ status: 429 }), /too many/iu],
    [failure({ status: 400 }), /not valid/u],
    [failure({ status: 422, problem: { detail: secret } }), /not valid/u],
    [failure({ kind: 'unexpected', reason: 'schema', status: 200 }), /could not be read/u],
    [failure({ kind: 'unexpected', reason: 'too-large', status: 200 }), /could not be read/u],
    [failure({ kind: 'unexpected', reason: 'input' }), /could not be built/u],
    [failure({ kind: 'unexpected', reason: 'status', status: 418 }), /unexpected answer/u],
    [failure({ kind: 'unexpected', reason: 'too-large', status: 401, product: 'casework' }), /could not be read/u],
    [failure({ kind: 'refused', reason: 'configuration', status: 401, product: 'casework' }), /not available from this page/u],
    [failure({ kind: 'refused', reason: 'sign-in-expired', status: 401 }), /sign-in has ended/u],
  ]
  for (const [error, pattern] of cases) {
    const sentence = describeError(error)
    assert.match(sentence, pattern)
    assert.match(sentence, oneSentence)
    assert.ok(!sentence.includes(trace) && !sentence.includes(secret))
  }
  assert.match(describeError(new TypeError('Missing path value ' + secret)), /could not be built/u)
  assert.ok(!describeError(new TypeError(secret)).includes(secret))
  assert.match(describeError(new Error(secret)), /went wrong/u)
  assert.match(describeError('x'), /went wrong/u)
})

test('a failed page can be retried at the same cursor and the walk continues', async () => {
  const requested: Array<string | undefined> = []
  let failNext = true
  const walk = pages<number>(async cursor => {
    requested.push(cursor)
    if (cursor === 'p2' && failNext) { failNext = false; throw new Error('offline') }
    return cursor === undefined ? { items: [1], nextCursor: 'p2' }
      : cursor === 'p2' ? { items: [2], nextCursor: 'p3' } : { items: [3], nextCursor: null }
  })
  assert.deepEqual((await walk.next()).value, { items: [1], nextCursor: 'p2' })
  await assert.rejects(walk.next(), /offline/u)
  assert.deepEqual((await walk.next()).value, { items: [2], nextCursor: 'p3' })
  assert.deepEqual((await walk.next()).value, { items: [3], nextCursor: null })
  assert.equal((await walk.next()).done, true)
  assert.deepEqual(requested, [undefined, 'p2', 'p2', 'p3'])
})

test('a failed page does not count toward the cap and repeated cursors still end the walk', async () => {
  let failures = 0
  let calls = 0
  const walk = pages<number>(async () => {
    if (failures < 3) { failures++; throw new Error('offline') }
    return { items: [++calls], nextCursor: String(calls) }
  }, 2)
  for (let i = 0; i < 3; i++) await assert.rejects(walk.next(), /offline/u)
  await walk.next()
  await walk.next()
  await assert.rejects(walk.next(), /cap/iu)
  assert.equal((await walk.next()).done, true)
  const repeating = pages<number>(async () => ({ items: [], nextCursor: 'same' }))
  await repeating.next()
  await assert.rejects(repeating.next(), /repeated/iu)
  assert.equal((await repeating.next()).done, true)
})

test('pages still works with for await', async () => {
  const seen: number[] = []
  for await (const page of pages<number>(async cursor => cursor ? { items: [2], nextCursor: null } : { items: [1], nextCursor: 'b' })) {
    seen.push(...page.items)
  }
  assert.deepEqual(seen, [1, 2])
})

test('Action availability is a typed generated call', async () => {
  const body = { availability: { available: false, observedRevision: 3, reason: 'guard-not-satisfied', recovery: 'none', guardReason: 'case-closed', guardLabel: 'The case is closed.' } }
  const client = make(FacilityClient, { baseUrl: 'https://registry.example.org', token: () => 't', fetch: async (url, init) => {
    assert.equal(new URL(String(url)).pathname, '/v1/actions/register-facility/availability')
    assert.equal(init?.method, 'POST')
    assert.equal(new Headers(init?.headers).has('idempotency-key'), false)
    return Response.json(body)
  } })
  const { data } = await client.call('actions.register-facility.availability', {
    body: { input: { operatorId: '00000000-0000-4000-8000-000000000001' }, targetInput: 'operatorId' },
  })
  const answer = data.availability
  if (answer.available === false) {
    assert.equal(answer.guardReason, 'case-closed')
    assert.equal(answer.guardLabel, 'The case is closed.')
    assert.equal(answer.observedRevision, 3)
  } else assert.fail('expected an unavailable answer')
  // @ts-expect-error availability has no members beyond the declared ones
  void answer.guardText
})

test('generated Action input metadata matches the document exactly', () => {
  const document = JSON.parse(readFileSync(new URL('../../../products/breg/generated/facility/generated/openapi.json', import.meta.url), 'utf8'))
  const expected: Record<string, unknown> = {}
  for (const item of Object.values<Record<string, any>>(document.paths)) {
    for (const operation of Object.values<Record<string, any>>(item)) {
      const action = operation['x-registry-action']
      if (action) expected[action.id] = { display: action.display, inputMode: action.inputMode, inputs: action.inputs }
    }
  }
  assert.ok(Object.keys(expected).length > 0)
  assert.deepEqual(JSON.parse(JSON.stringify(actionInputs)), expected)
  const first = actionInputs['register-facility'].inputs[0]
  assert.equal(first.apiName, 'facilityCode')
  assert.equal(first.required, true)
})
