import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { RegistryError, Transport, clientSentences, describeError } from '../core.ts'
import { Client as Documents } from '../generated/documents.ts'
import { documentCommands, saveBlob, type DocumentClient } from '../tasks/files.ts'

const baseUrl = 'https://registry.example.org'
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(new URL(`./fixtures/tasks/${name}.json`, import.meta.url), 'utf8'))
const ready = fixture('document-ready')
const pending = fixture('document-pending')
const policies = fixture('document-policies')
const reservation = fixture('document-reservation')
const grant = fixture('document-grant')

const docId = '5b2f1c3e-7a4d-4e8b-9c1a-0d2e3f4a5b6c'
const versionId = '8e6d4c2a-1b3f-4a5c-9d7e-2f1a3b4c5d6e'
const grantId = '3c9a7e5b-2d4f-4b6a-8c1e-9f0a1b2c3d4e'
const uploadId = '0f8fad5b-d9cb-469f-a165-70867728950e'

const pdf = (text = 'hello world!') => new Blob([text], { type: 'application/pdf' })
const sha = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex')
const versionOf = (view: Record<string, unknown>) => view.version as Record<string, unknown>
const withVersion = (changes: Record<string, unknown>) => ({ ...ready, version: { ...versionOf(ready), ...changes } })
const withStatus = (status: string) => withVersion({ status })
// A ready document whose stored digest and length match `text`.
const readyFor = (text: string) => withVersion({ expectedDigest: `sha256:${sha(text)}`, length: new TextEncoder().encode(text).length })

interface Seen { method: string; path: string; headers: Headers; body: string; signal?: AbortSignal | null }
type Handler = (request: Seen) => Response | Promise<Response>

// Routes by "METHOD /path" and records every request.
function server(routes: Record<string, Handler | Response>, token = true) {
  const seen: Seen[] = []
  const options = {
    baseUrl,
    ...(token ? { token: () => 'fixture' } : {}),
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      const target = new URL(String(url))
      const body = init?.body instanceof Blob || init?.body instanceof Uint8Array ? await new Response(init.body).text() : String(init?.body ?? '')
      const request: Seen = { method: init?.method ?? 'GET', path: target.pathname + target.search, headers: new Headers(init?.headers), body, signal: init?.signal }
      seen.push({ ...request, path: target.origin + request.path })
      const route = routes[`${request.method} ${target.pathname}`]
      if (route === undefined) throw new Error(`unrouted ${request.method} ${target.href}`)
      return typeof route === 'function' ? route(request) : route.clone()
    }) as typeof fetch,
  }
  const documents = new Documents(new Transport(options))
  return { documents, seen, commands: documentCommands(documents, { custodian: 'person-1' }) }
}

const json = (body: unknown, status = 200) => Response.json(body, { status })
const uploadRoutes = (view: unknown = pending): Record<string, Handler | Response> => ({
  'GET /v1/document-policies': json(policies),
  'POST /v1/documents': json(reservation, 201),
  [`PUT /v1/uploads/${uploadId}/content`]: json(view),
})
const keyOf = (request: Seen) => request.headers.get('idempotency-key')
const posts = (seen: Seen[]) => seen.filter(r => r.method === 'POST')

// The screen shows the table's sentence for the code, never the detail or a served value.
function onScreen(error: RegistryError): void {
  assert.equal(error.raisedByClient, true)
  assert.ok(Object.hasOwn(clientSentences, error.code!), `${error.code} has a sentence`)
  assert.equal(describeError(error), clientSentences[error.code!])
  assert.ok(error.detail && !describeError(error).includes(error.detail))
}

async function refusal(promise: Promise<unknown>, code: string): Promise<RegistryError> {
  const error = await promise.then(() => assert.fail('expected a refusal'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError, String(error))
  assert.equal(error.code, code)
  // A register answer rebuilt by a helper keeps the wire's code and is not a client sentence.
  if (code.startsWith('client.')) onScreen(error)
  else assert.equal(error.raisedByClient, false)
  return error
}

test('upload checks the policy, reserves with the digest, then sends the bytes to the reserved upload', async () => {
  const { commands, seen } = server(uploadRoutes())
  const view = await commands.upload(pdf(), { policy: 'licence-evidence', label: 'Diploma' })
  assert.deepEqual(view, pending)
  assert.deepEqual(seen.map(r => `${r.method} ${new URL(r.path).pathname}`), [
    'GET /v1/document-policies', 'POST /v1/documents', `PUT /v1/uploads/${uploadId}/content`,
  ])
  const reserve = seen[1]!
  assert.deepEqual(JSON.parse(reserve.body), {
    custodian: { subject: 'person-1' }, expectedDigest: `sha256:${sha('hello world!')}`, length: 12,
    mediaType: 'application/pdf', policyId: 'licence-evidence', label: 'Diploma',
  })
  const put = seen[2]!
  assert.equal(put.body, 'hello world!')
  assert.equal(put.headers.get('content-type'), 'application/pdf')
  assert.equal(put.headers.get('authorization'), 'Bearer fixture')
})

test('upload uses the resolved media type in the reservation and byte transfer', async () => {
  for (const file of [
    new File(['x'], 'support.pdf'),
    new File(['x'], 'support.unknown', { type: 'application/x-pdf' }),
  ]) {
    const { commands, seen } = server(uploadRoutes())
    await commands.upload(file, { policy: 'licence-evidence' })
    assert.equal(JSON.parse(posts(seen)[0]!.body).mediaType, 'application/pdf')
    assert.equal(seen.find(request => request.method === 'PUT')?.headers.get('content-type'), 'application/pdf')
  }
})

test('upload infers CSV when the browser reports an unaccepted spreadsheet type', async () => {
  const items = (policies.items as Record<string, unknown>[]).map(policy => ({ ...policy, allowedContentTypes: ['text/csv'] }))
  const reserved = { ...reservation, document: { ...(reservation.document as object),
    version: { ...versionOf(reservation.document as Record<string, unknown>), mediaType: 'text/csv' } } }
  const { commands, seen } = server({
    ...uploadRoutes(), 'GET /v1/document-policies': json({ items }), 'POST /v1/documents': json(reserved, 201),
  })
  await commands.upload(new File(['x'], 'rows.csv', { type: 'application/vnd.ms-excel' }), { policy: 'licence-evidence' })
  assert.equal(JSON.parse(posts(seen)[0]!.body).mediaType, 'text/csv')
  assert.equal(seen.find(request => request.method === 'PUT')?.headers.get('content-type'), 'text/csv')
})

test('the PUT content type is the reserved media type from the reservation', async () => {
  const reserved = { ...reservation, document: { ...(reservation.document as object), version: { ...versionOf(reservation.document as Record<string, unknown>), mediaType: 'image/png' } } }
  const { commands, seen } = server({ ...uploadRoutes(), 'POST /v1/documents': json(reserved, 201) })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  assert.equal(seen.find(r => r.method === 'PUT')!.headers.get('content-type'), 'image/png')
})

test('the reservation key is random per call, within the 128 byte limit, and a given key is used as is', async () => {
  const { commands, seen } = server(uploadRoutes())
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  await commands.upload(pdf(), { policy: 'licence-evidence', idempotencyKey: 'caller-key-1' })
  const keys = posts(seen).map(keyOf)
  assert.equal(keys.length, 3)
  assert.ok(keys[0] && keys[1])
  assert.notEqual(keys[0], keys[1])
  assert.ok(new TextEncoder().encode(keys[0]!).length <= 128)
  assert.equal(keys[2], 'caller-key-1')
})

test('a retry with the key from a failed PUT replays the reservation and sends to the same upload path', async () => {
  let puts = 0
  const { commands, seen } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: () => (++puts === 1 ? new Response(null, { status: 503 }) : json(pending)),
  })
  const failure = await commands.upload(pdf(), { policy: 'licence-evidence' }).then(() => assert.fail('expected a failure'), (e: unknown) => e)
  assert.ok(failure instanceof RegistryError)
  assert.equal(failure.status, 503)
  assert.ok(failure.idempotencyKey)
  assert.equal(failure.idempotencyKey, keyOf(posts(seen)[0]!))

  const view = await commands.upload(pdf(), { policy: 'licence-evidence', idempotencyKey: failure.idempotencyKey })
  assert.deepEqual(view, pending)
  const reserves = posts(seen)
  assert.equal(reserves.length, 2)
  assert.equal(keyOf(reserves[1]!), failure.idempotencyKey)
  const putPaths = seen.filter(r => r.method === 'PUT').map(r => r.path)
  assert.deepEqual(putPaths, [`${baseUrl}/v1/uploads/${uploadId}/content`, `${baseUrl}/v1/uploads/${uploadId}/content`])
})

test('an error thrown by upload keeps its fields and carries the key, whether the reserve or a refusal fails', async () => {
  const reserveFails = server({ ...uploadRoutes(), 'POST /v1/documents': new Response(null, { status: 503 }) })
  const error = await reserveFails.commands.upload(pdf(), { policy: 'licence-evidence', idempotencyKey: 'k-1' }).then(() => assert.fail('expected a failure'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.kind, 'unreachable')
  assert.equal(error.status, 503)
  assert.equal(error.idempotencyKey, 'k-1')

  const refused = server(uploadRoutes())
  const refusedError = await refusal(refused.commands.upload(pdf(), { policy: 'nope', idempotencyKey: 'k-2' }), 'client.unknown-policy')
  assert.equal(refusedError.idempotencyKey, 'k-2')
})

test('the custodian comes from the call, then the instance', async () => {
  const body = (seen: Seen[]) => JSON.parse(posts(seen)[0]!.body) as Record<string, unknown>
  const own = server(uploadRoutes())
  await own.commands.upload(pdf(), { policy: 'licence-evidence', custodian: 'person-2' })
  assert.deepEqual(body(own.seen).custodian, { subject: 'person-2' })
  const instance = server(uploadRoutes())
  await instance.commands.upload(pdf(), { policy: 'licence-evidence' })
  assert.deepEqual(body(instance.seen).custodian, { subject: 'person-1' })
})

test('upload sends no custodian member when none is set, so the register uses the caller', async () => {
  const { documents, seen } = server(uploadRoutes())
  await documentCommands(documents).upload(pdf(), { policy: 'licence-evidence' })
  const body = JSON.parse(posts(seen)[0]!.body) as Record<string, unknown>
  assert.equal('custodian' in body, false)
  assert.equal(seen.length, 3)
})

test('the policy list is read once per instance', async () => {
  const { commands, seen } = server(uploadRoutes())
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  await commands.upload(pdf('second'), { policy: 'licence-evidence' })
  assert.equal(seen.filter(r => r.path.endsWith('/v1/document-policies')).length, 1)
})

test('a failed policy read is not cached', async () => {
  let calls = 0
  const { commands } = server({
    ...uploadRoutes(),
    'GET /v1/document-policies': () => (++calls === 1 ? new Response(null, { status: 503 }) : json(policies)),
  })
  await assert.rejects(commands.upload(pdf(), { policy: 'licence-evidence' }), RegistryError)
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  assert.equal(calls, 2)
})

test('one caller aborting during the shared policy read does not fail another', async () => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const { commands, seen } = server({ ...uploadRoutes(), 'GET /v1/document-policies': async () => { await gate; return json(policies) } })
  const controller = new AbortController()
  const first = commands.upload(pdf(), { policy: 'licence-evidence', signal: controller.signal })
  const second = commands.upload(pdf('second'), { policy: 'licence-evidence' })
  while (seen.length === 0) await new Promise(resolve => setTimeout(resolve, 1))
  controller.abort()
  release()
  await assert.rejects(first, (e: unknown) => e instanceof RegistryError && e.reason === 'aborted')
  assert.deepEqual(await second, pending)
  assert.equal(seen.filter(r => r.path.endsWith('/v1/document-policies')).length, 1)
})

test('upload refuses before reserving: unknown policy, file type, size', async () => {
  const { commands, seen } = server(uploadRoutes())
  const unknown = await refusal(commands.upload(pdf(), { policy: 'nope' }), 'client.unknown-policy')
  assert.equal(unknown.kind, 'refused')
  assert.equal(unknown.reason, 'input')
  assert.match(unknown.detail ?? '', /licence-evidence/)

  const type = await refusal(commands.upload(new Blob(['x'], { type: 'text/html' }), { policy: 'licence-evidence' }), 'client.file-type')
  assert.match(type.detail ?? '', /application\/pdf, image\/png/)
  await refusal(commands.upload(new Blob(['x']), { policy: 'licence-evidence' }), 'client.file-type')

  const big = await refusal(commands.upload(pdf('x'.repeat(1025)), { policy: 'licence-evidence' }), 'client.file-too-large')
  assert.match(big.detail ?? '', /1024/)
  assert.equal(seen.some(r => r.method === 'POST' || r.method === 'PUT'), false)
})

const hostile: [string, string][] = [
  ['wrong segments', '/v1/uploads/0f8fad5b-d9cb-469f-a165-70867728950e/other'],
  ['extra segment after content', `/v1/uploads/${uploadId}/content/more`],
  ['uppercase id', '/v1/uploads/0F8FAD5B-D9CB-469F-A165-70867728950E/content'],
  ['not a uuid', '/v1/uploads/not-a-uuid/content'],
  ['empty', ''],
  ['query string', `/v1/uploads/${uploadId}/content?next=https://evil.example`],
  ['fragment', `/v1/uploads/${uploadId}/content#x`],
  ['other collection', `/v1/documents/${uploadId}/content`],
]

for (const [name, uploadPath] of hostile) {
  test(`upload refuses an upload path with ${name} and sends no bytes`, async () => {
    const { commands, seen } = server({ ...uploadRoutes(), 'POST /v1/documents': json({ ...reservation, uploadPath }, 201) })
    const error = await refusal(commands.upload(pdf(), { policy: 'licence-evidence' }), 'client.upload-path')
    assert.equal(error.kind, 'unexpected')
    assert.equal(error.reason, 'schema')
    assert.equal(seen.some(r => r.method === 'PUT'), false)
  })
}

test('upload takes only the id from an absolute upload path and sends to its own host', async () => {
  const { commands, seen } = server({
    ...uploadRoutes(),
    'POST /v1/documents': json({ ...reservation, uploadPath: `https://evil.example/prefix/v1/uploads/${uploadId}/content` }, 201),
  })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  const put = seen.find(r => r.method === 'PUT')!
  assert.equal(put.path, `${baseUrl}/v1/uploads/${uploadId}/content`)
  assert.ok(seen.every(r => r.path.startsWith(baseUrl)))
})

test('upload works in page mode and sends no bearer token', async () => {
  const { commands, seen } = server(uploadRoutes(), false)
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  assert.equal(seen.every(r => r.headers.get('authorization') === null), true)
  assert.equal(seen.length, 3)
})

test('every command stops on a signal that is already aborted', async () => {
  const { commands, seen } = server(uploadRoutes())
  const controller = new AbortController()
  controller.abort()
  const { signal } = controller
  const calls: Promise<unknown>[] = [
    commands.list({ signal }),
    commands.upload(pdf(), { policy: 'licence-evidence', signal }),
    commands.waitUntilReady(docId, { signal }),
    commands.download(docId, { signal }),
    commands.share(docId, { with: 'official-7', signal }),
    commands.shares(docId, { signal }),
    commands.revoke(grantId, { signal }),
    commands.requestErasure(docId, { signal }),
  ]
  for (const call of calls) {
    await assert.rejects(call, (e: unknown) => e instanceof RegistryError && e.reason === 'aborted')
  }
  assert.equal(seen.some(r => r.method !== 'GET'), false)
})

test('upload passes the signal to the reserve and the byte transfer', async () => {
  const { commands, seen } = server(uploadRoutes())
  const controller = new AbortController()
  await commands.upload(pdf(), { policy: 'licence-evidence', signal: controller.signal })
  const writes = seen.filter(r => r.method !== 'GET')
  assert.equal(writes.length, 2)
  controller.abort()
  for (const request of writes) {
    assert.ok(request.signal)
    assert.equal(request.signal.aborted, true)
  }
})

test('waitUntilReady polls until the version is ready', async () => {
  let reads = 0
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => json(++reads < 2 ? pending : ready) })
  const view = await commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 5000 })
  assert.deepEqual(view, ready)
  assert.equal(reads, 2)
})

for (const status of ['rejected', 'suspended', 'erasure-pending', 'erased']) {
  test(`waitUntilReady stops at once on ${status}`, async () => {
    let reads = 0
    const { commands } = server({ [`GET /v1/documents/${docId}`]: () => (reads++, json(withStatus(status))) })
    const error = await refusal(commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 5000 }), `client.document-${status}`)
    assert.equal(error.kind, 'refused')
    assert.equal(reads, 1)
  })
}

test('waitUntilReady times out with client.wait-timeout', async () => {
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => json(pending) })
  const started = Date.now()
  const error = await refusal(commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 40 }), 'client.wait-timeout')
  assert.equal(error.reason, 'timeout')
  assert.ok(Date.now() - started < 1000)
})

test('waitUntilReady stops sleeping when the signal aborts', async () => {
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => json(pending) })
  const controller = new AbortController()
  const waiting = commands.waitUntilReady(docId, { intervalMs: 10_000, timeoutMs: 60_000, signal: controller.signal })
  setTimeout(() => controller.abort(), 20)
  await assert.rejects(waiting, (e: unknown) => e instanceof RegistryError && e.reason === 'aborted')
})

for (const [name, opts, code] of [
  ['NaN timeout', { timeoutMs: NaN }, 'client.invalid-timeout'],
  ['negative timeout', { timeoutMs: -1 }, 'client.invalid-timeout'],
  ['infinite timeout', { timeoutMs: Infinity }, 'client.invalid-timeout'],
  ['NaN interval', { intervalMs: NaN }, 'client.invalid-interval'],
  ['infinite interval', { intervalMs: Infinity }, 'client.invalid-interval'],
] as const) {
  test(`waitUntilReady refuses a ${name} before any request`, async () => {
    const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: json(pending) })
    const error = await refusal(commands.waitUntilReady(docId, opts), code)
    assert.equal(error.kind, 'refused')
    assert.equal(seen.length, 0)
  })
}

test('waitUntilReady clamps a tiny interval to 250 ms, so 0 does not busy-loop', async () => {
  let reads = 0
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => json(++reads < 2 ? pending : ready) })
  const started = Date.now()
  await commands.waitUntilReady(docId, { intervalMs: 0, timeoutMs: 5000 })
  assert.equal(reads, 2)
  assert.ok(Date.now() - started >= 240)
})

test('download refuses a document that is not ready, without fetching content', async () => {
  const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: json(pending) })
  await refusal(commands.download(docId), 'client.document-not-ready')
  assert.equal(seen.length, 1)
})

// An unusable document never becomes ready, so download says so, as waitUntilReady does.
for (const status of ['rejected', 'suspended', 'erasure-pending', 'erased']) {
  test(`download refuses a document that is ${status}, with its own code, without fetching content`, async () => {
    const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: json(withStatus(status)) })
    const error = await refusal(commands.download(docId), `client.document-${status}`)
    assert.equal(error.reason, 'status')
    assert.equal(describeError(error), clientSentences[`client.document-${status}`])
    assert.equal(seen.length, 1)
  })
}

test('download refuses a document that is still awaiting its content as not ready', async () => {
  const { commands } = server({ [`GET /v1/documents/${docId}`]: json(withStatus('awaiting-content')) })
  await refusal(commands.download(docId), 'client.document-not-ready')
})

// A call the generated client cannot build throws a TypeError. Both helpers show the configuration sentence.
test('a call the generated client cannot build is a configuration refusal, as in the Proposals helper', async () => {
  const failing = async () => { throw new TypeError('A page client calls only its own origin') }
  const stub = { call: failing, listDocumentsPage: failing, listDocumentGrantsPage: failing, listReceivedGrantsPage: failing } as unknown as DocumentClient
  const commands = documentCommands(stub)
  const attempts: Array<[string, () => Promise<unknown>]> = [
    ['download', () => commands.download(docId)],
    ['upload', () => commands.upload(pdf(), { policy: 'licence-evidence' })],
    ['share', () => commands.share(docId, { with: 'someone' })],
    ['revoke', () => commands.revoke(grantId)],
    ['requestErasure', () => commands.requestErasure(docId)],
    ['waitUntilReady', () => commands.waitUntilReady(docId, { timeoutMs: 1000 })],
    ['list', () => commands.list()],
    ['received', () => commands.received()],
    ['shares', () => commands.shares(docId)],
  ]
  for (const [name, attempt] of attempts) {
    const error = await attempt().then(() => assert.fail(`${name} should refuse`), (e: unknown) => e)
    assert.ok(error instanceof RegistryError, `${name}: ${String(error)}`)
    assert.equal(error.code, 'client.unknown-operation', name)
    assert.equal(error.raisedByClient, true, name)
    assert.equal(describeError(error), clientSentences['client.unknown-operation'], name)
  }
})

test('download refuses when the document does not offer download', async () => {
  const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: json({ ...ready, actions: ['share'] }) })
  const error = await refusal(commands.download(docId), 'client.action-unavailable')
  assert.equal(error.kind, 'refused')
  assert.equal(seen.length, 1)
})

test('download returns the bytes typed with a safe served type', async () => {
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(readyFor('%PDF-1.7')),
    [`GET /v1/documents/${docId}/versions/${versionId}/content`]: new Response('%PDF-1.7', { headers: { 'Content-Type': 'application/pdf' } }),
  })
  const blob = await commands.download(docId)
  assert.equal(blob.type, 'application/pdf')
  assert.equal(await blob.text(), '%PDF-1.7')
  assert.equal(seen.length, 2)
})

for (const [served, expected] of [['image/png', 'image/png'], ['image/jpeg', 'image/jpeg'], ['text/html', 'application/octet-stream'], ['image/svg+xml', 'application/octet-stream']] as const) {
  test(`download types ${served} as ${expected}`, async () => {
    const { commands } = server({
      [`GET /v1/documents/${docId}`]: json(readyFor('x')),
      [`GET /v1/documents/${docId}/versions/${versionId}/content`]: new Response('x', { headers: { 'Content-Type': served } }),
    })
    assert.equal((await commands.download(docId)).type, expected)
  })
}

test('download refuses bytes whose SHA-256 differs from the stored digest', async () => {
  const { commands } = server({
    [`GET /v1/documents/${docId}`]: json(readyFor('the stored bytes')),
    [`GET /v1/documents/${docId}/versions/${versionId}/content`]: new Response('other bytes!!!!', { headers: { 'Content-Type': 'application/pdf' } }),
  })
  const error = await refusal(commands.download(docId), 'client.content-digest')
  assert.equal(error.kind, 'unexpected')
})

test('download caps the answer at the stored length, so a longer body fails', async () => {
  const { commands } = server({
    [`GET /v1/documents/${docId}`]: json(readyFor('short')),
    [`GET /v1/documents/${docId}/versions/${versionId}/content`]: new Response('short but then a much longer body', { headers: { 'Content-Type': 'application/pdf' } }),
  })
  await assert.rejects(commands.download(docId), (e: unknown) => e instanceof RegistryError && e.reason === 'too-large')
})

test('share reads the current version, then issues a grant with a random key', async () => {
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: json(grant, 201),
  })
  const view = await commands.share(docId, { with: 'official-7', expiryHours: 48 })
  assert.deepEqual(view, grant)
  const issue = seen[1]!
  assert.deepEqual(JSON.parse(issue.body), { grantee: { kind: 'human', subject: 'official-7' }, versionId, expiryHours: 48 })
  assert.ok(keyOf(issue))
  assert.ok(new TextEncoder().encode(keyOf(issue)!).length <= 128)
})

test('sharing again after a revoke sends a new key, so it issues a new grant', async () => {
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: json(grant, 201),
    [`DELETE /v1/document-grants/${grantId}`]: json({ ...grant, state: 'revoked' }),
  })
  await commands.share(docId, { with: 'official-7' })
  await commands.revoke(grantId)
  await commands.share(docId, { with: 'official-7' })
  const [first, second] = posts(seen)
  assert.ok(keyOf(first!) && keyOf(second!))
  assert.notEqual(keyOf(first!), keyOf(second!))
})

test('share uses a given key, and an error carries the key for a retry', async () => {
  const issueFails = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: new Response(null, { status: 503 }),
  })
  const error = await issueFails.commands.share(docId, { with: 'official-7', idempotencyKey: 'share-key-1' }).then(() => assert.fail('expected a failure'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.idempotencyKey, 'share-key-1')
  assert.equal(keyOf(posts(issueFails.seen)[0]!), 'share-key-1')

  const readFails = server({ [`GET /v1/documents/${docId}`]: new Response(null, { status: 503 }) })
  const early = await readFails.commands.share(docId, { with: 'official-7' }).then(() => assert.fail('expected a failure'), (e: unknown) => e)
  assert.ok(early instanceof RegistryError)
  assert.equal(early.status, 503)
})

test('share defaults the kind to human and accepts a service', async () => {
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: json(grant, 201),
  })
  await commands.share(docId, { with: 'svc-1', kind: 'service' })
  assert.deepEqual(JSON.parse(posts(seen)[0]!.body), { grantee: { kind: 'service', subject: 'svc-1' }, versionId })
})

test('share refuses when the document does not offer sharing', async () => {
  const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: json({ ...ready, actions: ['download'] }) })
  await refusal(commands.share(docId, { with: 'official-7' }), 'client.action-unavailable')
  assert.equal(seen.length, 1)
})

test('list and shares return items and a null cursor at the end', async () => {
  const { commands, seen } = server({
    'GET /v1/documents': json({ items: [ready], nextCursor: 'c2' }),
    [`GET /v1/documents/${docId}/grants`]: json({ items: [grant] }),
  })
  assert.deepEqual(await commands.list({ cursor: 'c1', limit: 5 }), { items: [ready], nextCursor: 'c2' })
  assert.deepEqual(await commands.shares(docId, { limit: 10 }), { items: [grant], nextCursor: null })
  assert.match(seen[0]!.path, /\?cursor=c1&limit=5$|\?limit=5&cursor=c1$/)
  assert.match(seen[1]!.path, /\?limit=10$/)
})

test('revoke and requestErasure make one call each', async () => {
  const revoked = { ...grant, state: 'revoked', revokedAt: '2026-11-27T10:00:00Z' }
  const erasing = withStatus('erasure-pending')
  const { commands, seen } = server({
    [`DELETE /v1/document-grants/${grantId}`]: json(revoked),
    [`POST /v1/documents/${docId}/erasure`]: json(erasing),
  })
  assert.deepEqual(await commands.revoke(grantId), revoked)
  assert.deepEqual(await commands.requestErasure(docId), erasing)
  assert.equal(seen.length, 2)
})

test('server failures surface as the core error, not a helper error', async () => {
  const problem = { type: 'https://id.registrystack.org/problems/registry-documents/upload/digest-mismatch', title: 'Digest mismatch', code: 'upload.digest-mismatch', status: 422, detail: 'no', traceId: 'a'.repeat(32) }
  const { commands } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: new Response(JSON.stringify(problem), { status: 422, headers: { 'Content-Type': 'application/problem+json' } }),
  })
  await assert.rejects(commands.upload(pdf(), { policy: 'licence-evidence' }), { status: 422, code: 'upload.digest-mismatch' })
})

test('saveBlob downloads through a link, never navigates, and revokes the URL after a delay', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const calls: string[] = []
  const link: Record<string, unknown> = { click: () => calls.push('click'), remove: () => calls.push('remove') }
  const original = { document: Reflect.get(globalThis, 'document'), create: URL.createObjectURL, revoke: URL.revokeObjectURL }
  Reflect.set(globalThis, 'document', {
    createElement: (tag: string) => { calls.push(`create ${tag}`); return link },
    body: { append: () => calls.push('append') },
  })
  URL.createObjectURL = () => 'blob:fixture'
  URL.revokeObjectURL = (url: string) => { calls.push(`revoke ${url}`) }
  try {
    saveBlob(pdf(), 'diploma.pdf')
    assert.deepEqual(calls, ['create a', 'append', 'click', 'remove'])
    t.mock.timers.tick(4000)
  } finally {
    Reflect.set(globalThis, 'document', original.document)
    URL.createObjectURL = original.create
    URL.revokeObjectURL = original.revoke
  }
  assert.equal(link.href, 'blob:fixture')
  assert.equal(link.download, 'diploma.pdf')
  assert.equal(link.rel, 'noopener')
  assert.deepEqual(calls, ['create a', 'append', 'click', 'remove', 'revoke blob:fixture'])
})

test('saveBlob refuses when there is no document body, without making an object URL', () => {
  const original = { document: Reflect.get(globalThis, 'document'), create: URL.createObjectURL }
  let made = false
  Reflect.set(globalThis, 'document', { createElement: () => ({}), body: null })
  URL.createObjectURL = () => { made = true; return 'blob:x' }
  try {
    assert.throws(() => saveBlob(pdf(), 'x.pdf'), (e: unknown) => e instanceof RegistryError && e.code === 'client.browser-only' && (onScreen(e), true))
  } finally {
    Reflect.set(globalThis, 'document', original.document)
    URL.createObjectURL = original.create
  }
  assert.equal(made, false)
})

test('saveBlob outside a browser refuses with a helper error', () => {
  assert.throws(() => saveBlob(pdf(), 'x.pdf'), (e: unknown) => e instanceof RegistryError && e.code === 'client.browser-only' && (onScreen(e), true))
})

// The transfer progress hook is passed through to the core. A stub client records the call options.
function recordingClient() {
  const calls: { operation: string; input: Record<string, unknown> }[] = []
  const answers: Record<string, unknown> = {
    listDocumentPolicies: policies,
    reserveDocument: reservation,
    uploadDocumentContent: pending,
    readDocument: withVersion({ expectedDigest: `sha256:${sha(new Uint8Array([1]))}`, length: 1 }),
    downloadDocumentVersion: { bytes: new Uint8Array([1]), mediaType: 'application/pdf' },
  }
  const stub: DocumentClient = {
    call: (async (operation: string, input: object = {}) => {
      calls.push({ operation, input: input as Record<string, unknown> })
      return { data: answers[operation] }
    }) as DocumentClient['call'],
    listDocumentsPage: async () => ({ items: [], nextCursor: null }),
    listDocumentGrantsPage: async () => ({ items: [], nextCursor: null }),
    listReceivedGrantsPage: async () => ({ items: [], nextCursor: null }),
  }
  return { commands: documentCommands(stub, { custodian: 'person-1' }), calls, stub }
}

test('upload passes onProgress unchanged to the byte transfer only', async () => {
  const { commands, calls } = recordingClient()
  const onProgress = () => {}
  await commands.upload(pdf(), { policy: 'licence-evidence', onProgress })
  const withHook = calls.filter(c => 'onProgress' in c.input)
  assert.deepEqual(withHook.map(c => c.operation), ['uploadDocumentContent'])
  assert.equal(withHook[0]!.input.onProgress, onProgress)
})

test('download passes onProgress unchanged to the byte transfer only', async () => {
  const { commands, calls } = recordingClient()
  const onProgress = () => {}
  await commands.download(docId, { onProgress })
  const withHook = calls.filter(c => 'onProgress' in c.input)
  assert.deepEqual(withHook.map(c => c.operation), ['downloadDocumentVersion'])
  assert.equal(withHook[0]!.input.onProgress, onProgress)
})

test('without onProgress the transfer calls carry no hook', async () => {
  const { commands, calls } = recordingClient()
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  await commands.download(docId)
  assert.equal(calls.some(c => 'onProgress' in c.input), false)
})

test('download caps the transfer at the stored length', async () => {
  const { commands, calls } = recordingClient()
  await commands.download(docId)
  assert.equal(calls.find(c => c.operation === 'downloadDocumentVersion')!.input.maxResponseBytes, 1)
})

// Compile-time checks: the helper's view of the client is typed per operation and matches the generated Client.
export async function compileChecks(real: Documents, typed: DocumentClient) {
  const body = { custodian: { subject: 's' }, expectedDigest: 'sha256:x', length: 1, mediaType: 'application/pdf', policyId: 'p' }
  await real.call('reserveDocument', { body })
  await typed.call('reserveDocument', { body })
  // @ts-expect-error a misspelt operation does not exist on the generated client
  await real.call('reserveDocuments', { body })
  // @ts-expect-error a misspelt operation does not exist in the helper's client type
  await typed.call('reserveDocuments', { body })
  // @ts-expect-error the reserve body needs a policy
  await real.call('reserveDocument', { body: { custodian: { subject: 's' }, expectedDigest: 'sha256:x', length: 1, mediaType: 'application/pdf' } })
  // @ts-expect-error the reserve body needs a policy in the helper's client type too
  await typed.call('reserveDocument', { body: { custodian: { subject: 's' }, expectedDigest: 'sha256:x', length: 1, mediaType: 'application/pdf' } })
  // @ts-expect-error a client that offers only some operations is not a DocumentClient
  documentCommands({ call: (async () => ({ data: undefined })) as (operation: 'readDocument', input: { path: { documentId: string } }) => Promise<{ data: never }>, listDocumentsPage: typed.listDocumentsPage, listDocumentGrantsPage: typed.listDocumentGrantsPage, listReceivedGrantsPage: typed.listReceivedGrantsPage })
  const commands = documentCommands(real)
  await commands.call('listReceivedGrants')
  // @ts-expect-error the exposed call is the generated client's, so a misspelt operation fails
  await commands.call('listReceivedGrant')
}

test('waitUntilReady times out when a read is slower than the whole budget', async () => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const { commands } = server({ [`GET /v1/documents/${docId}`]: async () => { await gate; return json(ready) } })
  const started = Date.now()
  const error = await refusal(commands.waitUntilReady(docId, { timeoutMs: 1 }), 'client.wait-timeout')
  release()
  assert.equal(error.reason, 'timeout')
  assert.ok(Date.now() - started < 1000)
})

test('waitUntilReady keeps waiting through a transient read failure', async () => {
  let reads = 0
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => (++reads === 1 ? new Response(null, { status: 503 }) : json(ready)) })
  const view = await commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 5000 })
  assert.deepEqual(view, ready)
  assert.equal(reads, 2)
})

test('waitUntilReady reports a transient failure that lasts to the deadline as a timeout', async () => {
  const { commands } = server({ [`GET /v1/documents/${docId}`]: new Response(null, { status: 503 }) })
  await refusal(commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 300 }), 'client.wait-timeout')
})

test('waitUntilReady throws a register refusal at once', async () => {
  let reads = 0
  const problem = { type: 'https://id.registrystack.org/problems/registry-documents/resource/not-found', title: 'Not found', code: 'resource.not-found', status: 404, detail: 'no such document', traceId: 'a'.repeat(32) }
  const { commands } = server({ [`GET /v1/documents/${docId}`]: () => (reads++, new Response(JSON.stringify(problem), { status: 404, headers: { 'Content-Type': 'application/problem+json' } })) })
  await assert.rejects(commands.waitUntilReady(docId, { intervalMs: 250, timeoutMs: 5000 }), { status: 404, kind: 'refused' })
  assert.equal(reads, 1)
})

test('waitUntilReady gives every read a signal that the caller can still abort', async () => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const { commands, seen } = server({ [`GET /v1/documents/${docId}`]: async () => { await gate; return json(ready) } })
  const controller = new AbortController()
  const waiting = commands.waitUntilReady(docId, { timeoutMs: 60_000, signal: controller.signal })
  while (seen.length === 0) await new Promise(resolve => setTimeout(resolve, 1))
  controller.abort()
  await assert.rejects(waiting, (e: unknown) => e instanceof RegistryError && e.reason === 'aborted')
  release()
})

const problemOf = (status: number, code: string, slug: string) => new Response(JSON.stringify({
  type: `https://id.registrystack.org/problems/registry-documents/${slug}`, title: code, code, status, detail: 'The register said no.', traceId: 'b'.repeat(32),
}), { status, headers: { 'Content-Type': 'application/problem+json' } })

test('the same upload after a network failure reuses the key, so the register replays the reservation', async () => {
  let puts = 0
  const { commands, seen } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: () => (++puts === 1 ? new Response(null, { status: 503 }) : json(pending)),
  })
  await assert.rejects(commands.upload(pdf(), { policy: 'licence-evidence' }), { status: 503 })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  const [first, second] = posts(seen)
  assert.ok(keyOf(first!))
  assert.equal(keyOf(first!), keyOf(second!))
})

test('after a success the same upload gets a new key', async () => {
  const { commands, seen } = server(uploadRoutes())
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  const [first, second] = posts(seen)
  assert.notEqual(keyOf(first!), keyOf(second!))
})

test('after a definite refusal the same upload gets a new key', async () => {
  let puts = 0
  const { commands, seen } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: () => (++puts === 1 ? problemOf(422, 'upload.digest-mismatch', 'upload/digest-mismatch') : json(pending)),
  })
  await assert.rejects(commands.upload(pdf(), { policy: 'licence-evidence' }), { status: 422 })
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  const [first, second] = posts(seen)
  assert.notEqual(keyOf(first!), keyOf(second!))
})

test('another file after a failure does not reuse the key, and a given key wins over the kept one', async () => {
  let puts = 0
  const { commands, seen } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: () => (++puts === 1 ? new Response(null, { status: 503 }) : json(pending)),
  })
  await assert.rejects(commands.upload(pdf(), { policy: 'licence-evidence' }), { status: 503 })
  await commands.upload(pdf('another file'), { policy: 'licence-evidence' })
  await commands.upload(pdf(), { policy: 'licence-evidence', idempotencyKey: 'mine' })
  const keys = posts(seen).map(keyOf)
  assert.notEqual(keys[0], keys[1])
  assert.equal(keys[2], 'mine')
})

for (const [code, slug, where] of [['upload.expired', 'upload/expired', 'put'], ['idempotency.expired', 'idempotency/expired', 'reserve']] as const) {
  test(`${code} clears the kept key, carries no key on the error, and says a new key is needed`, async () => {
    let attempts = 0
    const fail = () => problemOf(410, code, slug)
    const { commands, seen } = server({
      ...uploadRoutes(),
      ...(where === 'put'
        ? { [`PUT /v1/uploads/${uploadId}/content`]: () => (++attempts === 1 ? fail() : json(pending)) }
        : { 'POST /v1/documents': () => (++attempts === 1 ? fail() : json(reservation, 201)) }),
    })
    const error = await refusal(commands.upload(pdf(), { policy: 'licence-evidence', idempotencyKey: 'old-key' }), code)
    assert.equal(error.status, 410)
    assert.equal(error.idempotencyKey, undefined)
    assert.match(error.detail ?? '', /new key/)
    assert.match(error.detail ?? '', /The register said no\./)
    await commands.upload(pdf(), { policy: 'licence-evidence' })
    assert.ok(posts(seen).every(r => keyOf(r) !== null))
    assert.notEqual(keyOf(posts(seen).at(-1)!), 'old-key')
  })
}

test('upload.expired with an automatic key is followed by a fresh key on the next call', async () => {
  let puts = 0
  const { commands, seen } = server({
    ...uploadRoutes(),
    [`PUT /v1/uploads/${uploadId}/content`]: () => (++puts === 1 ? problemOf(410, 'upload.expired', 'upload/expired') : json(pending)),
  })
  await refusal(commands.upload(pdf(), { policy: 'licence-evidence' }), 'upload.expired')
  await commands.upload(pdf(), { policy: 'licence-evidence' })
  const [first, second] = posts(seen)
  assert.notEqual(keyOf(first!), keyOf(second!))
})

test('the same share after a network failure reuses the key, and a share after success gets a new one', async () => {
  let issues = 0
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: () => (++issues === 1 ? new Response(null, { status: 503 }) : json(grant, 201)),
  })
  await assert.rejects(commands.share(docId, { with: 'official-7' }), { status: 503 })
  await commands.share(docId, { with: 'official-7' })
  await commands.share(docId, { with: 'official-7' })
  const keys = posts(seen).map(keyOf)
  assert.equal(keys[0], keys[1])
  assert.notEqual(keys[1], keys[2])
})

test('a share to someone else or with another expiry does not reuse a kept key', async () => {
  let issues = 0
  const { commands, seen } = server({
    [`GET /v1/documents/${docId}`]: json(ready),
    [`POST /v1/documents/${docId}/grants`]: () => (++issues === 1 ? new Response(null, { status: 503 }) : json(grant, 201)),
  })
  await assert.rejects(commands.share(docId, { with: 'official-7' }), { status: 503 })
  await commands.share(docId, { with: 'official-8' })
  const keys = posts(seen).map(keyOf)
  assert.notEqual(keys[0], keys[1])
})

test('upload sends the Blob itself and reads the file once for the digest', async () => {
  const { commands, calls, stub } = recordingClient()
  void commands
  const file = pdf()
  let reads = 0
  const original = file.arrayBuffer.bind(file)
  file.arrayBuffer = () => { reads++; return original() }
  await documentCommands(stub, { custodian: 'person-1' }).upload(file, { policy: 'licence-evidence' })
  const put = calls.find(c => c.operation === 'uploadDocumentContent')!
  assert.equal(put.input.body, file)
  assert.equal(reads, 1)
})

test('the commands expose the client calls and page methods, and received lists grants shared with the caller', async () => {
  const { commands, seen } = server({
    'GET /v1/document-policies': json(policies),
    'GET /v1/document-grants': json({ items: [grant], nextCursor: 'g2' }),
    'GET /v1/documents': json({ items: [ready] }),
  })
  assert.deepEqual((await commands.call('listDocumentPolicies')).data, policies)
  assert.deepEqual(await commands.received({ cursor: 'g1', limit: 3 }), { items: [grant], nextCursor: 'g2' })
  assert.match(seen[1]!.path, /\?cursor=g1&limit=3$|\?limit=3&cursor=g1$/)
  assert.deepEqual(await commands.listReceivedGrantsPage(), { items: [grant], nextCursor: 'g2' })
  assert.deepEqual(await commands.listDocumentsPage(), { items: [ready], nextCursor: null })
})
