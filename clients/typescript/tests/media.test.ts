import test from 'node:test'
import assert from 'node:assert/strict'
import { Client as Evidence } from '../generated/evidence.ts'
import { Client as Documents } from '../generated/documents.ts'
import { Client as Messaging } from '../generated/messaging.ts'
import { Client as Scheduling } from '../generated/scheduling.ts'
import { Client as Facility } from '../generated/breg-facility.ts'
import { Client as Coordinator } from '../generated/coordinator.ts'
import { Transport } from '../core.ts'
import { validator } from '../schema.ts'
import { readFileSync } from 'node:fs'

const fixture = (fetch: typeof globalThis.fetch) => ({
  baseUrl: 'https://registry.example', token: () => undefined, fetch,
})
const bytes = Uint8Array.of(0, 255, 7)

test('Documents download accepts its declared wildcard and returns exact bytes and media', async () => {
  const documents = new Documents(fixture(async () =>
    new Response(bytes, { headers: { 'Content-Type': 'application/pdf' } })))
  const result = await documents.call('downloadDocumentVersion', {
    path: { documentId: 'fixture', versionId: 'fixture' },
  })
  assert.deepEqual(result.data, { bytes, mediaType: 'application/pdf' })
})

test('BReg attachment has a fixed media type', async () => {
  let media = 'application/octet-stream'
  const facility = new Facility(fixture(async () =>
    new Response(bytes, { headers: { 'Content-Type': media } })))
  const result = await facility.call('proposals.attachments.supporting-document.get', {
    path: { proposal_id: 'fixture' },
    query: { accessProfile: 'facility-correction-author', submissionVersion: 1 },
  })
  assert.deepEqual(result.data, { bytes, mediaType: 'application/octet-stream' })
  media = 'application/pdf'
  await assert.rejects(facility.call('proposals.attachments.supporting-document.get', {
    path: { proposal_id: 'fixture' },
    query: { accessProfile: 'facility-correction-author', submissionVersion: 1 },
  }), { kind: 'unexpected', status: 200, raw: bytes })
})

test('Evidence supports declared compact credentials and typed Accept negotiation', async () => {
  const credential = 'header.payload.signature~'
  let media = 'application/dc+sd-jwt'
  const evidence = new Evidence(fixture(async (_url, init) => {
    assert.equal(new Headers(init?.headers).get('accept'), 'application/dc+sd-jwt')
    return new Response(credential, { headers: { 'Content-Type': media } })
  }))
  const options = { body: { purpose: 'fixture', requestNonce: 'fixture', requirement: 'fixture', subjects: [] }, accept: 'application/dc+sd-jwt' as const }
  assert.deepEqual((await evidence.call('createEvidence', options)).data, { text: credential, mediaType: media })
  media = 'application/jwt'
  await assert.rejects(evidence.call('createEvidence', options), { kind: 'unexpected' })
})

test('bodyless response retains status and rejects a transmitted body', async () => {
  const scheduling = new Scheduling(fixture(async (_url, init) => {
    assert.equal(new Headers(init?.headers).has('idempotency-key'), false)
    return new Response(null, { status: 204 })
  }))
  const result = await scheduling.call('releaseHold', { path: { hold_id: 'fixture' } })
  assert.equal(result.data, undefined)
  assert.equal(result.status, 204)
  assert.equal(result.idempotencyKey, undefined)
  const transport = new Transport(fixture(async () => new Response('body')))
  await assert.rejects(transport.call({ method: 'GET', path: '/health', responses: { 200: [{ mode: 'empty' }] } }),
    { kind: 'unexpected', status: 200 })
})

test('response byte cap cancels a streaming answer', async () => {
  let cancelled = false
  const transport = new Transport({ ...fixture(async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(bytes) },
    cancel() { cancelled = true },
  }))), maxResponseBytes: 2 })
  await assert.rejects(transport.call({ method: 'GET', path: '/health', responses: { 200: [{ mode: 'empty' }] } }),
    { kind: 'unexpected', status: 200 })
  assert.equal(cancelled, true)
})

test('Evidence conditional GET accepts its declared 304 and retains ETag', async () => {
  const evidence = new Evidence(fixture(async (_url, init) => {
    assert.equal(new Headers(init?.headers).get('if-none-match'), '"current"')
    return new Response(null, { status: 304, headers: { ETag: '"current"' } })
  }))
  const result = await evidence.call('getEvidenceJwks', { headers: { 'If-None-Match': '"current"' } })
  assert.equal(result.status, 304)
  const noBody: undefined = result.data
  assert.equal(noBody, undefined)
  assert.equal(result.headers.get('etag'), '"current"')
})

test('Documents label pattern allows ordinary text and rejects control characters', () => {
  const contract = JSON.parse(readFileSync(new URL(
    '../../../products/documents/generated/registry-documents.openapi.json', import.meta.url,
  ), 'utf8'))
  const label = validator({}, contract.components.schemas.DocumentLabel)
  assert.equal(label('Birth certificate'), true)
  assert.equal(label('Birth\u0007certificate'), false)
})

test('response objects tolerate later fields while known members remain validated', async () => {
  const rule = validator({}, { type: 'object', additionalProperties: false,
    required: ['items'], properties: { items: { type: 'array' } } })
  assert.equal(rule({ items: [], futureField: true }), true)
  assert.equal(rule({ futureField: true }), false)
  assert.equal(rule({ items: 'wrong', futureField: true }), false)
})

test('wildcard uploads require a concrete media type and a binary or string body', async () => {
  let requests = 0
  const documents = new Documents(fixture(async (_url, init) => {
    requests++
    assert.equal(new Headers(init?.headers).get('content-type'), 'application/octet-stream')
    assert.equal(init?.body, 'fixture')
    return new Response(null, { status: 503 })
  }))
  const options = { path: { uploadId: 'fixture' }, body: 'fixture', contentType: 'application/octet-stream' }
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, contentType: '*/*' }),
    { name: 'TypeError', message: 'Invalid request media type' })
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, body: {} as never }),
    { name: 'TypeError', message: 'Binary request body must be a Uint8Array, Blob or string' })
  assert.equal(requests, 0)
  await assert.rejects(documents.call('uploadDocumentContent', options), {
    kind: 'unreachable', outcomeUnknown: true, idempotencyKey: undefined,
  })
  assert.equal(requests, 1)
})

test('unknown generated names reject asynchronously', async () => {
  const facility = new Facility(fixture(async () => { throw new Error('unexpected fetch') }))
  await assert.rejects(facility.call('unknown' as never, {} as never), TypeError)
  await assert.rejects(facility.invoke('unknown' as never, {} as never), TypeError)
})

test('Messaging only exposes retry delay on a declared, correlated refusal', async () => {
  const traceId = '1'.repeat(32)
  let type = 'https://id.registrystack.org/problems/registry-messaging/rate-limit/exceeded'
  const messaging = new Messaging(fixture(async () => new Response(JSON.stringify({
    type, status: 429, title: 'Too Many Requests', code: 'rate-limit.exceeded', detail: 'Try again later', traceId,
  }), { status: 429, headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '30',
    traceparent: '00-' + traceId + '-' + '2'.repeat(16) + '-01' } })))
  const call = () => messaging.call('submitMessage', { body: { senderProfile: 'fixture', to: { email: 'fixture@example.org' }, content: { text: 'fixture' } } })
  await assert.rejects(call(), { kind: 'refused', code: 'rate-limit.exceeded', retryAfterSeconds: 30 })
  type = 'https://id.registrystack.org/problems/registry-messaging/quota/exceeded'
  await assert.rejects(call(), { kind: 'unexpected', retryAfterSeconds: undefined, code: undefined })
})

test('receipt lookup refuses a missing original key before dispatch', async () => {
  let requests = 0
  const messaging = new Messaging(fixture(async () => {
    requests++
    return new Response(null, { status: 500 })
  }))
  await assert.rejects(messaging.call('readMessageReceipt', { body: {} } as never),
    { name: 'TypeError', message: 'Receipt lookup requires its original idempotency key' })
  assert.equal(requests, 0)
})

test('Scheduling receipt lookup needs the original key and sends exactly it as a read', async () => {
  const keys: Array<string | null> = []
  const scheduling = new Scheduling(fixture(async (_url, init) => {
    keys.push(new Headers(init?.headers).get('idempotency-key'))
    return new Response(null, { status: 503 })
  }))
  const body = {} as never
  await assert.rejects(scheduling.call('readAppointmentReceipt', { body } as never),
    { name: 'TypeError', message: 'Receipt lookup requires its original idempotency key' })
  assert.deepEqual(keys, [])
  await assert.rejects(scheduling.call('readAppointmentReceipt', { body, idempotencyKey: 'original-key' }),
    { kind: 'unreachable', status: 503, outcomeUnknown: false, idempotencyKey: 'original-key' })
  assert.deepEqual(keys, ['original-key'])
})

test('a signed Coordinator event sends the signed bytes unchanged and no bearer credential', async () => {
  const signed = new TextEncoder().encode('{ "id" : "evt-1",\n  "type": "fixture" }\n')
  let asked = 0
  let seen: { body: unknown; authorization: string | null; credentials: unknown } | undefined
  const coordinator = new Coordinator({ baseUrl: 'https://registry.example', token: () => { asked++; return 'bearer' },
    fetch: async (_url, init) => {
      seen = { body: init?.body, authorization: new Headers(init?.headers).get('authorization'), credentials: init?.credentials }
      return new Response(null, { status: 204 })
    } })
  const headers = { 'webhook-id': '00000000-0000-4000-8000-000000000001', 'webhook-timestamp': '1614265330', 'webhook-signature': 'v1,fixture' }
  const answer = await coordinator.call('admitEvent', { path: { workflow: 'w', trigger: 't' }, headers, body: signed })
  assert.equal(answer.status, 204)
  assert.ok(seen?.body instanceof Uint8Array)
  assert.deepEqual(seen.body, signed)
  assert.equal(seen.authorization, null)
  assert.equal(seen.credentials, 'omit')
  assert.equal(asked, 0)
  await assert.rejects(coordinator.call('admitEvent', { path: { workflow: 'w', trigger: 't' }, headers,
    body: { id: 'evt-1' } as never }), { name: 'TypeError', message: 'Signed request body must be the signed bytes' })
})
