import test from 'node:test'
import assert from 'node:assert/strict'
import { RegistryError, Transport, describeError, pageRequestHeader, type Operation } from '../core.ts'
import { Client as Minimal, createRegistryClient } from '../generated/breg-minimal.ts'
import { Client as Documents } from '../generated/documents.ts'
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

test('the page request header is one exported constant', () => {
  assert.deepEqual(pageRequestHeader, { name: 'Registry-Client', value: 'page' })
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

test('with a token the client sends the bearer, omits cookies and still sends the page header', async () => {
  const { seen, fetch } = recording()
  await new Transport({ baseUrl, token: () => 'fixture', fetch }).call(read)
  await new Transport({ baseUrl, token: () => undefined, fetch }).call(read)
  assert.deepEqual(seen, [
    { authorization: 'Bearer fixture', credentials: 'omit', page: 'page' },
    { authorization: null, credentials: 'omit', page: 'page' },
  ])
})

test('a generated client needs no token in page mode', async () => {
  const { seen, fetch } = recording(() => Response.json({ items: [], meta, pageInfo: { nextCursor: null } }))
  const client: Minimal = createRegistryClient({ baseUrl, fetch })
  await client.records_contact_listPage()
  assert.deepEqual(seen, [{ authorization: null, credentials: 'same-origin', page: 'page' }])
})

test('in page mode any 401 is sign-in-expired with a known outcome, whatever the body', async () => {
  const bodies = [
    () => new Response('Unauthorized', { status: 401, headers: { 'Content-Type': 'text/plain' } }),
    () => new Response(null, { status: 401 }),
    () => new Response(JSON.stringify({ status: 401, title: 'Unauthorized', code: 'sign-in-expired' }),
      { status: 401, headers: { 'Content-Type': 'application/problem+json' } }),
  ]
  for (const answer of bodies) {
    const { fetch } = recording(answer)
    const error = await new Transport({ baseUrl, fetch }).call(write, { body: {} }).catch((caught: unknown) => caught)
    assert.ok(error instanceof RegistryError)
    assert.deepEqual([error.kind, error.reason, error.status, error.outcomeUnknown], ['refused', 'sign-in-expired', 401, false])
    assert.equal(describeError(error), 'Your sign-in has ended, so sign in again.')
  }
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
  const coordinator = new Coordinator({ baseUrl, fetch })
  const headers = { 'webhook-id': '00000000-0000-4000-8000-000000000001', 'webhook-timestamp': '1', 'webhook-signature': 'v1,x' }
  await assert.rejects(coordinator.call('admitEvent', { path: { workflow: 'w', trigger: 't' }, headers, body: Uint8Array.of(123, 125) }),
    { reason: 'status', status: 401 })
  assert.deepEqual(seen, [{ authorization: null, credentials: 'omit', page: 'page' }])
})

test('every call takes a signal, including page helpers, Actions and byte transfers', async () => {
  const aborted = AbortSignal.abort()
  let requests = 0
  const fetch: typeof globalThis.fetch = async () => { requests++; return Response.json({}) }
  const minimal = new Minimal({ baseUrl, fetch })
  const documents = new Documents({ baseUrl, fetch })
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
