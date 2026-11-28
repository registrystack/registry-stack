import assert from 'node:assert/strict'
import { RegistryError, describeError } from '../../core.ts'
import { Client as MinimalClient } from '../../generated/breg-minimal.ts'
import { Client as DocumentsClient } from '../../generated/documents.ts'

const meta = { datasetIdentifier: 'directory', recordTypeIdentifier: 'contact', registryIdentifier: 'local-directory' }

Deno.test('a generated client calls through Fetch and walks a page', async () => {
  const seen: string[] = []
  const client = new MinimalClient({ baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async (url, init) => {
      seen.push(String(url))
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer fixture')
      return Response.json({ items: [], meta, pageInfo: { nextCursor: null } })
    } })
  const page = await client.records_contact_listPage({ query: { accessProfile: 'directory-editor', $top: 5 } })
  assert.deepEqual(page, { items: [], nextCursor: null })
  assert.equal(seen[0], 'https://registry.example.org/v1/records/contacts?accessProfile=directory-editor&%24top=5')
})

Deno.test('a path base resolves against the page origin and dot segments are refused', () => {
  const before = Object.getOwnPropertyDescriptor(globalThis, 'location')
  Object.defineProperty(globalThis, 'location', { value: { origin: 'https://app.example.org' }, configurable: true })
  try {
    new MinimalClient({ baseUrl: '/registry', token: () => undefined })
    assert.throws(() => new MinimalClient({ baseUrl: '/registry/../other', token: () => undefined }),
      /Invalid registry base URL/u)
  } finally {
    if (before) Object.defineProperty(globalThis, 'location', before)
  }
})

Deno.test('plain http to a public host is refused even with allowInsecureHttp', () => {
  assert.throws(() => new MinimalClient({ baseUrl: 'http://registry.example.org', token: () => 'fixture',
    allowInsecureHttp: true }), /Invalid registry base URL/u)
  new MinimalClient({ baseUrl: 'http://breg:8080', token: () => 'fixture', allowInsecureHttp: true })
})

Deno.test('page mode sends the page header and same-origin cookies, and reads a 401 as sign-in-expired', async () => {
  let seen: { credentials: unknown; page: string | null; authorization: string | null } | undefined
  const client = new MinimalClient({ baseUrl: 'https://registry.example.org', fetch: async (_url, init) => {
    const headers = new Headers(init?.headers)
    seen = { credentials: init?.credentials, page: headers.get('Registry-Client'), authorization: headers.get('authorization') }
    return new Response('Unauthorized', { status: 401 })
  } })
  const error = await client.records_contact_listPage().catch((caught: unknown) => caught)
  assert.deepEqual(seen, { credentials: 'same-origin', page: 'page', authorization: null })
  assert.ok(error instanceof RegistryError)
  assert.deepEqual([error.reason, error.outcomeUnknown], ['sign-in-expired', false])
})

Deno.test('a moving download outlasts the deadline and an upload sends a File as given', async () => {
  let sent = 0
  const slow = new ReadableStream<Uint8Array>({ async pull(controller) {
    await new Promise(resolve => setTimeout(resolve, 20))
    if (sent === 10) { controller.close(); return }
    sent++
    controller.enqueue(new Uint8Array(512))
  } })
  const bodies: unknown[] = []
  const documents = new DocumentsClient({ baseUrl: 'https://registry.example.org', token: () => 'fixture', timeoutMs: 100,
    fetch: async (_url, init) => {
      if (init?.method === 'PUT') { bodies.push(init.body); return new Response(null, { status: 503 }) }
      return new Response(slow, { headers: { 'Content-Type': 'application/pdf' } })
    } })
  const { data } = await documents.call('downloadDocumentVersion', { path: { documentId: 'd', versionId: 'v' } })
  assert.equal(data.bytes.length, 10 * 512)
  const file = new File([Uint8Array.of(1, 2)], 'diploma.pdf', { type: 'application/pdf' })
  await assert.rejects(documents.call('uploadDocumentContent', { path: { uploadId: 'u' }, body: file, contentType: 'application/pdf' }),
    { status: 503 })
  assert.equal(bodies[0], file)
})

Deno.test('a 5xx answer to a write gives the outcome-unknown sentence', async () => {
  const client = new MinimalClient({ baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async () => new Response(null, { status: 503 }) })
  const error = await client.invoke('update-contact-email', { contactId: '00000000-0000-4000-8000-000000000001',
    email: 'alice@example.org' }, { preconditions: { contactId: { ifMatch: '"1"' } } }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.outcomeUnknown, true)
  assert.equal(describeError(error), 'The change may or may not have been made, so check before trying again.')
})
