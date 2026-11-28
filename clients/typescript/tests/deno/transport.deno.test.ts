import assert from 'node:assert/strict'
import { RegistryError, describeError } from '../../core.ts'
import { Client as MinimalClient } from '../../generated/breg-minimal.ts'

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

Deno.test('a 5xx answer to a write gives the outcome-unknown sentence', async () => {
  const client = new MinimalClient({ baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async () => new Response(null, { status: 503 }) })
  const error = await client.invoke('update-contact-email', { contactId: '00000000-0000-4000-8000-000000000001',
    email: 'alice@example.org' }, { preconditions: { contactId: { ifMatch: '"1"' } } }).catch((caught: unknown) => caught)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.outcomeUnknown, true)
  assert.equal(describeError(error), 'The change may or may not have been made, so check before trying again.')
})
