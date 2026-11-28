import test from 'node:test'
import assert from 'node:assert/strict'
import { allPages } from '../core.ts'
import { Client } from '../generated/breg-minimal.ts'
import { Client as FacilityClient } from '../generated/breg-facility.ts'

const id = '00000000-0000-4000-8000-000000000001'
const input = { contactId: id, email: 'alice@example.org' }
const meta = { datasetIdentifier: 'directory', recordTypeIdentifier: 'contact', registryIdentifier: 'local-directory' }
const json = (body: unknown) => Response.json(body)

test('BReg continuation keeps the same route and just the profile and skiptoken', async () => {
  let count = 0
  const client = new Client({
    baseUrl: 'http://localhost', token: () => 'fixture',
    fetch: async url => {
      const parsed = new URL(String(url))
      assert.equal(parsed.pathname, '/v1/records/contacts')
      if (++count === 1) {
        assert.equal(parsed.searchParams.get('$top'), '1')
        assert.equal(parsed.searchParams.get('$filter'), "name eq 'Alice'")
      } else {
        assert.deepEqual([...parsed.searchParams], [['accessProfile', 'directory-editor'], ['$skiptoken', 'opaque+/=']])
      }
      return json({ items: [], meta, pageInfo: { nextCursor: count === 1 ? 'opaque+/=' : null } })
    },
  })
  await allPages(cursor => client.records_contact_listPage({
    query: { accessProfile: 'directory-editor', $top: 1, $filter: "name eq 'Alice'" },
  }, cursor))
  assert.equal(count, 2)
})

test('BReg resends the exact key, input and target conditions', async () => {
  const preconditions = { contactId: { ifMatch: '"revision-1"' } }
  const receipt = {
    action: 'update-contact-email', applicationId: id,
    results: { 'contact-email': { recordType: 'contact', recordId: id, revision: 2 } },
  }
  let writes = 0
  const ledger = new Map<string, string>()
  const client = new Client({
    baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async (url, request) => {
      const headers = new Headers(request?.headers)
      const body = String(request?.body)
      if (String(url).endsWith('/target-conditions')) {
        assert.deepEqual(JSON.parse(body), { input: { contactId: id } })
        assert.equal(headers.has('idempotency-key'), false)
        return json({ preconditions })
      }
      const key = headers.get('idempotency-key')!
      assert.ok(key)
      assert.deepEqual(JSON.parse(body).preconditions, preconditions)
      const previous = ledger.get(key)
      if (previous && previous !== body) {
        return new Response(JSON.stringify({ title: 'Conflict', type: 'https://id.registrystack.org/problems/registry-breg/idempotency/key-reused',
          code: 'idempotency.key-reused', status: 409, detail: 'The key is already in use.', traceId: '1'.repeat(32) }),
        { status: 409, headers: { 'Content-Type': 'application/problem+json' } })
      }
      if (previous === undefined) {
        writes++
        ledger.set(key, body)
      }
      return json(receipt)
    },
  })
  assert.deepEqual(await client.targetConditions('update-contact-email', { contactId: id }), preconditions)
  const first = await client.invoke('update-contact-email', input, { preconditions })
  assert.match(first.idempotencyKey!, /^[a-f0-9-]{36}$/u)
  const options = { preconditions, idempotencyKey: first.idempotencyKey }
  assert.deepEqual((await client.invoke('update-contact-email', input, options)).data, first.data)
  await assert.rejects(client.invoke('update-contact-email', { ...input, email: 'bob@example.org' }, options),
    { status: 409, kind: 'refused', code: 'idempotency.key-reused', idempotencyKey: first.idempotencyKey })
  assert.equal(writes, 1)
})

test('invoke never reads target conditions itself', async () => {
  const routes: string[] = []
  const bodies: unknown[] = []
  const refusal = { title: 'Precondition Required', code: 'precondition.required', status: 428 }
  const client = new Client({
    baseUrl: 'https://registry.example.org', token: () => 'fixture',
    fetch: async (url, request) => {
      routes.push(new URL(String(url)).pathname)
      bodies.push(JSON.parse(String(request?.body)))
      if (JSON.parse(String(request?.body)).preconditions === undefined) {
        return new Response(JSON.stringify(refusal), { status: 428, headers: { 'Content-Type': 'application/problem+json' } })
      }
      return json({ action: 'update-contact-email', applicationId: id,
        results: { 'contact-email': { recordType: 'contact', recordId: id, revision: 2 } } })
    },
  })
  const preconditions = { contactId: { ifMatch: '"revision-1"' } }
  await client.invoke('update-contact-email', input, { preconditions })
  await assert.rejects(client.invoke('update-contact-email', input, {} as never), { status: 428 })
  assert.deepEqual(routes, ['/v1/actions/update-contact-email', '/v1/actions/update-contact-email'])
  assert.deepEqual(bodies, [{ input, preconditions }, { input }])
})

function typeChecks(client: Client, facility: FacilityClient) {
  // @ts-expect-error Action IDs are project-defined.
  client.invoke('other', input, {})
  // @ts-expect-error input names are project-defined.
  client.targetConditions('update-contact-email', { contact: id })
  // @ts-expect-error this Action requires preconditions.
  client.invoke('update-contact-email', input)
  // @ts-expect-error this Action has no preconditions.
  facility.invoke('register-facility', {} as never, { preconditions: {} })
  // @ts-expect-error access profiles are operation-specific.
  client.call('records.contact.list', { query: { accessProfile: 'missing' } })
  // @ts-expect-error the operation does not exist on this project.
  client.call('records.user.list')
  client.records_contact_listPage().then(page => {
    // @ts-expect-error record fields are project-defined.
    return page.items[0]?.domainData.missing
  })
}
void typeChecks
