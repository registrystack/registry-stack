import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { registryClientHeader } from '../core.ts'
import { Client as Facility } from '../generated/breg-facility.ts'
import { Client as Minimal } from '../generated/breg-minimal.ts'
import { make } from './helpers.ts'
import { Client as Casework } from '../generated/casework.ts'
import { Client as Documents } from '../generated/documents.ts'
import { Client as Evidence } from '../generated/evidence.ts'
import { Client as Coordinator } from '../generated/coordinator.ts'
import {
  createRegistryClient as createThree, createRegistryServerClient as createThreeServer,
} from '../generated/services/breg-facility-documents-casework-evidence.ts'
import {
  createRegistryClient as createAll, createRegistryServerClient as createAllServer,
} from '../generated/services/breg-facility-all-products.ts'
import { generateService } from '../generate-service.ts'

const baseUrl = 'https://registry.example.org'
const hostile = { stub: true }

interface Seen { url: string; authorization: string | null; credentials: unknown; page: string | null }
function recording() {
  const seen: Seen[] = []
  const fetch: typeof globalThis.fetch = async (url, init) => {
    const headers = new Headers(init?.headers)
    seen.push({ url: String(url), authorization: headers.get('authorization'), credentials: init?.credentials,
      page: headers.get('Registry-Client') })
    return Response.json({})
  }
  return { seen, fetch }
}
const ignore = () => undefined

test('the page entry has no token member, in the type and at run time', () => {
  // @ts-expect-error a page client takes no token
  const typed = { baseUrl, token: () => 'fixture' } satisfies Parameters<typeof createThree>[0]
  assert.throws(() => createThree(typed), { name: 'TypeError', message: /token/u })
  assert.throws(() => createThree({ baseUrl, token: undefined } as never), { name: 'TypeError' })
})

test('the page entry sends no Authorization, the page header and same-origin cookies', async () => {
  const { seen, fetch } = recording()
  const registry = createThree({ baseUrl, fetch })
  await registry.records_facility_listPage().catch(ignore)
  await registry.casework.call('health').catch(ignore)
  await registry.documents.call('health').catch(ignore)
  assert.equal(seen.length, 3)
  for (const call of seen) {
    assert.equal(call.authorization, null)
    assert.equal(call.credentials, 'same-origin')
    assert.equal(call.page, registryClientHeader.value)
  }
})

test('the page entry offers no Coordinator and no Messaging, in the type and at run time', () => {
  const page = createAll({ baseUrl })
  assert.ok(!('coordinator' in page))
  assert.ok(!('messaging' in page))
  // @ts-expect-error the page entry has no Coordinator
  void page.coordinator
  // @ts-expect-error the page entry has no Messaging
  void page.messaging
  assert.ok(page.scheduling)
})

test('the server entry requires a token, in the type and at run time', () => {
  // @ts-expect-error a server client needs a token
  assert.throws(() => createThreeServer({ baseUrl }), { name: 'TypeError', message: /token/u })
  assert.throws(() => createThreeServer({ baseUrl, token: 'fixture' } as never), { name: 'TypeError' })
})

test('the server entry sends the bearer, omits cookies and does not send the page header', async () => {
  const { seen, fetch } = recording()
  const registry = createThreeServer({ baseUrl, token: async () => 'fixture', fetch })
  await registry.casework.call('health').catch(ignore)
  assert.deepEqual(seen.map(({ authorization, credentials, page }) => ({ authorization, credentials, page })),
    [{ authorization: 'Bearer fixture', credentials: 'omit', page: null }])
})

test('the server entry refuses to construct where a document exists', () => {
  Object.defineProperty(globalThis, 'document', { value: hostile, configurable: true })
  try {
    assert.throws(() => createThreeServer({ baseUrl, token: () => 'fixture' }), (error: unknown) =>
      error instanceof TypeError && error.message === 'A server client cannot run in a page, so use createRegistryClient in a page.')
  } finally {
    Reflect.deleteProperty(globalThis, 'document')
  }
  createThreeServer({ baseUrl, token: () => 'fixture' })
})

test('the server entry offers every installed product', () => {
  const registry = createAllServer({ baseUrl, token: () => 'fixture' })
  for (const product of ['casework', 'documents', 'evidence', 'scheduling', 'coordinator', 'messaging']) {
    assert.equal(typeof (registry as unknown as Record<string, { call?: unknown }>)[product]?.call, 'function', product)
  }
  assert.ok(registry.coordinator instanceof Coordinator)
  assert.ok(registry.casework instanceof Casework)
  assert.ok(registry instanceof Facility)
  assert.ok(!('proposals' in registry))
})

test('only the installed products are present', () => {
  const registry = createThreeServer({ baseUrl, token: () => 'fixture' })
  assert.ok(registry.documents instanceof Documents && registry.evidence instanceof Evidence)
  assert.ok(!('scheduling' in registry) && !('coordinator' in registry) && !('messaging' in registry))
})

test('modules of one service share one transport: one token call and one base URL per request', async () => {
  const { seen, fetch } = recording()
  let asked = 0
  const registry = createThreeServer({ baseUrl, token: () => { asked++; return 'fixture' }, fetch })
  await registry.records_facility_listPage().catch(ignore)
  await registry.casework.call('health').catch(ignore)
  await registry.documents.call('health').catch(ignore)
  await registry.evidence.call('getEvidenceJwks').catch(ignore)
  assert.equal(asked, 4)
  assert.equal(seen.length, 4)
  assert.ok(seen.every(call => call.url.startsWith(baseUrl + '/')))
})

test('a product module exports its Client and no factory', () => {
  for (const file of readdirSync(new URL('../generated/', import.meta.url)).filter(name => name.endsWith('.ts'))) {
    const source = readFileSync(new URL('../generated/' + file, import.meta.url), 'utf8')
    assert.match(source, /^export class Client \{$/mu, file)
    assert.doesNotMatch(source, /createRegistry(Server)?Client/u, file)
    assert.match(source, /constructor\(transport: Transport\)/u, file)
  }
})

test('the generator refuses unknown products and a register that is not a BReg module', () => {
  assert.throws(() => generateService({ register: 'breg-facility', products: ['bogus'] }), /Unknown product/u)
  assert.throws(() => generateService({ register: 'casework', products: [] }), /register/u)
  assert.throws(() => generateService({ register: 'breg-facility', products: ['casework', 'casework'] }), /twice/u)
})

test('the generator is deterministic and names the hook point', () => {
  const description = { register: 'breg-facility', products: ['casework', 'documents'] }
  const output = generateService(description)
  assert.equal(generateService(description), output)
  assert.match(output, /HOOK POINT: task helpers/u)
  assert.match(output, /must keep `call` reachable/u)
  assert.match(output, /registry\.documents = documentCommands\(<the Document Store client>\)/u)
  assert.match(output, /accessProfile: <the service's author profile, not set> \}\)/u)
  assert.match(generateService({ ...description, authorProfile: 'facility-registrar' }),
    /proposalCommands\(<the register client>, \{ accessProfile: "facility-registrar" \}\)/u)
})

// Type-checked by `npm run check:types`, never called: each service's object is typed to its
// register's operations and its installed products.
export function typedToItsOwnService(): void {
  const registry = createThreeServer({ baseUrl, token: () => 'fixture' })
  void registry.records_facility_listPage()
  // @ts-expect-error the facility registry has no contact records
  void registry.records_contact_listPage()
  // @ts-expect-error this service does not install Scheduling
  void registry.scheduling
}

test('both service entries supply the default profile only on routes that declare it', async () => {
  for (const create of [createThree, options => createThreeServer({ ...options, token: () => 'fixture' })] satisfies
    Array<(options: Parameters<typeof createThree>[0]) => Pick<Facility, 'call' | 'list' | 'read' | 'records_facility_listPage'> & { casework: Casework }>) {
    const { seen, fetch } = recording()
    const profile = 'facility-correction-author'
    const registry = create({ baseUrl, fetch, profile })
    await registry.call('proposals.list').catch(ignore)
    await registry.call('proposals.list', { query: { accessProfile: 'facility-correction-applier' } }).catch(ignore)
    await registry.casework.call('health').catch(ignore)
    const reader = create({ baseUrl, fetch, profile: 'facility-reader' })
    await reader.list('facility').catch(ignore)
    await reader.read('facility', '00000000-0000-4000-8000-000000000001').catch(ignore)
    await reader.records_facility_listPage({}, 'cursor').catch(ignore)
    assert.deepEqual(seen.map(({ url }) => new URL(url).searchParams.get('accessProfile')),
      [profile, 'facility-correction-applier', null, 'facility-reader', 'facility-reader', 'facility-reader'])
  }
})

test('a route that requires an access profile refuses locally when neither the call nor the client names one', async () => {
  for (const create of [createThree, options => createThreeServer({ ...options, token: () => 'fixture' })] satisfies
    Array<(options: Parameters<typeof createThree>[0]) => Pick<Facility, 'call'>>) {
    const { seen, fetch } = recording()
    const registry = create({ baseUrl, fetch })
    const refusal = { name: 'TypeError', message: 'This list needs an access profile' }
    await assert.rejects(registry.call('proposals.list'), refusal)
    await assert.rejects(registry.call('proposals.get', { path: { proposal_id: 'p' } }), refusal)
    await assert.rejects(registry.call('proposals.list', { query: {} }), refusal)
    assert.equal(seen.length, 0)
    // A route whose parameter is optional still sends none.
    await registry.call('records.facility.list').catch(ignore)
    await registry.call('proposals.list', { query: { accessProfile: 'facility-correction-applier' } }).catch(ignore)
    assert.deepEqual(seen.map(({ url }) => new URL(url).searchParams.get('accessProfile')),
      [null, 'facility-correction-applier'])
  }
})

test('invoke and targetConditions send the default profile and let the call override it', async () => {
  const seen: string[] = []
  const fetch: typeof globalThis.fetch = async url => { seen.push(String(new URL(String(url)).searchParams.get('accessProfile'))); return Response.json({}) }
  const input = { contactId: '00000000-0000-4000-8000-000000000001', email: 'alice@example.org' }
  const preconditions = { contactId: { ifMatch: '"1"' } }
  const withDefault = make(Minimal, { baseUrl, fetch, token: () => 'fixture', profile: 'directory-editor' })
  await withDefault.invoke('update-contact-email', input, { preconditions }).catch(ignore)
  await withDefault.targetConditions('update-contact-email', { contactId: input.contactId }).catch(ignore)
  await withDefault.invoke('update-contact-email', input, { preconditions, accessProfile: 'other-editor' as never }).catch(ignore)
  await make(Minimal, { baseUrl, fetch, token: () => 'fixture' }).invoke('update-contact-email', input, { preconditions }).catch(ignore)
  assert.deepEqual(seen, ['directory-editor', 'directory-editor', 'other-editor', 'null'])
})

test('OID4VCI is available only in the server entry of a service that installs it', () => {
  const page = createAll({ baseUrl })
  // @ts-expect-error credential offers are served only by the server entry
  assert.equal(page.oid4vci, undefined)
  assert.ok(!('oid4vci' in page))
  const server = createAllServer({ baseUrl, token: () => 'fixture' })
  assert.equal(typeof server.oid4vci.call, 'function')
  assert.ok(!('oid4vci' in createThreeServer({ baseUrl, token: () => 'fixture' })))
})
