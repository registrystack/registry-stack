import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
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
import {
  createRegistryClient as createMinimal, createRegistryServerClient as createMinimalServer,
} from '../generated/services/breg-minimal-casework.ts'
import { createRegistryClient as createTwo } from '../generated/services/two-registers.ts'
import { fileURLToPath } from 'node:url'
import { generateService, generateServiceFile } from '../generate-service.ts'
import { execFileSync } from 'node:child_process'
import { generateFile } from '../generate.ts'

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
  await registry.facility.records_facility_listPage().catch(ignore)
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
  assert.ok(registry.facility instanceof Facility)
  assert.equal(typeof registry.facility.proposals.get, 'function')
})

test('only the installed products are present', () => {
  const registry = createThreeServer({ baseUrl, token: () => 'fixture' })
  assert.ok(registry.evidence instanceof Evidence)
  assert.equal(typeof registry.documents.call, 'function')
  assert.ok(!('scheduling' in registry) && !('coordinator' in registry) && !('messaging' in registry))
})

test('modules of one service share one transport: one token call and one base URL per request', async () => {
  const { seen, fetch } = recording()
  let asked = 0
  const registry = createThreeServer({ baseUrl, token: () => { asked++; return 'fixture' }, fetch })
  await registry.facility.records_facility_listPage().catch(ignore)
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
    assert.match(source, file.startsWith('breg-') ? /constructor\(transport: Pick<Transport/u : /constructor\(transport: Transport\)/u, file)
  }
})

const description = (register: string, products: string[] = [], authorProfiles?: string[]) =>
  ({ registers: { facility: { register, authorProfiles } }, products })

test('the generator refuses unknown products and a register that is not a BReg module', () => {
  assert.throws(() => generateService(description('breg-facility', ['bogus'])), /Unknown product/u)
  assert.throws(() => generateService(description('casework')), /register/u)
  assert.throws(() => generateService(description('breg-facility', ['casework', 'casework'])), /twice/u)
})

test('the generator is deterministic and attaches the helpers when installed', () => {
  const service = description('breg-facility', ['casework', 'documents'], ['facility-correction-author'])
  const output = generateService(service)
  assert.equal(generateService(service), output)
  assert.match(output, /proposalCommands/u)
  assert.match(output, /documentCommands/u)
  assert.doesNotMatch(generateService({ ...service, products: ['casework'] }), /documentCommands/u)
})

test('a register that uses Proposals needs an author profile', () => {
  for (const register of ['breg-facility', 'breg-minimal']) {
    assert.throws(() => generateService(description(register)), error =>
      error instanceof Error && /authorProfiles/u.test(error.message) && error.message.includes(register))
  }
})

test('a single author profile preserves the committed example output', () => {
  const output = generateService(description('breg-facility', ['documents', 'casework', 'evidence'], ['facility-correction-author']), {
    coreImport: '../../core.ts', tasksImport: '../../tasks/index.ts', modulesImport: '../', modulesExtension: '.ts',
  })
  assert.equal(output, readFileSync(new URL('../generated/services/breg-facility-documents-casework-evidence.ts', import.meta.url), 'utf8'))
})

test('a profile without Proposal start is refused', () => {
  const author = 'facility-correction-author'
  const reader = 'facility-correction-applier'
  assert.throws(() => generateService(description('breg-facility', [], [author, reader])),
    /facility-correction-applier.*start.*facility-correction-author/u)
})

test('a register with Proposal reads but no starts refuses a declared author profile', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'register-source-')))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const source = join(directory, 'breg-quiet.ts')
  writeFileSync(source, '  "proposals.get": { input: CallOptions & { query?: { "accessProfile"?: "quiet-author" } } }\n')
  assert.throws(() => generateService(description('breg-quiet'), { registers: { facility: { source } } }), /authorProfile/u)
  assert.throws(() => generateService(description('breg-quiet', [], ['quiet-author']),
    { registers: { facility: { source } } }), /quiet-author.*start.*none/u)
})

test('generated author profiles have separate queues, send their own profiles and compile the README example', { timeout: 15_000 }, async t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'service-authors-')))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const source = join(directory, 'breg-facility.ts')
  const openapi = join(directory, 'openapi.json')
  const service = join(directory, 'service.ts')
  const root = fileURLToPath(new URL('../', import.meta.url))
  const contract = JSON.parse(readFileSync(new URL('../../../products/breg/generated/facility/generated/openapi.json', import.meta.url), 'utf8'))
  const first = 'facility-correction-author'
  const second = 'facility-correction-applier'
  // The real fixture's applier can read Proposals. Give it start authority in this synthetic register.
  contract.paths['/v1/actions/correct-address/proposals'].post['x-registry-accessProfiles'].push(second)
  writeFileSync(openapi, JSON.stringify(contract))
  generateFile(openapi, source, false, true, [], true)
  generateServiceFile(description('breg-facility', [], [first, second]), service, false, {
    registers: { facility: { source } }, coreImport: relative(directory, join(root, 'core.ts')),
    tasksImport: relative(directory, join(root, 'tasks/index.ts')), modulesImport: './', modulesExtension: '.ts',
  })

  const readme = readFileSync(join(root, 'README.md'), 'utf8')
  const example = /### Several Proposal author profiles[\s\S]*?```ts\n([\s\S]*?)```/u.exec(readme)?.[1]
  assert.ok(example)
  const compile = join(directory, 'example.ts')
  writeFileSync(compile, example + `
registry.facility.proposalsAs('${first}')
// @ts-expect-error this profile was never declared
registry.facility.proposalsAs('facility-reader')
// @ts-expect-error this Action was never declared
registry.facility.proposalsAs('${second}').start('unknown-action', {})
`)
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '--strict', '--noEmit',
    '--allowImportingTsExtensions', '--target', 'ES2023', '--module', 'NodeNext',
    '--typeRoots', join(root, 'node_modules/@types'), compile])

  const { createRegistryClient, createRegistryServerClient } = await import(service)
  const doc = JSON.parse(readFileSync(new URL('./fixtures/tasks/proposal-draft-optional.json', import.meta.url), 'utf8'))
  for (const create of [createRegistryClient, createRegistryServerClient]) {
    const reads: string[] = []
    const starts: string[] = []
    const writes: string[] = []
    let releaseWrite!: () => void
    let signalFirstWrite!: () => void
    const blocked = new Promise<void>(resolve => { releaseWrite = resolve })
    const firstWrite = new Promise<void>(resolve => { signalFirstWrite = resolve })
    const registry = create({ baseUrl, ...(create === createRegistryClient ? {} : { token: () => 'fixture' }), fetch: async (url: string | URL, init: RequestInit) => {
      const target = new URL(url)
      const profile = target.searchParams.get('accessProfile')!
      if (target.pathname.endsWith('/edit')) {
        writes.push(JSON.parse(String(init.body)).input.addressLine)
        if (writes.length === 1) {
          signalFirstWrite()
          await blocked
        }
      } else if (target.pathname.startsWith('/v1/actions/')) {
        starts.push(profile)
        return Response.json(doc, { status: 201 })
      } else {
        reads.push(profile)
      }
      return Response.json(doc)
    } })
    assert.equal(registry.facility.proposalsAs(first), registry.facility.proposals)
    assert.equal(registry.facility.proposalsAs(second), registry.facility.proposalsAs(second))
    assert.notEqual(registry.facility.proposalsAs(second), registry.facility.proposals)
    const input = { facilityId: '295068a7-7ce1-4987-ac95-242545af5076', addressLine: '123 Main Street' }
    const a = await registry.facility.proposals.start('correct-address', input)
    const b = await registry.facility.proposalsAs(second).start('correct-address', input)
    assert.deepEqual(starts, [first, second])
    assert.deepEqual(reads, [first, second])
    const one = registry.facility.proposals.edit(a, { addressLine: 'first' })
    await firstWrite
    const two = registry.facility.proposalsAs(first).edit(a, { addressLine: 'queued' })
    try {
      await registry.facility.proposalsAs(second).edit(b, { addressLine: 'independent' })
      assert.deepEqual(writes, ['first', 'independent'])
    } finally {
      releaseWrite()
      await Promise.all([one, two])
    }
    assert.deepEqual(writes, ['first', 'independent', 'queued'])
    assert.deepEqual(reads, [first, second, second, first, first])
  }
})

test('a register with no Proposal operations needs no author profile and attaches no proposals', () => {
  const output = generateService(description('breg-list', ['documents']),
    { registers: { facility: { source: fileURLToPath(new URL('./fixtures/breg-list.ts', import.meta.url)) } } })
  assert.doesNotMatch(output, /proposalCommands|proposals:/u)
  assert.match(output, /documentCommands/u)
})

test('every example author profile is one its generated register accepts on every Proposal read', () => {
  const files = readdirSync(new URL('../generated/services/', import.meta.url)).filter(name => name.endsWith('.ts'))
  assert.ok(files.length >= 3)
  for (const file of files) {
    const service = readFileSync(new URL('../generated/services/' + file, import.meta.url), 'utf8')
    const modules = [...service.matchAll(/Client as Register\d+.*from "\.\.\/(breg-[a-z0-9-]+)\.ts"/gu)]
    const profiles = [...service.matchAll(/proposals: proposalsAs\("([^"]+)"\)/gu)]
    assert.equal(modules.length, profiles.length, file)
    for (const [index, match] of modules.entries()) {
      const module = match[1]!
      const profile = profiles[index]![1]!
      const register = readFileSync(new URL(`../generated/${module}.ts`, import.meta.url), 'utf8')
      for (const operation of ['proposals.get', 'proposals.list']) {
        const line = register.split('\n').find(row => row.startsWith(`  "${operation}": `))
        assert.ok(line, operation)
        const accepted = /"accessProfile"\??: ([^;}]+)/u.exec(line)![1]!
        assert.ok(accepted.split('|').map(item => item.trim().replaceAll('"', '')).includes(profile), `${file} ${operation} accepts ${accepted}`)
      }
    }
  }
})

test('both entries attach the task helpers: proposals under the author profile, documents with its typed calls', async () => {
  for (const create of [createThree, options => createThreeServer({ ...options, token: () => 'fixture' })] satisfies
    Array<(options: Parameters<typeof createThree>[0]) => { facility: { proposals: { get(id: string): Promise<unknown> } }; documents: { upload: unknown; call: unknown } }>) {
    const { seen, fetch } = recording()
    const registry = create({ baseUrl, fetch })
    assert.equal(typeof registry.documents.upload, 'function')
    assert.equal(typeof registry.documents.call, 'function')
    await registry.facility.proposals.get('prop-1').catch(ignore)
    await registry.documents.call('health').catch(ignore)
    const sent = new URL(seen[0]!.url)
    assert.equal(sent.pathname, '/v1/proposals/prop-1')
    assert.equal(sent.searchParams.get('accessProfile'), 'facility-correction-author')
  }
})

test('a service without the Document Store has no documents member, in the type and at run time', () => {
  for (const registry of [createMinimal({ baseUrl }), createMinimalServer({ baseUrl, token: () => 'fixture' })]) {
    assert.ok(!('documents' in registry))
    assert.equal(typeof registry.directory.proposals.start, 'function')
    assert.equal(typeof registry.casework.call, 'function')
    // @ts-expect-error this service does not install the Document Store
    void registry.documents
  }
})

// Type-checked by `npm run check:types`, never called: each service's object is typed to its
// register's operations and its installed products.
export function typedToItsOwnService(): void {
  const registry = createThreeServer({ baseUrl, token: () => 'fixture' })
  void registry.facility.records_facility_listPage()
  // @ts-expect-error the facility registry has no contact records
  void registry.facility.records_contact_listPage()
  // @ts-expect-error this service does not install Scheduling
  void registry.scheduling
}

test('both service entries supply the default profile only on routes that declare it', async () => {
  for (const create of [createThree, options => createThreeServer({ ...options, token: () => 'fixture' })] satisfies
    Array<(options: Parameters<typeof createThree>[0]) => { facility: Pick<Facility, 'call' | 'list' | 'read' | 'records_facility_listPage'>; casework: Casework }>) {
    const { seen, fetch } = recording()
    const profile = 'facility-correction-author'
    const registry = create({ baseUrl, fetch, profile })
    await registry.facility.call('proposals.list').catch(ignore)
    await registry.facility.call('proposals.list', { query: { accessProfile: 'facility-correction-applier' } }).catch(ignore)
    await registry.casework.call('health').catch(ignore)
    const reader = create({ baseUrl, fetch, profile: 'facility-reader' })
    await reader.facility.list('facility').catch(ignore)
    await reader.facility.read('facility', '00000000-0000-4000-8000-000000000001').catch(ignore)
    await reader.facility.records_facility_listPage({}, 'cursor').catch(ignore)
    assert.deepEqual(seen.map(({ url }) => new URL(url).searchParams.get('accessProfile')),
      [profile, 'facility-correction-applier', null, 'facility-reader', 'facility-reader', 'facility-reader'])
  }
})

test('a route that requires an access profile refuses locally when neither the call nor the client names one', async () => {
  for (const create of [createThree, options => createThreeServer({ ...options, token: () => 'fixture' })] satisfies
    Array<(options: Parameters<typeof createThree>[0]) => { facility: Pick<Facility, 'call'> }>) {
    const { seen, fetch } = recording()
    const registry = create({ baseUrl, fetch })
    const refusal = { name: 'TypeError', message: 'This call needs an access profile' }
    await assert.rejects(registry.facility.call('proposals.list'), refusal)
    await assert.rejects(registry.facility.call('proposals.get', { path: { proposal_id: 'p' } }), refusal)
    await assert.rejects(registry.facility.call('proposals.list', { query: {} }), refusal)
    assert.equal(seen.length, 0)
    // A route whose parameter is optional still sends none.
    await registry.facility.call('records.facility.list').catch(ignore)
    await registry.facility.call('proposals.list', { query: { accessProfile: 'facility-correction-applier' } }).catch(ignore)
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

test('generation refuses colliding register member names', () => {
  for (const member of ['casework', 'oid4vci', 'constructor', '__proto__']) {
    assert.throws(() => generateService({
      registers: { [member]: { register: 'breg-minimal' } }, products: [],
    }), new RegExp(member))
  }
})

test('two register members route independently beside shared products', async () => {
  const { seen, fetch } = recording()
  const registry = createTwo({ baseUrl: baseUrl + '/gateway', fetch, registers: {
    directory: { routePrefix: '/contacts', profile: 'directory-editor' },
  } })
  await registry.facility.proposals.get('one').catch(ignore)
  await registry.directory.proposals.get('two').catch(ignore)
  await registry.casework.call('health').catch(ignore)
  assert.deepEqual(seen.map(({ url }) => url), [
    baseUrl + '/gateway/facilities/v1/proposals/one?accessProfile=facility-correction-author',
    baseUrl + '/gateway/contacts/v1/proposals/two?accessProfile=directory-editor',
    baseUrl + '/gateway/health',
  ])
  assert.throws(() => createTwo({ baseUrl, registers: { directory: { routePrefix: '//other.example' } } }), TypeError)
})

export function registerMemberTypes(registry: ReturnType<typeof createTwo>) {
  // @ts-expect-error register operations live on a named member
  void registry.call
  // @ts-expect-error the contact operation belongs to directory
  void registry.facility.call('records.contact.list')
  // @ts-expect-error the facility author belongs to facility
  void registry.directory.proposalsAs('facility-correction-author')
  // @ts-expect-error this Proposal Action belongs to facility
  void registry.directory.proposals.start('correct-address', {})
}
