import test from 'node:test'
import { make } from './helpers.ts'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { generate } from '../generate.ts'
import { Client } from './fixtures/breg-list.ts'
import { Client as FacilityClient } from '../generated/breg-facility.ts'

const fixturePath = new URL('./fixtures/breg-list.openapi.json', import.meta.url)
const fixture = () => JSON.parse(readFileSync(fixturePath, 'utf8'))
const baseUrl = 'https://registry.example.org'
const holderId = '00000000-0000-4000-8000-000000000001'
const licence = { domainData: { licenceNumber: 'L-1', status: 'active' }, recordIdentifier: 'r1', revisionIdentifier: 'v1' }

function recording(answer: () => Response = () => Response.json({ items: [licence], pageInfo: { nextCursor: 'next-1' }, count: 7 }), profile?: string) {
  const urls: URL[] = []
  const fetch: typeof globalThis.fetch = async (url) => { urls.push(new URL(String(url))); return answer() }
  return { urls, client: make(Client, { baseUrl, profile, token: () => 'fixture', fetch }) }
}
const query = (url: URL) => Object.fromEntries(url.searchParams)

test('the generator types list options from each query profile', () => {
  const output = generate(readFileSync(fixturePath, 'utf8'), { breg: true })
  assert.match(output, /^export interface ListOptions \{$/mu)
  assert.match(output, /accessProfile\?: "licence-holder"; where: \(\{ "holderId": FieldValue<ListRows\["licence"\], "holderId"> \} \| \{ "licenceNumber": FieldValue<[^>]+>; "status": FieldValue<[^>]+> \}\) & \{/u)
  assert.match(output, /accessProfile\?: "licence-officer"; where\?: \{ "expiresOn"\?: Filter<FieldValue<ListRows\["licence"\], "expiresOn">, "range">/u)
  assert.match(output, /orderBy\?: "expiresOn" \| "holderName" \| "holderName desc"; select\?: ReadonlyArray<"expiresOn" \| "fee" \| "holderName" \| "licenceNumber" \| "region" \| "status">; count\?: boolean; top\?: number/u)
  assert.match(output, /"site": \(CallOptions & \{ accessProfile\?: never; where\?: \{ "siteCode"\?: /u)
})

test('an empty requiredFilters list, as BReg publishes for a profile without one, requires no filter', () => {
  const doc = fixture()
  const officer = doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer']
  assert.deepEqual(officer.requiredFilters, [])
  const output = generate(JSON.stringify(doc), { breg: true })
  assert.match(output, /accessProfile\?: "licence-officer"; where\?: \{/u)
  assert.match(output, /\\"licence-officer\\":\{[^}]*\\"maximumPageSize\\":50/u)
  assert.doesNotMatch(output, /\\"licence-officer\\":\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\\"requiredFilters\\"/u)
})

for (const [name, change, pointer] of [
  ['a required filter that is not an equality filter', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer'].requiredFilters = [['holderName']]
  }, 'licence-officer/requiredFilters/0/0'],
  ['an empty required filter alternative', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-holder'].requiredFilters = [[]]
  }, 'licence-holder/requiredFilters/0'],
  ['required filters that are not a list of lists', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-holder'].requiredFilters = ['holderId']
  }, 'licence-holder/requiredFilters'],
  ['an unknown filter operator', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer'].filterableProperties[0].operators = ['between']
  }, 'licence-officer/filterableProperties/0'],
  ['a profile filed under another name', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer'].profile = 'licence-holder'
  }, 'licence-officer'],
  ['a list profile of another kind', (doc: any) => {
    doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer'].kind = 'snapshot'
  }, 'licence-officer'],
  ['a maximum page size below one', (doc: any) => {
    doc.paths['/v1/records/sites'].get['x-registry-queryProfile'].maximumPageSize = 0
  }, 'x-registry-queryProfile'],
  ['a property name that is not an identifier', (doc: any) => {
    doc.paths['/v1/records/sites'].get['x-registry-queryProfile'].selectableProperties = ["label') or (1 eq 1"]
  }, 'x-registry-queryProfile/selectableProperties/0'],
  ['both profile forms on one operation', (doc: any) => {
    const operation = doc.paths['/v1/records/sites'].get
    operation['x-registry-queryProfiles'] = { 'site-planner': operation['x-registry-queryProfile'] }
  }, 'sites/get'],
  ['several profiles on a route without an access profile parameter', (doc: any) => {
    const operation = doc.paths['/v1/records/licences'].get
    operation.parameters = operation.parameters.filter((entry: any) => !entry.$ref.endsWith('/accessProfile'))
  }, 'licences/get'],
] as const) {
  test('the generator refuses ' + name, () => {
    const doc = fixture()
    change(doc)
    assert.throws(() => generate(JSON.stringify(doc), { breg: true }), (error: Error) => error.message.includes(pointer))
  })
}

test('list builds the query from where, orderBy, select, top and count', async () => {
  const { urls, client } = recording()
  const page = await client.list('licence', {
    accessProfile: 'licence-officer',
    where: {
      status: ['active', 'suspended'], region: 'north', holderName: { startsWith: "O'Br" },
      expiresOn: { lt: '2028-01-01', ge: '2027-01-01' }, suspendedOn: { isNull: true }, fee: 25.5,
    },
    orderBy: 'holderName desc', select: ['licenceNumber', 'status'], top: 25, count: true,
  })
  assert.deepEqual(page, { items: [{ id: licence.recordIdentifier, revision: licence.revisionIdentifier, data: licence.domainData }], nextCursor: 'next-1', count: 7 })
  assert.equal(urls[0]!.pathname, '/v1/records/licences')
  assert.deepEqual(query(urls[0]!), {
    accessProfile: 'licence-officer',
    $filter: "status in ('active','suspended') and region eq 'north' and startswith(holderName,'O''Br')" +
      " and expiresOn ge '2027-01-01' and expiresOn lt '2028-01-01' and suspendedOn eq null and fee eq 25.5",
    $orderby: 'holderName desc', $select: 'licenceNumber,status', $top: '25', $count: 'true',
  })
})

test('a call profile beats the default on a list, and a list without a profile parameter sends none', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }), 'licence-officer')
  await client.list('licence', { accessProfile: 'licence-holder', where: { holderId } })
  await client.list('licence', { where: { region: 'north' } })
  await client.list('site')
  assert.deepEqual(urls.map(url => url.searchParams.get('accessProfile')), ['licence-holder', 'licence-officer', null])
})

test('a continuation sends only the access profile and the cursor', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  const options = { accessProfile: 'licence-officer', after: 'next-1' } as const
  assert.deepEqual(await client.list('licence', options), { items: [], nextCursor: null })
  assert.deepEqual(query(urls[0]!), { accessProfile: 'licence-officer', $skiptoken: 'next-1' })
})

test('a single-profile route sends no access profile', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  await client.list('site', { where: { siteCode: 'S-1' }, orderBy: 'label' })
  await client.list('site')
  await client.list('site', { after: 'next-2' })
  await client.records_site_listPage({ query: { $top: 3 } }, 'next-3')
  assert.deepEqual(urls.map(query), [{ $filter: "siteCode eq 'S-1'", $orderby: 'label' }, {}, { $skiptoken: 'next-2' },
    { $skiptoken: 'next-3' }])
})

test('a profile with required filters lists only with one of its alternatives', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  const refusal = 'Profile `licence-holder` lists only with an equality filter on `holderId`, or on `licenceNumber` and `status`'
  for (const where of [undefined, { licenceNumber: 'L-1' }, { licenceNumber: ['L-1'], status: 'active' }]) {
    await assert.rejects(client.list('licence', { accessProfile: 'licence-holder', where } as never),
      { name: 'TypeError', message: refusal })
  }
  assert.equal(urls.length, 0)
  await client.list('licence', { accessProfile: 'licence-holder', where: { holderId } })
  await client.list('licence', { accessProfile: 'licence-holder', where: { status: 'active', licenceNumber: 'L-1' } })
  assert.deepEqual(urls.map(url => url.searchParams.get('$filter')),
    [`holderId eq '${holderId}'`, "status eq 'active' and licenceNumber eq 'L-1'"])
})

test('list explains a refusal from the profile and never repeats a value', async () => {
  const { urls, client } = recording()
  const officer = { accessProfile: 'licence-officer' } as const
  const cases: Array<[object, string]> = [
    [{ ...officer, where: { region: { startsWith: 'n' } } }, '`region` cannot be filtered with prefix under profile `licence-officer`'],
    [{ ...officer, where: { licenceNumber: 'L-1' } }, '`licenceNumber` cannot be filtered under profile `licence-officer`'],
    [{ ...officer, where: { 'Alice Example': 'x' } }, 'A property cannot be filtered under profile `licence-officer`'],
    [{ ...officer, where: { status: null } }, 'Use isNull to filter on a missing value'],
    [{ ...officer, where: { status: [] } }, 'An in filter needs 1 to 100 values'],
    [{ ...officer, where: { status: Array.from({ length: 101 }, () => 'active') } }, 'An in filter needs 1 to 100 values'],
    [{ ...officer, where: { fee: Number.NaN } }, 'Filter values must be strings, booleans or plain decimal numbers'],
    [{ ...officer, where: { fee: 1e21 } }, 'Filter values must be strings, booleans or plain decimal numbers'],
    [{ ...officer, where: { fee: {} } }, 'A filter is a value, a list of values, or one of startsWith, contains, isNull, gt, ge, lt and le'],
    [{ ...officer, where: { holderName: { startsWith: 'a', contains: 'b' } } },
      'A filter is a value, a list of values, or one of startsWith, contains, isNull, gt, ge, lt and le'],
    [{ ...officer, orderBy: 'region' }, '`region` cannot be sorted that way under profile `licence-officer`'],
    [{ ...officer, orderBy: 'expiresOn desc' }, '`expiresOn` cannot be sorted that way under profile `licence-officer`'],
    [{ ...officer, orderBy: 'Alice Example' }, 'A property cannot be sorted that way under profile `licence-officer`'],
    [{ ...officer, select: [] }, '`select` needs at least one property'],
    [{ ...officer, select: ['fee', 'fee'] }, '`select` names a property twice'],
    [{ ...officer, select: ['suspendedOn'] }, '`suspendedOn` cannot be selected under profile `licence-officer`'],
    [{ ...officer, top: 0 }, '`top` must be a whole number from 1 to 50 under profile `licence-officer`'],
    [{ ...officer, top: 51 }, '`top` must be a whole number from 1 to 50 under profile `licence-officer`'],
    [{ ...officer, top: 1.5 }, '`top` must be a whole number from 1 to 50 under profile `licence-officer`'],
    [{ accessProfile: 'licence-holder', where: { holderId, region: 'private' } }, '`region` cannot be filtered under profile `licence-holder`'],
    [{ accessProfile: 'licence-holder', where: { holderId }, count: true }, 'Profile `licence-holder` does not allow count'],
    [{ ...officer, count: 'yes' }, '`count` must be true or false'],
    [{ ...officer, where: 'status eq 1' }, '`where` must be an object'],
    [{ where: { region: 'north' } }, 'This list needs an access profile'],
    [{ accessProfile: 'Alice Example' }, 'Unknown access profile'],
  ]
  for (const [options, message] of cases) {
    await assert.rejects(client.list('licence', options as never), { name: 'TypeError', message })
  }
  await assert.rejects(client.list('site', { accessProfile: 'site-planner' } as never),
    { name: 'TypeError', message: 'This list takes no access profile' })
  await assert.rejects(client.list('missing' as never, {} as never), { name: 'TypeError', message: 'Unknown record type for list' })
  assert.equal(urls.length, 0)
})

test('list keeps the call options and returns typed rows from a real BReg document', async () => {
  const seen: Array<{ url: URL; signal: unknown }> = []
  const facility = make(FacilityClient, { baseUrl, token: () => 'fixture', fetch: async (url, init) => {
    seen.push({ url: new URL(String(url)), signal: init?.signal })
    return Response.json({ items: [], meta: { datasetIdentifier: 'facility-registry', recordTypeIdentifier: 'facility-assignment', registryIdentifier: 'facility-registry' },
      pageInfo: { nextCursor: null } })
  } })
  const page = await facility.list('facility-assignment', {
    accessProfile: 'facility-reader', where: { facility: [holderId], operator: { isNull: false } }, select: ['facility'],
  })
  assert.deepEqual(page, { items: [], nextCursor: null })
  assert.deepEqual(query(seen[0]!.url), { accessProfile: 'facility-reader',
    $filter: `facility in ('${holderId}') and operator ne null`, $select: 'facility' })
  await assert.rejects(facility.list('facility-assignment', { accessProfile: 'facility-reader', signal: AbortSignal.abort() }),
    { name: 'RegistryError', reason: 'aborted' })
  assert.equal(seen.length, 1)
})

function typeChecks(client: Client, facility: FacilityClient) {
  // @ts-expect-error a profile with required filters lists only with one of its alternatives.
  client.list('licence', { accessProfile: 'licence-holder' })
  // @ts-expect-error an in filter does not satisfy a required filter.
  client.list('licence', { accessProfile: 'licence-holder', where: { licenceNumber: ['L-1'], status: 'active' } })
  // @ts-expect-error half an alternative is not enough.
  client.list('licence', { accessProfile: 'licence-holder', where: { licenceNumber: 'L-1' } })
  client.list('licence', { accessProfile: 'licence-holder', where: { licenceNumber: 'L-1', status: 'active' } })
  client.list('licence', { accessProfile: 'licence-holder', where: { holderId } })
  client.list('licence', { where: { region: 'north' } })
  // @ts-expect-error count is not allowed under this profile.
  client.list('licence', { accessProfile: 'licence-holder', where: { holderId }, count: true })
  // @ts-expect-error region is not filterable by prefix.
  client.list('licence', { accessProfile: 'licence-officer', where: { region: { startsWith: 'n' } } })
  // @ts-expect-error licenceNumber is not filterable under the officer profile.
  client.list('licence', { accessProfile: 'licence-officer', where: { licenceNumber: 'L-1' } })
  // @ts-expect-error a status value comes from the record type.
  client.list('licence', { accessProfile: 'licence-officer', where: { status: 'lapsed' } })
  // @ts-expect-error region is not sortable.
  client.list('licence', { accessProfile: 'licence-officer', orderBy: 'region' })
  // @ts-expect-error expiresOn sorts ascending only.
  client.list('licence', { accessProfile: 'licence-officer', orderBy: 'expiresOn desc' })
  // @ts-expect-error fee is not selectable under the holder profile.
  client.list('licence', { accessProfile: 'licence-holder', where: { holderId }, select: ['fee'] })
  // @ts-expect-error the site list has one profile and takes no access profile.
  client.list('site', { accessProfile: 'site-planner' })
  // @ts-expect-error not a list operation with query profiles.
  client.list('missing')
  client.list('licence', { accessProfile: 'licence-officer', where: {
    expiresOn: { ge: '2027-01-01' }, suspendedOn: { isNull: false }, holderName: { contains: 'Br' }, fee: 3,
  }, orderBy: 'holderName desc', count: true, top: 10 }).then(page => page.count)
  client.list('site').then(page => {
    const code: string | undefined = page.items[0]?.data.siteCode
    // @ts-expect-error rows are typed.
    return page.items[0]?.data.missing ?? code
  })
  // @ts-expect-error facility-assignment filters facility by equality, in and null checks only.
  facility.list('facility-assignment', { accessProfile: 'facility-reader', where: { facility: { startsWith: 'a' } } })
}
void typeChecks

test('continuation skips required filters and refuses new query options before dispatch', async () => {
  const { urls, client } = recording()
  await client.list('licence', { accessProfile: 'licence-holder', after: 'cursor' })
  for (const extra of [{ where: { holderId } }, { orderBy: 'expiresOn' }, { select: ['status'] }, { count: false }]) {
    await assert.rejects(client.list('licence', { accessProfile: 'licence-holder', after: 'private', ...extra } as never),
      { name: 'TypeError', message: 'Use after without where, orderBy, select or count.' })
  }
  assert.deepEqual(urls.map(query), [{ accessProfile: 'licence-holder', $skiptoken: 'cursor' }])
})

test('list and read return the same facility row and preserve the sub-collection methods', async () => {
  const row = { recordIdentifier: holderId, revisionIdentifier: '1', domainData: { name: 'Clinic' } }
  const meta = { datasetIdentifier: 'facility-registry', recordTypeIdentifier: 'facility', registryIdentifier: 'facility-registry' }
  const urls: URL[] = []
  const client = make(FacilityClient, { baseUrl, token: () => 'fixture', fetch: async url => {
    const address = new URL(String(url))
    urls.push(address)
    if (address.pathname.endsWith('/operators')) {
      return Response.json({ items: [], pageInfo: { nextCursor: null }, meta: { ...meta, recordTypeIdentifier: 'operator' } })
    }
    return Response.json(address.pathname.endsWith(holderId) ? { data: row, meta } : { items: [row], pageInfo: { nextCursor: null }, meta })
  } })
  const { items: [item] } = await client.list('facility', { accessProfile: 'facility-reader' })
  assert.deepEqual(item, { id: holderId, revision: '1', data: { name: 'Clinic' } })
  assert.deepEqual(await client.read('facility', item!.id, { accessProfile: 'facility-reader' }), item)
  assert.equal(urls[1]?.pathname, '/v1/records/facilities/' + holderId)
  assert.deepEqual(query(urls[1]!), { accessProfile: 'facility-reader' })
  assert.deepEqual((await client.call('records.facility.path.operators', {
    path: { record_id: holderId }, query: { accessProfile: 'facility-reader' },
  })).data.items, [])
  assert.deepEqual((await client.records_facility_path_operatorsPage({
    path: { record_id: holderId }, query: { accessProfile: 'facility-reader' },
  })).items, [])
})

test('read refuses a private profile locally and preserves a 404 refusal', async () => {
  const calls: string[] = []
  const client = make(FacilityClient, { baseUrl, token: () => 'fixture', fetch: async url => {
    calls.push(String(url))
    return new Response(JSON.stringify({ type: 'https://id.registrystack.org/problems/registry-breg/resource/not_found', title: 'Not Found', status: 404, code: 'resource.not_found', detail: 'The requested resource was not found.', traceId: '11111111111111111111111111111111' }),
      { status: 404, headers: { 'Content-Type': 'application/problem+json' } })
  } })
  await assert.rejects(client.read('facility', holderId),
    { name: 'TypeError', message: 'Reading facility needs an access profile.' })
  await assert.rejects(client.read('facility', holderId, { accessProfile: 'private' } as never),
    { name: 'TypeError', message: 'Unknown access profile for reading facility.' })
  assert.equal(calls.length, 0)
  await assert.rejects(client.read('facility', holderId, { accessProfile: 'facility-reader' }), { kind: 'refused', status: 404 })
  assert.equal(calls.length, 1)
})

function readTypeChecks(client: FacilityClient, licence: Client) {
  void client.read('facility', holderId)
  // @ts-expect-error the get route declares its profiles
  void client.read('facility', holderId, { accessProfile: 'operator-editor' })
  // @ts-expect-error sub-collections use call or their generated page method
  void client.list('records.facility.path.operators')
  // @ts-expect-error a continuation carries the original filters
  void licence.list('licence', { accessProfile: 'licence-officer', after: 'cursor', count: false })
  void client.read('facility', holderId, { accessProfile: 'proposal-reviewer' }).then(row => {
    const name: string | undefined = row.data.name
    // @ts-expect-error the facility row only exposes declared domain fields
    return row.data.missing ?? name
  })
}
void readTypeChecks


test('list checks filters against the default profile and reuses it for after', async () => {
  const { client, urls } = recording(undefined, 'licence-officer')
  const page = await client.list('licence', { where: { region: 'north' } })
  await assert.rejects(client.list('licence', { where: { licenceNumber: 'L-1' } } as never),
    { name: 'TypeError', message: '`licenceNumber` cannot be filtered under profile `licence-officer`' })
  await client.list('licence', { after: page.nextCursor! })
  assert.deepEqual(urls.map(query), [
    { accessProfile: 'licence-officer', $filter: "region eq 'north'" },
    { accessProfile: 'licence-officer', $skiptoken: 'next-1' },
  ])
})

test('an explicit list profile overrides the default when checking filters and sending', async () => {
  const { client, urls } = recording(undefined, 'licence-officer')
  await client.list('licence', { accessProfile: 'licence-holder', where: { holderId } })
  assert.equal(urls.length, 1)
  assert.equal(query(urls[0]!).accessProfile, 'licence-holder')
})

test('read sends the default profile and lets the call override it', async () => {
  const row = { recordIdentifier: holderId, revisionIdentifier: '1', domainData: { name: 'Clinic' } }
  const meta = { datasetIdentifier: 'facility-registry', recordTypeIdentifier: 'facility', registryIdentifier: 'facility-registry' }
  const urls: URL[] = []
  const client = make(FacilityClient, { baseUrl, profile: 'facility-reader', token: () => 'fixture', fetch: async url => {
    urls.push(new URL(String(url)))
    return Response.json({ data: row, meta })
  } })
  await client.read('facility', holderId)
  await client.read('facility', holderId, { accessProfile: 'proposal-reviewer' })
  assert.deepEqual(urls.map(query), [{ accessProfile: 'facility-reader' }, { accessProfile: 'proposal-reviewer' }])
})
