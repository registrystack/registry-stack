import test from 'node:test'
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

function recording(answer: () => Response = () => Response.json({ items: [licence], pageInfo: { nextCursor: 'next-1' }, count: 7 })) {
  const urls: URL[] = []
  const fetch: typeof globalThis.fetch = async (url) => { urls.push(new URL(String(url))); return answer() }
  return { urls, client: new Client({ baseUrl, token: () => 'fixture', fetch }) }
}
const query = (url: URL) => Object.fromEntries(url.searchParams)

test('the generator types list options from each query profile', () => {
  const output = generate(readFileSync(fixturePath, 'utf8'), { breg: true })
  assert.match(output, /^export interface ListOptions \{$/mu)
  assert.match(output, /accessProfile: "licence-holder"; where: \(\{ "holderId": FieldValue<ListRows\["records\.licence\.list"\], "holderId"> \} \| \{ "licenceNumber": FieldValue<[^>]+>; "status": FieldValue<[^>]+> \}\) & \{/u)
  assert.match(output, /accessProfile: "licence-officer"; where\?: \{ "expiresOn"\?: Filter<FieldValue<ListRows\["records\.licence\.list"\], "expiresOn">, "range">/u)
  assert.match(output, /orderBy\?: "expiresOn" \| "holderName" \| "holderName desc"; select\?: ReadonlyArray<"expiresOn" \| "fee" \| "holderName" \| "licenceNumber" \| "region" \| "status">; count\?: boolean; top\?: number/u)
  assert.match(output, /"records\.site\.list": \(CallOptions & \{ accessProfile\?: never; where\?: \{ "siteCode"\?: /u)
})

test('an empty requiredFilters list, as BReg publishes for a profile without one, requires no filter', () => {
  const doc = fixture()
  const officer = doc.paths['/v1/records/licences'].get['x-registry-queryProfiles']['licence-officer']
  assert.deepEqual(officer.requiredFilters, [])
  const output = generate(JSON.stringify(doc), { breg: true })
  assert.match(output, /accessProfile: "licence-officer"; where\?: \{/u)
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
  const page = await client.list('records.licence.list', {
    accessProfile: 'licence-officer',
    where: {
      status: ['active', 'suspended'], region: 'north', holderName: { startsWith: "O'Br" },
      expiresOn: { lt: '2028-01-01', ge: '2027-01-01' }, suspendedOn: { isNull: true }, fee: 25.5,
    },
    orderBy: 'holderName desc', select: ['licenceNumber', 'status'], top: 25, count: true,
  })
  assert.deepEqual(page, { items: [licence], nextCursor: 'next-1', count: 7 })
  assert.equal(urls[0]!.pathname, '/v1/records/licences')
  assert.deepEqual(query(urls[0]!), {
    accessProfile: 'licence-officer',
    $filter: "status in ('active','suspended') and region eq 'north' and startswith(holderName,'O''Br')" +
      " and expiresOn ge '2027-01-01' and expiresOn lt '2028-01-01' and suspendedOn eq null and fee eq 25.5",
    $orderby: 'holderName desc', $select: 'licenceNumber,status', $top: '25', $count: 'true',
  })
})

test('a continuation sends only the access profile and the cursor', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  const options = { accessProfile: 'licence-officer', where: { region: 'north' }, top: 5 } as const
  assert.deepEqual(await client.list('records.licence.list', options, 'next-1'), { items: [], nextCursor: null })
  assert.deepEqual(query(urls[0]!), { accessProfile: 'licence-officer', $skiptoken: 'next-1' })
})

test('a single-profile route sends no access profile', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  await client.list('records.site.list', { where: { siteCode: 'S-1' }, orderBy: 'label' })
  await client.list('records.site.list')
  await client.list('records.site.list', {}, 'next-2')
  await client.records_site_listPage({ query: { $top: 3 } }, 'next-3')
  assert.deepEqual(urls.map(query), [{ $filter: "siteCode eq 'S-1'", $orderby: 'label' }, {}, { $skiptoken: 'next-2' },
    { $skiptoken: 'next-3' }])
})

test('a profile with required filters lists only with one of its alternatives', async () => {
  const { urls, client } = recording(() => Response.json({ items: [], pageInfo: { nextCursor: null } }))
  const refusal = 'Profile `licence-holder` lists only with an equality filter on `holderId`, or on `licenceNumber` and `status`'
  for (const where of [undefined, { licenceNumber: 'L-1' }, { licenceNumber: ['L-1'], status: 'active' }]) {
    await assert.rejects(client.list('records.licence.list', { accessProfile: 'licence-holder', where } as never),
      { name: 'TypeError', message: refusal })
  }
  assert.equal(urls.length, 0)
  await client.list('records.licence.list', { accessProfile: 'licence-holder', where: { holderId } })
  await client.list('records.licence.list', { accessProfile: 'licence-holder', where: { status: 'active', licenceNumber: 'L-1' } })
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
    [{ accessProfile: 'licence-holder', where: { holderId }, count: true }, 'Profile `licence-holder` does not allow count'],
    [{ ...officer, count: 'yes' }, '`count` must be true or false'],
    [{ ...officer, where: 'status eq 1' }, '`where` must be an object'],
    [{ where: { region: 'north' } }, 'This list needs an access profile'],
    [{ accessProfile: 'Alice Example' }, 'Unknown access profile'],
  ]
  for (const [options, message] of cases) {
    await assert.rejects(client.list('records.licence.list', options as never), { name: 'TypeError', message })
  }
  await assert.rejects(client.list('records.site.list', { accessProfile: 'site-planner' } as never),
    { name: 'TypeError', message: 'This list takes no access profile' })
  await assert.rejects(client.list('records.missing.list' as never, {} as never), { name: 'TypeError', message: 'Unknown list operation' })
  assert.equal(urls.length, 0)
})

test('list keeps the call options and returns typed rows from a real BReg document', async () => {
  const seen: Array<{ url: URL; signal: unknown }> = []
  const facility = new FacilityClient({ baseUrl, token: () => 'fixture', fetch: async (url, init) => {
    seen.push({ url: new URL(String(url)), signal: init?.signal })
    return Response.json({ items: [], meta: { datasetIdentifier: 'facility-registry', recordTypeIdentifier: 'facility-assignment', registryIdentifier: 'facility-registry' },
      pageInfo: { nextCursor: null } })
  } })
  const page = await facility.list('records.facility-assignment.list', {
    accessProfile: 'facility-reader', where: { facility: [holderId], operator: { isNull: false } }, select: ['facility'],
  })
  assert.deepEqual(page, { items: [], nextCursor: null })
  assert.deepEqual(query(seen[0]!.url), { accessProfile: 'facility-reader',
    $filter: `facility in ('${holderId}') and operator ne null`, $select: 'facility' })
  await assert.rejects(facility.list('records.facility-assignment.list', { accessProfile: 'facility-reader', signal: AbortSignal.abort() }),
    { name: 'RegistryError', reason: 'aborted' })
  assert.equal(seen.length, 1)
})

function typeChecks(client: Client, facility: FacilityClient) {
  // @ts-expect-error a profile with required filters lists only with one of its alternatives.
  client.list('records.licence.list', { accessProfile: 'licence-holder' })
  // @ts-expect-error an in filter does not satisfy a required filter.
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { licenceNumber: ['L-1'], status: 'active' } })
  // @ts-expect-error half an alternative is not enough.
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { licenceNumber: 'L-1' } })
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { licenceNumber: 'L-1', status: 'active' } })
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { holderId } })
  // @ts-expect-error a list with two profiles names one.
  client.list('records.licence.list', { where: { region: 'north' } })
  // @ts-expect-error count is not allowed under this profile.
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { holderId }, count: true })
  // @ts-expect-error region is not filterable by prefix.
  client.list('records.licence.list', { accessProfile: 'licence-officer', where: { region: { startsWith: 'n' } } })
  // @ts-expect-error licenceNumber is not filterable under the officer profile.
  client.list('records.licence.list', { accessProfile: 'licence-officer', where: { licenceNumber: 'L-1' } })
  // @ts-expect-error a status value comes from the record type.
  client.list('records.licence.list', { accessProfile: 'licence-officer', where: { status: 'lapsed' } })
  // @ts-expect-error region is not sortable.
  client.list('records.licence.list', { accessProfile: 'licence-officer', orderBy: 'region' })
  // @ts-expect-error expiresOn sorts ascending only.
  client.list('records.licence.list', { accessProfile: 'licence-officer', orderBy: 'expiresOn desc' })
  // @ts-expect-error fee is not selectable under the holder profile.
  client.list('records.licence.list', { accessProfile: 'licence-holder', where: { holderId }, select: ['fee'] })
  // @ts-expect-error the site list has one profile and takes no access profile.
  client.list('records.site.list', { accessProfile: 'site-planner' })
  // @ts-expect-error not a list operation with query profiles.
  client.list('records.missing.list')
  client.list('records.licence.list', { accessProfile: 'licence-officer', where: {
    expiresOn: { ge: '2027-01-01' }, suspendedOn: { isNull: false }, holderName: { contains: 'Br' }, fee: 3,
  }, orderBy: 'holderName desc', count: true, top: 10 }).then(page => page.count)
  client.list('records.site.list').then(page => {
    const code: string | undefined = page.items[0]?.domainData.siteCode
    // @ts-expect-error rows are typed.
    return page.items[0]?.domainData.missing ?? code
  })
  // @ts-expect-error facility-assignment filters facility by equality, in and null checks only.
  facility.list('records.facility-assignment.list', { accessProfile: 'facility-reader', where: { facility: { startsWith: 'a' } } })
}
void typeChecks
