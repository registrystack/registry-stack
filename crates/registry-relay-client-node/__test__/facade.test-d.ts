import {
  Capability,
  ListOptions,
  RecordCollectionResponse,
  RecordResponse,
  RelayClient,
  SearchOptions,
  ServiceMetadata,
} from '..'

declare const client: RelayClient

const listOptions: ListOptions = { filters: { status: 'active' }, pageSize: 25 }
const searchOptions: SearchOptions = { bbox: [100.45, 13.65, 100.65, 13.85], pageSize: 25 }

client.listRecords('people', listOptions)
client.search('premises', 'within-bbox', searchOptions)

// @ts-expect-error List operations do not accept spatial query facts.
client.listRecords('people', { bbox: [100.45, 13.65, 100.65, 13.85] })
// @ts-expect-error Search options and their bbox are required.
client.search('premises', 'within-bbox')
client.search('premises', 'within-bbox', {
  bbox: [100.45, 13.65, 100.65, 13.85],
  // @ts-expect-error Search operations do not accept equality filters.
  filters: { status: 'active' },
})

// @ts-expect-error Node uses the same canonical record-format vocabulary as Python.
client.readRecord('people', 'one', { format: 'geo-json-rfc7946' })
// @ts-expect-error Node uses the same canonical SDMX structure vocabulary as Python.
client.sdmxStructure({ kind: 'data-structure', agency: 'AGENCY', resource: 'FLOW', version: '1.0.0' })

declare const service: ServiceMetadata
declare const capability: Capability
declare const record: RecordResponse
declare const records: RecordCollectionResponse

service.registryIdentifier
capability.family
if ('data' in record) record.data.domainData
if ('items' in records) records.items[0].domainData

// @ts-expect-error Fixed service metadata does not admit deployment-defined members.
service.deploymentDefined
// @ts-expect-error Capability families are closed by the Relay contract.
capability.unknownCapability
