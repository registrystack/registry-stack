import { ListOptions, RelayClient, SearchOptions } from '..'

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
