import { breg, discovery, evidence, relay } from '..'

const bregClient = new breg.BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' })
const discoveryClient = new discovery.DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/' })
const relayClient = new relay.RelayClient({ baseUrl: 'https://relay.example.invalid/' })

bregClient.listRecords('people', { top: 25 })
relayClient.listRecords('people', { pageSize: 25 })
void discoveryClient
void evidence

// @ts-expect-error Product query vocabularies remain distinct.
bregClient.listRecords('people', { pageSize: 25 })
// @ts-expect-error Product query vocabularies remain distinct.
relayClient.listRecords('people', { top: 25 })
