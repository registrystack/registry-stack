import { breg, discovery, evidence, relay } from '..'

const bregClient = new breg.BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' })
const discoveryClient = new discovery.DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/' })
const evidenceClient = new evidence.EvidenceClient({
  baseUrl: 'https://evidence.example.invalid/',
  trustedJwks: { keys: [] },
  revokedKeyIds: [],
  token: { static: 'placeholder-token' },
})
const relayClient = new relay.RelayClient({ baseUrl: 'https://relay.example.invalid/' })

bregClient.listRecords('people', { top: 25 })
relayClient.listRecords('people', { pageSize: 25 })
void discoveryClient

// The progressive request surface refines the generated declaration: it names
// the request shape and discriminates the result on its response format.
async function readEvidence(): Promise<Buffer | string> {
  const result = await evidenceClient.request({
    requirement: 'example.requirement',
    selectors: { identifier: 'example' },
  })
  return result.responseFormat === 'signed-jws' ? result.assertion : result.credential
}
void readEvidence

// @ts-expect-error Product query vocabularies remain distinct.
bregClient.listRecords('people', { pageSize: 25 })
// @ts-expect-error Product query vocabularies remain distinct.
relayClient.listRecords('people', { top: 25 })
