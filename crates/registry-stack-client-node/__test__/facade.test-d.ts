import { breg, casework, discovery, evidence, relay } from '..'

const bregClient = new breg.BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' })
const discoveryClient = new discovery.DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/' })
const evidenceClient = new evidence.EvidenceClient({
  baseUrl: 'https://evidence.example.invalid/',
  trustedJwks: { keys: [] },
  revokedKeyIds: [],
  token: { static: 'placeholder-token' },
})
const relayClient = new relay.RelayClient({ baseUrl: 'https://relay.example.invalid/' })
const caseworkClient = new casework.CaseworkClient({ baseUrl: 'https://casework.example.invalid/' })

bregClient.listRecords('people', { top: 25 })
breg.verifyWebhookDelivery({
  method: 'POST',
  path: '/hooks/registry',
  headers: { 'X-Registry-Signature': 'v1=opaque' },
  body: Buffer.from('{}'),
  key: Buffer.alloc(32),
}).deliveryTime.toUpperCase()
relayClient.listRecords('people', { pageSize: 25 })
void discoveryClient
void caseworkClient.description('header.payload.signature', 'staff')

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
