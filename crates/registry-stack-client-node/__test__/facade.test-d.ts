import { breg, casework, discovery, evidence, messaging, relay } from '..'

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
const messagingClient = new messaging.MessagingClient({ baseUrl: 'https://messaging.example.invalid/' })

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
const reviewer = { issuer: 'https://idp.example.invalid/', subject: 'reviewer' }
void caseworkClient.assignReviewTask(
  'header.payload.signature', 'supervisor', 'task-1', 1, 'assign-1',
  { assignee: reviewer }, 'source-reviewer',
)
void caseworkClient.delegateReviewTask(
  'header.payload.signature', 'staff', 'task-1', 1, 'delegate-1',
  { delegate: reviewer }, 'source-reviewer',
)
void caseworkClient.reviewTaskDraft(
  'header.payload.signature', 'staff', 'task-1', 'source-reviewer',
)
void caseworkClient.saveReviewTaskDraft(
  'header.payload.signature', 'staff', 'task-1', 1, 'draft-1',
  { body: { note: 'Check the source context' } }, 'source-reviewer',
)
void caseworkClient.deleteReviewTaskDraft(
  'header.payload.signature', 'staff', 'task-1', 2, 'draft-2', 'source-reviewer',
)

async function sendNotice(): Promise<messaging.MessageStatus> {
  const receipt = await messagingClient.submit('header.payload.signature', 'notice-1', {
    senderProfile: 'notices',
    to: { email: 'person@example.invalid' },
    template: { id: 'notice', version: '1' },
    locale: 'en',
  })
  const view = await messagingClient.message('header.payload.signature', receipt.value.id)
  return view.value.status
}
void sendNotice

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
