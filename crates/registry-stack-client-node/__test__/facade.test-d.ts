import { breg, casework, discovery, evidence, messaging, scheduling } from '..'

const bregClient = new breg.BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' })
const discoveryClient = new discovery.DiscoveryClient({ baseUrl: 'https://discovery.example.invalid/' })
const evidenceClient = new evidence.EvidenceClient({
  baseUrl: 'https://evidence.example.invalid/',
  trustedJwks: { keys: [] },
  revokedKeyIds: [],
  token: { static: 'placeholder-token' },
})
const caseworkClient = new casework.CaseworkClient({ baseUrl: 'https://casework.example.invalid/' })
const messagingClient = new messaging.MessagingClient({ baseUrl: 'https://messaging.example.invalid/' })
const schedulingClient = new scheduling.SchedulingClient({ baseUrl: 'https://scheduling.example.invalid/' })

bregClient.listRecords('people', { top: 25 })
breg.verifyWebhookDelivery({
  method: 'POST',
  path: '/hooks/registry',
  headers: { 'X-Registry-Signature': 'v1=opaque' },
  body: Buffer.from('{}'),
  key: Buffer.alloc(32),
}).deliveryTime.toUpperCase()
void discoveryClient
void caseworkClient.description('header.payload.signature', 'staff')
const supervisoryLookup: casework.SupervisoryReviewTaskQuery = {
  requestId: '00000000-0000-0000-0000-000000000009', queue: 'review', limit: 25,
}
void caseworkClient.supervisoryReviewTasks('header.payload.signature', 'supervisor', supervisoryLookup)
const ownLookup: casework.OwnReviewDecisionQuery = { queue: 'review', limit: 25 }
void caseworkClient.ownReviewDecisions('header.payload.signature', 'staff', ownLookup).then((page) => {
  const row: casework.OwnReviewDecision | undefined = page.value.items[0]
  const pinnedLabel: string | undefined = row?.decisionReceipt.outcomeLabel
  void pinnedLabel
})
void caseworkClient.reviewAccountability('header.payload.signature', 'supervisor', '00000000-0000-0000-0000-000000000009').then((record) => {
  const selected: casework.ReviewDecisionReceipt | undefined = record.value.decisionReceipt
  void selected
})
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
void messagingClient.submit('header.payload.signature', 'reminder-1', {
  senderProfile: 'reminders-sms',
  to: { phone: '+15550100' },
  content: { text: 'Appointment tomorrow' },
})
void schedulingClient.availability('header.payload.signature', 'clinic-visit', {
  start: '2026-10-06T08:00:00Z',
  limit: 10,
})
void schedulingClient.createAppointment('header.payload.signature', 'book-1', { hold: 'hold-1' })

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

// The unified package bypasses each standalone napi-rs loader, so its product
// namespaces cannot expose the generated loader diagnostic.
type HasNoLoaderTarget<T> = '__napiBindingTarget' extends keyof T ? false : true
type Assert<T extends true> = T
type DiscoveryHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof discovery>>
type EvidenceHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof evidence>>
type BregHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof breg>>
type CaseworkHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof casework>>
type MessagingHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof messaging>>
type SchedulingHasNoLoaderTarget = Assert<HasNoLoaderTarget<typeof scheduling>>

// @ts-expect-error Product query vocabularies remain distinct.
bregClient.listRecords('people', { pageSize: 25 })
// @ts-expect-error A Scheduling appointment confirms a hold or books directly, never both.
void schedulingClient.createAppointment('header.payload.signature', 'book-2', {
  hold: 'hold-1',
  admission: {
    offering: 'clinic-visit',
    start: '2026-10-06T08:00:00Z',
    party: { recipients: 1, attendees: 1 },
    policyRevision: 1,
    capabilities: [],
    prerequisites: [],
  },
})
