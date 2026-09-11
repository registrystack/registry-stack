import {
  CaseworkClient,
  CaseworkClientError,
  type ClockNextEffect,
  type CaseworkProblemCode,
  type DecideRequest,
  type DirectoryMember,
  type HostedCreateRequest,
  type HostedDecisionRequest,
  type HistoryEntry,
  type WorkItem,
} from '../client'

const client = new CaseworkClient({ baseUrl: 'https://casework.example.test/' })
const token: string = 'header.payload.signature'
const profile: string = 'staff'
const sourceProfile: string = 'reviewer'
const item: WorkItem = {} as WorkItem
const decision: DecideRequest = {
  displayedBinding: item.binding,
  sourceProfileId: 'reviewer',
  operation: 'approve',
}
void client.decideWorkItem(token, profile, sourceProfile, item.actions[0], 'attempt-1', decision)
void client.claimWorkItem(token, profile, sourceProfile, item.actions[0], 'claim-1')
void client.recoverDecisionByKey(
  token,
  profile,
  sourceProfile,
  item.itemId,
  'attempt-1',
  { sourceProfileId: sourceProfile },
)
void client.workItemHistory(token, profile, sourceProfile, item.itemId, { cursor: 'opaque', limit: 25 })
void client.holdings(token, profile, sourceProfile, { cursor: 'opaque', limit: 25 })
void client.nextWorkItem(token, profile, sourceProfile, { queue: 'review', cursor: 'opaque' }).then((page) => {
  const status: string = page.value.status
  const item: WorkItem | undefined = page.value.items[0]
  void status
  void item
})
void client.listWorkItems(token, profile, sourceProfile, {
  view: 'my_teams', sourceId: 'source-one', subjectKind: 'resident-record', subjectId: 'human-reference-42',
}).then((page) => {
  const servedQueue: string | undefined = page.value.servedQueues[0]
  void servedQueue
})
// @ts-expect-error subject selectors must include all three fields
void client.listWorkItems(token, profile, sourceProfile, { view: 'my_teams', sourceId: 'source-one' })
void client.directoryTargets(token, profile, { purpose: 'assignment', queue: 'review', limit: 25 })
void client.directoryTargets(token, profile, { purpose: 'absence_person' }).then((page) => {
  const displayName: string | null | undefined = page.value.items[0]?.displayName
  void displayName
})
void client.directoryTargets(token, profile, { purpose: 'absence_person' })
void client.directoryTargets(token, profile, {
  purpose: 'absence_cover', personIssuer: 'https://idp.example', personSubject: 'officer',
})
// @ts-expect-error assignment target discovery requires a queue
void client.directoryTargets(token, profile, { purpose: 'assignment' })
// @ts-expect-error absence cover discovery requires the complete person identity
void client.directoryTargets(token, profile, { purpose: 'absence_cover', personIssuer: 'https://idp.example' })
client.absences(token, profile).then((result) => {
  const directoryRevision: number = result.value.directoryRevision
  const absenceCount: number = result.value.items.length
  void directoryRevision
  void absenceCount
})

const hostedCreate: HostedCreateRequest = {
  kind: 'decision',
  requesterReference: 'batch-42',
  display: { summary: 'Review the prepared batch' },
}
const hostedDecision: HostedDecisionRequest = { outcome: 'confirmed' }
void client.createHostedItem(token, 'requester', 'create-42', hostedCreate)
void client.requesterHostedNotes(token, 'requester', item.itemId, { limit: 25 })
void client.hostedTerminalItems(token, 'requester', { limit: 25 })
void client.listHostedWorkItems(token, profile, { view: 'my_teams', limit: 25 })
void client.hostedWorkItemHistory(token, profile, item.itemId, { limit: 25 })
void client.hostedAccountabilityRecord(token, 'supervisor', '00000000-0000-0000-0000-000000000000')
void client.decideHostedWorkItem(token, profile, item.actions[0], 'decide-42', hostedDecision)

const officer = { issuer: 'https://idp.example', subject: 'officer' }
const cover = { issuer: 'https://idp.example', subject: 'cover' }
const namedOfficer: DirectoryMember = { ...officer, displayName: 'Officer One' }
void client.createAbsence(token, 'administrator', 1, 'absence-1', {
  person: officer, cover, from: '2026-09-14T00:00:00Z', until: '2026-09-19T00:00:00Z',
})
void client.assignWorkItem(token, 'supervisor', item.itemId, item.revision, 'assign-1', { assignee: officer }, sourceProfile)
const movement = { from: officer, to: cover, reason: 'Cover the absent officer' }
void client.previewCaseloadMove(token, 'supervisor', movement, { limit: 25 }, sourceProfile)
void client.applyCaseloadMove(token, 'supervisor', 'move-1', {
  movement, items: [{ itemId: item.itemId, expectedRevision: item.revision }],
}, sourceProfile)

if (item.occurrenceKind === 'hosted') {
  const requesterReference: string | undefined = item.hosted?.requesterReference
  void requesterReference
}
const routedBy: string | undefined = item.routing?.ruleId
const nextClockEffect = item.clockOccurrences?.[0]?.nextEffect
const upcomingClockEffect: ClockNextEffect | undefined = item.clockOccurrences?.[0]?.upcomingEffects?.[0]
if (nextClockEffect?.kind === 'reassign') {
  const queueId: string = nextClockEffect.queueId
  void queueId
}
void routedBy
void upcomingClockEffect
const liveAttemptId: string | undefined = item.liveAttempt?.attemptId
void liveAttemptId
const heldSince: string | undefined = item.heldSince
void heldSince

function completedAccountability(entry: HistoryEntry): string | undefined {
  if (entry.kind !== 'action_completed') return undefined
  return `${entry.detail.bindingReference}:${entry.detail.sourceReceipt.sourceRevision}`
}
void completedAccountability

function settlementDecision(entry: HistoryEntry): string | undefined {
  if (entry.kind !== 'attempt_settled') return undefined
  const outcome: 'applied' | 'not_applied' = entry.detail.outcome
  return `${entry.detail.attemptId}:${entry.detail.bindingReference}:${outcome}:${entry.detail.reason}:${entry.detail.decidedBy}`
}
void settlementDecision

function recoveryReference(error: CaseworkClientError): string | undefined {
  const code: CaseworkProblemCode | undefined = error.code
  return code === 'work-item.recovery-pending' ? error.originalAttemptId : undefined
}
void recoveryReference

void client.workItemClocks(token, profile, sourceProfile, item.itemId)
void client.holidayRevision(token, 'administrator', 'office', 7)
void client.createHolidayRevision(token, 'administrator', 'holiday-7', { document: { holidaySet: 'office', revision: 7, dates: ['2026-09-07'] } })
void client.previewClockRecompute(token, 'administrator', { clockId: 'review-deadline', holidaySet: 'office', holidayRevision: 7 })
void client.applyClockRecompute(token, 'administrator', 'apply-preview', { previewId: item.itemId })

void client.updateDirectoryTeam(token, 'administrator', 'review-team', 4, 'team-update', { staff: [namedOfficer], supervisors: [cover], servedQueues: ['review'] })
