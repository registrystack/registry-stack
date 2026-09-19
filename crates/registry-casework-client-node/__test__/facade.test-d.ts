import {
  CaseworkClient,
  CaseworkClientError,
  type ClockNextEffect,
  type ContentDigest,
  type CaseworkProblemCode,
  type DecideRequest,
  type DirectoryMember,
  type HistoryEntry,
  type ReviewCreateRequest,
  type ReviewRequestAccepted,
  type ReviewTaskContext,
  type ReviewTaskDecisionRequest,
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
client.absences(token, profile, { cursor: 'opaque-absence-cursor', limit: 1000 }).then((result) => {
  const directoryRevision: number = result.value.directoryRevision
  const absenceCount: number = result.value.items.length
  const nextCursor: string | undefined = result.value.nextCursor
  void directoryRevision
  void absenceCount
  void nextCursor
})

const digest = `sha256:${'a'.repeat(64)}` as ContentDigest
const reviewCreate: ReviewCreateRequest = {
  kind: 'batch-validation',
  subject: { source: 'breg', type: 'batch', id: 'batch-43', version: '1', digest },
  requesterReference: 'batch-43',
  context: { strategy: 'submitted', snapshot: { summary: 'Review the prepared batch' } },
  resultConstraints: { acceptedCount: { minimum: 0, maximum: 412 } },
}
const accepted: ReviewRequestAccepted = {
  requestId: item.itemId,
  subject: reviewCreate.subject,
  policy: { id: 'batch-validation', version: '1', digest },
  submissionDigest: digest,
}
void client.createOrRecoverReviewRequest(token, 'requester', 'create-43', reviewCreate, digest)
void client.reviewRequest(token, 'requester', item.itemId)
void client.reviewResult(token, 'requester', accepted)
void client.reviewResults(token, 'requester', { limit: 25 })
void client.reviewTasks(token, profile, { queue: 'review', limit: 25 }, sourceProfile)
client.reviewTaskContext(token, profile, item.itemId, sourceProfile).then((response) => {
  const context: ReviewTaskContext = response.value
  if (context.context.strategy === 'source' && context.context.bindingStatus === 'current') {
    const sourceRevision: string | undefined = context.context.projection?.binding.sourceRevision
    void sourceRevision
  }
})
void client.reviewHistory(token, profile, item.itemId, { limit: 25 })
void client.reviewAccountability(token, 'supervisor', '00000000-0000-0000-0000-000000000000')
  .then((record) => {
    const resultDigest: string | undefined = record.value.resultDigest
    void resultDigest
  })
const reviewDecision: ReviewTaskDecisionRequest = { decision: { type: 'approve' } }
void client.decideReviewTask(token, profile, item.itemId, item.revision, 'decide-43', reviewDecision, sourceProfile)

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

void client.previewTaskTemplates(token, profile, sourceProfile, item.itemId).then(result => {
  const revision: number = result.value.itemRevision
  const lifetime: number | undefined = result.value.templates[0]?.lifetimeSeconds
  void revision; void lifetime
})
void client.listTaskGrants(token, profile, sourceProfile, item.itemId)
void client.approveTaskGrant(token, profile, sourceProfile, item.itemId, 7, 'task-key', { templateId: 'verify-status', templateVersion: '1' })
void client.revokeTaskGrant(token, profile, sourceProfile, item.itemId, item.itemId)
void client.taskAssertion(token, item.itemId)
void client.taskGrantStatus(token, item.itemId)
// @ts-expect-error Policy bounds must come from the governed template.
void client.approveTaskGrant(token, profile, sourceProfile, item.itemId, 7, 'task-key', { templateId: 'verify-status', templateVersion: '1', resource: 'urn:forged' })
// @ts-expect-error Agent assertion calls do not accept human profiles.
void client.taskAssertion(token, profile, sourceProfile, item.itemId)
