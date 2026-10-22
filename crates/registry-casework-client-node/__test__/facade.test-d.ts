import { CaseworkClient, CaseworkClientError, submissionDigest, type ContentDigest, type SubjectBinding,
  type PolicyBinding, type ReviewCreateRequest, type ReviewRequestAccepted,
  type ReviewTask, type SupervisoryReviewTask, type StaffingDiagnostic, type ReviewTaskDecisionRequest, type ReviewStaffingQuery,
  type ReviewCaseloadMoveRequest, type ReviewClockRecomputeRequest } from '../client'
const client = new CaseworkClient({ baseUrl: 'https://casework.example.test/', attemptTimeoutMilliseconds: 1500, maximumResponseBytes: 1500, maximumMutationRetries: 0 })
// @ts-expect-error the public response-bound name is maximumResponseBytes
new CaseworkClient({ baseUrl: 'https://casework.example.test/', maxResponseBytes: 1500 })
// @ts-expect-error null is not an omission in JavaScript configuration
new CaseworkClient({ baseUrl: 'https://casework.example.test/', attemptTimeoutMilliseconds: null })
// @ts-expect-error trust roots are PEM text, not binary data
new CaseworkClient({ baseUrl: 'https://casework.example.test/', trustedRootCertificates: Buffer.from('certificate') })
// @ts-expect-error the per-exchange timeout is named for one attempt
new CaseworkClient({ baseUrl: 'https://casework.example.test/', requestTimeoutMilliseconds: 1500 })
// @ts-expect-error the retry ceiling uses the authored maximum spelling
new CaseworkClient({ baseUrl: 'https://casework.example.test/', maxMutationRetries: 0 })
const token = 'one-call-secret', profile = 'staff', id = '00000000-0000-4000-8000-000000000001'
const digest: ContentDigest = `sha256:${'a'.repeat(64)}`
const subject: SubjectBinding = { source: 'registry', type: 'proposal', id: 'proposal-1', version: '1', digest }
const policy: PolicyBinding = { id: 'review', version: '1', digest }
const submitted: ReviewCreateRequest = { policy, subject, requesterReference: 'proposal-1', context: { mode: 'submitted', snapshot: { reference: 'proposal-1' } } }
const current: ReviewCreateRequest = { ...submitted, context: { mode: 'current-source', binding: { reference: 'proposal-1' } } }
void client.createOrRecoverReviewRequest(token, 'requester', 'submit-1', current, digest)
const computed: ContentDigest = submissionDigest('producer', subject.source, submitted)
void client.createOrRecoverReviewRequest(token, 'requester', 'submit-2', submitted, computed)
// @ts-expect-error admission requires the expected immutable policy binding
const missingPolicy: ReviewCreateRequest = { subject, requesterReference: 'proposal-1', context: { mode: 'submitted', snapshot: {} } }
void missingPolicy
const query: ReviewStaffingQuery = { queue: 'review', ownership: 'assigned-to-me', subjectSource: subject.source, subjectType: subject.type, subjectId: subject.id, subjectVersion: subject.version, subjectDigest: subject.digest, sort: 'due', limit: 25 }
void client.reviewTasks(token, profile, query).then(({ value }) => { const task: ReviewTask | undefined = value.items[0]; void task })
void client.nextReviewTask(token, profile, query).then(({ value }) => { const task: ReviewTask | null = value; void task })
void client.reviewTaskHoldings(token, profile, query)
void client.reviewPolicies(token, profile)
void client.reviewPolicy(token, profile, 'review')
const accepted: ReviewRequestAccepted = { requestId: id, subject, policy, submissionDigest: digest }
void client.reviewRequest(token, 'requester', id)
void client.reviewResult(token, 'requester', accepted)
void client.reviewResults(token, 'requester', { limit: 25 })
void client.cancelReviewRequest(token, 'requester', accepted, 'cancel-1', { subject, reason: 'Superseded' })
void client.claimReviewTask(token, profile, id, 1, 'claim-1')
void client.releaseReviewTask(token, profile, id, 2, 'release-1')
void client.assignReviewTask(token, profile, id, 2, 'assign-1', { assignee: { issuer: 'https://issuer.example', subject: 'staff-2' } })
void client.delegateReviewTask(token, profile, id, 2, 'delegate-1', { delegate: { issuer: 'https://issuer.example', subject: 'staff-2' } })
void client.reviewTaskDraft(token, profile, id)
void client.saveReviewTaskDraft(token, profile, id, 2, 'draft-1', { body: { note: 'Private' } })
void client.deleteReviewTaskDraft(token, profile, id, 2, 'delete-1')
const decision: ReviewTaskDecisionRequest = { decision: { type: 'approve', outcome: 'approved', publicReason: 'Approved as submitted.' } }
// @ts-expect-error an approval names one of the policy's approval outcomes
const bareApproval: ReviewTaskDecisionRequest = { decision: { type: 'approve' } }
void bareApproval
void client.decideReviewTask(token, profile, id, 2, 'decision-1', decision)
void client.reviewHistory(token, profile, id, { limit: 25 })
void client.ownReviewDecisions(token, profile, { limit: 25 })
void client.supervisoryReviewTasks(token, 'supervisor', { requestId: id, limit: 25 })
void client.reviewAccountability(token, 'supervisor', id)
const movement: ReviewCaseloadMoveRequest = { from: { issuer: 'https://issuer.example', subject: 'staff-1' }, to: { issuer: 'https://issuer.example', subject: 'staff-2' }, reason: 'Cover' }
void client.previewCaseloadMove(token, 'administrator', movement)
void client.applyCaseloadMove(token, 'administrator', 'move-1', { previewId: id })
const recompute: ReviewClockRecomputeRequest = { taskIds: [id] }
void client.previewClockRecompute(token, 'administrator', recompute)
void client.applyClockRecompute(token, 'administrator', 'recompute-1', { previewId: id })
const error = {} as CaseworkClientError
const unknown: boolean = error.outcomeUnknown
void unknown
// @ts-expect-error WorkItem lifecycle was removed
void client.listWorkItems(token, profile, {})
// @ts-expect-error generic source action execution was removed
void client.decideWorkItem(token, profile, {})

// @ts-expect-error partial SubjectBinding selectors cannot name exact work
const partial: ReviewStaffingQuery = { subjectId: "proposal-1" }
void partial

void client.previewReviewTaskTemplates(token, profile, { taskId: id, sourceProfile: 'source-reviewer' })
void client.listReviewTaskGrants(token, profile, { taskId: id })
// @ts-expect-error positional source profile and task ID cannot name a task grant read
void client.previewReviewTaskTemplates(token, profile, 'source-reviewer', id)
// @ts-expect-error positional source profile and task ID cannot name a task grant read
void client.listReviewTaskGrants(token, profile, 'source-reviewer', id)

const currentPolicyRequest: ReviewCreateRequest = { ...submitted, policy: { id: 'review' } }
void client.createOrRecoverReviewRequest(token, 'requester', 'default-policy', currentPolicyRequest, digest)
// @ts-expect-error a strict policy selector needs both version and digest
const missingPolicyDigest: ReviewCreateRequest = { ...submitted, policy: { id: 'review', version: '1' } }
// @ts-expect-error a strict policy selector needs both version and digest
const missingPolicyVersion: ReviewCreateRequest = { ...submitted, policy: { id: 'review', digest } }
// @ts-expect-error an accepted request must retain a concrete policy binding
const unboundAccepted: ReviewRequestAccepted = { ...accepted, policy: { id: 'review' } }
void missingPolicyDigest; void missingPolicyVersion; void unboundAccepted

const staffingNotice: StaffingDiagnostic = 'no-cover-available'
const supervisionNotice: SupervisoryReviewTask = { taskId: id, requestId: id, queue: 'review', revision: 1, state: 'open', staffingDiagnostic: staffingNotice }
void supervisionNotice
void client.reviewTasks(token, profile).then(({ value }) => {
  const diagnostic: StaffingDiagnostic | undefined = value.items[0]?.staffingDiagnostic
  void diagnostic
})
// @ts-expect-error staffing diagnostics use a closed vocabulary
const unknownStaffingNotice: StaffingDiagnostic = 'unavailable'
void unknownStaffingNotice
// @ts-expect-error AssignmentContext was unused and removed from the maintained contract
import type { AssignmentContext } from '../client'
