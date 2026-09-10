import {
  CaseworkClient,
  CaseworkClientError,
  type CaseworkProblemCode,
  type DecideRequest,
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

function completedAccountability(entry: HistoryEntry): string | undefined {
  if (entry.kind !== 'action_completed') return undefined
  return `${entry.detail.bindingReference}:${entry.detail.sourceReceipt.sourceRevision}`
}
void completedAccountability

function recoveryReference(error: CaseworkClientError): string | undefined {
  const code: CaseworkProblemCode | undefined = error.code
  return code === 'work-item.recovery-pending' ? error.originalAttemptId : undefined
}
void recoveryReference
