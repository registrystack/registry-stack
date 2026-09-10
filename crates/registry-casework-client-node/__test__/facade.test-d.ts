import {
  CaseworkClient,
  CaseworkClientError,
  type CaseworkProblemCode,
  type DecideRequest,
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

if (item.occurrenceKind === 'hosted') {
  const requesterReference: string | undefined = item.hosted?.requesterReference
  void requesterReference
}

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
