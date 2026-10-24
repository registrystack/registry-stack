import {
  BaseRegistryClient,
  BaseRegistryClientError,
  BRegActionTargetConditions,
  BRegBatchBinding,
  BRegCreateBinding,
  BRegActionBinding,
  BRegIngestionChunk,
  BRegMetadata,
  BRegPatchBinding,
  BRegPreparedAction,
  BRegPreparedCreate,
  BRegRecoveredAction,
  BRegRecoveredCreate,
  BRegProposal,
  BRegProposalGetBinding,
  BRegPreparedProposal,
  BRegTombstoneBinding,
  AsOfListContinuation,
  CurrentListContinuation,
  GeoJsonListContinuation,
  RelationshipListContinuation,
  SnapshotListContinuation,
  ListContinuation,
  ListOptions,
  RecordEnvelope,
  VerifiedHookDelivery,
  HookVerificationRefusalCode,
  verifyHookDelivery,
} from '..'

declare const client: BaseRegistryClient
new BaseRegistryClient({
  baseUrl: 'https://registry.example.test/',
  maximumResponseBytes: 8 * 1024 * 1024,
  trustedRootCertificates: '-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----',
})
// @ts-expect-error The abbreviated response-bound spelling is retired.
new BaseRegistryClient({ baseUrl: 'https://registry.example.test/', maxResponseBytes: 1024 })
// @ts-expect-error Optional configuration values are omitted rather than set to null.
new BaseRegistryClient({ baseUrl: 'https://registry.example.test/', maximumResponseBytes: null })
declare const failure: BaseRegistryClientError
if (failure.constraint?.constraintKind === 'compare') {
  failure.constraint.left.toUpperCase()
  failure.constraint.right.toUpperCase()
  // @ts-expect-error Compare constraints name left and right fields.
  failure.constraint.field.toUpperCase()
} else if (failure.constraint) {
  failure.constraint.field.toUpperCase()
  // @ts-expect-error Single-field constraints do not name a left field.
  failure.constraint.left.toUpperCase()
}
declare const create: BRegCreateBinding
declare const patch: BRegPatchBinding
declare const metadata: BRegMetadata
declare const record: RecordEnvelope
declare const continuation: ListContinuation
declare const preparedAction: BRegPreparedAction
declare const preparedCreate: BRegPreparedCreate
declare const proposal: BRegProposal
declare const proposalGet: BRegProposalGetBinding
declare const preparedProposal: BRegPreparedProposal
declare const recoveredAction: BRegRecoveredAction
declare const recoveredCreate: BRegRecoveredCreate
declare const immediateAction: BRegActionBinding
declare const conditions: BRegActionTargetConditions
client.getProposal(metadata.selectProposalGet('reviewer'), '00000000-0000-4000-8000-000000000001')
client.getProposal(proposalGet, proposal.identifier)
// @ts-expect-error Get capability comes only from caller-visible metadata.
new BRegProposalGetBinding()
declare const batch: BRegBatchBinding
declare const chunk: BRegIngestionChunk
declare const tombstone: BRegTombstoneBinding
declare const currentContinuation: CurrentListContinuation
declare const asOfContinuation: AsOfListContinuation
declare const snapshotContinuation: SnapshotListContinuation
declare const relationshipContinuation: RelationshipListContinuation
declare const geoJsonContinuation: GeoJsonListContinuation

metadata.actions[0]?.inputs[0]?.schemaJson.toUpperCase()
metadata.actions[0]?.attachments[0]?.contentTypes[0]?.toUpperCase()
metadata.actions[0]?.attachments[0]?.maximumBytes.toFixed()
metadata.proposalActions[0]?.actionId.toUpperCase()
metadata.proposalActions[0]?.accessProfile.toUpperCase()
metadata.proposalActions[0]?.operations[0]?.toUpperCase()
metadata.proposalActions[0]?.readableInputs[0]?.toUpperCase()
// @ts-expect-error Inventory is descriptive and read-only.
metadata.proposalActions[0].operations.push('apply')

if (metadata.statisticalDatasets !== null) {
  const dataset = metadata.statisticalDatasets[0]
  dataset?.id.toUpperCase()
  dataset?.periodKind satisfies 'flow' | 'stock'
  dataset?.granularity satisfies 'day' | 'month' | 'quarter' | 'year'
  dataset?.dimensions[0]?.codes[0]?.toUpperCase()
}

const verifiedHook: VerifiedHookDelivery = verifyHookDelivery({
  method: 'POST',
  path: '/hooks/registry',
  headers: { 'X-Registry-Signature': 'v1=opaque' },
  body: Buffer.from('{}'),
  key: Buffer.alloc(32),
})
verifiedHook.id.toUpperCase()
verifiedHook.source.toUpperCase()
verifiedHook.type.toUpperCase()
verifiedHook.time.toUpperCase()
verifiedHook.dataschema.toUpperCase()
verifiedHook.generation.toUpperCase()
verifiedHook.attempt.toUpperCase()
verifiedHook.deliveryTime.toUpperCase()
verifiedHook.idempotencyKey.toUpperCase()
verifiedHook.body.byteLength.toFixed()
const webhookRefusal: HookVerificationRefusalCode = 'signature-mismatch'
webhookRefusal.toUpperCase()
// @ts-expect-error Hook bodies must remain exact bytes.
verifyHookDelivery({ method: 'POST', path: '/', headers: {}, body: '{}', key: Buffer.alloc(32) })
// @ts-expect-error Header values must be exact strings.
verifyHookDelivery({ method: 'POST', path: '/', headers: { 'ce-id': 1 }, body: Buffer.from('{}'), key: Buffer.alloc(32) })

const options: ListOptions = { top: 25, filter: 'status eq active', count: true, bbox: ['100.1', '13.1', '100.2', '13.2'] }
client.listRecords('people', options)
client.createRecord(create, { name: 'Ada' }, 'create-person-1')
client.patchRecord(patch, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', [
  { op: 'replace', field: 'name', value: 'Grace' },
], 'patch-person-1')
client.recordRevisions('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 'auditor')
client.getRecordRevision('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 2)
client.getGeoJsonRecord('people', '9f6973f9-10b3-4c58-b41b-494cba26796f')
client.getGeoJsonRecordJson('people', '9f6973f9-10b3-4c58-b41b-494cba26796f')
client.listGeoJsonRecords('people', { bbox: ['100.1', '13.1', '100.2', '13.2'] })
client.listGeoJsonRecordsJson('people')
client.continueGeoJsonList(geoJsonContinuation)
client.continueGeoJsonListJson(geoJsonContinuation)
client.listCurrentRecords('people')
client.listCurrentRecordsJson('people')
client.continueCurrentList(currentContinuation)
client.continueCurrentListJson(currentContinuation)
client.listRecordsAsOf('people', { asOf: '2026-09-10T00:00:00Z' })
client.listRecordsAsOfJson('people', { asOf: '2026-09-10T00:00:00Z' })
client.continueAsOfList(asOfContinuation)
client.continueAsOfListJson(asOfContinuation)
client.listSnapshotRecords('people', { snapshot: 'breg1_opaque', validAt: '2026-09-10T00:00:00Z' })
client.listSnapshotRecordsJson('people')
client.continueSnapshotList(snapshotContinuation)
client.continueSnapshotListJson(snapshotContinuation)
client.listRelationshipRecords('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 'related')
client.listRelationshipRecordsJson('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 'related')
client.continueRelationshipList(relationshipContinuation)
client.continueRelationshipListJson(relationshipContinuation)
client.actionTargetConditions(immediateAction, { targetId: '9f6973f9-10b3-4c58-b41b-494cba26796f' })
client.actionTargetConditionsJson(immediateAction, '{"targetId":"9f6973f9-10b3-4c58-b41b-494cba26796f"}')
client.invokeAction(immediateAction, { targetId: '9f6973f9-10b3-4c58-b41b-494cba26796f' }, 'invoke-1', conditions)
client.invokeActionJson(immediateAction, '{"targetId":"9f6973f9-10b3-4c58-b41b-494cba26796f"}', 'invoke-2', conditions)
const actionBytes: Buffer = client.prepareAction(immediateAction, { targetId: '9f6973f9-10b3-4c58-b41b-494cba26796f' }, 'invoke-3', conditions).toBytes()
client.prepareActionJson(immediateAction, '{"targetId":"9f6973f9-10b3-4c58-b41b-494cba26796f"}', 'invoke-4', conditions).toBytes()
BRegPreparedAction.fromBytes(actionBytes)
client.recoverAction(immediateAction, preparedAction, { targetId: '9f6973f9-10b3-4c58-b41b-494cba26796f' }, 'invoke-3')
client.recoverActionJson(immediateAction, preparedAction, '{"targetId":"9f6973f9-10b3-4c58-b41b-494cba26796f"}', 'invoke-4')
client.executeRecoveredAction(immediateAction, recoveredAction).then(outcome => outcome.value.applicationId)
client.executeRecoveredActionJson(immediateAction, recoveredAction).then(outcome => outcome.valueJson)
// @ts-expect-error Recovery needs the original idempotency key, never a fresh one.
client.recoverAction(immediateAction, preparedAction, { targetId: '9f6973f9-10b3-4c58-b41b-494cba26796f' })
client.batchRecords(batch, { items: [{ operation: 'create', data: { name: 'Ada' } }], changeContext: { kind: 'correction', reasonCode: 'source-fix' } }, 'batch-1')
client.batchRecordsJson(batch, '{"items":[{"operation":"create","data":{"name":"Ada"}}]}', 'batch-2')
client.tombstoneRecord(tombstone, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', 'remove-1')
client.tombstoneRecordJson(tombstone, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', 'remove-2')
client.createIngestionRun('people', {
  operation: 'create',
  profileId: 'facility-operator',
  packageRevision: 'revision-1',
  schemaFingerprint: 'fingerprint-1',
  inputDigest: 'a'.repeat(64),
  inputLength: 640,
  itemCount: 5,
  chunkCount: 2,
  chunkAlgorithmVersion: 'greedy-canonical-http-batch-v1',
})
client.listIngestionRuns('people', { accessProfile: 'auditor', limit: 25, cursor: 'opaque', status: 'open', inputDigest: 'a'.repeat(64) })
client.readIngestionRun('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 'auditor')
client.readIngestionRun('people', '9f6973f9-10b3-4c58-b41b-494cba26796f')
client.submitIngestionChunk('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', chunk, 'facility-operator')
client.cancelIngestionRun('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 'auditor')
client.cancelIngestionRun('people', '9f6973f9-10b3-4c58-b41b-494cba26796f')
client.ingestionChunkReceipt('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', 1, 'facility-operator')
// @ts-expect-error Chunk submissions and receipts must carry the run's access profile.
client.submitIngestionChunk('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', chunk)
// @ts-expect-error Run list queries accept only the fields the route parses.
client.listIngestionRuns('people', { pageSize: 25 })
client.prepareCreate(create, { name: 'Ada' }, 'prepared-create-1').toBytes()
client.prepareCreateJson(create, '{"wide":9007199254740992}', 'prepared-create-2').toBytes()
BRegPreparedCreate.fromBytes(preparedCreate.toBytes())
client.recoverCreate(create, preparedCreate)
client.executeRecoveredCreate(create, recoveredCreate)
client.executeRecoveredCreateJson(create, recoveredCreate)
client.startProposal(immediateAction, '{}', 'proposal-start')
client.executeRecoveredProposalStart(immediateAction, recoveredAction)
client.readProposal(proposal)
client.listProposals(metadata.selectProposals('author'), '{}')
client.prepareProposal(proposal, 'submit', '{}', 'proposal-submit').toBytes()
BRegPreparedProposal.fromBytes(preparedProposal.toBytes())
client.recoverProposal(proposal, preparedProposal)
client.executeProposal(preparedProposal)
client.continueList(continuation)
record.data.recordIdentifier.toUpperCase()
record.data.revisionIdentifier.toUpperCase()
record.meta.registryIdentifier.toUpperCase()
record.meta.datasetIdentifier.toUpperCase()
record.meta.entityTypeIdentifier.toUpperCase()
continuation.registryIdentifier.toUpperCase()
continuation.datasetIdentifier.toUpperCase()
continuation.entityTypeIdentifier.toUpperCase()
if (metadata.etag !== null) metadata.etag.toUpperCase()

// @ts-expect-error Direct writes require metadata-selected opaque authority.
client.createRecord({}, { name: 'Ada' }, 'create-person-1')
// @ts-expect-error List options do not accept Relay page-size vocabulary.
client.listRecords('people', { pageSize: 25 })
// @ts-expect-error Base Registry Engine record formats are closed.
client.getRecord('people', '9f6973f9-10b3-4c58-b41b-494cba26796f', { format: 'geojson' })
// @ts-expect-error Continuations carry only the cursor's immutable collection binding.
client.continueList({ ...continuation, select: ['name'] })
// @ts-expect-error Continuations must preserve the complete collection binding.
client.continueList({
  route: 'records',
  skiptoken: 'opaque',
  format: 'json',
  datasetIdentifier: 'people',
  entityTypeIdentifier: 'person',
})
// @ts-expect-error Relay-only record members are not promised by BReg.
record.data.lifecycleState.toUpperCase()

client.createRecordJson(create, '{"wide":9007199254740992}', 'exact-create')
client.patchRecordJson(patch, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', '[{"op":"remove","field":"name"}]', 'exact-patch')
client.getRecordJson('people', '9f6973f9-10b3-4c58-b41b-494cba26796f').then(result => result.valueJson.toUpperCase())
client.listRecordsJson('people').then(result => result.continuation?.skiptoken.toUpperCase())
client.lookupRecordJson('people', 'identifier', '{"name":"Ada"}')
metadata.operations.map(operation => operation.query?.filterableFields.map(field => field.apiName))
metadata.operations.map(operation => operation.request.allowCreate === false)
// @ts-expect-error Exact JSON methods require text, not already coerced JavaScript values.
client.createRecordJson(create, { wide: 9007199254740992 }, 'exact-create')


client.statisticsLive('population', null, null, 'reader', 'csv').then((raw) => raw.reprDigest?.toUpperCase())

const once = new BaseRegistryClient({
  baseUrl: 'https://registry.example.test/',
  attemptTimeoutMilliseconds: 30_000,
  connectTimeoutMilliseconds: 10_000,
  maximumMutationRetries: 0,
})
void once
// @ts-expect-error Retired option names are refused before I/O.
new BaseRegistryClient({ baseUrl: 'https://registry.example.test/', requestTimeoutMilliseconds: 30_000 })
// @ts-expect-error Retired option names are refused before I/O.
new BaseRegistryClient({ baseUrl: 'https://registry.example.test/', maxMutationRetries: 0 })

function mayHaveTakenEffect(error: BaseRegistryClientError): boolean {
  const unknown: boolean = error.outcomeUnknown
  return unknown
}
void mayHaveTakenEffect

client.readProposalReviewStatus(proposal).then(outcome => {
  const acceptedRequestId: string | undefined = outcome.value.requestId
  acceptedRequestId?.toUpperCase()
})
client.readProposalSubmission(proposal, 1).then(outcome => {
  const status: 'approved' | 'rejected' | 'changes-requested' | 'answered' | undefined = outcome.value.decision?.status
  const publicReason: string | undefined = outcome.value.decision?.publicReason
  void status
  publicReason?.toUpperCase()
})

client.readProposalReviewContextBatch(metadata.selectProposalReviewContext('reviewer', 'correct'), []).then(outcome => {
  outcome.value.forEach(context => {
    const id: string | undefined = context?.id
    id?.toUpperCase()
  })
})
