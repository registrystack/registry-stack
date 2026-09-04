import {
  BaseRegistryClient,
  BRegCreateBinding,
  BRegLifecycleAction,
  BRegLifecycleAuthority,
  BRegMetadata,
  BRegPatchBinding,
  ListContinuation,
  ListOptions,
  RecordEnvelope,
} from '..'

declare const client: BaseRegistryClient
declare const create: BRegCreateBinding
declare const patch: BRegPatchBinding
declare const authority: BRegLifecycleAuthority
declare const action: BRegLifecycleAction
declare const metadata: BRegMetadata
declare const record: RecordEnvelope
declare const continuation: ListContinuation

const options: ListOptions = { top: 25, filter: 'status eq active', count: true }
client.listRecords('people', options)
client.createRecord(create, { name: 'Ada' }, 'create-person-1')
client.patchRecord(patch, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', [
  { op: 'replace', field: 'name', value: 'Grace' },
], 'patch-person-1')
client.lifecycleActions(authority, record)
client.executeLifecycleAction(action, 'approve-request-1')
client.continueList(continuation)
record.data.recordIdentifier.toUpperCase()
record.data.revisionIdentifier.toUpperCase()
record.meta.registryIdentifier.toUpperCase()
record.meta.datasetIdentifier.toUpperCase()
record.meta.entityTypeIdentifier.toUpperCase()
continuation.registryIdentifier.toUpperCase()
continuation.datasetIdentifier.toUpperCase()
continuation.entityTypeIdentifier.toUpperCase()
if (action.stage !== null) action.stage.toUpperCase()
if (action.review !== null) action.review.targets.map((target) => target.operation)
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
