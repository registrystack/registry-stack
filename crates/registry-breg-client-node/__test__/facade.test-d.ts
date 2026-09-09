import {
  BaseRegistryClient,
  BRegAttachmentSlot,
  BRegAttachmentUpload,
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
declare const slot: BRegAttachmentSlot
declare const upload: BRegAttachmentUpload

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

client.createRecordJson(create, '{"wide":9007199254740992}', 'exact-create')
client.patchRecordJson(patch, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', '[{"op":"remove","field":"name"}]', 'exact-patch')
client.getRecordJson('people', '9f6973f9-10b3-4c58-b41b-494cba26796f').then(result => result.valueJson.toUpperCase())
client.listRecordsJson('people').then(result => result.continuation?.skiptoken.toUpperCase())
client.lookupRecordJson('people', 'identifier', '{"name":"Ada"}')
client.lifecycleActionsJson(authority, '{}')
client.executeLifecycleActionJson(action, 'exact-action')
action.bodyJson.toUpperCase()
action.reviewJson?.toUpperCase()
metadata.operations.map(operation => operation.query?.filterableFields.map(field => field.apiName))
// @ts-expect-error Exact JSON methods require text, not already coerced JavaScript values.
client.createRecordJson(create, { wide: 9007199254740992 }, 'exact-create')

const reasonAction: BRegLifecycleAction = action.withReason("Please revise the submitted values.")
client.executeLifecycleAction(reasonAction, "request-revision-1")
// @ts-expect-error review reasons must be strings
action.withReason(null)

metadata.selectAttachments('company', 'company-writer').map((value) => value.slotIdentifier)
slot.prepareUpload('application/pdf', Buffer.from('%PDF-1.7'))
client.uploadAttachment(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', upload, 'upload-1')
client.uploadAttachmentJson(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', upload, 'upload-1')
client.downloadAttachment(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', 2).then((raw) => raw.body.byteLength)
client.deleteAttachment(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', 'remove-1')
client.deleteAttachmentJson(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', 'remove-1')
const value = slot.valueIn(record)
if (value.kind === 'filled') value.value.sha256.toUpperCase()
// @ts-expect-error Slot policy is served metadata, never caller-set.
slot.maximumBytes = 1
// @ts-expect-error Uploads must be bound to a slot before they can be sent.
client.uploadAttachment(slot, '9f6973f9-10b3-4c58-b41b-494cba26796f', '"breg-1"', Buffer.from('%PDF-1.7'), 'upload-1')
