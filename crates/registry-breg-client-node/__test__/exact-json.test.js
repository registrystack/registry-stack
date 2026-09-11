'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const util = require('node:util');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedCreate, BRegPreparedLifecycle } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const id = '00000000-0000-4000-8000-000000000001';
const profile = 'writer';
const digest = `sha256:${'0123456789abcdef'.repeat(4)}`;
const proposalVersion = 3;
const applicationId = '00000000-0000-4000-8000-000000000003';
const appliedAt = '2026-09-01T12:00:00Z';
const actionIfMatch = '"breg-action-1"';
const lifecycleRecordId = '00000000-0000-4000-8000-000000000002';
const lifecycleRecordRevision = 5;
const receiptRevision = lifecycleRecordRevision + 1;
const fields = ['wide', 'decimal', 'date', 'nullable', 'reference'].map(name => ({
  id: name, apiName: name, label: name, schema: {type: name === 'wide' ? 'integer' : 'string'},
  required: false, nullable: true, readOnly: false, removable: true,
}));
fields[0].codeLabels = { active: 'Active' };
fields[0].storageValidation = { kind: 'postgresql-are', pattern: '^[A-Z]+$' };
fields[0].reference = { manualEntry: true, targetEntity: 'item', operations: [
  { operationId: 'records.item.lookup', accessProfile: profile, labelFields: ['wide'] },
] };
const query = {
  kind: 'list', selectableFields: [{id: 'wide', apiName: 'wide'}],
  filterableFields: [{id: '__request_breg_state', apiName: 'bregState', operators: ['equals', 'in']}],
  sortableFields: [], allowCount: true, defaultPageSize: 20, maxPageSize: 100,
  maxFilterClauses: 10, maxInValues: 20,
  pagination: {parameter:'$skiptoken', responsePath:'pageInfo.nextCursor', exclusive:true}, temporal:{mode:'current'},
};
function operation(kind) {
  return {id:`records.item.${kind}`, method:kind === 'create' ? 'POST' : kind === 'patch' ? 'PATCH' : 'GET',
    path:`/v1/records/items${kind === 'patch' ? '/{record_id}' : ''}`, operation:kind,
    sourceEntity:'item', responseEntity:'item', accessProfile:profile, requiredCapabilities:[],
    entityLabel:'Item', identifier:{apiName:'id',location:'envelope'}, titleFields:[], fields,
    readableFields:fields.map(f=>f.id), readableRequestFields:['reason'],
    createWritableFields:kind === 'create' ? fields.map(f=>f.id) : [],
    patchWritableFields:kind === 'patch' ? fields.map(f=>f.id) : [], selectors:[], query:kind === 'list' ? query : null,
    request:kind === 'list' ? {fieldNames:'api',queryParameters:['$filter','$skiptoken']} : {
      fieldNames:'api',queryParameters:[],body:kind === 'create' ? 'data_envelope' : 'json_patch',
      contentType:kind === 'create' ? 'application/json' : 'application/json-patch+json',
      idempotencyKeyRequired:true,mutationSemantics:'direct',schema:{type:kind === 'create' ? 'object' : 'array'},
      ...(kind === 'patch' ? {ifMatchRequired:true,patchPathPrefix:'/data/',patchOperations:['add','replace','remove','test'],removeSemantics:'set_null'} : {}),
    },
  };
}
function lookupOperation() {
  return {id:'records.item.lookup', method:'POST', path:'/v1/records/items:lookup', operation:'lookup',
    sourceEntity:'item', responseEntity:'item', accessProfile:profile, requiredCapabilities:[],
    entityLabel:'Item', identifier:{apiName:'id',location:'envelope'}, titleFields:[], fields,
    readableFields:fields.map(f=>f.id), createWritableFields:[], patchWritableFields:[],
    selectors:[{id:'by-wide-value',label:'By wide value',valueOrigin:'request',
      fields:[{id:'wide',apiName:'wide',label:'Wide',schema:{type:'integer'},required:true}],requestFields:['wide']}],
    readPath:{id:'related-items',label:'Related items'}, query:null,
    request:{fieldNames:'api',queryParameters:[],body:'lookup_selector',contentType:'application/json',
      idempotencyKeyRequired:false,mutationSemantics:'lookup',schema:{type:'object'}},
  };
}
function lifecycleOperation() {
  return {id:'records.item.request.apply', method:'POST', path:'/v1/records/items/{record_id}/actions/apply',
    operation:'apply_request', sourceEntity:'item', responseEntity:'item', accessProfile:profile,
    requiredCapabilities:['change_request_lifecycle'],
    entityLabel:'Item', identifier:{apiName:'id',location:'envelope'}, titleFields:[], fields:[],
    readableFields:[], createWritableFields:[], patchWritableFields:[], selectors:[], query:null,
    request:{fieldNames:'api',queryParameters:[],body:'change_request_action',contentType:'application/json',
      idempotencyKeyRequired:true,ifMatchRequired:true,mutationSemantics:'change_request_lifecycle',
      schema:{
        $schema:'https://json-schema.org/draft/2020-12/schema', type:'object', additionalProperties:false,
        required:['proposalVersion','effectDigest'],
        properties:{
          proposalVersion:{type:'integer',format:'int64',minimum:1,maximum:4294967295},
          effectDigest:{type:'string',pattern:'^sha256:[0-9a-f]{64}$',description:'Digest of the immutable proposal effects displayed to the actor.'},
        },
      },
    },
  };
}
function tombstoneOperation() {
  const value = operation('tombstone');
  return {...value, id:'records.item.tombstone', method:'DELETE', path:'/v1/records/items/{record_id}',
    operation:'tombstone', request:{fieldNames:'api',queryParameters:[],body:'none',ifMatchRequired:true,
      idempotencyKeyRequired:true,mutationSemantics:'direct'}};
}
function batchOperation() {
  const value = operation('batch');
  return {...value, id:'records.item.batch', method:'POST', path:'/v1/records/items:batch', operation:'batch',
    createWritableFields:fields.map(f=>f.id), patchWritableFields:[],
    request:{fieldNames:'api',queryParameters:[],body:'batch',contentType:'application/json',
      idempotencyKeyRequired:true,mutationSemantics:'direct',maximumItems:4,maximumBodyBytes:16384,
      allowCreate:true,allowPatch:false,schema:{type:'object',additionalProperties:false,required:['items'],
        properties:{items:{type:'array',minItems:1,maxItems:4,items:{oneOf:[
          {type:'object',properties:{operation:{const:'create'},data:{type:'object'}}},
        ]}}}}}};
}
function otherCreateOperation() {
  return {...operation('create'),id:'records.other.create',path:'/v1/records/others',
    sourceEntity:'other',responseEntity:'other'};
}
const metadata = {id:'test-registry',version:'1',revision:`sha256:${'a'.repeat(64)}`,metadataVersion:'1',
  entities:[{id:'item',datasetIdentifier:'items',route:'items',schema:'/v1/schemas/item',
    operations:['create','patch','list','lookup','apply_request','tombstone','batch'].map(operation=>({operation,accessProfile:profile})),readableFields:fields.map(f=>f.id),
    changeRequest:{planner:{kind:'declarative'},reviewMode:'staged',stages:[
      {id:'legal-review',approvals:2,excludeSubmitter:true,excludePreviousReviewers:true},
      {id:'operations',approvals:1,excludeSubmitter:false},
    ],application:{mode:'automatic',allowedDispositions:['apply'],queueReasons:[]}}},
    {id:'other',datasetIdentifier:'other-items',route:'others',schema:'/v1/schemas/other',
      operations:[{operation:'create',accessProfile:profile}],readableFields:fields.map(f=>f.id)}],
  operations:[...['create','patch','list'].map(operation), lookupOperation(), lifecycleOperation(), tombstoneOperation(), batchOperation(), otherCreateOperation()],
};
const meta = {registryIdentifier:'test-registry',datasetIdentifier:'items',entityTypeIdentifier:'item'};
const record = `{"recordIdentifier":"${id}","revisionIdentifier":"1","snapshot":"breg1_${id}","domainData":{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","nullable":null,"reference":"${id}"}}`;
const lookupValues = '{"wide":9007199254740992,"decimal":"12.3400"}';
const lookupRecord = `{"recordIdentifier":"${id}","revisionIdentifier":"1","domainData":{"wide":9007199254740992,"decimal":"12.3400"}}`;
const lifecycleActionHref = `/v1/records/items/${lifecycleRecordId}/actions/apply?accessProfile=${profile}`;
const lifecycleRecord = JSON.stringify({
  data: {
    recordIdentifier: lifecycleRecordId, revisionIdentifier: String(lifecycleRecordRevision), domainData: {},
    request: {
      bregState: 'submitted', proposalVersion, editable: false, effectDigest: digest,
      submitterReference: 'opaque-submitter',
      review: {stages:[{id:'legal-review',approvals:2,excludeSubmitter:true}],submittedAt:'2026-09-01T10:00:00Z',pendingStage:null,stageEnteredAt:null},
      reviewTiming: {firstSubmittedAt:'2026-09-01T10:00:00Z',pausedMilliseconds:0,pauseStartedAt:null,completedAt:null},
      decisions: [{stageId:'legal-review',kind:'approve',decidedAt:'2026-09-01T11:00:00Z',reasonPresent:false,actorReference:'opaque-reviewer'}],
      actions: [{operation:'apply_request', method:'POST', href:lifecycleActionHref, ifMatch:actionIfMatch, proposalVersion, effectDigest:digest}],
    },
  },
  meta,
});
const receipt = {
  id: lifecycleRecordId, revision: receiptRevision, snapshot: `breg1_${lifecycleRecordId}`,
  actorReference: 'opaque-applier',
  request: {
    bregState: 'applied', proposalVersion, effectDigest: digest,
    application: {applicationId, proposalVersion, effectDigest: digest, appliedAt},
  },
};

test('native JSON methods preserve values, metadata, cursors and mutation preconditions', async () => {
  const requests = [];
  let responseNumber = '9007199254740992';
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({method:request.method,url:request.url,body,headers:request.headers});
    response.setHeader('traceparent','00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('content-type','application/json');
    response.setHeader('cache-control','no-store');
    response.setHeader('vary','authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(metadata));
    const path = request.url.split('?')[0];
    if (path.endsWith(':lookup')) {
      response.setHeader('link','<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/item>; rel="describedby"');
      return response.end(`{"data":${lookupRecord},"meta":${JSON.stringify(meta)}}`);
    }
    if (path.endsWith('/actions/apply')) return response.end(JSON.stringify(receipt));
    if (path.endsWith(':batch')) {
      const revision = request.headers['idempotency-key'] === 'exact-batch' ? '9007199254740992' : '2';
      return response.end(`{"snapshot":"breg1_${applicationId}","results":[{"operation":"create","id":"${id}","revision":${revision},"etag":"\\"breg-record-000000000002\\"","data":{"wide":9007199254740992}}]}`);
    }
    response.setHeader('link','<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/item>; rel="describedby"');
    response.setHeader('etag','"breg-record-000000000001"');
    const exactRecord = record.replace('9007199254740992', responseNumber);
    if (request.method === 'GET' && !request.url.split('?')[0].endsWith(id)) {
      response.removeHeader('etag');
      return response.end(`{"items":[${exactRecord}],"meta":${JSON.stringify(meta)},"pageInfo":{"nextCursor":${request.url.includes('$skiptoken=') ? 'null' : '"cursor-1"'}}}`);
    }
    if (request.method === 'POST') {
      response.statusCode = 201;
      response.setHeader('location',`/v1/records/items/${id}`);
    }
    response.end(`{"data":${exactRecord},"meta":${JSON.stringify(meta)}}`);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const client = new BaseRegistryClient({baseUrl:`http://127.0.0.1:${server.address().port}`});
    const contract = await client.registryContract(profile);
    const list = contract.operations.find(op=>op.kind === 'list');
    assert.deepEqual(list.readableRequestFields,['reason']);
    assert.equal(list.query.filterableFields[0].apiName,'bregState');
    assert.equal(list.fields[0].schemaJson,'{"type":"integer"}');
    assert.equal(list.fields[0].codeLabels.active,'Active');
    assert.equal(list.fields[0].storageValidation.pattern,'^[A-Z]+$');
    assert.equal(list.fields[0].reference.operations[0].operationId,'records.item.lookup');
    const lookupDescriptor = contract.operations.find(op=>op.kind === 'lookup');
    assert.equal(lookupDescriptor.selectors[0].requestFields[0],'wide');
    assert.equal(lookupDescriptor.readPath.id,'related-items');
    assert.equal(contract.changeRequestCapability('item').application.mode,'automatic');
    assert.deepEqual(contract.changeRequestCapability('item').stages,[
      {id:'legal-review',approvals:2,excludeSubmitter:true,excludePreviousReviewers:true},
      {id:'operations',approvals:1,excludeSubmitter:false,excludePreviousReviewers:false},
    ]);
    list.id = 'forged';
    assert.equal(contract.operations.find(op=>op.kind === 'list').id,'records.item.list');
    const binding = contract.selectCreate('records.item.create',profile);
    const data = `{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","nullable":null,"reference":"${id}"}`;
    const structuredCreateCount = requests.length;
    assert.throws(() => client.createRecord(binding,{wide:Number.MAX_SAFE_INTEGER + 1},'unsafe-create'),error=>error.kind === 'invalid_request');
    assert.equal(requests.length,structuredCreateCount);
    const preparedCreate = client.prepareCreateJson(binding,data,'recover-create');
    const preparedCreateBytes = preparedCreate.toBytes();
    assert.match(util.inspect(preparedCreate),/^BRegPreparedCreate\(<redacted>\)$/);
    assert.doesNotMatch(util.inspect(preparedCreate),/recover-create|9007199254740992/);
    const restoredCreate = BRegPreparedCreate.fromBytes(preparedCreateBytes);
    assert.deepEqual(restoredCreate.toBytes(),preparedCreateBytes);
    const restartedClient = new BaseRegistryClient({baseUrl:`http://127.0.0.1:${server.address().port}`});
    const restartedContract = await restartedClient.registryContract(profile);
    const restartedBinding = restartedContract.selectCreate('records.item.create',profile);
    const recoveredCreate = restartedClient.recoverCreate(restartedBinding,restoredCreate);
    const recoveredCreated = await restartedClient.executeRecoveredCreateJson(restartedBinding,recoveredCreate);
    assert.match(recoveredCreated.valueJson,/"wide":9007199254740992/);
    assert.equal(requests.at(-1).headers['idempotency-key'],'recover-create');
    const recoveryRequestCount = requests.length;
    const otherBinding = restartedContract.selectCreate('records.other.create',profile);
    await assert.rejects(restartedClient.executeRecoveredCreate(otherBinding,recoveredCreate),error=>error.kind === 'invalid_request');
    assert.equal(requests.length,recoveryRequestCount);
    const created = await client.createRecordJson(binding,data,'exact-create');
    assert.match(created.valueJson,/"wide":9007199254740992/);
    assert.match(requests.at(-1).body,/"wide":9007199254740992/);
    assert.equal(requests.at(-1).headers['idempotency-key'],'exact-create');
    assert.equal(JSON.parse(created.valueJson).data.domainData.decimal,'12.3400');
    assert.ok(!Object.hasOwn(JSON.parse(created.valueJson).data.domainData,'absent'));
    const before = requests.length;
    for (const invalid of ['{"wide":9007199254740993}','{"wide":9007199254740993.0}','{"wide":0.10000000000000001}','{"wide":1,"wide":2}','{"wide":1e9999}']) {
      await assert.rejects(client.createRecordJson(binding,invalid,'refused'), error=>error.kind === 'invalid_request');
    }
    assert.equal(requests.length,before);
    const patch = contract.selectPatch('records.item.patch',profile);
    const structuredPatchCount = requests.length;
    assert.throws(() => client.patchRecord(patch,id,created.etag,[{op:'replace',field:'wide',value:Number.MAX_SAFE_INTEGER + 1}],'unsafe-patch'),error=>error.kind === 'invalid_request');
    assert.equal(requests.length,structuredPatchCount);
    await client.patchRecordJson(patch,id,created.etag,'[{"op":"replace","field":"wide","value":9007199254740992}]','exact-patch');
    assert.equal(requests.at(-1).headers['if-match'],created.etag);
    assert.match(requests.at(-1).body,/"path":"\/data\/wide"/);
    const batch = contract.selectBatch('item',profile);
    const batchDescriptor = contract.operations.find(op=>op.kind === 'batch');
    assert.equal(batchDescriptor.request.allowCreate,true);
    assert.equal(batchDescriptor.request.allowPatch,false);
    assert.equal(contract.operations.find(op=>op.kind === 'tombstone').request.allowCreate,null);
    const batchResult = await client.batchRecords(batch,{items:[{operation:'create',data:{wide:1}}],
      changeContext:{kind:'correction',reasonCode:'verified-source',reasonText:'Correct source',sourceReferences:['case:1']}},'batch-one');
    assert.equal(batchResult.value.results[0].revision,2);
    assert.match(requests.at(-1).body,/"reasonCode":"verified-source"/);
    const exactBatch = await client.batchRecordsJson(batch,'{"items":[{"operation":"create","data":{"wide":9007199254740992}}]}','exact-batch');
    assert.match(exactBatch.valueJson,/"revision":9007199254740992/);
    assert.match(requests.at(-1).body,/"wide":9007199254740992/);
    const tombstone = contract.selectTombstone('item',profile);
    const removed = await client.tombstoneRecord(tombstone,id,'"breg-record-000000000001"','remove-one');
    assert.equal(removed.value.data.recordIdentifier,id);
    assert.equal(requests.at(-1).method,'DELETE');
    assert.equal(requests.at(-1).headers['if-match'],'"breg-record-000000000001"');
    const removedJson = await client.tombstoneRecordJson(tombstone,id,'"breg-record-000000000001"','remove-two');
    assert.match(removedJson.valueJson,/9007199254740992/);
    const mutationRequestCount = requests.length;
    await assert.rejects(client.batchRecords(batch,{items:[]},'empty-batch'),error=>error.kind === 'invalid_request');
    assert.throws(() => client.batchRecords(batch,{items:[{operation:'create',data:{wide:Number.MAX_SAFE_INTEGER + 1}}]},'unsafe-batch'),error=>error.kind === 'invalid_request');
    await assert.rejects(client.tombstoneRecord(tombstone,'not-a-uuid','"breg-record-000000000001"','bad-remove'),error=>error.kind === 'invalid_request');
    const foreign = new BaseRegistryClient({baseUrl:'http://127.0.0.1:1'});
    await assert.rejects(foreign.batchRecords(batch,{items:[{operation:'create',data:{wide:1}}]},'foreign-batch'),error=>error.kind === 'invalid_request');
    assert.equal(requests.length,mutationRequestCount);
    const page = await client.listRecordsJson('items',{accessProfile:profile,filter:"bregState eq 'submitted'"});
    assert.match(page.valueJson,/9007199254740992/);
    assert.equal(page.continuation.skiptoken,'cursor-1');
    await client.continueListJson(page.continuation);
    assert.match(requests.at(-1).url,/\$skiptoken=cursor-1/);
    responseNumber = '9007199254740993';
    const read = await client.getRecordJson('items',id,{accessProfile:profile});
    assert.match(read.valueJson,/9007199254740993/);
    responseNumber = '0.10000000000000001';
    await assert.rejects(client.getRecordJson('items',id,{accessProfile:profile}), error=>error.kind === 'protocol');

    const lookup = await client.lookupRecordJson('items','by-wide-value',lookupValues,{accessProfile:profile});
    assert.match(requests.at(-1).body,/"selector":"by-wide-value"/);
    assert.match(requests.at(-1).body,/"wide":9007199254740992/);
    assert.match(requests.at(-1).body,/"decimal":"12\.3400"/);
    assert.match(lookup.valueJson,/"wide":9007199254740992/);
    assert.equal(JSON.parse(lookup.valueJson).data.domainData.decimal,'12.3400');

    const authority = contract.selectLifecycle('item',profile);
    const actions = client.lifecycleActionsJson(authority,lifecycleRecord);
    assert.equal(actions.length,1);
    assert.equal(actions[0].operation,'apply_request');
    assert.equal(actions[0].stage,null);
    assert.equal(actions[0].href,lifecycleActionHref);
    const malformedLifecycleRecord = JSON.parse(lifecycleRecord);
    malformedLifecycleRecord.data.request.review.stages[0].excludePreviousReviewers = null;
    assert.throws(
      () => client.lifecycleActions(authority,malformedLifecycleRecord),
      error => error.kind === 'lifecycle_promotion' && error.code === 'binding',
    );
    const preparedLifecycle = client.prepareLifecycleActionJson(
      authority,lifecycleRecord,actions[0],'recover-apply',
    );
    const preparedLifecycleBytes = preparedLifecycle.toBytes();
    assert.match(util.inspect(preparedLifecycle),/^BRegPreparedLifecycle\(<redacted>\)$/);
    assert.doesNotMatch(util.inspect(preparedLifecycle),/recover-apply|effectDigest/);
    const restoredLifecycle = BRegPreparedLifecycle.fromBytes(preparedLifecycleBytes);
    const restartedAuthority = restartedContract.selectLifecycle('item',profile);
    const recoveredLifecycle = restartedClient.recoverLifecycleAction(
      restartedAuthority,restoredLifecycle,
    );
    const recoveredExecuted = await restartedClient.executeRecoveredLifecycleActionJson(
      recoveredLifecycle,
    );
    assert.equal(JSON.parse(recoveredExecuted.valueJson).id,lifecycleRecordId);
    assert.equal(requests.at(-1).headers['idempotency-key'],'recover-apply');
    const executed = await client.executeLifecycleActionJson(actions[0],'exact-apply');
    assert.match(requests.at(-1).url.split('?')[0],/\/actions\/apply$/);
    assert.equal(requests.at(-1).headers['idempotency-key'],'exact-apply');
    assert.equal(requests.at(-1).headers['if-match'],actionIfMatch);
    assert.match(requests.at(-1).body,/"proposalVersion":3/);
    assert.match(requests.at(-1).body,new RegExp(`"effectDigest":"${digest}"`));
    const executedValue = JSON.parse(executed.valueJson);
    assert.equal(executedValue.id,lifecycleRecordId);
    assert.equal(executedValue.revision,receiptRevision);
    assert.equal(executedValue.actorReference,'opaque-applier');
    assert.equal(executedValue.request.application.id,applicationId);
    assert.equal(executedValue.request.application.proposalVersion,proposalVersion);
    assert.equal(executedValue.request.application.effectDigest,digest);

    const revisions = await client.recordRevisions('items',id,profile);
    assert.equal(revisions.mediaType,'application/json');
    assert.match(requests.at(-1).url,/\/v1\/records\/items\/00000000-0000-4000-8000-000000000001\/revisions\?accessProfile=writer$/);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});
