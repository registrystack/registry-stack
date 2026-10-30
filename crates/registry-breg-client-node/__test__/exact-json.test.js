'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const util = require('node:util');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedCreate, BRegPreparedProposal } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const id = '00000000-0000-4000-8000-000000000001';
const profile = 'writer';
const applicationId = '00000000-0000-4000-8000-000000000003';
const fields = ['wide', 'decimal', 'date', 'nullable', 'reference'].map(name => ({
  id: name, apiName: name, label: name, schema: {type: name === 'wide' ? 'integer' : 'string'},
  required: false, nullable: true, readOnly: false, removable: true,
}));
fields[0].codeLabels = { active: 'Active' };
fields[0].storageValidation = { kind: 'postgresql-are', pattern: '^[A-Z]+$' };
fields[0].reference = { manualEntry: true, targetRecordType: 'item', operations: [
  { operationId: 'records.item.lookup', accessProfile: profile, labelFields: ['wide'] },
] };
const query = {
  kind: 'list', selectableFields: [{id: 'wide', apiName: 'wide'}],
  filterableFields: [{id: 'wide', apiName: 'wide', operators: ['equals', 'in']}],
  sortableFields: [], allowCount: true, defaultPageSize: 20, maximumPageSize: 100,
  maximumFilterClauses: 10, maximumInValues: 20,
  pagination: {parameter:'$skiptoken', responsePath:'pageInfo.nextCursor', exclusive:true}, temporal:{mode:'current'},
};
function operation(kind) {
  return {id:`records.item.${kind}`, method:kind === 'create' ? 'POST' : kind === 'patch' ? 'PATCH' : 'GET',
    path:`/v1/records/items${kind === 'patch' ? '/{record_id}' : ''}`, operation:kind,
    sourceRecordType:'item', responseRecordType:'item', accessProfile:profile, requiredCapabilities:[],
    futureExecutionMember:{ignored:true},
    recordTypeLabel:'Item', identifier:{apiName:'id',location:'envelope'}, titleFields:[], fields,
    readableFields:fields.map(f=>f.id),
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
    sourceRecordType:'item', responseRecordType:'item', accessProfile:profile, requiredCapabilities:[],
    recordTypeLabel:'Item', identifier:{apiName:'id',location:'envelope'}, titleFields:[], fields,
    readableFields:fields.map(f=>f.id), createWritableFields:[], patchWritableFields:[],
    selectors:[{id:'by-wide-value',label:'By wide value',valueOrigin:'request',
      fields:[{id:'wide',apiName:'wide',label:'Wide',schema:{type:'integer'},required:true}],requestFields:['wide']}],
    readPath:{id:'related-items',label:'Related items'}, query:null,
    request:{fieldNames:'api',queryParameters:[],body:'lookup_selector',contentType:'application/json',
      idempotencyKeyRequired:false,mutationSemantics:'lookup',schema:{type:'object'}},
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
    createWritableFields:fields.map(f=>f.id), patchWritableFields:fields.map(f=>f.id),
    request:{fieldNames:'api',queryParameters:[],body:'batch',contentType:'application/json',
      idempotencyKeyRequired:true,mutationSemantics:'direct',maximumItems:4,maximumBodyBytes:16384,
      allowCreate:true,allowPatch:true,schema:{type:'object',additionalProperties:false,required:['items'],
        properties:{items:{type:'array',minItems:1,maxItems:4,items:{oneOf:[
          {type:'object',properties:{operation:{const:'create'},data:{type:'object'}}},
          {type:'object',properties:{operation:{const:'patch'},recordIdentifier:{type:'string'},ifMatch:{type:'string'},patch:{type:'array'}}},
        ]}}}}}};
}
function otherCreateOperation() {
  return {...operation('create'),id:'records.other.create',path:'/v1/records/others',
    sourceRecordType:'other',responseRecordType:'other'};
}
const metadata = {id:'test-registry',version:'1',revision:`sha256:${'a'.repeat(64)}`,metadataVersion:'2',
  futureDescription:{label:'Future registry description'},
  recordTypes:[{id:'item',datasetIdentifier:'items',route:'items',schema:'/v1/schemas/item',
    operations:['create','patch','list','lookup','tombstone','batch'].map(operation=>({operation,accessProfile:profile})),readableFields:fields.map(f=>f.id)},
    {id:'other',datasetIdentifier:'other-items',route:'others',schema:'/v1/schemas/other',
      operations:[{operation:'create',accessProfile:profile}],readableFields:fields.map(f=>f.id)}],
  operations:[...['create','patch','list'].map(operation), lookupOperation(), tombstoneOperation(), batchOperation(), otherCreateOperation()],
};
const meta = {registryIdentifier:'test-registry',datasetIdentifier:'items',recordTypeIdentifier:'item'};
const record = `{"recordIdentifier":"${id}","revisionIdentifier":"1","domainData":{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","nullable":null,"reference":"${id}"}}`;
const lookupValues = '{"wide":9007199254740992,"decimal":"12.3400"}';
const lookupRecord = `{"recordIdentifier":"${id}","revisionIdentifier":"1","domainData":{"wide":9007199254740992,"decimal":"12.3400"}}`;
test('native JSON methods preserve values, metadata, cursors and mutation preconditions', async () => {
  const requests = [];
  let responseNumber = '9007199254740992';
  let metadataWire = null;
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({method:request.method,url:request.url,body,headers:request.headers});
    response.setHeader('traceparent','00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('content-type','application/json');
    response.setHeader('cache-control','no-store');
    response.setHeader('vary','authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(metadataWire ?? JSON.stringify(metadata));
    const path = request.url.split('?')[0];
    if (path.endsWith(':lookup')) {
      response.setHeader('link','<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/item>; rel="describedby"');
      return response.end(`{"data":${lookupRecord},"meta":${JSON.stringify(meta)}}`);
    }
    if (path.endsWith(':batch')) {
      const revision = request.headers['idempotency-key'] === 'exact-batch' ? '9007199254740992' : '2';
      const operation = JSON.parse(body).items[0].operation;
      return response.end(`{"snapshot":"breg1_${applicationId}","results":[{"operation":"${operation}","recordIdentifier":"${id}","revisionIdentifier":"${revision}","etag":"\\"breg-record-000000000002\\"","domainData":{"wide":9007199254740992}}]}`);
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
    assert.equal(list.sourceRecordType,'item');
    assert.equal(list.query.filterableFields[0].apiName,'wide');
    assert.equal(list.fields[0].schemaJson,'{"type":"integer"}');
    assert.equal(list.fields[0].codeLabels.active,'Active');
    assert.equal(list.fields[0].storageValidation.pattern,'^[A-Z]+$');
    assert.equal(list.fields[0].reference.operations[0].operationId,'records.item.lookup');
    const lookupDescriptor = contract.operations.find(op=>op.kind === 'lookup');
    assert.equal(lookupDescriptor.selectors[0].requestFields[0],'wide');
    assert.equal(lookupDescriptor.readPath.id,'related-items');
    list.id = 'forged';
    assert.equal(contract.operations.find(op=>op.kind === 'list').id,'records.item.list');
    const binding = contract.selectCreate('records.item.create',profile);

    metadata.operations[0].requiredCapabilities = ['future-write-protocol'];
    const partlyUnsupported = await client.registryContract(profile);
    assert.throws(
      () => partlyUnsupported.selectCreate('records.item.create',profile),
      error => error.kind === 'metadata-selection' && error.code === 'required-capability',
    );
    assert.doesNotThrow(() => partlyUnsupported.selectPatch('records.item.patch',profile));
    metadata.operations[0].requiredCapabilities = [];

    metadataWire = JSON.stringify(metadata).replace(
      '"id":"test-registry"',
      '"id":"test-registry","id":"duplicate-registry"',
    );
    await assert.rejects(client.registryContract(profile), error => error.kind === 'protocol');
    metadataWire = null;

    metadata.futureDescription.label = 'x'.repeat(65_537);
    await assert.rejects(client.registryContract(profile), error => error.kind === 'protocol');
    metadata.futureDescription.label = 'Future registry description';

    const data = `{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","nullable":null,"reference":"${id}"}`;
    const structuredCreateCount = requests.length;
    assert.throws(() => client.createRecord(binding,{wide:Number.MAX_SAFE_INTEGER + 1},'unsafe-create'),error=>error.kind === 'invalid-request');
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
    await assert.rejects(restartedClient.executeRecoveredCreate(otherBinding,recoveredCreate),error=>error.kind === 'invalid-request');
    assert.equal(requests.length,recoveryRequestCount);
    const created = await client.createRecordJson(binding,data,'exact-create');
    assert.match(created.valueJson,/"wide":9007199254740992/);
    assert.match(requests.at(-1).body,/"wide":9007199254740992/);
    assert.equal(requests.at(-1).headers['idempotency-key'],'exact-create');
    assert.equal(JSON.parse(created.valueJson).data.domainData.decimal,'12.3400');
    assert.ok(!Object.hasOwn(JSON.parse(created.valueJson).data.domainData,'absent'));
    const before = requests.length;
    for (const invalid of ['{"wide":9007199254740993}','{"wide":9007199254740993.0}','{"wide":0.10000000000000001}','{"wide":1,"wide":2}','{"wide":1e9999}']) {
      await assert.rejects(client.createRecordJson(binding,invalid,'refused'), error=>error.kind === 'invalid-request');
    }
    assert.equal(requests.length,before);
    const patch = contract.selectPatch('records.item.patch',profile);
    const structuredPatchCount = requests.length;
    assert.throws(() => client.patchRecord(patch,id,created.etag,[{op:'replace',field:'wide',value:Number.MAX_SAFE_INTEGER + 1}],'unsafe-patch'),error=>error.kind === 'invalid-request');
    assert.equal(requests.length,structuredPatchCount);
    await client.patchRecordJson(patch,id,created.etag,'[{"op":"replace","field":"wide","value":9007199254740992}]','exact-patch');
    assert.equal(requests.at(-1).headers['if-match'],created.etag);
    assert.match(requests.at(-1).body,/"path":"\/data\/wide"/);
    const batch = contract.selectBatch('item',profile);
    const batchDescriptor = contract.operations.find(op=>op.kind === 'batch');
    assert.equal(batchDescriptor.request.allowCreate,true);
    assert.equal(batchDescriptor.request.allowPatch,true);
    assert.equal(contract.operations.find(op=>op.kind === 'tombstone').request.allowCreate,null);
    const batchResult = await client.batchRecords(batch,{items:[{operation:'create',data:{wide:1}}],
      changeContext:{kind:'correction',reasonCode:'verified-source',reasonText:'Correct source',sourceReferences:['case:1']}},'batch-one');
    assert.equal(batchResult.value.results[0].recordIdentifier,id);
    assert.equal(batchResult.value.results[0].revisionIdentifier,'2');
    assert.equal(batchResult.value.results[0].domainData.wide,9007199254740992);
    assert.match(requests.at(-1).body,/"reasonCode":"verified-source"/);
    const batchPatch = await client.batchRecords(batch,{items:[{operation:'patch',recordIdentifier:id,
      ifMatch:'"breg-record-000000000001"',patch:[{op:'replace',field:'wide',value:2}]}]},'batch-patch');
    assert.equal(batchPatch.value.results[0].operation,'patch');
    assert.deepEqual(JSON.parse(requests.at(-1).body),{items:[{operation:'patch',recordIdentifier:id,
      ifMatch:'"breg-record-000000000001"',patch:[{op:'replace',path:'/data/wide',value:2}]}]});
    await assert.rejects(client.batchRecords(batch,{items:[{operation:'patch',recordIdentifier:id,
      etag:'"breg-record-000000000001"',operations:[{op:'replace',field:'wide',value:2}]}]},'retired-batch-patch'),
      error=>error.kind === 'invalid-request');
    const exactBatch = await client.batchRecordsJson(batch,'{"items":[{"operation":"create","data":{"wide":9007199254740992}}]}','exact-batch');
    assert.match(exactBatch.valueJson,/"revisionIdentifier":"9007199254740992"/);
    assert.match(requests.at(-1).body,/"wide":9007199254740992/);
    const tombstone = contract.selectTombstone('item',profile);
    const removed = await client.tombstoneRecord(tombstone,id,'"breg-record-000000000001"','remove-one');
    assert.equal(removed.value.data.recordIdentifier,id);
    assert.equal(requests.at(-1).method,'DELETE');
    assert.equal(requests.at(-1).headers['if-match'],'"breg-record-000000000001"');
    const removedJson = await client.tombstoneRecordJson(tombstone,id,'"breg-record-000000000001"','remove-two');
    assert.match(removedJson.valueJson,/9007199254740992/);
    const mutationRequestCount = requests.length;
    await assert.rejects(client.batchRecords(batch,{items:[]},'empty-batch'),error=>error.kind === 'invalid-request');
    assert.throws(() => client.batchRecords(batch,{items:[{operation:'create',data:{wide:Number.MAX_SAFE_INTEGER + 1}}]},'unsafe-batch'),error=>error.kind === 'invalid-request');
    await assert.rejects(client.tombstoneRecord(tombstone,'not-a-uuid','"breg-record-000000000001"','bad-remove'),error=>error.kind === 'invalid-request');
    const foreign = new BaseRegistryClient({baseUrl:'http://127.0.0.1:1'});
    await assert.rejects(foreign.batchRecords(batch,{items:[{operation:'create',data:{wide:1}}]},'foreign-batch'),error=>error.kind === 'invalid-request');
    assert.equal(requests.length,mutationRequestCount);
    const page = await client.listRecordsJson('items',{accessProfile:profile,filter:"wide eq 1"});
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

    const revisions = await client.recordRevisions('items',id,profile);
    assert.equal(revisions.mediaType,'application/json');
    assert.match(requests.at(-1).url,/\/v1\/records\/items\/00000000-0000-4000-8000-000000000001\/revisions\?accessProfile=writer$/);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});

test('native Proposal objects refuse unsafe values and preserve protected edit recovery', async () => {
  const requests = [];
  const revision = `sha256:${'a'.repeat(64)}`;
  const proposal = {
    id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 2, state: 'draft',
    input: {wide: 9007199254740992, decimal: '12.3400', nullable: null},
    links: {
      self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: profile, operation: 'get'},
      edit: {method: 'POST', path: `/v1/proposals/${id}/edit`, accessProfile: profile, operation: 'edit', ifMatch: '"edit-condition"'},
    },
  };
  const contractDocument = {id: 'proposal-json', version: '1', revision, metadataVersion: '2', recordTypes: [], operations: [],
    proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: [], actions: [],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: [profile]}}};
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({url: request.url, body, headers: request.headers});
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store', 'vary': 'authorization, accept',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    const value = request.url.startsWith('/tenant/v1/registry') ? contractDocument
      : request.method === 'POST' && request.url.includes('/edit?')
        ? {...proposal, input: JSON.parse(body).input, revision: proposal.revision + 1} : proposal;
    response.end(JSON.stringify(value)
      .replace('9007199254740992', '9007199254740993'));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const contract = await client.registryContract(profile);
    assert.throws(() => contract.selectProposals(profile), error => error.kind === 'metadata-selection');
    const current = await client.getProposal(contract.selectProposalGet(profile), id);
    assert.match(current.inputJson, /"wide":9007199254740993/);
    assert.match(current.documentJson, /"wide":9007199254740993/);
    assert.equal(JSON.parse(current.inputJson).decimal, '12.3400');
    assert.equal(JSON.parse(current.inputJson).nullable, null);
    assert.ok(!Object.hasOwn(JSON.parse(current.inputJson), 'undisclosed'));
    assert.doesNotMatch(util.inspect(current), /9007199254740993|12\.3400/);
    const before = requests.length;
    // Exact reads retain wide integers; object writes refuse values that JavaScript cannot represent safely.
    for (const invalid of [{input: {wide: Number.NaN}}, {input: {wide: 9007199254740992}}, '{"input":{"wide":1}}']) {
      assert.throws(() => client.prepareProposal(current, 'edit', invalid, 'refused'), error => error.kind === 'invalid-request' && error.outcomeUnknown === false, invalid);
    }
    assert.equal(requests.length, before);
    const body = {input: {wide: 9007199254740990, decimal: '12.3400', nullable: null}};
    const prepared = client.prepareProposal(current, 'edit', body, 'exact-edit');
    const bytes = prepared.toBytes();
    assert.match(util.inspect(prepared), /^BRegPreparedProposal\(<redacted>\)$/);
    assert.doesNotMatch(util.inspect(prepared), /exact-edit|9007199254740990|12\.3400/);
    const restored = BRegPreparedProposal.fromBytes(bytes);
    await assert.rejects(client.executeProposal(restored), error => error.kind === 'invalid-request');
    const recovered = client.recoverProposal(await client.readProposal(current), restored);
    assert.deepEqual(recovered.toBytes(), bytes);
    const edited = JSON.parse((await client.executeProposal(recovered)).documentJson);
    assert.equal(edited.revision, proposal.revision + 1);
    assert.equal(edited.submissionVersion, proposal.submissionVersion);
    assert.equal(edited.state, 'draft');
    assert.equal(edited.input.wide, 9007199254740990);
    assert.equal(requests.at(-1).url, `/tenant/v1/proposals/${id}/edit?accessProfile=${profile}`);
    assert.equal(requests.at(-1).body, '{"input":{"decimal":"12.3400","nullable":null,"wide":9007199254740990.0}}');
    assert.match(requests.at(-1).body, /"wide":9007199254740990/);
    assert.equal(requests.at(-1).headers['if-match'], '"edit-condition"');
    assert.equal(requests.at(-1).headers['idempotency-key'], 'exact-edit');
  } finally { await new Promise(resolve => server.close(resolve)); }
});
