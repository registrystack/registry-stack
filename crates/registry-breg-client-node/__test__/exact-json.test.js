'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
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
    readableFields:fields.map(f=>f.id), createWritableFields:kind === 'create' ? fields.map(f=>f.id) : [],
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
    readableFields:fields.map(f=>f.id), createWritableFields:[], patchWritableFields:[], selectors:[], query:null,
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
const metadata = {id:'test-registry',version:'1',revision:`sha256:${'a'.repeat(64)}`,metadataVersion:'1',
  entities:[{id:'item',datasetIdentifier:'items',route:'items',schema:'/v1/schemas/item',
    operations:['create','patch','list','lookup','apply_request'].map(operation=>({operation,accessProfile:profile})),readableFields:fields.map(f=>f.id)}],
  operations:[...['create','patch','list'].map(operation), lookupOperation(), lifecycleOperation()],
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
      actions: [{operation:'apply_request', method:'POST', href:lifecycleActionHref, ifMatch:actionIfMatch, proposalVersion, effectDigest:digest}],
    },
  },
  meta,
});
const receipt = {
  id: lifecycleRecordId, revision: receiptRevision, snapshot: `breg1_${lifecycleRecordId}`,
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
    assert.equal(list.query.filterableFields[0].apiName,'bregState');
    assert.equal(list.fields[0].schemaJson,'{"type":"integer"}');
    list.id = 'forged';
    assert.equal(contract.operations.find(op=>op.kind === 'list').id,'records.item.list');
    const binding = contract.selectCreate('records.item.create',profile);
    const data = `{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","nullable":null,"reference":"${id}"}`;
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
    await client.patchRecordJson(patch,id,created.etag,'[{"op":"replace","field":"wide","value":9007199254740992}]','exact-patch');
    assert.equal(requests.at(-1).headers['if-match'],created.etag);
    assert.match(requests.at(-1).body,/"path":"\/data\/wide"/);
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
    const executed = await client.executeLifecycleActionJson(actions[0],'exact-apply');
    assert.match(requests.at(-1).url.split('?')[0],/\/actions\/apply$/);
    assert.equal(requests.at(-1).headers['idempotency-key'],'exact-apply');
    assert.equal(requests.at(-1).headers['if-match'],actionIfMatch);
    assert.match(requests.at(-1).body,/"proposalVersion":3/);
    assert.match(requests.at(-1).body,new RegExp(`"effectDigest":"${digest}"`));
    const executedValue = JSON.parse(executed.valueJson);
    assert.equal(executedValue.id,lifecycleRecordId);
    assert.equal(executedValue.revision,receiptRevision);
    assert.equal(executedValue.request.application.id,applicationId);
    assert.equal(executedValue.request.application.proposalVersion,proposalVersion);
    assert.equal(executedValue.request.application.effectDigest,digest);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});
