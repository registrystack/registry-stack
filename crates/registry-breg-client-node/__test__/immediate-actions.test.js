'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const util = require('node:util');
const { BaseRegistryClient, BRegPreparedAction } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const targetId = '00000000-0000-4000-8000-000000000001';
const applicationId = '00000000-0000-4000-8000-000000000002';
const metadata = {
  id: 'fixture-registry', version: '1',
  revision: `sha256:${'a'.repeat(64)}`, metadataVersion: '1', entities: [], operations: [],
  actions: [{
    id: 'update-item', route: '/v1/actions/update-item',
    conditionRoute: '/v1/actions/update-item/target-conditions',
    contractFingerprint: `sha256:${'b'.repeat(64)}`,
    inputMode: 'handler', maximumInputStringBytes: 16384,
    inputs: [
      { id: 'target', apiName: 'targetId', required: true, nullable: false, classification: 'internal', fieldType: { type: 'reference', target: 'item', onDelete: 'restrict' } },
      { id: 'label', apiName: 'label', required: false, nullable: true, classification: 'internal', fieldType: { type: 'string', minLength: 1, maxLength: 16 } },
      { id: 'sequence', apiName: 'sequence', required: false, nullable: true, classification: 'internal', fieldType: { type: 'int64' } },
    ],
    referenceInputs: [{ input: 'target', apiName: 'targetId', targetEntity: 'item' }],
    requiredConditionKeys: ['targetId'],
    resultEffects: [{ effect: 'item', entity: 'item', operation: 'patch' }],
    access: { selectedProfile: 'writer' },
    routes: {
      invoke: { method: 'POST', path: '/v1/actions/update-item', operationId: 'actions.update-item.invoke', requiresIdempotencyKey: true, inputSchema: 'action-update-item-invoke-input', responseSchema: 'action-update-item-invoke-response' },
      targetConditions: { method: 'POST', path: '/v1/actions/update-item/target-conditions', operationId: 'actions.update-item.target_conditions', requiresIdempotencyKey: false, inputSchema: 'action-update-item-target-conditions-input', responseSchema: 'action-update-item-target-conditions-response' },
    },
    bounds: { maximumTargets: 16, maximumFieldMutations: 128, maximumSnapshotBytes: 2097152 },
  }],
};

test('metadata-selected immediate action conditions and invocations use exact caller input', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({ url: request.url, body, headers: request.headers });
    response.setHeader('content-type', 'application/json');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(metadata));
    if (request.url.includes('/target-conditions')) return response.end(`{"preconditions":{"targetId":{"ifMatch":"\\"opaque-condition\\""}}}`);
    return response.end(`{"action":"update-item","applicationId":"${applicationId}","results":{"item":{"entity":"item","recordId":"${targetId}","revision":9007199254740992}}}`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    const contract = await client.registryContract('writer');
    assert.equal(contract.immediateActions[0].inputMode, 'handler');
    assert.equal(contract.immediateActions[0].maximumInputStringBytes, 16384);
    assert.equal(contract.immediateActions[0].inputs[1].nullable, true);
    assert.match(contract.actionsJson, /"update-item"/);
    const binding = contract.selectImmediateAction('update-item', 'writer');
    const conditions = await client.actionTargetConditions(binding, { targetId });
    assert.deepEqual(conditions.preconditionKeys, ['targetId']);
    assert.equal(conditions.valueJson, '{"preconditions":{"targetId":{"ifMatch":"\\"opaque-condition\\""}}}');
    const result = await client.invokeAction(binding, { targetId, label: null }, 'invoke-one', conditions);
    assert.equal(result.value.action, 'update-item');
    assert.equal(result.value.results.item.recordId, targetId);
    const exactConditions = await client.actionTargetConditionsJson(binding, `{"targetId":"${targetId}"}`);
    const exact = await client.invokeActionJson(binding, `{"targetId":"${targetId}","label":"new","sequence":9007199254740992}`, 'invoke-two', exactConditions);
    assert.match(exact.valueJson, /"revision":9007199254740992/);
    assert.equal(requests.at(-1).headers['idempotency-key'], 'invoke-two');
    assert.match(requests.at(-1).body, /"sequence":9007199254740992/);
    assert.match(requests.at(-1).body, /"preconditions":\{"targetId":\{"ifMatch":"\\"opaque-condition\\""\}\}/);
    const count = requests.length;
    await assert.rejects(client.invokeAction(binding, { targetId, unknown: true }, 'invalid'), error => error.kind === 'invalid_request');
    assert.throws(() => client.invokeAction(binding, { targetId, sequence: Number.MAX_SAFE_INTEGER + 1 }, 'unsafe'), error => error.kind === 'invalid_request');
    const foreign = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
    await assert.rejects(foreign.invokeAction(binding, { targetId }, 'foreign', conditions), error => error.kind === 'invalid_request');
    assert.equal(requests.length, count);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('an immediate action recovers after a lost response from persisted bytes and the same key', async () => {
  const requests = [];
  let loseNextInvocation = true;
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({ url: request.url, body, headers: request.headers });
    const invocation = request.url.startsWith('/v1/actions/update-item?');
    if (invocation && loseNextInvocation) {
      // The engine received the invocation, but its answer never arrives.
      loseNextInvocation = false;
      request.socket.destroy();
      return;
    }
    response.setHeader('content-type', 'application/json');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(metadata));
    if (request.url.includes('/target-conditions')) return response.end(`{"preconditions":{"targetId":{"ifMatch":"\\"opaque-condition\\""}}}`);
    return response.end(`{"action":"update-item","applicationId":"${applicationId}","results":{"item":{"entity":"item","recordId":"${targetId}","revision":9007199254740992}}}`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    // The process gives up after the lost answer instead of resending it.
    const client = new BaseRegistryClient({ baseUrl, maxMutationRetries: 0 });
    const binding = (await client.registryContract('writer')).selectImmediateAction('update-item', 'writer');
    const conditions = await client.actionTargetConditions(binding, { targetId });
    const inputs = { targetId, label: 'new' };
    const prepared = client.prepareAction(binding, inputs, 'invoke-lost', conditions);
    const persisted = prepared.toBytes();
    assert.ok(Buffer.isBuffer(persisted));
    assert.match(util.inspect(prepared), /^BRegPreparedAction\(<redacted>\)$/);
    assert.doesNotMatch(String(prepared), /invoke-lost|opaque-condition/);
    assert.throws(() => new BRegPreparedAction(), TypeError);
    await assert.rejects(
      client.invokeAction(binding, inputs, 'invoke-lost', conditions),
      error => error.kind === 'transport' && error.outcomeUnknown === true,
    );
    const lost = requests.at(-1);
    assert.equal(lost.headers['idempotency-key'], 'invoke-lost');

    const restarted = new BaseRegistryClient({ baseUrl });
    const restartedBinding = (await restarted.registryContract('writer')).selectImmediateAction('update-item', 'writer');
    const restored = BRegPreparedAction.fromBytes(persisted);
    assert.ok(restored instanceof BRegPreparedAction);
    assert.deepEqual(restored.toBytes(), persisted);
    const beforeRecovery = requests.length;
    assert.throws(() => BRegPreparedAction.fromBytes('not bytes'), error => error.kind === 'invalid_request');
    assert.throws(() => BRegPreparedAction.fromBytes(Buffer.from('{}')), error => error.kind === 'invalid_request');
    assert.throws(() => restarted.recoverAction(restartedBinding, restored, inputs, 'another-key'), error => error.kind === 'invalid_request');
    assert.throws(() => restarted.recoverAction(restartedBinding, restored, { targetId, label: 'changed' }, 'invoke-lost'), error => error.kind === 'invalid_request');
    const foreign = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
    assert.throws(() => foreign.recoverAction(restartedBinding, restored, inputs, 'invoke-lost'), error => error.kind === 'invalid_request');
    const recovered = restarted.recoverAction(restartedBinding, restored, inputs, 'invoke-lost');
    await assert.rejects(foreign.executeRecoveredAction(restartedBinding, recovered), error => error.kind === 'invalid_request');
    assert.equal(requests.length, beforeRecovery);

    const result = await restarted.executeRecoveredAction(restartedBinding, recovered);
    assert.equal(result.value.action, 'update-item');
    assert.equal(result.value.applicationId, applicationId);
    const replay = requests.at(-1);
    assert.equal(replay.url, lost.url);
    assert.match(replay.url, /^\/v1\/actions\/update-item\?/);
    assert.equal(replay.headers['idempotency-key'], 'invoke-lost');
    assert.equal(replay.body, lost.body);
    assert.equal(requests.filter(request => request.url.includes('/target-conditions')).length, 1);

    const exactInputs = `{"targetId":"${targetId}","sequence":9007199254740992}`;
    const preparedExact = restarted.prepareActionJson(restartedBinding, exactInputs, 'invoke-exact', conditions);
    assert.throws(() => restarted.recoverActionJson(restartedBinding, preparedExact, `{"targetId":"${targetId}","sequence":9007199254740993}`, 'invoke-exact'), error => error.kind === 'invalid_request');
    const recoveredExact = restarted.recoverActionJson(
      restartedBinding, BRegPreparedAction.fromBytes(preparedExact.toBytes()), exactInputs, 'invoke-exact',
    );
    const exact = await restarted.executeRecoveredActionJson(restartedBinding, recoveredExact);
    assert.match(exact.valueJson, /"revision":9007199254740992/);
    assert.equal(requests.at(-1).headers['idempotency-key'], 'invoke-exact');
    assert.match(requests.at(-1).body, /"sequence":9007199254740992/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
