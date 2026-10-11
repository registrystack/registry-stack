'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { inspect: inspectValue } = require('node:util');

const RUN_ID = '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d';
const STATUS = {
  runId: RUN_ID,
  workflowId: 'decision-follow-up',
  workflowVersion: '1',
  definitionDigest: 'sha256:definition',
  bindingDigest: 'sha256:binding',
  step: 'read-record',
  state: 'waiting',
  outcome: null,
  output: null,
  failureCode: null,
  failurePath: null,
  admittedAt: '2026-10-10T01:00:00Z',
  deadlineAt: '2026-10-10T02:00:00Z',
  nextDueAt: '2026-10-10T01:01:00Z',
  uncertain: false,
  restoreReviewRequired: false,
  cancelRequested: false,
};
const INSPECTION = {
  run: STATUS,
  steps: [{
    step: 'read-record',
    state: 'waiting',
    generation: 1,
    attempt: 1,
    nextDueAt: '2026-10-10T01:01:00Z',
    leaseExpiresAt: null,
    commandPrepared: true,
    uncertain: true,
    receiptExpired: false,
    failureCode: null,
    failurePath: null,
  }],
  recovery: {
    retryAllowed: false,
    reason: 'evaluation-uncertain',
    operation: {
      id: 'evaluate-decision',
      version: 1,
      product: 'decision',
      effect: 'evaluation',
      keyRequirement: 'required',
      requiresPreparation: true,
      recovery: 'hold-after-dispatch',
      readReceipt: true,
    },
  },
};

const RETRY_SCHEDULED = { runId: RUN_ID, status: 'retry-scheduled' };
const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;

// A refusal as the runtime answers it: an RFC 9457 document whose trace
// matches the answer's traceparent.
function problem(status, code, { title = 'withheld', detail = 'withheld' } = {}) {
  return {
    status,
    document: {
      type: `https://id.registrystack.org/problems/registry-coordinator/${code.replace('.', '/')}`,
      title,
      status,
      detail,
      code,
      traceId: TRACE_ID,
    },
  };
}

const UNAVAILABLE = problem(503, 'service.unavailable');
const CONFLICT = problem(409, 'idempotency.key-reused');

function scripted(answers) {
  let next = 0;
  return () => answers[Math.min(next++, answers.length - 1)];
}

async function serve(context, answer) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push({ method: request.method, path: request.url, headers: request.headers, body });
      const { status, document, contentType = status === 200 ? 'application/json' : 'application/problem+json' } = answer(request);
      response.writeHead(status, { 'content-type': contentType, traceparent: TRACEPARENT });
      response.end(JSON.stringify(document));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  return { baseUrl: `http://127.0.0.1:${server.address().port}/`, requests };
}

test('facade exports the maintained client and mapped error', () => {
  const client = require('../client');
  assert.equal(typeof client.CoordinatorClient, 'function');
  assert.equal(typeof client.CoordinatorClientError, 'function');
});

test('start preserves the caller token, key, and input', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200, document: STATUS }));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });
  const request = { flow: 'decision-follow-up', input: { record: 'case-42', priority: 2 } };

  assert.deepEqual(
    await client.start('one-call-secret', 'admission 42', request),
    { kind: 'complete', value: STATUS },
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/runs');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], 'admission 42');
  assert.equal(requests[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].body), request);
});

test('status, inspect, and reconcile use only the requested run routes', async (context) => {
  const { baseUrl, requests } = await serve(context, (request) => ({
    status: 200,
    document: request.url.endsWith('/inspect') || request.url.endsWith('/reconcile') ? INSPECTION : STATUS,
  }));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  assert.deepEqual(await client.status('read-secret', RUN_ID), { kind: 'complete', value: STATUS });
  assert.deepEqual(await client.inspect('inspect-secret', RUN_ID), { kind: 'complete', value: INSPECTION });
  assert.deepEqual(
    await client.reconcile('reconcile-secret', RUN_ID, 'operator reviewed the original receipt'),
    { kind: 'complete', value: INSPECTION },
  );
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ['GET', `/v1/runs/${RUN_ID}`],
    ['GET', `/v1/runs/${RUN_ID}/inspect`],
    ['POST', `/v1/runs/${RUN_ID}/reconcile`],
  ]);
  assert.deepEqual(JSON.parse(requests[2].body), { reason: 'operator reviewed the original receipt' });
});

test('a run and step status carry the failure path a refused call input names', async (context) => {
  for (const [member, expected] of [['/recordId', '/recordId'], [null, null], [undefined, null]]) {
    const run = { ...STATUS };
    const step = { ...INSPECTION.steps[0] };
    delete run.failurePath;
    delete step.failurePath;
    if (member !== undefined) {
      run.failurePath = member;
      step.failurePath = member;
    }
    const { baseUrl } = await serve(context, (request) => ({
      status: 200,
      document: request.url.endsWith('/inspect') ? { ...INSPECTION, run, steps: [step] } : run,
    }));
    const { CoordinatorClient } = require('../client');
    const client = new CoordinatorClient({ baseUrl });

    const status = await client.status('read-secret', RUN_ID);
    const inspection = await client.inspect('inspect-secret', RUN_ID);
    assert.equal(status.kind, 'complete');
    assert.equal(inspection.kind, 'complete');
    assert.equal(status.value.failurePath, expected);
    assert.equal(inspection.value.run.failurePath, expected);
    assert.equal(inspection.value.steps[0].failurePath, expected);
  }
});

test('list, retrySame, and cancel use only their exact routes and carry no key', async (context) => {
  const { baseUrl, requests } = await serve(context, (request) => {
    if (request.url.endsWith('/retry-same')) return { status: 200, document: RETRY_SCHEDULED };
    if (request.url.endsWith('/cancel')) return { status: 200, document: { ...STATUS, cancelRequested: true } };
    return { status: 200, document: { runs: [STATUS] } };
  });
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  assert.deepEqual(await client.list('list-secret', 5), { kind: 'complete', value: { runs: [STATUS] } });
  assert.deepEqual(
    await client.retrySame('retry-secret', RUN_ID, 'operator reviewed the inspection'),
    { kind: 'complete', value: RETRY_SCHEDULED },
  );
  assert.deepEqual(
    await client.cancel('cancel-secret', RUN_ID, 'caller withdrew the request'),
    { kind: 'complete', value: { ...STATUS, cancelRequested: true } },
  );
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ['GET', '/v1/runs?limit=5'],
    ['POST', `/v1/runs/${RUN_ID}/retry-same`],
    ['POST', `/v1/runs/${RUN_ID}/cancel`],
  ]);
  assert.equal(requests[0].headers.authorization, 'Bearer list-secret');
  assert.deepEqual(JSON.parse(requests[1].body), { reason: 'operator reviewed the inspection' });
  assert.deepEqual(JSON.parse(requests[2].body), { reason: 'caller withdrew the request' });
  for (const sent of requests) assert.equal(sent.headers['idempotency-key'], undefined);
});

test('a list limit outside one to one hundred fails before I/O', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200, document: { runs: [] } }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  for (const limit of [0, 101, -1, 1.5, 4_294_967_296, Number.NaN, Infinity, '5']) {
    await assert.rejects(async () => client.list('secret', limit), (error) => {
      assert.ok(error instanceof CoordinatorClientError, `${limit}`);
      assert.equal(error.kind, 'invalid-request', `${limit}`);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
  assert.equal(requests.length, 0);
  assert.deepEqual(await client.list('secret', 1), { kind: 'complete', value: { runs: [] } });
  assert.deepEqual(await client.list('secret', 100), { kind: 'complete', value: { runs: [] } });
  assert.equal(requests.length, 2);
});

test('an invalid retry or cancellation reason fails before I/O', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500, document: {} }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  for (const reason of ['', 'line\nbreak', 'r'.repeat(257), 'é'.repeat(129)]) {
    for (const method of ['retrySame', 'cancel']) {
      await assert.rejects(async () => client[method]('secret', RUN_ID, reason), (error) => {
        assert.ok(error instanceof CoordinatorClientError, method);
        assert.equal(error.kind, 'invalid-request', method);
        return true;
      });
    }
  }
  assert.equal(requests.length, 0);
});

test('a refused list, retry, or cancellation keeps its status and code', async (context) => {
  const { baseUrl, requests } = await serve(context, (request) => {
    if (request.method === 'GET') return problem(400, 'request.invalid', { detail: 'canary' });
    if (request.url.endsWith('/retry-same')) return problem(409, 'retry.refused', { detail: 'canary' });
    return problem(409, 'execution.held', { title: 'canary' });
  });
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  for (const [call, status, code] of [
    [() => client.list('secret', 20), 400, 'request.invalid'],
    [() => client.retrySame('secret', RUN_ID, 'operator reviewed the inspection'), 409, 'retry.refused'],
    [() => client.cancel('secret', RUN_ID, 'caller withdrew the request'), 409, 'execution.held'],
  ]) {
    await assert.rejects(call(), (error) => {
      assert.ok(error instanceof CoordinatorClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, status);
      assert.equal(error.code, code);
      assert.equal(error.outcomeUnknown, false);
      assert.doesNotMatch(inspectValue(error), /canary|secret/);
      return true;
    });
  }
  assert.equal(requests.length, 3);
});

test('retrySame and cancel are sent once even when their outcome is unknown', async (context) => {
  const { baseUrl, requests } = await serve(context, scripted([UNAVAILABLE, { status: 200, document: RETRY_SCHEDULED }]));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl, maxMutationRetries: 2 });

  await assert.rejects(client.retrySame('secret', RUN_ID, 'operator reviewed the inspection'), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 503);
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a retry answer for another run is a protocol failure', async (context) => {
  const { baseUrl } = await serve(context, () => ({
    status: 200,
    document: { runId: '1f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d', status: 'retry-scheduled' },
  }));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  await assert.rejects(client.retrySame('secret', RUN_ID, 'operator reviewed the inspection'), (error) => {
    assert.equal(error.kind, 'protocol');
    assert.equal(error.protocolFailure, 'body');
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
});

test('invalid request documents and run identifiers fail before I/O', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500, document: {} }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  assert.throws(
    () => client.start('secret', 'admission-42', { flow: 'decision-follow-up', input: { unsafe: 9_007_199_254_740_992 } }),
    (error) => error instanceof CoordinatorClientError && error.kind === 'invalid-request',
  );
  await assert.rejects(
    client.status('secret', 'not-a-run-id'),
    (error) => error instanceof CoordinatorClientError && error.kind === 'invalid-request',
  );
  assert.equal(requests.length, 0);
});

test('a service problem on a read is safe and is never resent', async (context) => {
  const problemMessage = 'internal operator detail secret-should-not-escape';
  const { baseUrl, requests } = await serve(context, () => problem(503, 'service.unavailable', {
    title: 'private runbook',
    detail: problemMessage,
  }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  await assert.rejects(
    client.reconcile('reconcile-secret', RUN_ID, 'check original receipt'),
    (error) => {
      assert.ok(error instanceof CoordinatorClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.code, 'service.unavailable');
      assert.equal(error.status, 503);
      assert.equal(error.outcomeUnknown, true);
      const displayed = inspectValue(error);
      assert.doesNotMatch(displayed, /secret-should-not-escape|private runbook|reconcile-secret/);
      return true;
    },
  );
  assert.equal(requests.length, 1);
});

test('an unknown admission outcome is resent under the same key and body', async (context) => {
  const { baseUrl, requests } = await serve(context, scripted([UNAVAILABLE, { status: 200, document: STATUS }]));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });
  const request = { flow: 'decision-follow-up', input: { record: 'case-42' } };

  assert.deepEqual(await client.start('one-call-secret', 'admission 42', request), { kind: 'complete', value: STATUS });
  assert.equal(requests.length, 2);
  for (const sent of requests) {
    assert.equal(sent.method, 'POST');
    assert.equal(sent.path, '/v1/runs');
    assert.equal(sent.headers['idempotency-key'], 'admission 42');
    assert.equal(sent.body, requests[0].body);
  }
});

test('a retry ceiling of zero sends an admission once and reports the outcome unknown', async (context) => {
  const { baseUrl, requests } = await serve(context, scripted([UNAVAILABLE, { status: 200, document: STATUS }]));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl, maxMutationRetries: 0 });

  await assert.rejects(client.start('one-call-secret', 'key-1', { flow: 'decision-follow-up', input: {} }), (error) => {
    assert.ok(error instanceof CoordinatorClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 503);
    assert.equal(error.code, 'service.unavailable');
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a 4xx refusal of an admission is never resent and reports the outcome known', async (context) => {
  const { baseUrl, requests } = await serve(context, scripted([CONFLICT, { status: 200, document: STATUS }]));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl, maxMutationRetries: 2 });

  await assert.rejects(client.start('one-call-secret', 'key-1', { flow: 'decision-follow-up', input: {} }), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 409);
    assert.equal(error.code, 'idempotency.key-reused');
    assert.equal(error.outcomeUnknown, false);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a flow the deployment does not serve is refused once with a known outcome', async (context) => {
  const { baseUrl, requests } = await serve(context, scripted([
    problem(404, 'flow.not-served', { title: 'private runbook', detail: 'canary' }),
    { status: 200, document: STATUS },
  ]));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl, maxMutationRetries: 2 });

  await assert.rejects(client.start('one-call-secret', 'key-1', { flow: 'decision-follow-up', input: {} }), (error) => {
    assert.ok(error instanceof CoordinatorClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 404);
    assert.equal(error.code, 'flow.not-served');
    assert.equal(error.outcomeUnknown, false);
    assert.doesNotMatch(inspectValue(error), /canary|private runbook|one-call-secret/);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a run of a flow outside the caller policy reads as absent on every run action', async (context) => {
  const { baseUrl, requests } = await serve(context, () => problem(404, 'run.not-visible'));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl, maxMutationRetries: 2 });

  for (const call of [
    () => client.status('secret', RUN_ID),
    () => client.inspect('secret', RUN_ID),
    () => client.reconcile('secret', RUN_ID, 'check original receipt'),
    () => client.retrySame('secret', RUN_ID, 'operator reviewed the inspection'),
    () => client.cancel('secret', RUN_ID, 'caller withdrew the request'),
  ]) {
    await assert.rejects(call(), (error) => {
      assert.ok(error instanceof CoordinatorClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, 404);
      assert.equal(error.code, 'run.not-visible');
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
  assert.equal(requests.length, 5);
});

test('a refusal that is not the exact problem document is a protocol failure', async (context) => {
  const wrongTrace = problem(404, 'run.not-visible');
  wrongTrace.document = { ...wrongTrace.document, traceId: '0af7651916cd43dd8448eb211c80319c' };
  const answers = [
    [{ ...problem(404, 'run.not-visible'), contentType: 'application/json' }, 'media-type'],
    [{ status: 404, document: { code: 'run.not-visible', message: 'canary', suggestedAction: null } }, 'problem'],
    [wrongTrace, 'problem'],
  ];
  const { baseUrl, requests } = await serve(context, scripted(answers.map(([answer]) => answer)));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  for (const [, failure] of answers) {
    await assert.rejects(client.status('secret', RUN_ID), (error) => {
      assert.ok(error instanceof CoordinatorClientError);
      assert.equal(error.kind, 'protocol');
      assert.equal(error.protocolFailure, failure);
      assert.equal(error.code, undefined);
      assert.doesNotMatch(inspectValue(error), /canary|secret/);
      return true;
    });
  }
  assert.equal(requests.length, 3);
});

test('a retry ceiling outside zero to two is a configuration error', () => {
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  for (const maxMutationRetries of [0, 1, 2, null]) {
    assert.ok(new CoordinatorClient({ baseUrl: 'https://coordinator.example/', maxMutationRetries }));
  }
  for (const maxMutationRetries of [3, 255, 256, -1, 1.5, '1']) {
    assert.throws(() => new CoordinatorClient({ baseUrl: 'https://coordinator.example/', maxMutationRetries }), (error) => {
      assert.ok(error instanceof CoordinatorClientError, `${maxMutationRetries}`);
      assert.equal(error.kind, 'configuration', `${maxMutationRetries}`);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
});

test('a configuration member outside the declared set is a configuration error', () => {
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  for (const member of ['maxMutationRetry', 'requestTimeoutMs', 'authorization']) {
    assert.throws(() => new CoordinatorClient({ baseUrl: 'https://coordinator.example/', [member]: 0 }), (error) => {
      assert.ok(error instanceof CoordinatorClientError, member);
      assert.equal(error.kind, 'configuration', member);
      return true;
    });
  }
});
