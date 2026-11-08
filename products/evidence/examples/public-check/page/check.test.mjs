import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ANSWER_SCHEMA,
  MESSAGES,
  buildRequestBody,
  describeAnswer,
  messageForStatus,
  normalizeCode,
  parseFragment,
  start,
} from './check.js';

test('parseFragment reads number and code', () => {
  assert.deepEqual(parseFragment('#n=RN-2026-004217&c=K7QWM4XRT5PZ3NB6VHJYDC2A'), {
    number: 'RN-2026-004217',
    code: 'K7QWM4XRT5PZ3NB6VHJYDC2A',
  });
});

test('parseFragment decodes a url-encoded number', () => {
  assert.deepEqual(parseFragment('#n=RN%2F2026%2004&c=AAAA'), {
    number: 'RN/2026 04',
    code: 'AAAA',
  });
});

test('parseFragment returns null without either member', () => {
  assert.equal(parseFragment(''), null);
  assert.equal(parseFragment('#'), null);
  assert.equal(parseFragment('#other=1'), null);
});

test('parseFragment fills a missing member with an empty string', () => {
  assert.deepEqual(parseFragment('#n=RN-1'), { number: 'RN-1', code: '' });
  assert.deepEqual(parseFragment('#c=ABCD'), { number: '', code: 'ABCD' });
});

test('normalizeCode strips spaces and hyphens only', () => {
  assert.equal(normalizeCode('K7QW-M4XR T5PZ\t3NB6-VHJY DC2A'), 'K7QWM4XRT5PZ3NB6VHJYDC2A');
  assert.equal(normalizeCode('k7qw'), 'k7qw');
  assert.equal(normalizeCode('AB_CD'), 'AB_CD');
});

test('buildRequestBody has exactly the two members', () => {
  const body = JSON.parse(buildRequestBody(' RN-2026-004217 ', 'K7QW-M4XR T5PZ3NB6VHJYDC2A'));
  assert.deepEqual(body, {
    documentNumber: 'RN-2026-004217',
    checkCode: 'K7QWM4XRT5PZ3NB6VHJYDC2A',
  });
});

test('messageForStatus maps each class to one fixed message', () => {
  assert.equal(messageForStatus(404), MESSAGES.notFound);
  assert.equal(messageForStatus(400), MESSAGES.badFormat);
  assert.equal(messageForStatus(429), MESSAGES.tooManyChecks);
  assert.notEqual(MESSAGES.tooManyChecks, MESSAGES.unavailable);
  assert.equal(messageForStatus(503), MESSAGES.unavailable);
  assert.equal(messageForStatus(500), MESSAGES.unavailable);
  assert.equal(messageForStatus(0), MESSAGES.unavailable);
});

test('describeAnswer labels known fields and keeps unknown keys', () => {
  const described = describeAnswer({
    schema: ANSWER_SCHEMA,
    status: 'valid',
    fields: { holderName: 'Jordan Sample', extra: 'x' },
    observedAt: '2026-11-08T09:14:03Z',
  });
  assert.deepEqual(described, {
    statusCode: 'valid',
    status: 'Valid',
    rows: [
      ['Holder', 'Jordan Sample'],
      ['extra', 'x'],
    ],
    observedAt: '2026-11-08T09:14:03Z',
  });
});

test('describeAnswer keeps the raw status so a revoked answer is never marked valid', () => {
  const described = describeAnswer({
    schema: ANSWER_SCHEMA,
    status: 'revoked',
    fields: {},
    observedAt: '2026-11-08T09:14:03Z',
  });
  assert.equal(described.statusCode, 'revoked');
  assert.equal(described.status, 'Revoked');
});

test('describeAnswer refuses anything that is not the answer schema', () => {
  const good = { schema: ANSWER_SCHEMA, status: 'valid', fields: {}, observedAt: 'x' };
  assert.notEqual(describeAnswer(good), null);
  assert.equal(describeAnswer(null), null);
  assert.equal(describeAnswer({ ...good, schema: 'other/v1' }), null);
  assert.equal(describeAnswer({ ...good, fields: null }), null);
  assert.equal(describeAnswer({ ...good, observedAt: 5 }), null);
});

function fakeDocument(metaContent) {
  const elements = {};
  const handlers = {};
  const element = () => ({
    textContent: '',
    value: '',
    hidden: true,
    dataset: {},
    replaceChildren() {},
    append() {},
    addEventListener(type, handler) {
      handlers[type] = handler;
    },
  });
  for (const id of ['origin', 'number', 'code', 'check-form', 'result', 'message', 'answer', 'observed']) {
    elements[id] = element();
  }
  return {
    elements,
    handlers,
    getElementById: (id) => elements[id],
    querySelector: () => (metaContent === undefined ? null : { content: metaContent }),
  };
}

for (const [name, content] of [
  ['missing', undefined],
  ['empty', ''],
  ['not a url', 'not a url'],
]) {
  test(`start shows the unavailable message when the endpoint meta is ${name}`, () => {
    const document = fakeDocument(content);
    start(document, { hash: '' });
    assert.equal(document.elements.message.textContent, MESSAGES.unavailable);
    assert.equal(document.elements.message.dataset.kind, 'problem');
    assert.equal(document.elements.result.hidden, false);
    assert.equal(document.elements.origin.textContent, '');
  });
}

test('start does not send a fragment check when the endpoint is unusable', () => {
  const document = fakeDocument(undefined);
  let fetched = false;
  const original = globalThis.fetch;
  globalThis.fetch = () => {
    fetched = true;
    return Promise.reject(new Error('unexpected request'));
  };
  try {
    start(document, { hash: '#n=RN-1&c=K7QWM4XRT5PZ3NB6VHJYDC2A' });
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(fetched, false);
  assert.equal(document.elements.message.textContent, MESSAGES.unavailable);
});

test('start shows the check origin for a usable endpoint', () => {
  const document = fakeDocument('https://check.example.org/v1/public-check');
  start(document, { hash: '' });
  assert.equal(document.elements.origin.textContent, 'Check origin: https://check.example.org');
  assert.equal(document.elements.result.hidden, true);
});

function fakeHistory() {
  const calls = [];
  return { calls, replaceState: (...args) => calls.push(args) };
}

const ENDPOINT = 'https://check.example.org/v1/public-check';

function jsonResponse(status, body) {
  return { status, json: async () => body };
}

async function withFetch(fetchImpl, run) {
  const original = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    await run();
  } finally {
    globalThis.fetch = original;
  }
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('start removes the fragment from the address bar after reading it', async () => {
  const document = fakeDocument(ENDPOINT);
  const history = fakeHistory();
  await withFetch(
    async () => jsonResponse(404, null),
    async () => {
      start(
        document,
        { hash: '#n=RN-1&c=K7QWM4XRT5PZ3NB6VHJYDC2A', pathname: '/', search: '' },
        history,
      );
      await settle();
    },
  );
  assert.deepEqual(history.calls, [[null, '', '/']]);
  assert.equal(document.elements.number.value, 'RN-1');
  assert.equal(document.elements.code.value, 'K7QWM4XRT5PZ3NB6VHJYDC2A');
});

test('start keeps the query string when it removes the fragment', async () => {
  const document = fakeDocument(ENDPOINT);
  const history = fakeHistory();
  await withFetch(
    async () => jsonResponse(404, null),
    async () => {
      start(document, { hash: '#n=RN-1&c=AAAA', pathname: '/c', search: '?lang=en' }, history);
      await settle();
    },
  );
  assert.deepEqual(history.calls, [[null, '', '/c?lang=en']]);
});

test('start leaves the history alone when there is no fragment', () => {
  const document = fakeDocument(ENDPOINT);
  const history = fakeHistory();
  start(document, { hash: '', pathname: '/', search: '' }, history);
  assert.deepEqual(history.calls, []);
});

test('start shows the rate-limit message for a 429', async () => {
  const document = fakeDocument(ENDPOINT);
  await withFetch(
    async () => jsonResponse(429, null),
    async () => {
      start(document, { hash: '#n=RN-1&c=AAAA', pathname: '/', search: '' }, fakeHistory());
      await settle();
    },
  );
  assert.equal(document.elements.message.textContent, MESSAGES.tooManyChecks);
  assert.equal(document.elements.message.dataset.kind, 'problem');
});

test('start drops a slow answer that arrives after a later request', async () => {
  const document = fakeDocument(ENDPOINT);
  const answer = (status) => ({
    schema: ANSWER_SCHEMA,
    status,
    fields: {},
    observedAt: '2026-11-08T09:14:03Z',
  });
  const pending = [];
  await withFetch(
    () => new Promise((resolve) => pending.push(resolve)),
    async () => {
      start(document, { hash: '#n=RN-1&c=AAAA', pathname: '/', search: '' }, fakeHistory());
      document.handlers.submit({ preventDefault() {} });
      assert.equal(pending.length, 2);
      pending[1](jsonResponse(200, answer('revoked')));
      await settle();
      assert.equal(document.elements.message.dataset.status, 'revoked');
      pending[0](jsonResponse(200, answer('valid')));
      await settle();
    },
  );
  assert.equal(document.elements.message.dataset.status, 'revoked');
  assert.equal(document.elements.message.textContent, 'Status: Revoked');
});
