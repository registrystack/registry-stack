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
  assert.equal(messageForStatus(429), MESSAGES.unavailable);
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
