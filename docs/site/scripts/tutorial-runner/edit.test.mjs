import assert from 'node:assert/strict';
import test from 'node:test';

import { applyEdit } from './edit.mjs';

const file = `grants:
  - profile: auditor
    access:
        readable: [code, label, group, status]
        filterable: [code]
  - profile: operator
    access:
        readable: [code, label, group, status]
        writable: [code, label, group, status]
        filterable: [code, status]
`;

test('an edit replaces the one place its lines appear, keeping their indentation', () => {
  const { text, error } = applyEdit(
    file,
    ['readable: [code, label, group, status]', 'writable: [code, label, group, status]'],
    ['readable: [code, label, group, status, note]', 'writable: [code, label, group, status, note]'],
  );
  assert.equal(error, undefined);
  assert.equal(
    text,
    file
      .replace('readable: [code, label, group, status]\n        writable: [code, label, group, status]', 'readable: [code, label, group, status, note]\n        writable: [code, label, group, status, note]'),
  );
});

test('relative indentation inside an edit is kept', () => {
  const { text } = applyEdit(file, ['- profile: auditor', '  access:'], ['- profile: auditor', '  role: read', '  access:']);
  assert.match(text, /^ {2}- profile: auditor\n {4}role: read\n {4}access:$/mu);
});

test('an edit that matches more than one place is refused', () => {
  const { error } = applyEdit(file, ['readable: [code, label, group, status]'], ['readable: []']);
  assert.equal(error, 'its lines match 2 places; show enough surrounding lines to name one');
});

test('an edit that matches nowhere is refused', () => {
  const { error } = applyEdit(file, ['readable: [code]'], ['readable: []']);
  assert.equal(error, 'its lines match no place in the file');
});
