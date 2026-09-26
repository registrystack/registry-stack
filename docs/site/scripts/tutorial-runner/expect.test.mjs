import assert from 'node:assert/strict';
import test from 'node:test';

import { checkExpectation } from './expect.mjs';

test('text matches the whole output, ignoring trailing spaces and surrounding blank lines', () => {
  assert.equal(checkExpectation('text', 'HTTP 404', '\nHTTP 404  \n\n'), null);
});

test('text reports a mismatch with both sides', () => {
  const problem = checkExpectation('text', 'HTTP 412', 'HTTP 200\n');
  assert.match(problem, /expected:\n  HTTP 412\nactual:\n  HTTP 200/u);
});

test('text output that has extra lines does not match', () => {
  assert.notEqual(checkExpectation('text', 'HTTP 404', 'HTTP 404\nmore\n'), null);
});

test('a <placeholder> in text stands for one run of non-space characters', () => {
  assert.equal(checkExpectation('text', 'revision  sha256:<digest>', 'revision  sha256:0a98f1\n'), null);
  assert.notEqual(checkExpectation('text', 'revision  sha256:<digest>', 'revision  sha256:\n'), null);
  assert.notEqual(checkExpectation('text', 'revision  sha256:<digest>', 'revision  sha256:a b\n'), null);
});

test('text outside placeholders is literal, not a regular expression', () => {
  assert.notEqual(checkExpectation('text', 'a.c (x)', 'abc (x)\n'), null);
  assert.equal(checkExpectation('text', 'a.c (x)', 'a.c (x)\n'), null);
});

test('json compares structure, so indentation and key order do not matter', () => {
  assert.equal(checkExpectation('json', '{\n  "b": [1],\n  "a": null\n}', '{"a": null, "b": [1]}'), null);
});

test('json reports the path of the first difference', () => {
  assert.match(
    checkExpectation('json', '{"data": {"revision": "2"}}', '{"data": {"revision": "1"}}'),
    /at \$\.data\.revision: expected "2", got "1"/u,
  );
  assert.match(checkExpectation('json', '{"a": 1}', '{"a": 1, "b": 2}'), /at \$: unexpected key "b"/u);
  assert.match(checkExpectation('json', '{"a": 1, "b": 2}', '{"a": 1}'), /at \$: missing key "b"/u);
  assert.match(checkExpectation('json', '[1, 2]', '[1]'), /at \$: expected 2 items, got 1/u);
});

test('a json string that is only a <placeholder> matches any string', () => {
  assert.equal(checkExpectation('json', '{"id": "<record-id>"}', '{"id": "b4038ec9"}'), null);
  assert.match(checkExpectation('json', '{"id": "<record-id>"}', '{"id": 7}'), /at \$\.id: expected a string/u);
});

test('output that is not JSON is reported as such', () => {
  assert.match(checkExpectation('json', '{}', 'curl: (7) refused\n'), /output is not JSON/u);
});

test('a <placeholder> inside a json string stands for one run of non-space characters', () => {
  assert.equal(checkExpectation('json', '{"digest": "sha256:<digest>"}', '{"digest": "sha256:0f3a"}'), null);
  assert.match(checkExpectation('json', '{"digest": "sha256:<digest>"}', '{"digest": "md5:0f3a"}'), /at \$\.digest/u);
  assert.match(checkExpectation('json', '{"digest": "sha256:<digest>"}', '{"digest": 7}'), /at \$\.digest/u);
});
