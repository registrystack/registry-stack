import assert from 'node:assert/strict';
import test from 'node:test';

import { checkExcerpt } from './excerpt.mjs';

const REPORT = `Locked the project modules. 1 artifact written.
  revision  sha256:aaa

0 errors, 2 findings.

{
  "changed": true,
  "modules": [
    {"digest": "sha256:bbb", "id": "record-notes", "status": "updated", "version": "0.2.0"}
  ]
}
`;

test('a text excerpt is a run of lines found at one indentation, with placeholders', () => {
  const file = 'entities:\n  - id: record\n    fields:\n      - {id: note, maxLength: 500}\n    modules:\n      - digest: "sha256:abc"\n';
  assert.equal(checkExcerpt('text', '- {id: note, maxLength: 500}', file), null);
  assert.equal(checkExcerpt('text', 'fields:\n  - {id: note, maxLength: 500}', file), null);
  assert.equal(checkExcerpt('text', 'modules:\n  - digest: "sha256:<digest>"', file), null);
});

test('a text excerpt whose lines are not together, or not at one indentation, is not found', () => {
  const file = 'a: 1\nb: 2\nc: 3\n  d: 4\n';
  assert.match(checkExcerpt('text', 'a: 1\nc: 3', file), /no run of lines matches/u);
  assert.match(checkExcerpt('text', 'c: 3\nd: 4', file), /no run of lines matches/u);
  assert.match(checkExcerpt('text', 'maxLength: 1000', file), /excerpt:\n {2}maxLength: 1000/u);
});

test('a JSON excerpt is an object whose keys and values some object in the source carries', () => {
  const excerpt = '{"digest": "sha256:<digest>", "id": "record-notes", "status": "updated", "version": "0.2.0"}';
  assert.equal(checkExcerpt('json', excerpt, REPORT), null);
  assert.equal(checkExcerpt('json', '{"changed": true}', REPORT), null);
  const schema = '{"properties": {"internalNote": {"anyOf": [{"type": "string"}, {"type": "null"}]}, "code": {"type": "string"}}}';
  assert.equal(checkExcerpt('json', '{"internalNote": {"anyOf": [{"type": "string"}, {"type": "null"}]}}', schema), null);
});

test('a JSON excerpt names the closest object when no object matches', () => {
  const problem = checkExcerpt('json', '{"id": "record-notes", "version": "0.3.0"}', REPORT);
  assert.match(problem, /no object in it carries every key of the excerpt with the same value/u);
  assert.match(problem, /closest: at \$\.version: expected "0\.3\.0", got "0\.2\.0"/u);
  assert.match(checkExcerpt('json', '{"missing": 1}', REPORT), /no object in it has the keys "missing"/u);
});

test('a JSON excerpt against output with no JSON in it says so', () => {
  assert.match(checkExcerpt('json', '{"a": 1}', 'plain text only\n'), /holds no JSON document/u);
  assert.match(checkExcerpt('json', '{"a": ', '{}'), /the page's own block is not JSON/u);
});
