import assert from 'node:assert/strict';
import { test } from 'node:test';

import { baseAwareHref } from '../src/lib/base-aware-href.mjs';

test('leaves root-relative links unchanged at the root base', () => {
  assert.equal(baseAwareHref('/configure/relay/'), '/configure/relay/');
});

test('prefixes root-relative links with a non-root base', () => {
  assert.equal(baseAwareHref('/configure/relay/', '/dev/'), '/dev/configure/relay/');
  assert.equal(baseAwareHref('/configure/relay/', '/dev'), '/dev/configure/relay/');
});

test('leaves external and protocol-relative links unchanged', () => {
  assert.equal(baseAwareHref('https://example.com/spec'), 'https://example.com/spec');
  assert.equal(baseAwareHref('//example.com/spec', '/dev/'), '//example.com/spec');
});
