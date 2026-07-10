import assert from 'node:assert/strict';
import { test } from 'node:test';

import { reviewStatusLabel } from '../src/lib/review-status.mjs';

test('renders an honest label for unreviewed generated pages', () => {
  assert.equal(reviewStatusLabel('unreviewed'), 'Not yet source-reviewed');
});

test('renders the existing label for reviewed pages', () => {
  assert.equal(reviewStatusLabel('2026-07-10'), 'Last reviewed 2026-07-10');
});

test('omits the review label when metadata is absent', () => {
  assert.equal(reviewStatusLabel(undefined), undefined);
});
