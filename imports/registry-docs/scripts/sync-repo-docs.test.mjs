// Unit tests for the Page-type banner stripper (scripts/sync-repo-docs.mjs).
// Run with `npm test` (node --test). The product repos carry a leading
// "> **Page type:** ..." banner under the H1 as a GitHub navigation aid; the
// aggregation pipeline drops it so it does not render on the docs site.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { stripPageTypeBanner } from './sync-repo-docs.mjs';

test('strips a leading Page-type banner and its trailing blank line', () => {
  const md = [
    '> **Page type:** Reference · **Product:** Registry Notary · **Audience:** operator',
    '',
    'Real content starts here.',
  ].join('\n');
  assert.equal(stripPageTypeBanner(md), 'Real content starts here.');
});

test('strips a banner that carries a stale Status marker', () => {
  const md = '> **Page type:** Concept · **Status:** draft\n\nBody.';
  assert.equal(stripPageTypeBanner(md), 'Body.');
});

test('skips leading blank lines before the banner (post H1-drop)', () => {
  const md = '\n\n> **Page type:** How-to · **Audience:** integrator\n\nBody.';
  assert.equal(stripPageTypeBanner(md), 'Body.');
});

test('leaves an ordinary leading blockquote intact', () => {
  const md = '> Note: this is a normal callout.\n\nBody.';
  assert.equal(stripPageTypeBanner(md), md);
});

test('returns content unchanged when there is no banner', () => {
  const md = '# Title\n\nBody paragraph.';
  assert.equal(stripPageTypeBanner(md), md);
});
