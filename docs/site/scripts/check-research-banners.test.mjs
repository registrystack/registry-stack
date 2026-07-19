import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import {
  RESEARCH_STATUS_BANNER,
  researchBannerErrors,
} from './check-research-banners.mjs';

test('requires the exact deterministic banner on every research note', (t) => {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-research-banners-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(root, { recursive: true });
  writeFileSync(resolve(root, 'README.md'), '# Research\n');
  writeFileSync(resolve(root, 'current.md'), `${RESEARCH_STATUS_BANNER}# Preserved body\n`);
  writeFileSync(resolve(root, 'missing.md'), '# Unmarked body\n');

  assert.deepEqual(researchBannerErrors(root), [
    'missing.md is missing the exact historical-research banner',
  ]);
});

test('accepts the checked-in historical research notes', () => {
  assert.deepEqual(researchBannerErrors(), []);
});
