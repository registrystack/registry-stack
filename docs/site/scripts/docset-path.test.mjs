import assert from 'node:assert/strict';
import { test } from 'node:test';

import { pathForDocset } from '../src/lib/docset-path.mjs';

test('removes the development base when linking to an archive', () => {
  assert.equal(
    pathForDocset('/dev/tutorials/example/', '/dev/', '/v/0.8.4/', '/dev/'),
    '/v/0.8.4/tutorials/example/',
  );
});

test('keeps the development path for the selected current docset', () => {
  assert.equal(
    pathForDocset('/dev/tutorials/example/', '/dev/', '/dev/', '/dev/'),
    '/dev/tutorials/example/',
  );
});

test('removes an archive base when linking to current documentation', () => {
  assert.equal(
    pathForDocset('/v/0.8.4/tutorials/example/', '/v/0.8.4/', '/dev/', '/v/0.8.4/'),
    '/dev/tutorials/example/',
  );
});

test('maps an old archive current-root option to the development namespace', () => {
  assert.equal(
    pathForDocset('/v/0.8.4/tutorials/example/', '/v/0.8.4/', '/', '/v/0.8.4/'),
    '/dev/tutorials/example/',
  );
});

test('preserves paths when switching from the canonical root to an archive', () => {
  assert.equal(
    pathForDocset('/tutorials/example/', '/', '/v/0.8.4/', '/'),
    '/v/0.8.4/tutorials/example/',
  );
});
