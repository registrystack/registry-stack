import assert from 'node:assert/strict';
import { test } from 'node:test';

import { pathForDocset } from '../src/lib/docset-path.mjs';

test('removes a current preview base when linking to an archive', () => {
  assert.equal(
    pathForDocset('/preview/tutorials/example/', '/', '/v/0.8.4/', '/preview/'),
    '/v/0.8.4/tutorials/example/',
  );
});

test('keeps the current preview path for the selected current docset', () => {
  assert.equal(
    pathForDocset('/preview/tutorials/example/', '/', '/', '/preview/'),
    '/preview/tutorials/example/',
  );
});

test('removes an archive base when linking to current documentation', () => {
  assert.equal(
    pathForDocset('/v/0.8.4/tutorials/example/', '/v/0.8.4/', '/', '/v/0.8.4/'),
    '/tutorials/example/',
  );
});

test('preserves paths when switching docsets at the canonical root', () => {
  assert.equal(
    pathForDocset('/tutorials/example/', '/', '/v/0.8.4/', '/'),
    '/v/0.8.4/tutorials/example/',
  );
});
