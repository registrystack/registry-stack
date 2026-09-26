import assert from 'node:assert/strict';
import test from 'node:test';

import { prerequisiteItems } from '../src/lib/quickstart-prerequisites.mjs';

test('a prerequisite is a label, or a label with the page that covers it', () => {
  assert.deepEqual(
    prerequisiteItems(['An editor', { label: 'The first tutorial', href: '/tutorials/first-breg/' }, { label: 'Python 3', href: 'https://www.python.org/downloads/' }], '/dev/'),
    [
      { label: 'An editor' },
      { label: 'The first tutorial', href: '/dev/tutorials/first-breg/' },
      { label: 'Python 3', href: 'https://www.python.org/downloads/' },
    ],
  );
});

test('missing or malformed prerequisites render nothing rather than breaking the page', () => {
  assert.deepEqual(prerequisiteItems(undefined, '/'), []);
  assert.deepEqual(prerequisiteItems(null, '/'), []);
});

test('a linked prerequisite without a label is refused', () => {
  assert.throws(() => prerequisiteItems([{ href: '/tutorials/first-breg/' }], '/'), /needs a label/u);
});
