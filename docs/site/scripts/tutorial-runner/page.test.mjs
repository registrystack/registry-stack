import assert from 'node:assert/strict';
import test from 'node:test';

import { parseAnnotations, readJourney } from './page.mjs';

test('annotations are the test- tokens of a fence meta string, other tokens ignored', () => {
  assert.deepEqual(parseAnnotations(''), {});
  assert.deepEqual(parseAnnotations('title="x.sh" test-expect'), { 'test-expect': true });
  assert.deepEqual(parseAnnotations('test-skip="installs; from the network"'), {
    'test-skip': 'installs; from the network',
  });
});

test('every sh fence runs, in document order, with the heading it sits under', () => {
  const { steps, errors } = readJourney(`---
title: t
---
import X from './x.astro';

Intro.

<X prop={['a']} />

## Create

\`\`\`sh
mkdir work
\`\`\`

{/* Evidence: somewhere. */}

\`\`\`yaml
shown: only
\`\`\`

## Use

\`\`\`sh
ls work
\`\`\`
`);
  assert.deepEqual(errors, []);
  assert.deepEqual(
    steps.map(({ kind, heading, code }) => ({ kind, heading, code })),
    [
      { kind: 'run', heading: 'Create', code: 'mkdir work' },
      { kind: 'run', heading: 'Use', code: 'ls work' },
    ],
  );
  assert.equal(steps[0].line, 12);
});

test('a fence indented inside a list item is found', () => {
  const { steps, errors } = readJourney(`## Steps

1. Make a directory:

   \`\`\`sh
   mkdir work
   \`\`\`

2. Done.
`);
  assert.deepEqual(errors, []);
  assert.deepEqual(steps.map((step) => step.code), ['mkdir work']);
});

test('a skipped fence records its reason and is not run', () => {
  const { steps, errors } = readJourney(`## Install

\`\`\`sh test-skip="reaches the network"
curl https://example.invalid | sh
\`\`\`
`);
  assert.deepEqual(errors, []);
  assert.equal(steps[0].kind, 'skip');
  assert.equal(steps[0].reason, 'reaches the network');
});

test('an expect block binds to the nearest run fence above it, across display blocks', () => {
  const { steps, errors } = readJourney(`## Read

\`\`\`sh
echo hello
\`\`\`

\`\`\`yaml
display: only
\`\`\`

\`\`\`text test-expect
hello
\`\`\`

\`\`\`json test-expect
{"a": 1}
\`\`\`
`);
  assert.deepEqual(errors, []);
  assert.deepEqual(
    steps.map(({ kind, format, runIndex }) => ({ kind, format, runIndex })),
    [
      { kind: 'run', format: undefined, runIndex: undefined },
      { kind: 'expect', format: 'text', runIndex: 0 },
      { kind: 'expect', format: 'json', runIndex: 0 },
    ],
  );
});

test('annotation mistakes are errors that name the line', () => {
  const { errors } = readJourney(`## A

\`\`\`text test-expect
before any command
\`\`\`

\`\`\`sh test-skip
echo no reason given
\`\`\`

\`\`\`sh test-expect
echo expect on a command
\`\`\`

\`\`\`yaml test-skip="not a command"
a: 1
\`\`\`

\`\`\`sh test-expcet
echo typo
\`\`\`

\`\`\`sh test-skip="skipped"
echo skipped
\`\`\`

\`\`\`text test-expect
output of a skipped command
\`\`\`
`);
  assert.deepEqual(errors, [
    'line 3: test-expect has no sh fence above it to check',
    'line 7: test-skip needs a reason, as test-skip="<why this fence is not run>"',
    'line 11: test-expect belongs on an output block, not on an sh fence',
    'line 15: test-skip applies only to sh fences',
    'line 19: unknown annotation test-expcet',
    'line 27: test-expect checks the output of the sh fence at line 23, which is skipped',
  ]);
});
