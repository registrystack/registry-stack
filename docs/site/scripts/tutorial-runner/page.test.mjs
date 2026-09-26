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

test('a test-edit diff block is an edit step on the file its title names', () => {
  const { steps, errors } = readJourney(`## Grant

\`\`\`diff lang="yaml" title="work/registry.yaml" test-edit
 filterable: [code]
-readable: [code]
+readable: [code, note]

\`\`\`
`);
  assert.deepEqual(errors, []);
  assert.deepEqual(steps, [
    {
      kind: 'edit',
      line: 3,
      heading: 'Grant',
      path: 'work/registry.yaml',
      before: ['filterable: [code]', 'readable: [code]'],
      after: ['filterable: [code]', 'readable: [code, note]'],
    },
  ]);
});

test('a test-edit block must be a titled diff of -, +, and context lines', () => {
  const { errors } = readJourney(`\`\`\`yaml title="a.yaml" test-edit
a: 1
\`\`\`

\`\`\`diff test-edit
-a
\`\`\`

\`\`\`diff title="a.yaml" test-edit
-a
b
\`\`\`

\`\`\`diff title="a.yaml" test-edit
 a
\`\`\`
`);
  assert.deepEqual(errors, [
    'line 1: test-edit applies only to diff blocks',
    'line 5: test-edit needs the file path, as title="<path>"',
    'line 9: every line of a test-edit block starts with -, +, or a space',
    'line 14: a test-edit block changes nothing: it needs a - or + line',
  ]);
});

test('test-exit names the exit status an sh fence must end with', () => {
  const { steps, errors } = readJourney(`\`\`\`sh test-exit="1"
false
\`\`\`

\`\`\`sh test-exit="no"
false
\`\`\`

\`\`\`text test-exit="1"
x
\`\`\`
`);
  assert.equal(steps[0].exit, 1);
  assert.deepEqual(errors, [
    'line 5: test-exit takes an exit status, as test-exit="1"',
    'line 9: test-exit applies only to sh fences',
  ]);
});

test('a test-edit line whose marker is followed by - or + is refused, since the page would show it unmarked', () => {
  const { errors } = readJourney(`\`\`\`diff title="a.yaml" test-edit
-- {id: a}
+- {id: b}
\`\`\`
`);
  assert.deepEqual(errors, [
    'line 1: a test-edit line starts with -- or +- or ++ or -+, which the page shows as plain text; start the change at the indentation it has in the file, with the line above as context',
  ]);
});

test('a test-excerpt block checks a file at that point, or with no path the output above it', () => {
  const { steps, errors } = readJourney(
    '## Read\n\n```sh\nmake-report\n```\n\n```json test-excerpt\n{"a": 1}\n```\n\n' +
      '```yaml test-excerpt="work/conf.yaml"\nb: 2\n```\n',
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(steps.slice(1), [
    { kind: 'excerpt', line: 7, heading: 'Read', format: 'json', text: '{"a": 1}', runIndex: 0 },
    { kind: 'excerpt', line: 11, heading: 'Read', format: 'text', text: 'b: 2', path: 'work/conf.yaml' },
  ]);
});

test('test-excerpt mistakes are errors that name the line', () => {
  const { errors } = readJourney(
    '```json test-excerpt\n{}\n```\n\n```sh test-excerpt\ntrue\n```\n\n' +
      '```sh test-skip="offline"\ntrue\n```\n\n```json test-excerpt\n{}\n```\n\n' +
      '```text test-excerpt test-expect\nx\n```\n',
  );
  assert.deepEqual(errors, [
    'line 1: test-excerpt has no sh fence above it to check',
    'line 5: test-excerpt belongs on a block the page shows, not on an sh fence',
    'line 13: test-excerpt checks the output of the sh fence at line 9, which is skipped',
    'line 17: a block is one of test-file, test-edit, test-expect, or test-excerpt',
  ]);
});

test('a titled block marked test-file is the whole file the page asks the reader to create', () => {
  const { steps, errors } = readJourney(
    '## Ask\n\nOpen `questions/q.yaml` and add:\n\n```yaml title="questions/q.yaml" test-file\nid: q\n```\n',
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(steps, [{ kind: 'file', line: 5, heading: 'Ask', path: 'questions/q.yaml', text: 'id: q\n' }]);
});

test('test-file mistakes are errors that name the line', () => {
  const { errors } = readJourney(
    '```yaml test-file\na: 1\n```\n\n```sh title="x.sh" test-file\ntrue\n```\n\n' +
      '```diff title="a.yaml" test-file\n+a\n```\n\n```yaml title="a.yaml" test-file test-excerpt\na\n```\n',
  );
  assert.deepEqual(errors, [
    'line 1: test-file needs the file path, as title="<path>"',
    'line 5: test-file belongs on a block showing the file, not on an sh fence',
    'line 9: test-file takes the whole file; a diff block is test-edit',
    'line 13: a block is one of test-file, test-edit, test-expect, or test-excerpt',
  ]);
});

test('test-background leaves an sh fence running until its ready URL answers, and test-cwd says where a fence runs', () => {
  const { steps, errors } = readJourney(
    '```sh test-background="http://127.0.0.1:4010/health" test-cwd="first"\nserve\n```\n\n' +
      '```text test-expect\nready\n```\n\n```sh test-cwd="first/project"\nls\n```\n',
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(steps[0], {
    kind: 'run',
    line: 1,
    heading: '',
    code: 'serve',
    background: 'http://127.0.0.1:4010/health',
    cwd: 'first',
  });
  assert.equal(steps[1].runIndex, 0);
  assert.equal(steps[2].cwd, 'first/project');
});

test('test-background and test-cwd mistakes are errors that name the line', () => {
  const { errors } = readJourney(
    '```sh test-background\nserve\n```\n\n```sh test-background="http://x/" test-exit="1"\nserve\n```\n\n' +
      '```sh test-background="http://x/" test-skip="offline"\nserve\n```\n\n' +
      '```sh test-cwd="/abs"\nls\n```\n\n```sh test-cwd="../up"\nls\n```\n\n```text test-cwd="a"\nx\n```\n',
  );
  assert.deepEqual(errors, [
    'line 1: test-background takes the URL that answers once the command is ready, as test-background="http://127.0.0.1:4010/"',
    'line 5: a test-background fence keeps running, so it cannot also be test-exit',
    'line 9: a test-background fence is run, so it cannot also be test-skip',
    'line 13: test-cwd takes a directory inside the reader directory, as test-cwd="first-project"',
    'line 17: test-cwd takes a directory inside the reader directory, as test-cwd="first-project"',
    'line 21: test-cwd applies only to sh fences',
  ]);
});
