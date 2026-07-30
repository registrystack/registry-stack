import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

const siteRoot = resolve(import.meta.dirname, '..');
const spreadsheetTutorial = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/use-your-spreadsheet.mdx'),
  'utf8',
);
const claimTutorial = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/verify-claim-registry-api.mdx'),
  'utf8',
);

const gateCommandPattern = /^registryctl (test|check|build|doctor|dev)\b/gm;

function assertSingleGatePerShellBlock(source) {
  for (const match of source.matchAll(/```sh\n([\s\S]*?)\n```/g)) {
    const commands = [...match[1].matchAll(gateCommandPattern)].map((command) => command[0]);
    assert.ok(
      commands.length <= 1,
      `gate commands must be progressive, not batched: ${commands.join(', ')}`,
    );
  }
}

function assertProgressiveObservations(source, expectations) {
  let previousPosition = -1;
  for (const expectation of expectations) {
    const position = source.indexOf(expectation.command, previousPosition + 1);
    assert.ok(position > previousPosition, `missing or misplaced command: ${expectation.command}`);
    previousPosition = position;

    const fenceEnd = source.indexOf('\n```', position);
    assert.ok(fenceEnd > position, `command has no closing shell fence: ${expectation.command}`);
    const nextHeadingMatch = source.slice(fenceEnd + 4).match(/\n#{2,3} /);
    const nextHeading = nextHeadingMatch
      ? fenceEnd + 4 + nextHeadingMatch.index
      : source.length;
    const observation = source.slice(fenceEnd + 4, nextHeading);

    for (const expectedText of expectation.observations) {
      assert.match(
        observation,
        expectedText,
        `${expectation.command} lacks its expected observation or meaning`,
      );
    }
  }
}

test('spreadsheet tutorial observes each offline and development gate progressively', () => {
  assertSingleGatePerShellBlock(spreadsheetTutorial);
  assertProgressiveObservations(spreadsheetTutorial, [
    {
      command: 'registryctl test',
      observations: [
        /synthetic match, planned, and no-match observations/,
        /authorization and minimization cases/,
      ],
    },
    {
      command: 'registryctl check --explain',
      observations: [/workbook path/, /principal-bound filter/, /minimized output/],
    },
    {
      command: 'registryctl dev --detach',
      observations: [/local HTTPS endpoints/, /owner-only request configuration/],
    },
    {
      command: 'registryctl dev smoke',
      observations: [
        /denial scenario must report zero source work/,
        /authorized scenario must report one snapshot lookup/,
        /does not retain workbook rows or raw credentials/,
      ],
    },
    {
      command: 'registryctl dev down',
      observations: [/authored workbook and project files remain/],
    },
    {
      command: 'registryctl build',
      observations: [/complete generated closure together/, /remain\s+author-owned/],
    },
  ]);
});

test('claim continuation distinguishes offline fixtures from live runtime evidence', () => {
  assertSingleGatePerShellBlock(claimTutorial);
  assertProgressiveObservations(claimTutorial, [
    {
      command: 'registryctl test \\',
      observations: [
        /matched synthetic record with `status: planned`/,
        /project-status-accepted: false/,
        /distinct from the `no-match` fixture/,
      ],
    },
    {
      command: 'registryctl test \\',
      observations: [/planned fixture now reports both claims as true/],
    },
    {
      command: 'registryctl test',
      observations: [
        /match and no-match fixtures plus their derived security cases must still pass/,
        /false existence predicate means no match in that source snapshot/,
      ],
    },
    {
      command: 'registryctl dev --detach',
      observations: [
        /owner-only `curl --config` request/,
        /generated credential file/,
      ],
    },
    {
      command: 'registryctl dev smoke',
      observations: [
        /denial scenario must report zero source work/,
        /authorized scenario must report one snapshot lookup/,
        /minimized claim identifiers/,
      ],
    },
    {
      command: 'registryctl check --explain',
      observations: [/exact snapshot selector/, /consultation output remains only `status`/],
    },
    {
      command: 'registryctl build',
      observations: [/does not sign or activate/],
    },
    {
      command: 'registryctl dev down',
      observations: [/authored policy and fixture edit remain/],
    },
  ]);
});

test('claim continuation orders the policy change before bounded runtime evidence', () => {
  const initialFalse = claimTutorial.indexOf('project-status-accepted: false');
  const authoredEdit = claimTutorial.indexOf('## Change the authored policy', initialFalse);
  const changedExpectation = claimTutorial.indexOf('project-status-accepted: true', authoredEdit);
  const focusedRerun = claimTutorial.indexOf('registryctl test \\', changedExpectation);
  const completeRerun = claimTutorial.indexOf('registryctl test\n', focusedRerun + 1);
  const runtime = claimTutorial.indexOf('registryctl dev smoke', completeRerun);
  const review = claimTutorial.indexOf('registryctl check --explain', runtime);
  const build = claimTutorial.indexOf('registryctl build', review);

  assert.ok(initialFalse >= 0, 'initial policy non-match is absent');
  assert.ok(authoredEdit > initialFalse, 'authored policy edit must follow the initial result');
  assert.ok(changedExpectation > authoredEdit, 'changed expectation must follow the policy edit');
  assert.ok(focusedRerun > changedExpectation, 'focused fixture rerun must follow the edit');
  assert.ok(completeRerun > focusedRerun, 'complete fixture gate must follow the focused rerun');
  assert.ok(runtime > completeRerun, 'runtime evidence must follow offline fixture evidence');
  assert.ok(review > runtime, 'redacted review must follow runtime evidence');
  assert.ok(build > review, 'build must follow the redacted review');
  assert.match(claimTutorial, /single `project` consultation/);
  assert.match(claimTutorial, /zero source work/);
  assert.match(claimTutorial, /project-record-exists,project-status-accepted/);
  assert.match(claimTutorial, /Do not replace it with a caller-supplied value or source-free assertion/);
});

test('progressive gate control rejects a batched command block', () => {
  assert.throws(
    () =>
      assertSingleGatePerShellBlock(
        '```sh\nregistryctl test --project-dir .\nregistryctl build --project-dir . --environment local\n```',
      ),
    /gate commands must be progressive/,
  );
});
