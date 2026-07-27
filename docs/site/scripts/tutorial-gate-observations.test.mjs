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

const gateCommandPattern = /^registryctl (test|preflight|check|compare|build|doctor|start)\b/gm;

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

test('spreadsheet tutorial uses one complete validation gate before the live result', () => {
  assertSingleGatePerShellBlock(spreadsheetTutorial);
  assertProgressiveObservations(spreadsheetTutorial, [
    {
      command: 'registryctl doctor --profile local',
      observations: [
        /selected worksheet and headers exist/,
        /every selected row matches/,
        /required keys are present and unique/,
        /matching release runtime can start/,
      ],
    },
    {
      command: 'registryctl start',
      observations: [/parses the workbook again/, /127\.0\.0\.1:4242/, /mounted read-only/],
    },
  ]);
  assert.match(spreadsheetTutorial, /Do not run `registryctl smoke` for this adapted project/);
});

test('claim continuation distinguishes offline fixtures from live runtime evidence', () => {
  assertSingleGatePerShellBlock(claimTutorial);
  assertProgressiveObservations(claimTutorial, [
    {
      command: 'registryctl add notary',
      observations: [
        /same human-owned project/,
        /three synthetic fixtures/,
        /generated\s+Relay or Notary files/,
      ],
    },
    {
      command: 'registryctl test --project-dir .',
      observations: [
        /authored lookup and claim meanings offline/,
        /requests[\s\S]*separately prove/,
      ],
    },
    {
      command: 'registryctl start',
      observations: [
        /Relay remains the only product that reads the workbook/,
        /private consultation binding/,
      ],
    },
    {
      command: 'registryctl restart',
      observations: [
        /regenerates the Relay and Notary inputs/,
        /unchanged planned-project request/,
        /do\s+not edit `?\.registry-stack\//,
      ],
    },
    {
      command: 'registryctl stop',
      observations: [
        /authored workbook[\s\S]*remain/,
        /Generated\s+runtime files[\s\S]*disposable/,
      ],
    },
  ]);
});

test('claim continuation observes scoped denial, distinct outcomes, and policy change', () => {
  const authorization = claimTutorial.indexOf('HTTP 403');
  const active = claimTutorial.indexOf('## Evaluate the active project', authorization);
  const planned = claimTutorial.indexOf('## Evaluate the planned project', active);
  const absent = claimTutorial.indexOf('## Check an absent record', planned);
  const authoredEdit = claimTutorial.indexOf('## Change the status policy', absent);
  const restart = claimTutorial.indexOf('registryctl restart', authoredEdit);
  const changedResult = claimTutorial.indexOf('"value": true', restart);

  assert.ok(authorization >= 0, 'under-scoped denial is absent');
  assert.ok(active > authorization, 'active-project result must follow scoped denial');
  assert.ok(planned > active, 'planned-project result must follow the active result');
  assert.ok(absent > planned, 'absent-record result must follow the planned result');
  assert.ok(authoredEdit > absent, 'authored policy change must follow the live results');
  assert.ok(restart > authoredEdit, 'restart must follow the authored policy change');
  assert.ok(changedResult > restart, 'changed live result must follow restart');
  assert.match(claimTutorial, /evidence:projects:read/);
  assert.match(claimTutorial, /public-works-case-management/);
  assert.match(claimTutorial, /http:\/\/127\.0\.0\.1:4255\/v1\/evaluations/);
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
