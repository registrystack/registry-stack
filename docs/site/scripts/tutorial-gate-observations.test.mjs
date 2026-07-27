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

const gateCommandPattern = /^registryctl (test|preflight|check|compare|build)\b/gm;

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
    const position = source.indexOf(expectation.command);
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

test('spreadsheet gates are progressive and explain each observed outcome', () => {
  assertSingleGatePerShellBlock(spreadsheetTutorial);
  assertProgressiveObservations(spreadsheetTutorial, [
    {
      command: 'registryctl test --project-dir .',
      observations: [
        /PASS: 0\/0 fixtures passed/,
        /maintained synthetic fixtures/,
        /does not validate workbook rows/,
      ],
    },
    {
      command: 'registryctl preflight --project-dir . --environment local',
      observations: [
        /is locally ready/,
        /runtime prerequisites/,
        /parses\s+every selected data row/,
        /production XLSX reader/,
      ],
    },
    {
      command: 'registryctl check --project-dir . --environment local --explain',
      observations: [
        /fictional-public-works-registry \(valid\)/,
        /validates the authored project/,
        /parses every selected\s+workbook row again/,
        /Relay's production XLSX reader/,
      ],
    },
    {
      command: 'registryctl compare --project-dir . --environment local --from-starter spreadsheet',
      observations: [
        /semantic comparison: different/,
        /disclosure intent/,
      ],
    },
    {
      command: 'registryctl build --project-dir . --environment local',
      observations: [
        /Built Registry Stack project "fictional-public-works-registry"/,
        /parses and validates every selected workbook row again/,
        /reviewable Relay input/,
        /Relay's production XLSX reader/,
      ],
    },
  ]);
  assert.match(
    spreadsheetTutorial,
    /workbook rows are first parsed during `preflight`, then\s+parsed again during `check` and `build`/,
  );
  assert.match(
    spreadsheetTutorial,
    /`registryctl start`, Relay parses the\s+workbook again during its initial load/,
  );
  assert.match(
    spreadsheetTutorial,
    /bash checks\/validate-negative-workbooks\.sh[\s\S]*duplicate primary key:[\s\S]*ingest\.schema_mismatch[\s\S]*formula source:[\s\S]*ingest\.source_unreadable[\s\S]*source project: unchanged/,
  );
  assert.match(
    spreadsheetTutorial,
    /Exact primary-key lookup cannot return an ambiguous multiple-row result[\s\S]*duplicate therefore blocks activation/,
  );
  assert.match(
    spreadsheetTutorial,
    /\| Match \|[\s\S]*\| No match \|[\s\S]*\| Denial \|[\s\S]*\| Ambiguous source \|[\s\S]*\| Unreadable source \|/,
  );
  assert.doesNotMatch(
    spreadsheetTutorial,
    /Diagnostics name the safe file, field, row class/,
  );
});

test('claim gates are progressive and distinguish offline authoring from runtime readiness', () => {
  assertSingleGatePerShellBlock(claimTutorial);
  assertProgressiveObservations(claimTutorial, [
    {
      command: 'registryctl test --project-dir .',
      observations: [/PASS: 5\/5 fixtures passed/, /validates the project's maintained/],
    },
    {
      command: 'registryctl preflight --project-dir . --environment local',
      observations: [/is not locally ready/, /exits nonzero/, /runtime prerequisites/],
    },
    {
      command: 'registryctl check --project-dir . --environment local --explain',
      observations: [/fictional-population-registry \(valid\)/, /validates the authored project/],
    },
    {
      command: 'registryctl compare --project-dir . --environment local --from-starter snapshot',
      observations: [/semantic comparison: equivalent/, /disclosure intent/],
    },
    {
      command: 'registryctl build --project-dir . --environment local',
      observations: [
        /Built Registry Stack project "fictional-population-registry"/,
        /reviewable Relay and Notary inputs/,
      ],
    },
  ]);
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
