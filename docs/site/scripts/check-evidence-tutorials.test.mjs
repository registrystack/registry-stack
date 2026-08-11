import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const gate = resolve(scriptDir, 'check-evidence-tutorials.sh');
const fenceHelper = resolve(scriptDir, 'evidence-tutorial-fence.sh');
const fhirTutorial = resolve(
  scriptDir,
  '../src/content/docs/tutorials/issue-fhir-evidence-as-vcs.mdx',
);

async function runGate(env = {}, args = ['--dry-run']) {
  try {
    const { stdout, stderr } = await execFileAsync('bash', [gate, ...args], {
      env: { ...process.env, ...env },
    });
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { code: error.code ?? 1, output: `${error.stdout}${error.stderr}` };
  }
}

async function runShell(script) {
  try {
    const { stdout, stderr } = await execFileAsync('bash', ['-c', script]);
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { code: error.code ?? 1, output: `${error.stdout}${error.stderr}` };
  }
}

test('the dry-run gate registers the shared Evidence start tutorials', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /first-evidence-assertion: 18 sh fences, 16 executed/u);
  assert.match(output, /request-evidence-as-sd-jwt-vc: 16 sh fences, 16 executed/u);
  assert.match(
    output,
    /run-oid4vci-interoperability-checks: 4 sh fences, 3 executed/u,
  );
  // Two of its sixteen are the documented clone and build of the client, which
  // the replay substitutes with a build of this checkout.
  assert.match(
    output,
    /request-evidence-from-an-application: 16 sh fences, 14 executed/u,
  );
  assert.match(output, /return-a-governed-value: 10 sh fences, 10 executed/u);
  assert.match(output, /assert-a-role-bound-relationship: 9 sh fences, 9 executed/u);
  assert.match(output, /refuse-unsafe-evidence-requests: 11 sh fences, 11 executed/u);
  assert.match(output, /verify-an-assertion-as-a-consumer: 3 sh fences, 3 executed/u);
  assert.match(output, /control-who-can-request-evidence: 20 sh fences, 20 executed/u);
  assert.match(output, /issue-fhir-evidence-as-vcs: 10 sh fences, 10 executed/u);
  assert.match(output, /Checked 10 tutorials\./u);
});

test('--only accepts the current first Evidence tutorial', async () => {
  const { code, output } = await runGate({}, [
    '--dry-run',
    '--only',
    'first-evidence-assertion',
  ]);
  assert.equal(code, 0, output);
  assert.match(output, /Checked 1 tutorial\./u);
});

test('--only accepts the role-bound relationship follow-up', async () => {
  const { code, output } = await runGate({}, [
    '--dry-run',
    '--only',
    'assert-a-role-bound-relationship',
  ]);
  assert.equal(code, 0, output);
  assert.match(output, /Checked 1 tutorial\./u);
});

test('--only accepts the deterministic FHIR tutorial replay', async () => {
  const { code, output } = await runGate({}, [
    '--dry-run',
    '--only',
    'issue-fhir-evidence-as-vcs',
  ]);
  assert.equal(code, 0, output);
  assert.match(output, /issue-fhir-evidence-as-vcs: 10 sh fences, 10 executed/u);
  assert.match(output, /Checked 1 tutorial\./u);
});

test('both FHIR tutorial clients bypass ambient proxies', async () => {
  const source = await readFile(fhirTutorial, 'utf8');
  const proxyFreeOpeners = source.match(
    /build_opener\(ProxyHandler\(\{\}\), NoRedirect\)/gu,
  );
  assert.equal(proxyFreeOpeners?.length, 2);
});

test('the FHIR tutorial test origin refuses a remote endpoint', async () => {
  const root = await mkdtemp(join(tmpdir(), 'fhir-tutorial-origin-test-'));
  const discovery = join(root, 'discover-fhir-records.py');
  try {
    await execFileAsync('bash', [
      fenceHelper,
      'write-fence',
      fhirTutorial,
      'Select live synthetic records',
      'python',
      '1',
      discovery,
    ]);
    await assert.rejects(
      execFileAsync('python3', [discovery], {
        env: {
          ...process.env,
          FHIR_TUTORIAL_TEST_BASE_URL: 'https://example.com',
        },
      }),
      (error) => {
        assert.match(error.stderr, /test origin must be numeric loopback HTTP/u);
        return true;
      },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the FHIR replay tracks the read-through adapter for cleanup', async () => {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(
    /\n\tissue-fhir-evidence-as-vcs\)[\s\S]*?\n\t\t;;/u,
  )?.[0];
  assert.ok(branch, 'the FHIR replay spec must exist');
  assert.match(branch, /"run:3"\s+"track-pid:fhir-read-through\.pid"/u);
  assert.match(source, /track-pid:\*\) emit_track_pid_step/u);
  assert.match(source, /BACKGROUND_PIDS\+=\("\$tracked_pid"\)/u);
});

// Every follow-up below begins from the project first-evidence-assertion
// builds. A full run gets that from the registration order, so a --only that
// skipped it would fail on the reader directory rather than on the tutorial,
// and only for the person running one slug by hand.
for (const slug of [
  'request-evidence-as-sd-jwt-vc',
  'request-evidence-from-an-application',
  'return-a-governed-value',
  'refuse-unsafe-evidence-requests',
  'verify-an-assertion-as-a-consumer',
  'control-who-can-request-evidence',
]) {
  test(`--only runs the starter project before ${slug}`, async () => {
    const { code, output } = await runGate({}, ['--dry-run', '--only', slug]);
    assert.equal(code, 0, output);
    const prerequisite = output.indexOf('first-evidence-assertion:');
    const followUp = output.indexOf(`${slug}:`);
    assert.notEqual(prerequisite, -1, output);
    assert.ok(followUp > prerequisite, output);
    assert.match(output, /Checked 2 tutorials\./u);
  });
}

// The application tutorial is the only registered replay that reaches the
// Evidence client SDK, and it reaches it through the Python binding. Losing
// either the registration or the substituted build would leave that path
// unproven while the gate still reported PASS.
test('the application tutorial replays the Python client from this checkout', async () => {
  const source = await readFile(gate, 'utf8');
  assert.match(source, /^\trequest-evidence-from-an-application$/mu);
  const branch = source.match(
    /\n\trequest-evidence-from-an-application\)[\s\S]*?\n\t\t;;/u,
  )?.[0];
  assert.ok(branch, 'the application replay spec must exist');
  assert.match(branch, /"python-client"/u);
  assert.match(branch, /"private_key_jwt"/u);
  assert.match(branch, /person-123 is_adult=True/u);
});

test('the caller-access replay expects the privacy-safe refusal audit line', async () => {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(
    /\n\tcontrol-who-can-request-evidence\)[\s\S]*?\n\t\t;;/u,
  )?.[0];
  assert.ok(branch, 'the caller-access replay spec must exist');
  assert.match(branch, /"ACCESS REFUSED requester="/u);
  assert.match(branch, /"reason=not_authorized"/u);
  assert.doesNotMatch(branch, /ACCESS AUTHORIZED age-bracket/u);
});

// EVIDENCE_TUTORIALS and EXCLUDED_EVIDENCE_TUTORIALS between them must
// account for every page under the tutorials directory, so a new page can
// never ship unreplayed and unexplained. Read the lists from the gate
// itself rather than restating them, so this test tracks the gate instead
// of drifting from it.
function extractBashArray(source, name) {
  const match = source.match(new RegExp(`\\n${name}=\\(([\\s\\S]*?)\\n\\)`, 'u'));
  assert.ok(match, `${name} array must exist in the gate`);
  return match[1]
    .split('\n')
    .map((line) => line.split('#')[0].trim())
    .filter(Boolean);
}

test('the tutorial coverage check fails on an unregistered page', async () => {
  const source = await readFile(gate, 'utf8');
  const excluded = extractBashArray(source, 'EXCLUDED_EVIDENCE_TUTORIALS');
  const root = await mkdtemp(join(tmpdir(), 'evidence-tutorial-coverage-test-'));
  try {
    // Stub every already-excluded page so only the deliberately unregistered
    // page below can trip the check.
    for (const slug of excluded) {
      await writeFile(join(root, `${slug}.mdx`), '---\ntitle: stub\n---\n');
    }
    await writeFile(join(root, 'orphan-tutorial.mdx'), '---\ntitle: stub\n---\n');
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'an unregistered tutorial page must fail the gate');
    assert.match(output, /tutorial coverage gap/u);
    assert.match(output, /orphan-tutorial\.mdx/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('--only refuses a slug that is not registered', async () => {
  const { code, output } = await runGate({}, ['--dry-run', '--only', 'no-such-tutorial']);
  assert.notEqual(code, 0, 'an unregistered slug must fail the gate');
  assert.match(output, /not a registered Evidence tutorial/u);
});

test('--only refuses an unpublished legacy tutorial', async () => {
  const { code, output } = await runGate({}, [
    '--dry-run',
    '--only',
    'serve-assertions-over-http',
  ]);
  assert.notEqual(code, 0, 'an unpublished tutorial must not be registered');
  assert.match(output, /not a registered Evidence tutorial/u);
});

// The replay runs inside a clean Debian userland holding a shell, coreutils
// and the toolset under test. An interpreter the container does not carry
// fails mid-journey, where the transcript makes it look like a tutorial
// defect, so the gate and everything it emits stay on that floor.
test('the gate depends on no interpreter beyond the replay userland', async () => {
  const source = await readFile(gate, 'utf8');
  const offenders = source
    .split('\n')
    .map((line, index) => [index + 1, line])
    // `python-client` is a step name and `python-module` is the directory the
    // application tutorial imports from. Both are data the gate writes or
    // matches, never an interpreter it runs, so they are removed before the
    // line is judged rather than exempting whole lines that carry them.
    .map(([number, line]) => [number, line.replaceAll(/python-(?:client|module)/gu, '')])
    .filter(([, line]) => /\b(?:node|npm|npx|python3?|ruby|perl)\b/u.test(line))
    // A save step names the Markdown fence language as data. It extracts that
    // fence with the shell helper and does not execute the named interpreter.
    .filter(([, line]) => !/^\s*"save:[^"]+\|[^|]+\|\d+\|[^"]+",?$/u.test(line));
  assert.deepEqual(offenders, [], 'the gate must not reach for an interpreter');
});

async function replayCargoTarget(slug) {
  const source = await readFile(gate, 'utf8');
  const runner = source.match(/\nrun_journey_script\(\) \{\n[\s\S]*?\n\}\n/u)?.[0];
  assert.ok(runner, 'the journey runner must exist');
  const root = await mkdtemp(join(tmpdir(), 'evidence-cargo-target-test-'));
  const journey = join(root, 'journey.sh');
  const harness = join(root, 'run.sh');
  await writeFile(journey, 'printf "%s\\n" "${CARGO_TARGET_DIR-unset}"\n');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      runner,
      'SHIM_DIR="$1"',
      'TARGET_DIR="$2"',
      'run_journey_script "$3" "$1" "$4"',
      '',
    ].join('\n'),
  );
  try {
    const expectedTarget = join(root, 'oid4vci-target');
    const { stdout } = await execFileAsync(
      'bash',
      [harness, root, expectedTarget, slug, journey],
      {
        env: { ...process.env, CARGO_TARGET_DIR: join(root, 'inherited-target') },
      },
    );
    return { output: stdout.trim(), expectedTarget };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the OID4VCI replay receives the gate Cargo target directory', async () => {
  const { output, expectedTarget } = await replayCargoTarget(
    'run-oid4vci-interoperability-checks',
  );
  assert.equal(output, expectedTarget);
});

test('other tutorial replays do not receive a Cargo target directory', async () => {
  const { output } = await replayCargoTarget('first-evidence-assertion');
  assert.equal(output, 'unset');
});

async function runFence(args) {
  try {
    const { stdout, stderr } = await execFileAsync('bash', [fenceHelper, ...args]);
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { code: error.code ?? 1, output: `${error.stdout}${error.stderr}` };
  }
}

const fenceFixture = [
  '---',
  'title: A tutorial',
  '---',
  '',
  '## Add a narrower selector profile',
  '',
  'Before:',
  '',
  '```yaml',
  '',
  'selectors:',
  '  - kind: broad',
  '',
  '```',
  '',
  'After:',
  '',
  '```yaml',
  'selectors:',
  '  - kind: narrow',
  '```',
  '',
  '## Run it',
  '',
  '```sh',
  'evidencectl check',
  '```',
  '',
].join('\n');

async function fenceScratch() {
  const root = await mkdtemp(join(tmpdir(), 'evidence-fence-test-'));
  await writeFile(join(root, 'tutorial.mdx'), fenceFixture);
  return root;
}

// Run the gate's own run-fails emitter over one fence, and return the journey
// lines it emits. The function is lifted out of the gate rather than restated
// here, so this exercises the shipped code: sourcing the gate would run it.
async function emitRunFailsStep(fenceBody) {
  const source = await readFile(gate, 'utf8');
  const emitter = source.match(/\nemit_run_fails_step\(\) \{\n[\s\S]*?\n\}\n/u)?.[0];
  assert.ok(emitter, 'the run-fails emitter must exist');
  const root = await mkdtemp(join(tmpdir(), 'evidence-refusal-test-'));
  await writeFile(join(root, 'fence-09.sh'), fenceBody);
  const harness = join(root, 'emit.sh');
  await writeFile(
    harness,
    ['#!/usr/bin/env bash', 'set -euo pipefail', emitter, 'emit_run_fails_step tutorial 9 "$1"', ''].join('\n'),
  );
  const { stdout } = await execFileAsync('bash', [harness, root]);
  return { root, journey: `set -euo pipefail\n${stdout}` };
}

// A refusal fence that prints after the command that refuses is the shape the
// pages actually carry: the reader sees the error, then the state it left
// behind. Bash suppresses errexit for everything inside an `if` condition,
// subshells included, so an emitter that tested the fence there would run the
// trailing line, read the whole fence as a success, and report drift on a
// tutorial that is doing exactly what it documents.
test('a documented refusal is accepted even when the fence prints after it', async () => {
  const { root, journey } = await emitRunFailsStep(
    'false\nprintf "kept going\\n"\n',
  );
  try {
    const { code, output } = await runShell(journey);
    assert.equal(code, 0, output);
    assert.doesNotMatch(output, /kept going/u);
    assert.doesNotMatch(output, /tutorial drift/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a refusal fence that starts succeeding is reported as drift', async () => {
  const { root, journey } = await emitRunFailsStep('true\n');
  try {
    const { code, output } = await runShell(journey);
    assert.notEqual(code, 0, 'a fence that no longer refuses must fail the gate');
    assert.match(output, /tutorial drift/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The steps after a documented refusal still run under the journey's errexit,
// so a later failure ends the journey where it happened instead of being
// carried past.
test('errexit is back in force after a documented refusal', async () => {
  const { root, journey } = await emitRunFailsStep('false\n');
  try {
    const { code, output } = await runShell(`${journey}\nfalse\nprintf "past it\\n"\n`);
    assert.notEqual(code, 0, 'the journey must stop at the failure after the refusal');
    assert.doesNotMatch(output, /past it/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('write-fence extracts one fence by heading, language and occurrence', async () => {
  const root = await fenceScratch();
  try {
    const out = join(root, 'before.yaml');
    const { code, output } = await runFence([
      'write-fence',
      join(root, 'tutorial.mdx'),
      'Add a narrower selector profile',
      'yaml',
      '1',
      out,
    ]);
    assert.equal(code, 0, output);
    // Blank lines at the edges of a fence are presentation, so they are
    // trimmed exactly as the published fence renders.
    assert.equal(await readFile(out, 'utf8'), 'selectors:\n  - kind: broad\n');

    const second = join(root, 'after.yaml');
    assert.equal((await runFence([
      'write-fence',
      join(root, 'tutorial.mdx'),
      'Add a narrower selector profile',
      'yaml',
      '2',
      second,
    ])).code, 0);
    assert.equal(await readFile(second, 'utf8'), 'selectors:\n  - kind: narrow\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('write-fence counts occurrences per heading and language', async () => {
  const root = await fenceScratch();
  try {
    const out = join(root, 'sh.txt');
    // The sh fence under a later heading is that heading's first, not the
    // document's third.
    const { code, output } = await runFence([
      'write-fence',
      join(root, 'tutorial.mdx'),
      'Run it',
      'sh',
      '1',
      out,
    ]);
    assert.equal(code, 0, output);
    assert.equal(await readFile(out, 'utf8'), 'evidencectl check\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('write-fence names the fence it could not find', async () => {
  const root = await fenceScratch();
  try {
    const { code, output } = await runFence([
      'write-fence',
      join(root, 'tutorial.mdx'),
      'Add a narrower selector profile',
      'yaml',
      '3',
      join(root, 'missing.yaml'),
    ]);
    assert.notEqual(code, 0, 'a missing fence must fail');
    assert.match(output, /missing yaml fence 3 under "Add a narrower selector profile"/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('replace-block applies a documented pair to the reader file', async () => {
  const root = await fenceScratch();
  try {
    const target = join(root, 'evidence.yaml');
    await writeFile(target, 'version: 1\nselectors:\n  - kind: broad\ntrailer: keep\n');
    await writeFile(join(root, 'b'), 'selectors:\n  - kind: broad\n');
    await writeFile(join(root, 'a'), 'selectors:\n  - kind: narrow\n');
    const { code, output } = await runFence([
      'replace-block',
      target,
      join(root, 'b'),
      join(root, 'a'),
    ]);
    assert.equal(code, 0, output);
    assert.equal(
      await readFile(target, 'utf8'),
      'version: 1\nselectors:\n  - kind: narrow\ntrailer: keep\n',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('replace-block refuses a block that is not in the target exactly once', async () => {
  const root = await fenceScratch();
  try {
    const target = join(root, 'evidence.yaml');
    await writeFile(join(root, 'b'), 'kind: broad\n');
    await writeFile(join(root, 'a'), 'kind: narrow\n');

    await writeFile(target, 'kind: broad\nkind: broad\n');
    const twice = await runFence(['replace-block', target, join(root, 'b'), join(root, 'a')]);
    assert.notEqual(twice.code, 0, 'an ambiguous edit must fail');
    assert.match(twice.output, /found 2/u);

    await writeFile(target, 'kind: other\n');
    const never = await runFence(['replace-block', target, join(root, 'b'), join(root, 'a')]);
    assert.notEqual(never.code, 0, 'an edit with nothing to change must fail');
    assert.match(never.output, /found 0/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('replace-block refuses a pair that changes nothing', async () => {
  const root = await fenceScratch();
  try {
    const target = join(root, 'evidence.yaml');
    await writeFile(target, 'kind: broad\n');
    await writeFile(join(root, 'b'), 'kind: broad\n');
    await writeFile(join(root, 'a'), 'kind: broad\n');
    const { code, output } = await runFence([
      'replace-block',
      target,
      join(root, 'b'),
      join(root, 'a'),
    ]);
    assert.notEqual(code, 0, 'a pair that changes nothing is a spec error');
    assert.match(output, /must change the target/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
