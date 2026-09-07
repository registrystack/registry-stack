import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const gate = resolve(scriptDir, 'check-breg-tutorial.sh');
const docsRoot = resolve(scriptDir, '../src/content/docs');
const firstBreg = resolve(docsRoot, 'tutorials/first-breg.mdx');

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

// Lift one named function out of the gate. Sourcing the gate would run it, so
// the tests below exercise the shipped text of the function instead of
// restating it.
async function liftFunction(source, name) {
  const lifted = source.match(
    new RegExp(`\\n${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, 'u'),
  )?.[0];
  assert.ok(lifted, `${name} must exist in the gate`);
  return lifted;
}

function extractBashArray(source, name) {
  const match = source.match(new RegExp(`\\n[ \\t]*${name}=\\(([\\s\\S]*?)\\n[ \\t]*\\)`, 'u'));
  assert.ok(match, `${name} array must exist in the gate`);
  return match[1]
    .split('\n')
    .map((line) => line.split('#')[0].trim())
    .filter(Boolean);
}

// Counts are reported, never required: a writer who adds or removes a command
// block under an existing heading changes these numbers and neither the gate
// nor this test may object. Only the registration is asserted.
test('the dry-run gate resolves every registered Base Registry Engine tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /tutorials\/first-breg: \d+ sh fences, \d+ executed/u);
  assert.match(output, /Checked 1 tutorial\./u);
});

// The unexecuted surface is information a reviewer needs, not a rule. The
// install one-liner reaches the network, and it is the only fence the journey
// leaves alone: everything after it is what the gate proves.
test('the gate names the sh fences it did not execute', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  const unexecuted = output.match(/not executed: fence \d+ under "[^"]+"/gu) ?? [];
  assert.equal(unexecuted.length, 1, output);
  assert.match(unexecuted[0], /under "Install Base Registry Engine"/u);
});

// The journey has to start the registry the page leaves running and stop it
// where the page says to. A replay that skipped either end would leave the
// middle untested or hold a database container after the gate exits.
test('the registered journey starts and stops the registry', async () => {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(/\n\ttutorials\/first-breg\)[\s\S]*?\n\t\t;;/u)?.[0];
  assert.ok(branch, 'the first Base Registry Engine replay spec must exist');
  const steps = extractBashArray(branch, 'SPEC_STEPS').map((step) => step.replaceAll('"', ''));
  assert.equal(steps[0], 'run:Create a project');
  assert.equal(steps[1], 'run:Start the registry');
  assert.equal(steps.at(-1), 'run:Stop the registry');
});

// Run the outer cleanup's session stop against a stand-in bregctl that records
// what it was asked to do, over a reader directory holding the given state
// files.
async function runStopDevSessions({ stateFiles, stub }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-stop-test-'));
  const readerDir = join(root, 'reader');
  const shimDir = join(root, 'bin');
  const calls = join(root, 'calls.log');
  await mkdir(shimDir);
  await writeFile(
    join(shimDir, 'bregctl'),
    `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >>'${calls}'\n${stub}\n`,
    { mode: 0o755 },
  );
  for (const relative of stateFiles) {
    await mkdir(dirname(join(readerDir, relative)), { recursive: true });
    await writeFile(join(readerDir, relative), '{}\n');
  }
  const harness = join(root, 'stop.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `READER_DIR='${readerDir}'`,
      `SHIM_DIR='${shimDir}'`,
      await liftFunction(source, 'stop_dev_sessions'),
      'if stop_dev_sessions; then status=0; else status=$?; fi',
      'printf "stop_dev_sessions: %d\\n" "$status"',
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`);
    let recorded = '';
    try {
      recorded = await readFile(calls, 'utf8');
    } catch {
      recorded = '';
    }
    return { ...result, readerDir, calls: recorded.split('\n').filter(Boolean) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// A journey that fails halfway leaves `bregctl dev` running with a database
// container behind it, and deleting the work root alone would orphan that
// container. The outer cleanup stops every session the replay started, with
// the toolset under test, and reclaims the container and volume.
test('the cleanup stops every local development session the replay started', async () => {
  const { code, output, readerDir, calls } = await runStopDevSessions({
    stateFiles: [
      'first-breg/tutorial-work/project/.breg/dev/state.json',
      'another/registry/.breg/dev/state.json',
    ],
    stub: 'exit 0',
  });
  assert.equal(code, 0, output);
  assert.deepEqual(
    calls.sort(),
    [
      `dev stop ${join(readerDir, 'another/registry')} --remove`,
      `dev stop ${join(readerDir, 'first-breg/tutorial-work/project')} --remove`,
    ],
  );
});

test('the cleanup leaves a stopped session alone', async () => {
  const { code, output, calls } = await runStopDevSessions({
    stateFiles: [],
    stub: 'exit 0',
  });
  assert.equal(code, 0, output);
  assert.deepEqual(calls, []);
});

// A session that will not stop is reported rather than hidden: the reader of
// the gate log has to know a container was left behind. It is also reported to
// the caller, which is what keeps the work root from being deleted.
test('the cleanup reports a session it could not stop', async () => {
  const { code, output, readerDir } = await runStopDevSessions({
    stateFiles: ['first-breg/tutorial-work/project/.breg/dev/state.json'],
    stub: 'exit 1',
  });
  assert.equal(code, 0, output);
  assert.match(output, /could not stop the local development session/u);
  assert.ok(output.includes(join(readerDir, 'first-breg/tutorial-work/project')), output);
  assert.match(output, /stop_dev_sessions: 1/u);
});

// Run the outer cleanup over a work root that exists, with the session stop
// forced to succeed or to fail, and report whether the work root survived.
async function runCleanup({ sessionsStopped }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-cleanup-test-'));
  const workRoot = join(root, 'work');
  await mkdir(join(workRoot, 'reader'), { recursive: true });
  await writeFile(join(workRoot, 'reader', 'state.json'), '{}\n');
  const harness = join(root, 'cleanup.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `WORK_ROOT='${workRoot}'`,
      await liftFunction(source, 'cleanup'),
      `stop_dev_sessions() { return ${sessionsStopped ? 0 : 1}; }`,
      'cleanup',
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`);
    return { ...result, workRoot, survived: existsSync(workRoot) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the cleanup removes the work root once every session is stopped', async () => {
  const { code, output, survived } = await runCleanup({ sessionsStopped: true });
  assert.equal(code, 0, output);
  assert.equal(survived, false, output);
  assert.match(output, /tutorial gate: PASS/u);
});

// The state document under the work root is what `bregctl dev stop --remove`
// reads, so deleting the work root after a failed stop would strand the
// container and the volume with no way left to reclaim them.
test('the cleanup keeps the work root when a session could not be stopped', async () => {
  const { code, output, workRoot, survived } = await runCleanup({ sessionsStopped: false });
  assert.equal(code, 0, output);
  assert.equal(survived, true, output);
  assert.ok(output.includes(workRoot), output);
});

// Every documented refusal on this page prints its status and exits zero, so a
// registry that stopped refusing would leave the replay green. These are the
// assertions that catch it, and losing one is losing the check.
test('the journey retains the refusals the page teaches', async () => {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(/\n\ttutorials\/first-breg\)[\s\S]*?\n\t\t;;/u)?.[0];
  assert.ok(branch, 'the first Base Registry Engine replay spec must exist');
  for (const expected of ['HTTP 404', 'HTTP 400', 'HTTP 412']) {
    assert.ok(branch.includes(expected), `${expected} must stay asserted`);
  }
  assert.ok(branch.includes('"revisionIdentifier": "2"'));
});

// ---------------------------------------------------------------------------
// Page coverage
// ---------------------------------------------------------------------------

// Build a docs root the gate will accept: every excluded page must exist and
// still carry Base Registry Engine commands, and the one registered page is
// the real one, edited.
async function docsFixtureRoot(edit = (page) => page) {
  const source = await readFile(gate, 'utf8');
  const excluded = extractBashArray(source, 'EXCLUDED_BREG_TUTORIALS');
  const sections = extractBashArray(source, 'BREG_DOC_SECTIONS');
  const root = await mkdtemp(join(tmpdir(), 'breg-tutorial-coverage-test-'));
  for (const section of sections) {
    await mkdir(join(root, section), { recursive: true });
  }
  for (const slug of excluded) {
    await writeFile(
      join(root, `${slug}.mdx`),
      '---\ntitle: stub\n---\n\n```sh\nbregctl check .\n```\n',
    );
  }
  const page = await readFile(firstBreg, 'utf8');
  await writeFile(join(root, 'tutorials/first-breg.mdx'), edit(page));
  return root;
}

test('the coverage check fails on an unregistered page that runs Base Registry Engine', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'tutorials/orphan-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nbregctl init tutorial-work/project\n```\n',
    );
    const { code, output } = await runGate({ BREG_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'an unregistered Base Registry Engine page must fail the gate');
    assert.match(output, /tutorial coverage gap/u);
    assert.match(output, /tutorials\/orphan-tutorial\.mdx/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The page set is derived from the commands each page carries, so a page that
// runs no Base Registry Engine command needs no entry anywhere. That is what
// keeps the Evidence pages, which share this directory, out of both lists.
test('a page that runs no Base Registry Engine command needs no entry', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'tutorials/an-evidence-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nevidencectl fixtures run --project adult-status\n```\n',
    );
    await writeFile(join(root, 'start/prose-only.mdx'), '---\ntitle: stub\n---\n\nProse.\n');
    const { code, output } = await runGate({ BREG_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// An excluded page that stopped carrying Base Registry Engine commands is a
// stale entry: nothing would ever detect it again, so the reason it names can
// no longer be checked against the page.
test('an excluded page that no longer runs Base Registry Engine commands fails', async () => {
  const root = await docsFixtureRoot();
  try {
    const source = await readFile(gate, 'utf8');
    const [stale] = extractBashArray(source, 'EXCLUDED_BREG_TUTORIALS');
    await writeFile(join(root, `${stale}.mdx`), '---\ntitle: stub\n---\n\nProse.\n');
    const { code, output } = await runGate({ BREG_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a stale exclusion must fail the gate');
    assert.match(output, /no longer runs Base Registry Engine commands/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Heading addressing
// ---------------------------------------------------------------------------

// The point of heading addressing. A writer who adds a command block under a
// heading the journey already runs must not have to touch the gate, and the
// added block must be replayed rather than silently skipped.
test('a command block added under a replayed heading needs no gate change', async () => {
  const before = await runGate();
  assert.equal(before.code, 0, before.output);
  const baseline = before.output.match(
    /tutorials\/first-breg: (\d+) sh fences, (\d+) executed/u,
  );
  assert.ok(baseline, before.output);

  const root = await docsFixtureRoot((page) =>
    page.replace(
      '\n## Create a record\n',
      '\n```sh\ncurl --version\n```\n\n## Create a record\n',
    ),
  );
  try {
    const { code, output } = await runGate({ BREG_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
    const added = output.match(/tutorials\/first-breg: (\d+) sh fences, (\d+) executed/u);
    assert.ok(added, output);
    assert.equal(Number(added[1]), Number(baseline[1]) + 1);
    assert.equal(Number(added[2]), Number(baseline[2]) + 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The trade heading addressing makes: a renamed heading is a structural edit
// to the journey, so it fails, by name, before any command runs.
test('a renamed heading fails the gate by name', async () => {
  const root = await docsFixtureRoot((page) =>
    page.replace('\n## Update the record\n', '\n## Change the record\n'),
  );
  try {
    const { code, output } = await runGate({ BREG_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a renamed heading must fail the gate');
    assert.match(output, /no sh fence answers to "Update the record"/u);
    // The message has to be actionable: it names the headings the page does
    // carry, so the fix is reading the list rather than the script.
    assert.match(output, /Change the record/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// A registered page with no replay spec would otherwise be skipped in silence.
test('a registered page without a replay spec fails by name', async () => {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-spec-test-'));
  try {
    const harness = join(root, 'spec.sh');
    await writeFile(
      harness,
      [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        await liftFunction(source, 'load_spec'),
        'load_spec tutorials/not-registered',
        '',
      ].join('\n'),
    );
    const { code, output } = await runShell(`bash ${harness}`);
    assert.notEqual(code, 0, 'an unregistered slug must fail');
    assert.match(output, /is not a registered Base Registry Engine tutorial/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Behaviour assertions
// ---------------------------------------------------------------------------

async function runAssertTranscript(asserts, transcript) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-asserts-test-'));
  const log = join(root, 'run.log');
  await writeFile(log, transcript);
  const harness = join(root, 'assert.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      await liftFunction(source, 'assert_transcript'),
      `SPEC_ASSERTS=(${asserts.map((entry) => `'${entry}'`).join(' ')})`,
      `assert_transcript tutorial '${log}'`,
      '',
    ].join('\n'),
  );
  try {
    return await runShell(`bash ${harness}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('a retained behaviour assertion missing from the transcript fails', async () => {
  const { code, output } = await runAssertTranscript(
    ['HTTP 404', 'HTTP 412'],
    '==> fence 06\nHTTP 404\n==> fence 15\nHTTP 200\n',
  );
  assert.notEqual(code, 0, 'a missing behaviour must fail the gate');
  assert.match(output, /HTTP 412/u);
});

test('a transcript showing every retained behaviour passes', async () => {
  const { code, output } = await runAssertTranscript(
    ['HTTP 404', 'HTTP 412'],
    'HTTP 404\nHTTP 412\n',
  );
  assert.equal(code, 0, output);
});

// ---------------------------------------------------------------------------
// The gate's own shape
// ---------------------------------------------------------------------------

test('the gate pins neither fence counts nor page strings', async () => {
  const source = await readFile(gate, 'utf8');
  assert.doesNotMatch(source, /SPEC_FENCES/u);
  assert.doesNotMatch(source, /SPEC_LITERALS/u);
});

test('the gate refuses an unknown argument', async () => {
  const { code, output } = await runGate({}, ['--replay-everything']);
  assert.notEqual(code, 0, 'an unknown argument must fail the gate');
  assert.match(output, /unknown argument/u);
});

// The dry run is what runs inside the docs checks, on a machine with no
// container runtime and no Rust toolchain. It resolves the journey against the
// page and stops there, so neither may be reached.
test('the dry run reaches neither a container runtime nor a compiler', async () => {
  const root = await mkdtemp(join(tmpdir(), 'breg-dry-run-test-'));
  try {
    for (const name of ['docker', 'cargo', 'uv']) {
      await writeFile(
        join(root, name),
        `#!/usr/bin/env bash\nprintf 'the dry run reached %s\\n' ${name} >&2\nexit 97\n`,
        { mode: 0o755 },
      );
    }
    const { code, output } = await runGate({ PATH: `${root}:${process.env.PATH}` });
    assert.equal(code, 0, output);
    assert.doesNotMatch(output, /the dry run reached/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The registry refuses to initialize a project under a path that traverses a
// symbolic link, and a temporary directory is one wherever the system temp
// directory is itself a link, so the journey has to run from a resolved path.
test('the work root the journey runs from traverses no symbolic link', async () => {
  const source = await readFile(gate, 'utf8');
  const assignment = source.match(/^WORK_ROOT=.*$/mu)?.[0];
  assert.ok(assignment, 'the gate must assign a work root');
  const root = await mkdtemp(join(tmpdir(), 'breg-work-root-'));
  try {
    const physical = join(root, 'physical');
    const linked = join(root, 'linked');
    await mkdir(physical);
    const { code, output } = await runShell(
      [
        'set -euo pipefail',
        `ln -s '${physical}' '${linked}'`,
        `export TMPDIR='${linked}'`,
        assignment,
        'printf "%s\\n" "$WORK_ROOT"',
      ].join('\n'),
    );
    assert.equal(code, 0, output);
    const resolved = await runShell(`cd '${output.trim()}' && pwd -P`);
    assert.equal(resolved.code, 0, resolved.output);
    assert.equal(output.trim(), resolved.output.trim());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
