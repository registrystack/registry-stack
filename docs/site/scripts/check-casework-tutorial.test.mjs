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
const gate = resolve(scriptDir, 'check-casework-tutorial.sh');
const docsRoot = resolve(scriptDir, '../src/content/docs');
const firstCasework = resolve(docsRoot, 'tutorials/first-casework.mdx');

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

async function spec(slug) {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(
    new RegExp(`\\n\\t${slug.replaceAll('/', '\\/')}\\)[\\s\\S]*?\\n\\t\\t;;`, 'u'),
  )?.[0];
  assert.ok(branch, `the ${slug} replay spec must exist`);
  return branch;
}

const caseworkSpec = () => spec('tutorials/first-casework');
const reviewSpec = () => spec('tutorials/review-breg-changes-in-casework');

// Split the gate's report into one block per tutorial, keyed by slug, so a
// test can ask about one tutorial's fences without the other's in the way.
function reportBlocks(output) {
  const blocks = new Map();
  let current = null;
  for (const line of output.split('\n')) {
    const header = line.match(/^(tutorials\/[a-z0-9-]+): \d+ sh fences, \d+ executed$/u);
    if (header) {
      current = [];
      blocks.set(header[1], current);
    } else if (current) {
      current.push(line);
    }
  }
  return blocks;
}

// Counts are reported, never required: a writer who adds or removes a command
// block under an existing heading changes these numbers and neither the gate
// nor this test may object. Only the registration is asserted.
test('the dry-run gate resolves every registered Registry Casework tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /tutorials\/first-casework: \d+ sh fences, \d+ executed/u);
  assert.match(output, /tutorials\/review-breg-changes-in-casework: \d+ sh fences, \d+ executed/u);
  assert.match(output, /Checked 2 tutorials\./u);
});

// The unexecuted surface is information a reviewer needs, not a rule. The
// install one-liners reach the network, and they are the only fences each
// journey leaves alone: everything after them is what the gate proves.
test('the gate names the sh fences it did not execute', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  const blocks = reportBlocks(output);
  const unexecutedUnder = (slug) =>
    (blocks.get(slug) ?? [])
      .map((line) => line.match(/not executed: fence \d+ under "([^"]+)"/u)?.[1])
      .filter(Boolean);
  assert.deepEqual(unexecutedUnder('tutorials/first-casework'), ['Install Registry Casework'], output);
  const review = unexecutedUnder('tutorials/review-breg-changes-in-casework');
  assert.ok(review.length > 0, output);
  assert.ok(
    review.every((heading) => heading === 'Install both products'),
    output,
  );
});

// The journey has to start the runtime the page leaves running and stop it
// where the page says to. A replay that skipped either end would leave the
// middle untested or hold a database container after the gate exits.
test('the registered journey starts and stops Casework', async () => {
  const steps = extractBashArray(await caseworkSpec(), 'SPEC_STEPS').map((step) =>
    step.replaceAll('"', ''),
  );
  assert.equal(steps[0], 'run:Create a project');
  assert.equal(steps[1], 'run:Start Casework');
  assert.equal(steps.at(-1), 'run:Stop Casework');
});

// The whole point of the journey is one work item reaching a decision through
// four profiles, so every profile the page uses has to appear in it.
test('the registered journey runs every profile the page teaches', async () => {
  const steps = extractBashArray(await caseworkSpec(), 'SPEC_STEPS').map((step) =>
    step.replaceAll('"', ''),
  );
  for (const step of [
    'run:Submit a request as the Requester',
    'run:Open the inbox as Staff',
    'run:Claim the item',
    'run:Decide the item',
    'run:Read the outcome as the Requester',
    'run:See who decided, as the Supervisor',
  ]) {
    assert.ok(steps.includes(step), `${step} must stay in the journey`);
  }
});

// The two-product journey has to start the registry before Casework can bind
// and reconcile its source, and it has to stop both at the end: a replay that
// stopped only one would hold a database container after the gate exits.
test('the two-product journey starts the registry first and stops both sessions', async () => {
  const steps = extractBashArray(await reviewSpec(), 'SPEC_STEPS').map((step) =>
    step.replaceAll('"', ''),
  );
  assert.equal(steps[0], 'run:Create the two projects');
  assert.ok(steps.indexOf('run:Start the registry') < steps.indexOf('run:Start Casework'));
  assert.equal(steps.at(-1), 'run:Stop both sessions');
});

// The point of the two-product journey is one change request moving from a
// registry submission through a Casework review and application back into the
// registry, so each leg has to stay in it.
test('the two-product journey runs every leg the page teaches', async () => {
  const steps = extractBashArray(await reviewSpec(), 'SPEC_STEPS').map((step) =>
    step.replaceAll('"', ''),
  );
  for (const step of [
    'run:Connect the registry to Casework',
    'run:Submit a change request',
    'run:Open the inbox as Staff',
    'run:Approve the review',
    'run:Apply the change',
    'run:Verify the registry',
  ]) {
    assert.ok(steps.includes(step), `${step} must stay in the journey`);
  }
});

// The two Casework decisions and the registry's own view of the result are
// read with curl --write-out and a human-readable example runner, so a review
// that stopped reaching the source, or an application that stopped changing
// the registry, would leave every command exiting zero.
test('the two-product journey retains the outcomes the page teaches', async () => {
  const branch = await reviewSpec();
  for (const expected of [
    '"resultingState": "approved"',
    '"resultingState": "applied"',
    '"bregState": "applied"',
  ]) {
    assert.ok(branch.includes(expected), `${expected} must stay asserted`);
  }
});

// Run the toolset preparation with every binary supplied, so no build runs,
// and report what the shim directory serves.
async function runPrepareToolset() {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'casework-toolset-test-'));
  const binDir = join(root, 'supplied');
  const shimDir = join(root, 'bin');
  await mkdir(binDir);
  const names = ['casework', 'caseworkctl', 'breg', 'bregctl'];
  for (const name of names) {
    await writeFile(join(binDir, name), '#!/usr/bin/env bash\nexit 0\n', { mode: 0o755 });
  }
  const harness = join(root, 'toolset.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `SHIM_DIR='${shimDir}'`,
      await liftFunction(source, 'prepare_toolset'),
      'prepare_toolset',
      `ls '${shimDir}'`,
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(
      `CASEWORK_BIN='${join(binDir, 'casework')}' CASEWORKCTL_BIN='${join(binDir, 'caseworkctl')}' ` +
        `BREG_BIN='${join(binDir, 'breg')}' ` +
        `BREGCTL_BIN='${join(binDir, 'bregctl')}' bash ${harness}`,
    );
    return { ...result, names };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// The two-product page calls `bregctl` and `breg` by name beside the Casework
// binaries, so the shim directory has to serve all four.
test('the toolset serves the Base Registry Engine binaries beside the Casework ones', async () => {
  const { code, output, names } = await runPrepareToolset();
  assert.equal(code, 0, output);
  const served = output.trim().split('\n').filter(Boolean).sort();
  assert.deepEqual(served, [...names].sort());
});

// Run the outer cleanup's session stop against stand-in caseworkctl and
// bregctl binaries that record what they were asked to do, over a reader
// directory holding the given state files.
async function runStopDevSessions({ stateFiles, stub }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'casework-stop-test-'));
  const readerDir = join(root, 'reader');
  const shimDir = join(root, 'bin');
  const calls = join(root, 'calls.log');
  await mkdir(shimDir);
  for (const binary of ['caseworkctl', 'bregctl']) {
    await writeFile(
      join(shimDir, binary),
      `#!/usr/bin/env bash\nprintf '${binary} %s\\n' "$*" >>'${calls}'\n${stub}\n`,
      { mode: 0o755 },
    );
  }
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

// A journey that fails halfway leaves `caseworkctl dev`, and on the two-product
// page `bregctl dev` beside it, running with a database container behind each,
// and deleting the work root alone would orphan those containers. The outer
// cleanup stops every session the replay started, with the toolset under test,
// and reclaims the containers and volumes. Casework sessions stop first so
// they no longer reconcile against a registry that is stopping.
test('the cleanup stops every local development session the replay started', async () => {
  const { code, output, readerDir, calls } = await runStopDevSessions({
    stateFiles: [
      'first-casework/tutorial-work/casework/.casework/dev/state.json',
      'another/project/.casework/dev/state.json',
      'review-breg-changes-in-casework/tutorial-work/registry/.breg/dev/state.json',
    ],
    stub: 'exit 0',
  });
  assert.equal(code, 0, output);
  assert.deepEqual(
    calls.slice(0, 2).sort(),
    [
      `caseworkctl dev stop ${join(readerDir, 'another/project')} --remove`,
      `caseworkctl dev stop ${join(readerDir, 'first-casework/tutorial-work/casework')} --remove`,
    ],
  );
  assert.deepEqual(calls.slice(2), [
    `bregctl dev stop ${join(readerDir, 'review-breg-changes-in-casework/tutorial-work/registry')} --remove`,
  ]);
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
    stateFiles: ['first-casework/tutorial-work/casework/.casework/dev/state.json'],
    stub: 'exit 1',
  });
  assert.equal(code, 0, output);
  assert.match(output, /could not stop the local development session/u);
  assert.ok(output.includes(join(readerDir, 'first-casework/tutorial-work/casework')), output);
  assert.match(output, /stop_dev_sessions: 1/u);
});

// Run the outer cleanup over a work root that exists, with the session stop
// forced to succeed or to fail, and report whether the work root survived.
async function runCleanup({ sessionsStopped }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'casework-cleanup-test-'));
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

// The state document under the work root is what `caseworkctl dev stop
// --remove` reads, so deleting the work root after a failed stop would strand
// the container and the volume with no way left to reclaim them.
test('the cleanup keeps the work root when a session could not be stopped', async () => {
  const { code, output, workRoot, survived } = await runCleanup({ sessionsStopped: false });
  assert.equal(code, 0, output);
  assert.equal(survived, true, output);
  assert.ok(output.includes(workRoot), output);
});

// Every documented refusal on this page prints its status and its problem code
// and exits zero, so a Casework that stopped refusing would leave the replay
// green. These are the assertions that catch it, and losing one is losing the
// check.
test('the journey retains the refusals the page teaches', async () => {
  const branch = await caseworkSpec();
  for (const expected of [
    'HTTP 412',
    'precondition.failed',
    'operation.not-authorized',
    'profile.not-authorized',
    'request.invalid',
  ]) {
    assert.ok(branch.includes(expected), `${expected} must stay asserted`);
  }
});

// A decision that stopped reaching a terminal state, or an accountability
// record that stopped naming the profile behind it, would also leave every
// command exiting zero.
test('the journey retains the decision outcomes the page teaches', async () => {
  const branch = await caseworkSpec();
  assert.ok(branch.includes('"state": "completed"'));
  assert.ok(branch.includes('"profileId": "staff"'));
});

// The tutorial passes no port flags, so the replay must run on the ports a
// reader gets. The three overrides reach `caseworkctl dev` from the caller's
// environment, for a developer whose machine already listens on one of them,
// and the gate itself sets none of them.
test('the gate sets none of the development port overrides', async () => {
  const source = await readFile(gate, 'utf8');
  for (const name of [
    'CASEWORKCTL_DEV_CASEWORK_PORT',
    'CASEWORKCTL_DEV_ISSUER_PORT',
    'CASEWORKCTL_DEV_DATABASE_PORT',
  ]) {
    assert.doesNotMatch(source, new RegExp(`^[^#\\n]*${name}=`, 'mu'), `${name} must stay unset`);
    assert.doesNotMatch(source, new RegExp(`export ${name}`, 'u'), `${name} must stay unset`);
  }
});

// ---------------------------------------------------------------------------
// Page coverage
// ---------------------------------------------------------------------------

// Build a docs root the gate will accept: every excluded page must exist and
// still carry Registry Casework commands, and every registered page is the
// real one, with the first tutorial edited.
async function docsFixtureRoot(edit = (page) => page) {
  const source = await readFile(gate, 'utf8');
  const registered = extractBashArray(source, 'CASEWORK_TUTORIALS');
  const excluded = extractBashArray(source, 'EXCLUDED_CASEWORK_TUTORIALS');
  const sections = extractBashArray(source, 'CASEWORK_DOC_SECTIONS');
  const root = await mkdtemp(join(tmpdir(), 'casework-tutorial-coverage-test-'));
  for (const section of sections) {
    await mkdir(join(root, section), { recursive: true });
  }
  for (const slug of excluded) {
    await writeFile(
      join(root, `${slug}.mdx`),
      '---\ntitle: stub\n---\n\n```sh\ncaseworkctl check .\n```\n',
    );
  }
  for (const slug of registered) {
    if (slug === 'tutorials/first-casework') {
      continue;
    }
    await writeFile(join(root, `${slug}.mdx`), await readFile(resolve(docsRoot, `${slug}.mdx`)));
  }
  const page = await readFile(firstCasework, 'utf8');
  await writeFile(join(root, 'tutorials/first-casework.mdx'), edit(page));
  return root;
}

test('the coverage check fails on an unregistered page that runs Registry Casework', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'tutorials/orphan-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\ncaseworkctl init tutorial-work/casework\n```\n',
    );
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'an unregistered Registry Casework page must fail the gate');
    assert.match(output, /tutorial coverage gap/u);
    assert.match(output, /tutorials\/orphan-tutorial\.mdx/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The page set is derived from the commands each page carries, so a page that
// runs no Registry Casework command needs no entry anywhere. That is what
// keeps the Base Registry Engine and Evidence pages, which share these
// directories, out of both lists.
test('a page that runs no Registry Casework command needs no entry', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'tutorials/a-breg-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nbregctl init tutorial-work/project\n```\n',
    );
    await writeFile(join(root, 'start/prose-only.mdx'), '---\ntitle: stub\n---\n\nProse.\n');
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// A page naming the project directory, the configuration file or the shell
// variable the tutorial uses is not a page that runs Casework. Reading those
// as invocations would demand an entry for every page that mentions a path.
test('a filename, a path segment and a shell variable are not invocations', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'start/mentions-only.mdx'),
      [
        '---',
        'title: stub',
        '---',
        '',
        '```sh',
        'cat casework.yaml',
        'ls tutorial-work/casework',
        'printf "%s\\n" "$casework_url"',
        '```',
        '',
      ].join('\n'),
    );
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// An excluded page that stopped carrying Registry Casework commands is a stale
// entry: nothing would ever detect it again, so the reason it names can no
// longer be checked against the page.
test('an excluded page that no longer runs Registry Casework commands fails', async () => {
  const root = await docsFixtureRoot();
  try {
    const source = await readFile(gate, 'utf8');
    const [stale] = extractBashArray(source, 'EXCLUDED_CASEWORK_TUTORIALS');
    await writeFile(join(root, `${stale}.mdx`), '---\ntitle: stub\n---\n\nProse.\n');
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a stale exclusion must fail the gate');
    assert.match(output, /no longer runs Registry Casework commands/u);
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
    /tutorials\/first-casework: (\d+) sh fences, (\d+) executed/u,
  );
  assert.ok(baseline, before.output);

  const root = await docsFixtureRoot((page) =>
    page.replace('\n## Claim the item\n', '\n```sh\ncurl --version\n```\n\n## Claim the item\n'),
  );
  try {
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
    const added = output.match(/tutorials\/first-casework: (\d+) sh fences, (\d+) executed/u);
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
    page.replace('\n## Decide the item\n', '\n## Complete the item\n'),
  );
  try {
    const { code, output } = await runGate({ CASEWORK_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a renamed heading must fail the gate');
    assert.match(output, /no sh fence answers to "Decide the item"/u);
    // The message has to be actionable: it names the headings the page does
    // carry, so the fix is reading the list rather than the script.
    assert.match(output, /Complete the item/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// A registered page with no replay spec would otherwise be skipped in silence.
test('a registered page without a replay spec fails by name', async () => {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'casework-spec-test-'));
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
    assert.match(output, /is not a registered Registry Casework tutorial/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Behaviour assertions
// ---------------------------------------------------------------------------

async function runAssertTranscript(asserts, transcript) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'casework-asserts-test-'));
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
    ['HTTP 412', 'profile.not-authorized'],
    '==> fence 06\nHTTP 412\n==> fence 15\nHTTP 200\n',
  );
  assert.notEqual(code, 0, 'a missing behaviour must fail the gate');
  assert.match(output, /profile\.not-authorized/u);
});

test('a transcript showing every retained behaviour passes', async () => {
  const { code, output } = await runAssertTranscript(
    ['HTTP 412', 'profile.not-authorized'],
    'HTTP 412\nprofile.not-authorized\n',
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
  const root = await mkdtemp(join(tmpdir(), 'casework-dry-run-test-'));
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

// `caseworkctl dev` canonicalizes the project path it retains, and a temporary
// directory sits under a symbolic link wherever the system temp directory is
// one, so the journey has to run from a resolved path for the gate to stop the
// session by the path the session recorded.
test('the work root the journey runs from traverses no symbolic link', async () => {
  const source = await readFile(gate, 'utf8');
  const assignment = source.match(/^WORK_ROOT=.*$/mu)?.[0];
  assert.ok(assignment, 'the gate must assign a work root');
  const root = await mkdtemp(join(tmpdir(), 'casework-work-root-'));
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
