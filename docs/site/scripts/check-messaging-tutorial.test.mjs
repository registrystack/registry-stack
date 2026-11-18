import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const gate = resolve(scriptDir, 'check-messaging-tutorial.sh');
const docsRoot = resolve(scriptDir, '../src/content/docs');

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

async function runShell(script, env = {}) {
  try {
    const { stdout, stderr } = await execFileAsync('bash', ['-c', script], {
      env: { ...process.env, ...env },
    });
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

async function messagingSpec() {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(/\n\ttutorials\/first-messaging\)[\s\S]*?\n\t\t;;/u)?.[0];
  assert.ok(branch, 'the tutorials/first-messaging replay spec must exist');
  return branch;
}

async function specSteps() {
  return extractBashArray(await messagingSpec(), 'SPEC_STEPS').map((step) =>
    step.replaceAll('"', ''),
  );
}

// Split the gate's report into one block per tutorial, keyed by slug, so a
// test can ask about one tutorial's fences without unrelated output in the way.
function reportBlocks(output) {
  const blocks = new Map();
  let current = null;
  for (const line of output.split('\n')) {
    const header = line.match(/^([a-z]+\/[a-z0-9-]+): \d+ sh fences, \d+ executed$/u);
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
async function registeredPages() {
  return extractBashArray(await readFile(gate, 'utf8'), 'MESSAGING_TUTORIALS');
}

test('the dry-run gate resolves every registered Registry Messaging tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  const registered = await registeredPages();
  for (const slug of registered) {
    assert.match(output, new RegExp(`^${slug}: \\d+ sh fences, \\d+ executed$`, 'mu'));
  }
  assert.match(output, new RegExp(`Checked ${registered.length} tutorials?\\.`, 'u'));
});

// The Author page continues in the tutorial's project, so it must replay
// after the tutorial and in its reader directory.
test('the Author page replays in the tutorial project, after the tutorial', async () => {
  const source = await readFile(gate, 'utf8');
  const registered = await registeredPages();
  assert.ok(
    registered.indexOf('tutorials/first-messaging') < registered.indexOf('configure/messaging'),
    registered.join(', '),
  );
  const branch = source.match(/\n\tconfigure\/messaging\)[\s\S]*?\n\t\t;;/u)?.[0];
  assert.ok(branch, 'the configure/messaging replay spec must exist');
  assert.match(branch, /SPEC_READER=first-messaging/u);
});

// The local first run is fully executable with the supplied source binaries.
// Hosted operation remains outside this gate, and every omitted fence is
// named so that the report does not overstate its coverage.
test('the gate executes the local journey and names the hosted fences it omits', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  const firstRunUnexecuted = (reportBlocks(output).get('tutorials/first-messaging') ?? [])
    .map((line) => line.match(/not executed: fence \d+ under "([^"]+)"/u)?.[1])
    .filter(Boolean);
  assert.deepEqual(firstRunUnexecuted, [], output);

  const hostedUnexecuted = (reportBlocks(output).get('operate/messaging') ?? [])
    .map((line) => line.match(/not executed: fence \d+ under "([^"]+)"/u)?.[1])
    .filter(Boolean);
  assert.deepEqual(
    [...new Set(hostedUnexecuted)],
    [
      'Install the binaries',
      'Check the runtime file',
      'Record and serve the package',
      'Operate messages',
      'Erase expired data on demand',
    ],
    output,
  );
});

// The run is what every later step talks to, and the page ends by stopping
// it. A replay that skipped either end would leave the middle untested or
// hold two containers after the gate exits.
test('the registered journey starts the run and stops it last', async () => {
  const steps = await specSteps();
  assert.equal(steps[0], 'run:Create a package');
  assert.ok(steps.includes('run:Start the run'), steps.join(', '));
  assert.equal(steps.at(-1), 'run:Stop the run');
});

test('the registered journey sends both messages the page teaches', async () => {
  const steps = await specSteps();
  for (const step of ['run:Send an SMS', 'run:Send an email']) {
    assert.ok(steps.includes(step), `${step} must stay in the journey`);
  }
});

// Every command exits zero whatever Messaging answers, so the outcomes the
// page promises are held as transcript assertions.
test('the journey retains the outcomes the page teaches', async () => {
  const branch = await messagingSpec();
  for (const expected of [
    '"status": "delivered"',
    '"status": "submitted"',
    'Subject: Votre rendez-vous du 01/10/2026',
    'send-a-reminder-sms: passed',
    'stopped',
  ]) {
    assert.ok(branch.includes(expected), `${expected} must stay asserted`);
  }
});

// ---------------------------------------------------------------------------
// Toolset
// ---------------------------------------------------------------------------

async function runPrepareToolset(env = {}) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-toolset-test-'));
  const supplied = join(root, 'supplied-messagingctl');
  const runtime = join(root, 'supplied-messaging');
  const rstack = join(root, 'supplied-rstack');
  const shimDir = join(root, 'bin');
  await writeFile(supplied, '#!/usr/bin/env bash\nprintf "ran %s\\n" "$*"\n', { mode: 0o755 });
  await writeFile(runtime, '#!/usr/bin/env bash\nprintf "runtime %s\\n" "$*"\n', { mode: 0o755 });
  await writeFile(
    rstack,
    '#!/usr/bin/env bash\nset -euo pipefail\ninstall_root="$2"\nshift 4\n[[ "$1" == messaging ]]\nshift\nexec "$install_root/current/components/messaging/messagingctl/messagingctl" "$@"\n',
    { mode: 0o755 },
  );
  const harness = join(root, 'toolset.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `REPO_ROOT='${resolve(scriptDir, '../../..')}'`,
      `SITE_ROOT='${resolve(scriptDir, '..')}'`,
      `WORK_ROOT='${join(root, 'work')}'`,
      `SHIM_DIR='${shimDir}'`,
      await liftFunction(source, 'prepare_toolset'),
      'prepare_toolset',
      `"${shimDir}/messagingctl" check`,
      `"${shimDir}/rstack" messaging check`,
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`, {
      MESSAGINGCTL_BIN: supplied,
      MESSAGING_BIN: runtime,
      RSTACK_BIN: rstack,
      ...env,
    });
    const shim = join(shimDir, 'messagingctl');
    const stat = existsSync(shim) ? await lstat(shim) : null;
    const managedLauncher = join(root, 'work/managed-rstack/current/rstack');
    const managedEntrypoint = join(root, 'work/managed-rstack/current/components/messaging/messagingctl/messagingctl');
    return {
      ...result,
      supplied,
      symlink: stat?.isSymbolicLink() ? await readlink(shim) : null,
      wrapper: stat?.isFile() ? await readFile(shim, 'utf8') : null,
      managedLauncher: existsSync(managedLauncher) ? await readFile(managedLauncher, 'utf8') : null,
      managedEntrypoint: existsSync(managedEntrypoint) ? await readFile(managedEntrypoint, 'utf8') : null,
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the toolset serves the supplied binary under its own name', async () => {
  const { code, output, supplied, symlink } = await runPrepareToolset({
    REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '',
  });
  assert.equal(code, 0, output);
  assert.equal(symlink, supplied);
  assert.equal(output.match(/ran check/gu)?.length, 2, output);
});

// macOS strips DYLD_* variables when it runs a protected executable, so a
// value inherited by the journey shell would not reach the binary. The shim
// carries it instead.
test('the toolset carries a runtime library directory into every managed wrapper', async () => {
  const { code, output, supplied, wrapper, managedLauncher, managedEntrypoint } = await runPrepareToolset({
    REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '/opt/fips/artifacts',
  });
  assert.equal(code, 0, output);
  assert.ok(wrapper, 'the shim must be a wrapper script');
  for (const managed of [wrapper, managedLauncher, managedEntrypoint]) {
    assert.match(managed, /DYLD_FALLBACK_LIBRARY_PATH=/u);
    assert.ok(managed.includes('/opt/fips/artifacts'), managed);
  }
  assert.ok(wrapper.includes(`exec ${supplied} "$@"`), wrapper);
  assert.equal(output.match(/ran check/gu)?.length, 2, output);
});

test('the toolset refuses a relative binary path', async () => {
  const { code, output } = await runPrepareToolset({ MESSAGINGCTL_BIN: 'target/ci/messagingctl' });
  assert.notEqual(code, 0, output);
  assert.match(output, /must be absolute/u);
});

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// Run the outer cleanup's run stop over a state directory holding one run
// directory, a hidden bookkeeping directory the runner keeps beside the runs,
// and a stand-in rstack that records what it was asked to do.
async function runStopDevRuns({ stopStatus = 0, withRun = true } = {}) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-stop-test-'));
  const stateDir = join(root, 'rstack-dev');
  const shimDir = join(root, 'bin');
  const calls = join(root, 'calls.log');
  await mkdir(shimDir);
  await mkdir(join(stateDir, '.recovery'), { recursive: true });
  if (withRun) {
    await mkdir(join(stateDir, 'run-one'));
  }
  await writeFile(
    join(shimDir, 'rstack'),
    [
      '#!/usr/bin/env bash',
      `printf 'rstack %s state=%s\\n' "$*" "$RSTACK_DEV_STATE_DIR" >>'${calls}'`,
      `exit ${stopStatus}`,
      '',
    ].join('\n'),
    { mode: 0o755 },
  );
  const harness = join(root, 'stop.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `DEV_STATE_DIR='${stateDir}'`,
      `SHIM_DIR='${shimDir}'`,
      await liftFunction(source, 'stop_dev_runs'),
      'if stop_dev_runs; then status=0; else status=$?; fi',
      'printf "stop_dev_runs: %d\\n" "$status"',
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`);
    const recorded = existsSync(calls) ? await readFile(calls, 'utf8') : '';
    return { ...result, stateDir, calls: recorded.split('\n').filter(Boolean) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// A journey that fails halfway leaves its run going with a PostgreSQL and a
// Mailpit container behind it. The cleanup stops each run the journey
// started, which removes them, and nothing else.
test('the cleanup stops each run the journey started', async () => {
  const { code, output, calls, stateDir } = await runStopDevRuns();
  assert.equal(code, 0, output);
  assert.match(output, /stop_dev_runs: 0/u);
  assert.deepEqual(calls, [`rstack dev stop run-one state=${stateDir}`]);
});

test('the cleanup reaches no runner when no run was started', async () => {
  const { code, output, calls } = await runStopDevRuns({ withRun: false });
  assert.equal(code, 0, output);
  assert.match(output, /stop_dev_runs: 0/u);
  assert.deepEqual(calls, []);
});

// A run that will not stop is reported rather than hidden, and reported to
// the caller, which is what keeps the run's state from being deleted.
test('the cleanup reports a run it could not stop', async () => {
  const { code, output } = await runStopDevRuns({ stopStatus: 1 });
  assert.equal(code, 0, output);
  assert.match(output, /could not stop the rstack dev run run-one/u);
  assert.match(output, /stop_dev_runs: 1/u);
});

async function runCleanup({ runsStopped }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-cleanup-test-'));
  const workRoot = join(root, 'work');
  await mkdir(join(workRoot, 'reader'), { recursive: true });
  await writeFile(join(workRoot, 'reader', 'marker'), '{}\n');
  const harness = join(root, 'cleanup.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `WORK_ROOT='${workRoot}'`,
      `DEV_STATE_DIR='${workRoot}/rstack-dev'`,
      await liftFunction(source, 'cleanup'),
      `stop_dev_runs() { return ${runsStopped ? 0 : 1}; }`,
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

test('the cleanup removes the work root once every run is stopped', async () => {
  const { code, output, survived } = await runCleanup({ runsStopped: true });
  assert.equal(code, 0, output);
  assert.equal(survived, false, output);
  assert.match(output, /tutorial gate: PASS/u);
});

test('the cleanup keeps the work root when a run could not be stopped', async () => {
  const { code, output, workRoot, survived } = await runCleanup({ runsStopped: false });
  assert.equal(code, 0, output);
  assert.equal(survived, true, output);
  assert.ok(output.includes(workRoot), output);
});

// ---------------------------------------------------------------------------
// Replay mechanics, against a stand-in messagingctl
// ---------------------------------------------------------------------------

// A page with the registered journey's headings whose fences print the
// outcomes the spec asserts, replayed against a stand-in binary. This proves
// the replay mechanics without Docker: the fences run in one shell, in order,
// and the transcript is checked afterwards.
const STAND_IN_PAGE = [
  '---',
  'title: stub',
  '---',
  '',
  '## Create a package',
  '',
  '```sh',
  'rstack messaging init tutorial-work/notices',
  `mkdir -p tutorial-work/notices && printf 'kind: starter\\nid: one\\n' >tutorial-work/starter.yaml`,
  '```',
  '',
  '## Start the run',
  '',
  '```sh',
  `printf 'send-a-reminder-sms: passed\\n'`,
  '```',
  '',
  '## Send an SMS',
  '',
  '```sh',
  `printf 'HTTP 202\\n"status": "delivered"\\n'`,
  '```',
  '',
  '## Send an email',
  '',
  '```sh',
  `printf '"status": "submitted"\\nSubject: Votre rendez-vous du 01/10/2026\\n'`,
  '```',
  '',
  '## Stop the run',
  '',
  '```sh',
  `printf 'Run r stopped\\n'`,
  '```',
  '',
].join('\n');

function standInMessagingctl() {
  return ['#!/usr/bin/env python3', 'import sys', 'print("messagingctl", *sys.argv[1:])', ''].join('\n');
}

// The Author and Deploy stand-ins continue in the tutorial's reader
// directory and show a file the tutorial stand-in wrote, as an excerpt.
function standInAuthorPage({ excerpt = 'id: one', path = 'tutorial-work/starter.yaml' } = {}) {
  return [
    '---',
    'title: stub',
    '---',
    '',
    '## Check the project',
    '',
    '```sh',
    'messagingctl check --project tutorial-work/notices',
    '```',
    '',
    `\`\`\`yaml title="starter.yaml" test-excerpt="${path}"`,
    excerpt,
    '```',
    '',
    '## Add a French SMS',
    '',
    '```sh',
    'test -f tutorial-work/starter.yaml',
    '```',
    '',
    '## Package the project',
    '',
    '```sh',
    'messagingctl package tutorial-work/notices --output tutorial-work/notices-package',
    '```',
    '',
  ].join('\n');
}

const STAND_IN_DEPLOY_PAGE = [
  '---',
  'title: stub',
  '---',
  '',
  '## Install the binaries',
  '',
  '```yaml title="starter.yaml" test-excerpt="tutorial-work/starter.yaml"',
  'kind: starter',
  '```',
  '',
  '```sh',
  'messaging --version',
  '```',
  '',
].join('\n');

async function replayStandIn(options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'messaging-replay-test-'));
  try {
    for (const section of ['start', 'tutorials', 'configure', 'operate']) {
      await mkdir(join(root, 'docs', section), { recursive: true });
    }
    await writeFile(
      join(root, 'docs/tutorials/first-messaging.mdx'),
      options.stopReport === false ? STAND_IN_PAGE.replace('Run r stopped', 'Run r gone') : STAND_IN_PAGE,
    );
    await writeFile(join(root, 'docs/configure/messaging.mdx'), standInAuthorPage(options.author));
    await writeFile(
      join(root, 'docs/configure/api-connections.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nmessagingctl connection list\n```\n',
    );
    await writeFile(join(root, 'docs/operate/messaging.mdx'), STAND_IN_DEPLOY_PAGE);
    const bin = join(root, 'messagingctl');
    const runtime = join(root, 'messaging');
    const rstack = join(root, 'rstack');
    await writeFile(bin, standInMessagingctl(), { mode: 0o755 });
    await writeFile(runtime, '#!/usr/bin/env bash\nprintf "messaging runtime\\n"\n', { mode: 0o755 });
    await writeFile(
      rstack,
      '#!/usr/bin/env bash\nset -euo pipefail\ninstall_root="$2"\nshift 4\n[[ "$1" == messaging ]]\nshift\nexec "$install_root/current/components/messaging/messagingctl/messagingctl" "$@"\n',
      { mode: 0o755 },
    );
    return await runGate(
      {
        MESSAGING_TUTORIAL_DOCS_ROOT: join(root, 'docs'),
        MESSAGINGCTL_BIN: bin,
        MESSAGING_BIN: runtime,
        RSTACK_BIN: rstack,
        REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '',
      },
      [],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the replay runs every fence in order and passes', async () => {
  const { code, output } = await replayStandIn();
  assert.equal(code, 0, output);
  assert.match(output, /Run r stopped/u);
  assert.match(output, /Registry Messaging tutorial gate: PASS/u);
});

test('the replay checks each file excerpt in the reader directory it shares', async () => {
  const { code, output } = await replayStandIn();
  assert.equal(code, 0, output);
  assert.match(output, /^configure\/messaging: 3 sh fences, 3 executed$/mu);
  assert.match(output, /^ {2}file excerpts: 1, checked after the journey$/mu);
  assert.match(output, /messagingctl package tutorial-work\/notices/u);
  assert.match(output, /Checked 3 tutorials\./u);
});

// A page that shows a file as it no longer is fails, naming the page and
// the file, even though every command exited zero.
test('an excerpt the file no longer holds fails the replay', async () => {
  const { code, output } = await replayStandIn({ author: { excerpt: 'id: two' } });
  assert.notEqual(code, 0, output);
  assert.match(output, /excerpt drift in configure\/messaging: excerpt 01 is not in tutorial-work\/starter\.yaml/u);
  assert.match(output, /no run of lines matches the excerpt/u);
});

test('an excerpt of a file the journey did not leave fails the replay', async () => {
  const { code, output } = await replayStandIn({ author: { path: 'tutorial-work/missing.yaml' } });
  assert.notEqual(code, 0, output);
  assert.match(output, /excerpt 01 shows tutorial-work\/missing\.yaml, which the journey did not leave behind/u);
});

test('an excerpt outside the reader directory fails the replay', async () => {
  const { code, output } = await replayStandIn({ author: { path: '../reader/first-messaging/x' } });
  assert.notEqual(code, 0, output);
  assert.match(output, /which is not inside the reader directory/u);
});

// A run that no longer reports it stopped is exactly the regression a
// successful exit hides.
test('a journey whose transcript lacks an asserted outcome fails the replay', async () => {
  const { code, output } = await replayStandIn({ stopReport: false });
  assert.notEqual(code, 0, output);
  assert.match(output, /never showed "stopped"/u);
});

// ---------------------------------------------------------------------------
// Page coverage
// ---------------------------------------------------------------------------

// Build a docs root the gate will accept: the registered pages are the real
// ones, with an optional edit to the tutorial.
async function docsFixtureRoot(edit = (page) => page) {
  const source = await readFile(gate, 'utf8');
  const sections = extractBashArray(source, 'MESSAGING_DOC_SECTIONS');
  const root = await mkdtemp(join(tmpdir(), 'messaging-tutorial-coverage-test-'));
  for (const section of sections) {
    await mkdir(join(root, section), { recursive: true });
  }
  const fixturePages = [
    ...extractBashArray(source, 'MESSAGING_TUTORIALS'),
    ...extractBashArray(source, 'EXCLUDED_MESSAGING_TUTORIALS'),
  ];
  for (const slug of fixturePages) {
    const page = await readFile(resolve(docsRoot, `${slug}.mdx`), 'utf8');
    await writeFile(join(root, `${slug}.mdx`), slug === 'tutorials/first-messaging' ? edit(page) : page);
  }
  return root;
}

test('the coverage check fails on an unregistered page that runs Registry Messaging', async () => {
  const root = await docsFixtureRoot();
  try {
    await writeFile(
      join(root, 'tutorials/orphan-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nmessagingctl init tutorial-work/notices\n```\n',
    );
    await writeFile(
      join(root, 'start/runs-the-runtime.mdx'),
      '---\ntitle: stub\n---\n\n```sh\nmessaging serve --config runtime.yaml\n```\n',
    );
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'an unregistered Registry Messaging page must fail the gate');
    assert.match(output, /tutorial coverage gap/u);
    assert.match(output, /tutorials\/orphan-tutorial\.mdx/u);
    assert.match(output, /start\/runs-the-runtime\.mdx/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a filename, a package, a path segment and a shell variable are not invocations', async () => {
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
        'cat messaging.yaml',
        'cargo build --release --locked -p registry-messagingctl',
        'ls tutorial-work/messaging',
        'printf "%s\\n" "$messaging_url"',
        '```',
        '',
      ].join('\n'),
    );
    await writeFile(
      join(root, 'tutorials/a-casework-tutorial.mdx'),
      '---\ntitle: stub\n---\n\n```sh\ncaseworkctl init tutorial-work/casework\n```\n',
    );
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Heading addressing
// ---------------------------------------------------------------------------

test('a command block added under a replayed heading needs no gate change', async () => {
  const before = await runGate();
  assert.equal(before.code, 0, before.output);
  const baseline = before.output.match(/tutorials\/first-messaging: (\d+) sh fences, (\d+) executed/u);
  assert.ok(baseline, before.output);

  const root = await docsFixtureRoot((page) =>
    page.replace('\n## Send an email\n', '\n```sh\ncurl --version\n```\n\n## Send an email\n'),
  );
  try {
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.equal(code, 0, output);
    const added = output.match(/tutorials\/first-messaging: (\d+) sh fences, (\d+) executed/u);
    assert.ok(added, output);
    assert.equal(Number(added[1]), Number(baseline[1]) + 1);
    assert.equal(Number(added[2]), Number(baseline[2]) + 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a renamed heading fails the gate by name', async () => {
  const root = await docsFixtureRoot((page) =>
    page.replace('\n## Send an SMS\n', '\n## Text the recipient\n'),
  );
  try {
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a renamed heading must fail the gate');
    assert.match(output, /no sh fence answers to "Send an SMS"/u);
    assert.match(output, /Text the recipient/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a registered page without a replay spec fails by name', async () => {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-spec-test-'));
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
    assert.match(output, /is not a registered Registry Messaging tutorial/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The gate's own shape
// ---------------------------------------------------------------------------

test('the gate pins neither fence counts nor page strings', async () => {
  const source = await readFile(gate, 'utf8');
  assert.doesNotMatch(source, /SPEC_FENCES/u);
  assert.doesNotMatch(source, /SPEC_LITERALS/u);
});

// Messaging runs under `rstack dev`, whose runs keep their state in a
// directory of the gate's own and are stopped by the cleanup.
test('the gate drives rstack dev and not a messagingctl session', async () => {
  const source = await readFile(gate, 'utf8');
  assert.doesNotMatch(source, /messagingctl dev/u);
  assert.match(source, /RSTACK_DEV_STATE_DIR/u);
});

test('the gate refuses an unknown argument', async () => {
  const { code, output } = await runGate({}, ['--replay-everything']);
  assert.notEqual(code, 0, 'an unknown argument must fail the gate');
  assert.match(output, /unknown argument/u);
});

// The dry run is what runs inside the docs checks, on a machine with no
// container runtime and no Rust toolchain.
test('the dry run reaches neither a container runtime nor a compiler', async () => {
  const root = await mkdtemp(join(tmpdir(), 'messaging-dry-run-test-'));
  try {
    for (const name of ['docker', 'cargo']) {
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
