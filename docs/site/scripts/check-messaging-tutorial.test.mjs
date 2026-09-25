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
const firstMessaging = resolve(docsRoot, 'tutorials/first-messaging.mdx');

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
test('the dry-run gate resolves every registered Registry Messaging tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /tutorials\/first-messaging: \d+ sh fences, \d+ executed/u);
  assert.match(output, /Checked 1 tutorial\./u);
});

// The source build reaches the network and a Rust toolchain, and the gate
// replaces it with the binary under test, so it is the only surface the
// journey leaves alone.
test('the gate names the sh fences it did not execute', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  const unexecuted = (reportBlocks(output).get('tutorials/first-messaging') ?? [])
    .map((line) => line.match(/not executed: fence \d+ under "([^"]+)"/u)?.[1])
    .filter(Boolean);
  assert.ok(unexecuted.length > 0, output);
  assert.deepEqual([...new Set(unexecuted)], ['Get messagingctl'], output);
});

// The session is what every later step talks to, and the page ends by
// stopping it. A replay that skipped either end would leave the middle
// untested or hold two containers after the gate exits.
test('the registered journey starts the session and stops it last', async () => {
  const steps = await specSteps();
  assert.equal(steps[0], 'run:Create a package');
  assert.ok(steps.includes('session:Start the session'), steps.join(', '));
  assert.equal(steps.at(-1), 'stop-session');
});

test('the registered journey sends both messages the page teaches', async () => {
  const steps = await specSteps();
  for (const step of ['run:Get a token', 'run:Send an SMS', 'run:Send an email']) {
    assert.ok(steps.includes(step), `${step} must stay in the journey`);
  }
});

// Every command exits zero whatever Messaging answers, so the outcomes the
// page promises are held as transcript assertions.
test('the journey retains the outcomes the page teaches', async () => {
  const branch = await messagingSpec();
  for (const expected of [
    'HTTP 202',
    '"status": "delivered"',
    '"status": "submitted"',
    'Subject: Votre rendez-vous du 01/10/2026',
    'containers are removed',
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
  const shimDir = join(root, 'bin');
  await writeFile(supplied, '#!/usr/bin/env bash\nprintf "ran %s\\n" "$*"\n', { mode: 0o755 });
  const harness = join(root, 'toolset.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `SHIM_DIR='${shimDir}'`,
      await liftFunction(source, 'prepare_toolset'),
      'prepare_toolset',
      `"${shimDir}/messagingctl" check`,
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`, { MESSAGINGCTL_BIN: supplied, ...env });
    const shim = join(shimDir, 'messagingctl');
    const stat = existsSync(shim) ? await lstat(shim) : null;
    return {
      ...result,
      supplied,
      symlink: stat?.isSymbolicLink() ? await readlink(shim) : null,
      wrapper: stat?.isFile() ? await readFile(shim, 'utf8') : null,
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
  assert.match(output, /ran check/u);
});

// macOS strips DYLD_* variables when it runs a protected executable, so a
// value inherited by the journey shell would not reach the binary. The shim
// carries it instead.
test('the toolset carries a runtime library directory into the shim', async () => {
  const { code, output, supplied, wrapper } = await runPrepareToolset({
    REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '/opt/fips/artifacts',
  });
  assert.equal(code, 0, output);
  assert.ok(wrapper, 'the shim must be a wrapper script');
  assert.match(wrapper, /DYLD_FALLBACK_LIBRARY_PATH=\/opt\/fips\/artifacts/u);
  assert.ok(wrapper.includes(`exec ${supplied} "$@"`), wrapper);
  assert.match(output, /ran check/u);
});

test('the toolset refuses a relative binary path', async () => {
  const { code, output } = await runPrepareToolset({ MESSAGINGCTL_BIN: 'target/ci/messagingctl' });
  assert.notEqual(code, 0, output);
  assert.match(output, /must be absolute/u);
});

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// Run the outer cleanup's session stop over a reader directory holding one
// session record, with a stand-in docker that lists one owned container and
// records what it was asked to do, and a stand-in session process that exits
// on SIGINT.
async function runStopDevSessions({ dockerRm = 'exit 0', withSession = true } = {}) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-stop-test-'));
  const readerDir = join(root, 'reader');
  const binDir = join(root, 'bin');
  const calls = join(root, 'calls.log');
  const pidFile = join(root, 'session.pid');
  await mkdir(binDir);
  await writeFile(
    join(binDir, 'docker'),
    [
      '#!/usr/bin/env bash',
      `printf 'docker %s\\n' "$*" >>'${calls}'`,
      'if [[ "$1" == ps ]]; then printf "c0ffee\\n"; exit 0; fi',
      dockerRm,
      '',
    ].join('\n'),
    { mode: 0o755 },
  );
  if (withSession) {
    const record = join(readerDir, 'first-messaging/tutorial-work/notices/.messaging/dev/session.json');
    await mkdir(dirname(record), { recursive: true });
    await writeFile(record, '{"owner":"owner-1","state":"ready","containers":["c0ffee"]}\n');
  }
  const harness = join(root, 'stop.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `READER_DIR='${readerDir}'`,
      `SESSION_PID_FILE='${pidFile}'`,
      "OWNER_LABEL='org.registrystack.messagingctl.dev-owner'",
      `PATH='${binDir}':"$PATH"`,
      await liftFunction(source, 'stop_dev_sessions'),
      // A background process of a non-interactive shell starts with SIGINT
      // ignored; the session, like this stand-in, installs its own handler.
      `python3 -c 'import signal, sys, time; signal.signal(signal.SIGINT, lambda *_: sys.exit(0)); open(sys.argv[1], "w").write("up"); time.sleep(60)' '${root}/up' &`,
      'session=$!',
      `printf '%s\\n' "$session" >'${pidFile}'`,
      `until [[ -f '${root}/up' ]]; do sleep 0.05; done`,
      'if stop_dev_sessions; then status=0; else status=$?; fi',
      'if kill -0 "$session" 2>/dev/null; then printf "session still running\\n"; fi',
      'printf "stop_dev_sessions: %d\\n" "$status"',
      '',
    ].join('\n'),
  );
  try {
    const result = await runShell(`bash ${harness}`);
    const recorded = existsSync(calls) ? await readFile(calls, 'utf8') : '';
    return { ...result, calls: recorded.split('\n').filter(Boolean) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// A journey that fails halfway leaves `messagingctl dev` running with two
// containers behind it. The cleanup interrupts the session, which removes its
// own containers, then sweeps by the owner label for whatever a crashed
// session left.
test('the cleanup interrupts the session and sweeps its owned containers', async () => {
  const { code, output, calls } = await runStopDevSessions();
  assert.equal(code, 0, output);
  assert.doesNotMatch(output, /session still running/u);
  assert.match(output, /stop_dev_sessions: 0/u);
  assert.deepEqual(calls, [
    'docker ps --all --quiet --filter label=org.registrystack.messagingctl.dev-owner=owner-1',
    'docker rm --force --volumes c0ffee',
  ]);
});

test('the cleanup reaches no container runtime when no session was recorded', async () => {
  const { code, output, calls } = await runStopDevSessions({ withSession: false });
  assert.equal(code, 0, output);
  assert.match(output, /stop_dev_sessions: 0/u);
  assert.deepEqual(calls, []);
});

// A container that will not go is reported rather than hidden, and reported to
// the caller, which is what keeps the session record from being deleted.
test('the cleanup reports a container it could not remove', async () => {
  const { code, output } = await runStopDevSessions({ dockerRm: 'exit 1' });
  assert.equal(code, 0, output);
  assert.match(output, /could not remove container c0ffee/u);
  assert.match(output, /stop_dev_sessions: 1/u);
});

async function runCleanup({ sessionsStopped }) {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'messaging-cleanup-test-'));
  const workRoot = join(root, 'work');
  await mkdir(join(workRoot, 'reader'), { recursive: true });
  await writeFile(join(workRoot, 'reader', 'session.json'), '{}\n');
  const harness = join(root, 'cleanup.sh');
  await writeFile(
    harness,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      `WORK_ROOT='${workRoot}'`,
      "OWNER_LABEL='org.registrystack.messagingctl.dev-owner'",
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

test('the cleanup keeps the work root when a container was left behind', async () => {
  const { code, output, workRoot, survived } = await runCleanup({ sessionsStopped: false });
  assert.equal(code, 0, output);
  assert.equal(survived, true, output);
  assert.ok(output.includes(workRoot), output);
});

// ---------------------------------------------------------------------------
// Replay mechanics, against a stand-in messagingctl
// ---------------------------------------------------------------------------

// A page with the registered journey's headings whose fences print the
// outcomes the spec asserts, replayed against a stand-in binary. This proves
// the session and stop steps without Docker: the session starts in the
// background, the journey waits for its ready line, and the stop step's
// SIGINT is what makes the stand-in print its stop report.
const STAND_IN_PAGE = [
  '---',
  'title: stub',
  '---',
  '',
  '## Create a package',
  '',
  '```sh',
  'messagingctl init tutorial-work/notices',
  '```',
  '',
  '## Start the session',
  '',
  '```sh',
  'messagingctl dev tutorial-work/notices',
  '```',
  '',
  '## Get a token',
  '',
  '```sh',
  'messagingctl dev token case-system tutorial-work/notices',
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
].join('\n');

function standInMessagingctl({ ready = true, stopReport = true } = {}) {
  return [
    '#!/usr/bin/env python3',
    'import signal, sys, time',
    'if sys.argv[1:2] == ["dev"] and len(sys.argv) == 3:',
    ready
      ? '    stop = []\n    signal.signal(signal.SIGINT, lambda *_: stop.append(1))\n    print("ready", flush=True)\n    while not stop:\n        time.sleep(0.05)'
      : '    print("the session could not start", flush=True)\n    sys.exit(3)',
    stopReport
      ? `    print("stopped; the session's containers are removed", flush=True)`
      : '    print("stopped", flush=True)',
    '    sys.exit(0)',
    'print("messagingctl", *sys.argv[1:])',
    '',
  ].join('\n');
}

async function replayStandIn(options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'messaging-replay-test-'));
  try {
    await mkdir(join(root, 'docs/start'), { recursive: true });
    await mkdir(join(root, 'docs/tutorials'), { recursive: true });
    await writeFile(join(root, 'docs/tutorials/first-messaging.mdx'), STAND_IN_PAGE);
    const bin = join(root, 'messagingctl');
    await writeFile(bin, standInMessagingctl(options), { mode: 0o755 });
    return await runGate(
      {
        MESSAGING_TUTORIAL_DOCS_ROOT: join(root, 'docs'),
        MESSAGINGCTL_BIN: bin,
        MESSAGING_TUTORIAL_READY_SECONDS: '20',
        REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '',
      },
      [],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the replay leaves the session running, then stops it with SIGINT', async () => {
  const { code, output } = await replayStandIn();
  assert.equal(code, 0, output);
  assert.match(output, /fence \d+ \(session, left running\)/u);
  assert.match(output, /^ready$/mu);
  assert.match(output, /messagingctl dev token case-system tutorial-work\/notices/u);
  assert.match(output, /stop the session \(Ctrl-C\)/u);
  assert.match(output, /containers are removed/u);
  assert.match(output, /Registry Messaging tutorial gate: PASS/u);
});

test('a session that stops before it is ready fails the replay', async () => {
  const { code, output } = await replayStandIn({ ready: false });
  assert.notEqual(code, 0, output);
  assert.match(output, /the session stopped before it reported ready/u);
  assert.match(output, /the session could not start/u);
});

// A session that no longer says it removed its containers is exactly the
// regression a successful exit hides.
test('a session that stops without removing its containers fails the replay', async () => {
  const { code, output } = await replayStandIn({ stopReport: false });
  assert.notEqual(code, 0, output);
  assert.match(output, /never showed "containers are removed"/u);
});

test('the gate sets none of the development port overrides', async () => {
  const source = await readFile(gate, 'utf8');
  for (const name of ['MESSAGINGCTL_DEV_PORT', 'MESSAGINGCTL_DEV_METRICS_PORT']) {
    assert.doesNotMatch(source, new RegExp(`^[^#\\n]*${name}=`, 'mu'), `${name} must stay unset`);
    assert.doesNotMatch(source, new RegExp(`export ${name}`, 'u'), `${name} must stay unset`);
  }
});

// ---------------------------------------------------------------------------
// Page coverage
// ---------------------------------------------------------------------------

// Build a docs root the gate will accept: the registered page is the real one,
// with an optional edit.
async function docsFixtureRoot(edit = (page) => page) {
  const source = await readFile(gate, 'utf8');
  const sections = extractBashArray(source, 'MESSAGING_DOC_SECTIONS');
  const root = await mkdtemp(join(tmpdir(), 'messaging-tutorial-coverage-test-'));
  for (const section of sections) {
    await mkdir(join(root, section), { recursive: true });
  }
  const page = await readFile(firstMessaging, 'utf8');
  await writeFile(join(root, 'tutorials/first-messaging.mdx'), edit(page));
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

// The session line runs in the background. A second command under the session
// heading would run ahead of it in the foreground or not at all, so the gate
// refuses the shape rather than guessing.
test('a session heading holding a second fence fails the gate', async () => {
  const root = await docsFixtureRoot((page) =>
    page.replace('\n## Get a token\n', '\n```sh\ndocker ps\n```\n\n## Get a token\n'),
  );
  try {
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, output);
    assert.match(output, /holds more than one sh fence/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a session fence holding a second command line fails the gate', async () => {
  const root = await docsFixtureRoot((page) =>
    page.replace(
      '```sh\nmessagingctl dev tutorial-work/notices\n```',
      '```sh\nmessagingctl dev tutorial-work/notices\nmessagingctl dev token case-system tutorial-work/notices\n```',
    ),
  );
  try {
    const { code, output } = await runGate({ MESSAGING_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, output);
    assert.match(output, /holds 2 command lines/u);
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
