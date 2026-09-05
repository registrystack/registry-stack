import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
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
  const match = source.match(new RegExp(`\\n${name}=\\(([\\s\\S]*?)\\n\\)`, 'u'));
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
// install one-liner reaches the network, the clone fetches the checkout this
// gate stages instead, and the token recovery block is documented for a reader
// who comes back after a pause. The gate says so rather than pinning them.
test('the gate names the sh fences it did not execute', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /not executed: fence \d+ under "Install Base Registry Engine"/u);
  assert.match(output, /not executed: fence \d+ under "Get the quickstart files"/u);
  assert.match(output, /not executed: fence \d+ under "Troubleshooting"/u);
});

// The journey has to start the launcher the page leaves running in the first
// terminal and stop it where the page says to press Ctrl+C. A replay that
// leaked the launcher would hold a database container after the gate exits.
test('the registered journey starts and stops the launcher', async () => {
  const source = await readFile(gate, 'utf8');
  const branch = source.match(/\n\ttutorials\/first-breg\)[\s\S]*?\n\t\t;;/u)?.[0];
  assert.ok(branch, 'the first Base Registry Engine replay spec must exist');
  assert.match(branch, /background:Start the registry/u);
  assert.match(branch, /wait-registry:/u);
  assert.match(branch, /stop-background/u);
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

// A heading holding more than one sh fence cannot answer a step that runs
// exactly one command, so the gate says which suffix is missing.
test('a one-fence step under a multi-fence heading names the missing occurrence', async () => {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-occurrence-test-'));
  try {
    await writeFile(join(root, 'index.tsv'), '01\t1\tStart the registry\n02\t2\tStart the registry\n');
    const harness = join(root, 'resolve.sh');
    await writeFile(
      harness,
      [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        await liftFunction(source, 'resolve_fences'),
        await liftFunction(source, 'resolve_one_fence'),
        'resolve_one_fence tutorial "Start the registry" "$1" background',
        '',
      ].join('\n'),
    );
    const { code, output } = await runShell(`bash ${harness} ${root}`);
    assert.notEqual(code, 0, 'an ambiguous one-fence step must fail');
    assert.match(output, /names 2/u);
    assert.match(output, /\|<occurrence>/u);
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

// The replay begins where the reader begins: in the checkout the page tells
// them to clone. The gate stages that checkout instead of cloning it, and the
// launcher the journey starts resolves its own repository root and the Mint
// key helper relative to it, so both have to be there and both have to be
// writable.
test('the staged reader checkout carries what the launcher resolves', async () => {
  const source = await readFile(gate, 'utf8');
  const root = await mkdtemp(join(tmpdir(), 'breg-stage-test-'));
  try {
    const readerDir = join(root, 'breg-tutorial');
    const harness = join(root, 'stage.sh');
    await writeFile(
      harness,
      [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        `REPO_ROOT=${resolve(scriptDir, '../../..')}`,
        await liftFunction(source, 'stage_reader_checkout'),
        `stage_reader_checkout '${readerDir}'`,
        '',
      ].join('\n'),
    );
    const { code, output } = await runShell(`bash ${harness}`);
    assert.equal(code, 0, output);
    for (const path of [
      'products/breg/quickstart/run.sh',
      'products/breg/quickstart/support/quickstart.py',
      'crates/registry-mint/demo/support/key_material.py',
    ]) {
      const probe = await runShell(`test -w '${join(readerDir, path)}'`);
      assert.equal(probe.code, 0, `${path} must be staged and writable`);
    }
    // The launcher refuses a run directory it did not create itself.
    const stale = await runShell(`test -e '${join(readerDir, 'products/breg/quickstart/.run')}'`);
    assert.notEqual(stale.code, 0, 'a stale run directory must not be staged');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
