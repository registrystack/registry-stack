import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const gate = resolve(scriptDir, 'check-evidence-tutorials.sh');
const fenceHelper = resolve(scriptDir, 'evidence-tutorial-fence.sh');
const docsRoot = resolve(scriptDir, '../src/content/docs/tutorials');
const authoringTutorial = 'author-an-acceptance-definition.mdx';

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

// Copy the registered current tutorials into a scratch docs root so a test can tamper
// with one without touching the tree.
async function scratchDocsRoot() {
  const root = await mkdtemp(join(tmpdir(), 'evidence-tutorial-test-'));
  await cp(docsRoot, root, { recursive: true });
  return root;
}

test('the dry-run gate passes against every registered tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /author-an-acceptance-definition: 13 sh fences/u);
});

test('removing a documented command block fails the drift check', async () => {
  const root = await scratchDocsRoot();
  try {
    const target = join(root, authoringTutorial);
    const source = await readFile(target, 'utf8');
    const tampered = source.replace(
      'evidencectl fixtures run --project .',
      'evidencectl fixtures run',
    );
    assert.notEqual(tampered, source, 'the tampering target must exist');
    await writeFile(target, tampered);
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a missing required literal must fail the gate');
    assert.match(output, /required literal missing/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a relative toolset binary path is refused before anything runs', async () => {
  // The journey runs from its own directory and reaches the binaries through
  // symlinks, so a relative path would resolve against the wrong directory and
  // surface much later as "command not found".
  const { code, output } = await runGate(
    { EVIDENCE_BIN: 'bin/evidence', EVIDENCECTL_BIN: 'bin/evidencectl', MINT_BIN: 'bin/mint' },
    [],
  );
  assert.notEqual(code, 0, 'a relative binary path must fail the gate');
  assert.match(output, /toolset binary path must be absolute/u);
});

test('changing the fence count fails the drift check', async () => {
  const root = await scratchDocsRoot();
  try {
    const target = join(root, authoringTutorial);
    const source = await readFile(target, 'utf8');
    await writeFile(target, `${source}\n\`\`\`sh\necho extra\n\`\`\`\n`);
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'an added fence must fail the count check');
    assert.match(output, /sh fences found, expected/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a registered tutorial that is not on disk fails by name', async () => {
  const root = await mkdtemp(join(tmpdir(), 'evidence-tutorial-test-'));
  try {
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_DOCS_ROOT: root });
    assert.notEqual(code, 0, 'a missing tutorial must fail the gate');
    assert.match(output, /author-an-acceptance-definition/u);
    assert.match(output, /not found/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('--only refuses a slug that is not registered', async () => {
  const { code, output } = await runGate({}, ['--dry-run', '--only', 'no-such-tutorial']);
  assert.notEqual(code, 0, 'an unregistered slug must fail the gate');
  assert.match(output, /not a registered Evidence tutorial/u);
});

test('--only narrows the run to one registered tutorial', async () => {
  const { code, output } = await runGate({}, [
    '--dry-run',
    '--only',
    'author-an-acceptance-definition',
  ]);
  assert.equal(code, 0, output);
  assert.match(output, /Checked 1 tutorial\./u);
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
    .filter(([, line]) => /\b(?:node|npm|npx|python3?|ruby|perl)\b/u.test(line));
  assert.deepEqual(offenders, [], 'the gate must not reach for an interpreter');
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
