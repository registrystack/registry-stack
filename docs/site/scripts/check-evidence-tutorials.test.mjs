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
const docsRoot = resolve(scriptDir, '../src/content/docs/tutorials');
const firstTutorial = 'first-evidence-assertion.mdx';

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

// Copy the published tutorials into a scratch docs root so a test can tamper
// with one without touching the tree.
async function scratchDocsRoot() {
  const root = await mkdtemp(join(tmpdir(), 'evidence-tutorial-test-'));
  await cp(docsRoot, root, { recursive: true });
  return root;
}

test('the dry-run gate passes against every registered tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /first-evidence-assertion: 8 sh fences/u);
});

test('removing a documented command block fails the drift check', async () => {
  const root = await scratchDocsRoot();
  try {
    const target = join(root, firstTutorial);
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
    { EVIDENCE_BIN: 'bin/evidence', EVIDENCECTL_BIN: 'bin/evidencectl' },
    [],
  );
  assert.notEqual(code, 0, 'a relative binary path must fail the gate');
  assert.match(output, /toolset binary path must be absolute/u);
});

test('changing the fence count fails the drift check', async () => {
  const root = await scratchDocsRoot();
  try {
    const target = join(root, firstTutorial);
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
    assert.match(output, /first-evidence-assertion/u);
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
    'first-evidence-assertion',
  ]);
  assert.equal(code, 0, output);
  assert.match(output, /Checked 1 tutorial\./u);
});
