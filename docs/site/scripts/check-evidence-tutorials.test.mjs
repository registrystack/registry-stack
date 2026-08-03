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
const tutorial = resolve(
  scriptDir,
  '../src/content/docs/tutorials/first-evidence-assertion.mdx',
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

test('the dry-run gate passes against the published tutorial', async () => {
  const { code, output } = await runGate();
  assert.equal(code, 0, output);
  assert.match(output, /Extracted 8 sh fences/u);
});

test('removing a documented command block fails the drift check', async () => {
  const workDir = await mkdtemp(join(tmpdir(), 'evidence-tutorial-test-'));
  try {
    const source = await readFile(tutorial, 'utf8');
    const tampered = source.replace(
      'evidencectl fixtures run --project .',
      'evidencectl fixtures run',
    );
    assert.notEqual(tampered, source, 'the tampering target must exist');
    const copy = join(workDir, 'tampered.mdx');
    await writeFile(copy, tampered);
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_FILE: copy });
    assert.notEqual(code, 0, 'a missing required literal must fail the gate');
    assert.match(output, /required literal missing/u);
  } finally {
    await rm(workDir, { recursive: true, force: true });
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
  const workDir = await mkdtemp(join(tmpdir(), 'evidence-tutorial-test-'));
  try {
    const source = await readFile(tutorial, 'utf8');
    const copy = join(workDir, 'extra-fence.mdx');
    await writeFile(copy, `${source}\n\`\`\`sh\necho extra\n\`\`\`\n`);
    const { code, output } = await runGate({ EVIDENCE_TUTORIAL_FILE: copy });
    assert.notEqual(code, 0, 'an added fence must fail the count check');
    assert.match(output, /sh fences found, expected/u);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});
