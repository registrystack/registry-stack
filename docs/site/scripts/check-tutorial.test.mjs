import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const siteRoot = new URL('..', import.meta.url);
const gatePath = fileURLToPath(new URL('check-tutorial.sh', import.meta.url));
const pagePath = fileURLToPath(
  new URL('../src/content/docs/tutorials/first-run-with-solmara-lab.mdx', import.meta.url),
);

async function dryRun(env = {}) {
  return execFileAsync('bash', ['scripts/check-tutorial.sh', '--dry-run'], {
    cwd: siteRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('the dry run reports the commands it extracted instead of pinning how many', async () => {
  const { stdout } = await dryRun();

  // Registration only. The count is reported so a reviewer sees the journey;
  // asserting a specific number here would rebuild the tripwire the gate just
  // dropped, one file further out.
  assert.match(stdout, /extracted \d+ Steps commands from tutorial:/u);
  assert.match(stdout, /extracted \d+ Verify commands from tutorial:/u);
});

test('a section the page no longer carries fails, rather than running nothing', async () => {
  const page = await readFile(pagePath, 'utf8');
  assert.match(page, /^## Verify$/mu, 'fixture assumption: the page carries a Verify section');

  const dir = await mkdtemp(join(tmpdir(), 'solmara-tutorial-'));
  const edited = join(dir, 'page.mdx');
  await writeFile(edited, page.replace(/^## Verify$/mu, '## Check the run'));

  await assert.rejects(
    () => dryRun({ SOLMARA_TUTORIAL_PAGE: edited }),
    (error) => {
      assert.match(error.stderr, /no shell commands under its "Verify" heading/u);
      return true;
    },
  );
});

test('the gate pins no extraction counts', async () => {
  const source = await readFile(gatePath, 'utf8');

  // These two constants made the page answerable to the gate: adding or
  // removing a documented command failed the build until someone bumped a
  // number. The service and artifact expectations below are a different thing
  // and stay: they compare what the page states to what actually runs.
  assert.doesNotMatch(source, /EXPECTED_STEP_COUNT/u);
  assert.doesNotMatch(source, /EXPECTED_VERIFY_COUNT/u);
  assert.match(source, /EXPECTED_RUNNING_TOTAL=\d+/u);
  assert.match(source, /EXPECTED_SERVICES=\(/u);
  assert.match(source, /EXPECTED_DEMO_ARTIFACTS=\d+/u);
});
