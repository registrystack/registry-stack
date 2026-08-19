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
const gatePath = fileURLToPath(new URL('check-discovery-tutorial.sh', import.meta.url));
const pagePath = fileURLToPath(
  new URL('../src/content/docs/tutorials/publish-and-consume-discovery-index.mdx', import.meta.url),
);

async function dryRun(env = {}) {
  return execFileAsync('bash', ['scripts/check-discovery-tutorial.sh', '--dry-run'], {
    cwd: siteRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('Discovery tutorial dry-run reports the reader journey it found', async () => {
  const { stdout } = await dryRun();

  // Registration only. Pinning the number here would rebuild the tripwire this
  // gate deliberately dropped, one file further out.
  assert.match(stdout, /Discovery tutorial dry-run: \d+ shell fences/u);
  assert.match(stdout, /Discovery tutorial reader gate: dry run only/u);
});

test('a page that stops documenting the command this gate runs fails by name', async () => {
  const page = await readFile(pagePath, 'utf8');
  const command = 'bash products/discovery/scripts/test-adopter-tutorial.sh';
  assert.ok(page.includes(command), 'fixture assumption: the page documents the runner command');

  const dir = await mkdtemp(join(tmpdir(), 'discovery-tutorial-'));
  const edited = join(dir, 'page.mdx');
  await writeFile(edited, page.replace(command, 'bash products/discovery/scripts/renamed.sh'));

  await assert.rejects(
    () => dryRun({ DISCOVERY_TUTORIAL_PAGE: edited }),
    (error) => {
      assert.match(error.stderr, /the page no longer documents the command this gate runs/u);
      assert.match(error.stderr, /bash products\/discovery\/scripts\/test-adopter-tutorial\.sh/u);
      return true;
    },
  );
});

test('the gate pins neither a fence count nor page strings', async () => {
  const source = await readFile(gatePath, 'utf8');

  // The two mechanisms this gate dropped, and the reason it dropped them: they
  // made the page answerable to the gate instead of to its reader. Keep the
  // transcript assertions below them; do not grow a page-content array back.
  assert.doesNotMatch(source, /expected_shell_fences/u);
  assert.doesNotMatch(source, /required_literals/u);
});
