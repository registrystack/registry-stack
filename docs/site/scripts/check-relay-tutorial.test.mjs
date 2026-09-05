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
const gatePath = fileURLToPath(new URL('check-relay-tutorial.sh', import.meta.url));
const pagePath = fileURLToPath(
  new URL(
    '../src/content/docs/tutorials/publish-governed-sqlite-registry.mdx',
    import.meta.url,
  ),
);

async function dryRun(env = {}) {
  return execFileAsync('bash', ['scripts/check-relay-tutorial.sh', '--dry-run'], {
    cwd: siteRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('Relay tutorial dry-run resolves the reader journey it found', async () => {
  const { stdout } = await dryRun();

  assert.match(stdout, /Relay tutorial: resolved \d+ fences/u);
  assert.match(stdout, /Relay tutorial reader gate: dry run only/u);
});

test('a section renamed out from under a fence address fails by name', async () => {
  const page = await readFile(pagePath, 'utf8');
  const heading = '## Write the contract';
  assert.ok(page.includes(heading), 'fixture assumption: the page still carries this heading');

  const dir = await mkdtemp(join(tmpdir(), 'relay-tutorial-'));
  const edited = join(dir, 'page.mdx');
  await writeFile(edited, page.replace(heading, '## Author the contract'));

  await assert.rejects(
    () => dryRun({ RELAY_TUTORIAL_PAGE: edited }),
    (error) => {
      assert.match(error.stderr, /missing yaml fence 1 under "Write the contract"/u);
      return true;
    },
  );
});

test("the gate replays the page's own fences rather than hand-duplicated commands", async () => {
  const source = await readFile(gatePath, 'utf8');

  // Every relayctl/relay invocation this gate runs comes from write-fence
  // against the live page. A hand-typed command here would keep passing
  // after the page changed underneath it, which is the exact failure mode
  // issue #788 reported.
  assert.doesNotMatch(source, /^[ \t]*relayctl [a-z]/mu);
  assert.doesNotMatch(source, /^[ \t]*relay serve/mu);
  assert.match(source, /wf "Write the contract" yaml/u);
  assert.match(source, /wf "Serve it" sh 1 serve\.sh/u);
});
