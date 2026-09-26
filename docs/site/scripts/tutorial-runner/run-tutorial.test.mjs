import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const runner = resolve(dirname(fileURLToPath(import.meta.url)), '../run-tutorial.mjs');

async function withPage(body, fn) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-runner-test.')));
  try {
    const page = join(dir, 'page.mdx');
    await writeFile(page, `---\ntitle: t\n---\n\n${body}`);
    return await fn({ dir, page });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function run(args, env = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [runner, ...args], {
      env: { ...process.env, ...env },
    });
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { code: error.code ?? 1, output: `${error.stdout}${error.stderr}` };
  }
}

const fence = (meta, code) => `\`\`\`${meta}\n${code}\n\`\`\`\n\n`;

test('a journey runs in one shell from an empty directory, and its expectations hold', async () => {
  const body =
    '## Install\n\n' +
    fence('sh test-skip="reaches the network"', 'exit 7') +
    '## Work\n\n' +
    fence('sh', 'mkdir work\ncd work\ngreeting=hello') +
    fence('sh', 'printf \'%s\\n\' "$greeting" >said.txt\ncat said.txt\nls -A ..') +
    fence('text test-expect', 'hello\nwork');
  await withPage(body, async ({ dir, page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
    assert.match(output, /skip {2}line 7 \(Install\): reaches the network/u);
    assert.match(output, /expect line 25: ok/u);
    assert.match(output, /tutorial PASS/u);
    assert.equal(existsSync(join(dir, 'work')), false, 'the journey must not run beside the page');
  });
});

test('a failing command stops the journey and names its fence', async () => {
  const body = '## Fail\n\n' + fence('sh', 'echo before\nfalse\necho after') + fence('sh', 'echo never');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /^before$/mu);
    assert.doesNotMatch(output, /^(after|never)$/mu);
    assert.match(output, /the sh fence at line 7 \(Fail\) failed/u);
    assert.match(output, /tutorial FAIL/u);
  });
});

test('an output that no longer matches fails after the journey completes', async () => {
  const body = '## Read\n\n' + fence('sh', "echo 'HTTP 200'") + fence('text test-expect', 'HTTP 412');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /expect line 11: output of the sh fence at line 7 does not match/u);
    assert.match(output, /expected:\n {2}HTTP 412\nactual:\n {2}HTTP 200/u);
  });
});

test('a dry run reports the plan and executes nothing', async () => {
  const body = '## A\n\n' + fence('sh', 'exit 1') + fence('text test-expect', 'x');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run(['--dry-run', page]);
    assert.equal(code, 0, output);
    assert.match(output, /run {3}line 7 \(A\): exit 1/u);
    assert.match(output, /expect line 11: checks line 7/u);
  });
});

test('an annotation error fails before anything runs', async () => {
  const body = '## A\n\n' + fence('sh test-expcet', 'echo x');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run(['--dry-run', page]);
    assert.equal(code, 2, output);
    assert.match(output, /line 7: unknown annotation test-expcet/u);
  });
});

test('the breg toolset serves the given binaries and stops every dev session, even after a failure', async () => {
  const body =
    '## Start\n\n' +
    fence('sh', 'breg --version\nbregctl dev work/project\nmkdir -p work/project/.breg/dev\necho {} >work/project/.breg/dev/state.json') +
    fence('sh', 'false');
  await withPage(body, async ({ dir, page }) => {
    const calls = join(dir, 'calls.log');
    for (const name of ['breg', 'bregctl']) {
      await writeFile(join(dir, name), `#!/bin/sh\nprintf '%s %s\\n' ${name} "$*" >>'${calls}'\n`);
      await chmod(join(dir, name), 0o755);
    }
    const { code, output } = await run(['--toolset', 'breg', page], {
      BREG_BIN: join(dir, 'breg'),
      BREGCTL_BIN: join(dir, 'bregctl'),
    });
    assert.equal(code, 1, output);
    const log = await readFile(calls, 'utf8');
    assert.match(log, /^breg --version$/mu);
    assert.match(log, /^bregctl dev work\/project$/mu);
    assert.match(log, /^bregctl dev stop \/\S+\/work\/project --remove$/mu);
  });
});

test('the breg toolset refuses a relative binary path', async () => {
  await withPage('## A\n\n' + fence('sh', 'true'), async ({ page }) => {
    const { code, output } = await run(['--toolset', 'breg', page], {
      BREG_BIN: 'breg',
      BREGCTL_BIN: 'bregctl',
    });
    assert.equal(code, 2, output);
    assert.match(output, /BREG_BIN must be an absolute path: breg/u);
  });
});

test('a test-edit block changes the file it names, relative to where the reader stands', async () => {
  const body =
    '## Setup\n\n' +
    fence('sh', "mkdir work\ncd work\nprintf 'a: 1\\n  b: 2\\n' >conf.yaml") +
    '## Edit\n\n' +
    fence('diff title="conf.yaml" test-edit', '-b: 2\n+b: 3') +
    fence('sh', 'cat conf.yaml') +
    fence('text test-expect', 'a: 1\n  b: 3');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
    assert.match(output, /edited conf\.yaml/u);
    assert.match(output, /tutorial PASS/u);
  });
});

test('an edit that cannot be applied stops the journey and names its block', async () => {
  const body = '## Edit\n\n' + fence('sh', 'echo "a: 1" >conf.yaml') + fence('diff title="conf.yaml" test-edit', '-b: 2\n+b: 3');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /the edit at line 11 \(Edit\) failed/u);
    assert.match(output, /conf\.yaml: its lines match no place in the file/u);
  });
});

test('test-exit expects a refusal, and a command that succeeds instead fails the journey', async () => {
  const refused = '## Check\n\n' + fence('sh test-exit="3"', "echo 'check refused.'\nsh -c 'exit 3'") + fence('text test-expect', 'check refused.');
  await withPage(refused, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
    assert.match(output, /tutorial PASS/u);
  });
  const accepted = '## Check\n\n' + fence('sh test-exit="3"', 'echo accepted');
  await withPage(accepted, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /the sh fence at line 7 \(Check\) exited 0; the page expects 3/u);
  });
});

test('pages given together replay in one reader directory, each in a fresh shell', async () => {
  await withPage('## First\n\n' + fence('sh', 'mkdir work\nshared=yes\ncd work'), async ({ dir, page }) => {
    const second = join(dir, 'second.mdx');
    await writeFile(second, '---\ntitle: s\n---\n\n## Second\n\n' + fence('sh', 'ls\necho "shared=${shared:-unset}"') + fence('text test-expect', 'work\nshared=unset'));
    const { code, output } = await run([page, second]);
    assert.equal(code, 0, output);
    assert.match(output, /==> page\.mdx line 7 \(First\)/u);
    assert.match(output, /expect second\.mdx line 12: ok/u);
  });
});
