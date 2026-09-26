import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
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

test('the harness sets no shell variable a page could use or clobber', async () => {
  const body =
    '## Work\n\n' +
    fence('sh', 'echo "harness:${OUT-}"\nOUT=dist\nstatus=kept') +
    fence('sh test-exit="3"', 'bash -c "exit 3"') +
    fence('sh', 'echo "$OUT $status"') +
    fence('text test-expect', 'dist kept');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
    assert.match(output, /^harness:$/mu);
    assert.match(output, /tutorial PASS/u);
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
    await writeFile(second, '---\ntitle: s\n---\n\n## Second\n\n' + fence('sh', 'ls\necho "shared=${shared:-unset}"') + fence('text test-expect', 'work\nshared=unset') + fence('text test-excerpt', 'shared=unset'));
    const { code, output } = await run([page, second]);
    assert.equal(code, 0, output);
    assert.match(output, /==> page\.mdx line 7 \(First\)/u);
    assert.match(output, /expect second\.mdx line 12: ok/u);
    assert.match(output, /excerpt second\.mdx line 17: ok/u);
    const plan = await run(['--dry-run', page, second]);
    assert.match(plan.output, /excerpt second\.mdx line 17: checks line 7/u);
  });
});

test('a file excerpt is checked against the file as it stood at that point of the journey', async () => {
  const body =
    '## Write\n\n' +
    fence('sh', "printf 'a: 1\\n  b: 2\\n' >conf.yaml") +
    fence('yaml test-excerpt="conf.yaml"', 'b: 2') +
    fence('sh', "printf 'a: 1\\n  b: 3\\n' >conf.yaml\nprintf 'done\\n{\\n  \"b\": 3,\\n  \"c\": 4\\n}\\n'") +
    fence('json test-excerpt', '{"b": 3}');
  await withPage(body, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
    assert.match(output, /excerpt line 11: ok/u);
    assert.match(output, /excerpt line 20: ok/u);
    const plan = await run(['--dry-run', page]);
    assert.match(plan.output, /excerpt line 11: conf\.yaml/u);
    assert.match(plan.output, /excerpt line 20: checks line 15/u);
  });
});

test('an excerpt that is not there fails after the journey, and a missing file stops it', async () => {
  const absent = '## Read\n\n' + fence('sh', "echo '{\"b\": 3}'") + fence('json test-excerpt', '{"b": 4}');
  await withPage(absent, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /excerpt line 11: the output of the sh fence at line 7 does not contain it/u);
    assert.match(output, /closest: at \$\.b: expected 4, got 3/u);
  });
  const missing = '## Read\n\n' + fence('yaml test-excerpt="nowhere.yaml"', 'b: 2') + fence('sh', 'echo never');
  await withPage(missing, async ({ page }) => {
    const { code, output } = await run([page]);
    assert.equal(code, 1, output);
    assert.match(output, /the excerpt at line 7 \(Read\) failed/u);
    assert.match(output, /nowhere\.yaml/u);
    assert.doesNotMatch(output, /^never$/mu);
  });
});

async function withGateDocs(pages, fn) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-runner-gate.')));
  try {
    for (const [slug, text] of Object.entries(pages)) {
      await mkdir(dirname(join(dir, 'docs', slug)), { recursive: true });
      await writeFile(join(dir, 'docs', `${slug}.mdx`), `---\ntitle: t\n${text}`);
    }
    for (const name of ['breg', 'bregctl']) {
      await writeFile(join(dir, name), `#!/bin/sh\nprintf '%s %s\\n' ${name} "$*"\n`);
      await chmod(join(dir, name), 0o755);
    }
    const env = { TUTORIAL_DOCS_ROOT: join(dir, 'docs'), BREG_BIN: join(dir, 'breg'), BREGCTL_BIN: join(dir, 'bregctl') };
    return await fn(env);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const GATE_PAGES = {
  'tutorials/first': 'tutorial_test:\n  toolset: breg\n---\n\n## One\n\n```sh\nbregctl init work\nmkdir work\n```\n',
  'tutorials/second':
    'tutorial_test:\n  toolset: breg\n  after: tutorials/first\n---\n\n## Two\n\n```sh\nls\nbregctl check work\n```\n\n```text test-expect\nwork\nbregctl check work\n```\n',
  'tutorials/later': 'tutorial_test:\n  toolset: breg\n  skip: needs a production database\n---\n\n```sh\nbregctl deploy\n```\n',
};

test('a gate replays every declared journey and names the skipped pages', async () => {
  await withGateDocs(GATE_PAGES, async (env) => {
    const plan = await run(['--gate', 'breg', '--dry-run'], env);
    assert.equal(plan.code, 0, plan.output);
    assert.match(plan.output, /skip  page tutorials\/later: needs a production database/u);
    assert.match(plan.output, /journey tutorials\/first -> tutorials\/second/u);
    assert.match(plan.output, /run {3}first\.mdx line 9 \(One\): bregctl init work/u);
    const { code, output } = await run(['--gate', 'breg'], env);
    assert.equal(code, 0, output);
    assert.match(output, /expect second\.mdx line 15: ok/u);
    assert.match(output, /gate PASS: 1 journey replayed, 1 page skipped/u);
  });
});

test('a gate with a coverage gap runs nothing and names the page', async () => {
  const pages = { ...GATE_PAGES, 'start/new': '---\n\n```sh\nbreg --version\n```\n' };
  await withGateDocs(pages, async (env) => {
    const { code, output } = await run(['--gate', 'breg'], env);
    assert.equal(code, 2, output);
    assert.match(output, /start\/new\.mdx runs breg commands but declares no tutorial_test/u);
    assert.doesNotMatch(output, /==>/u);
  });
});

test('a gate needs a toolset that names its commands, and no pages beside it', async () => {
  assert.match((await run(['--gate', 'none'])).output, /toolset none has no commands to gate/u);
  assert.match((await run(['--gate', 'breg', 'page.mdx'])).output, /--gate takes no pages/u);
});

test('a journey whose page asks for the checkout starts at the root of a copy of it', async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-runner-checkout.')));
  try {
    const page = join(dir, 'page.mdx');
    await writeFile(
      page,
      '---\ntitle: t\ntutorial_test:\n  toolset: none\n  checkout: true\n---\n\n' +
        fence('sh', 'test -f docs/site/scripts/run-tutorial.mjs\ntest ! -e .git\nprintf copied') +
        fence('text test-expect', 'copied'),
    );
    const plan = await run(['--dry-run', page]);
    assert.match(plan.output, /^start in a copy of the checkout$/mu);
    const { code, output } = await run([page]);
    assert.equal(code, 0, output);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an interrupt stops the whole journey and shows what the running fence printed', async () => {
  const body = '## Wait\n\n' + fence('sh', 'echo started\nsleep 30\necho never');
  await withPage(body, async ({ page }) => {
    const child = spawn(process.execPath, [runner, page], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const seen = new Promise((resolvePromise) => {
      child.stdout.on('data', (chunk) => {
        output += chunk;
        if (output.includes('==>')) resolvePromise();
      });
    });
    child.stderr.on('data', (chunk) => {
      output += chunk;
    });
    const closed = new Promise((resolvePromise) => child.on('close', resolvePromise));
    await seen;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 300));
    const sent = Date.now();
    child.kill('SIGINT');
    const code = await closed;
    assert.equal(code, 130, output);
    assert.ok(Date.now() - sent < 10000, 'the fence must be stopped, not waited for');
    assert.match(output, /tutorial interrupted during the sh fence at line 7 \(Wait\)/u);
    assert.match(output, /^started$/mu);
    assert.doesNotMatch(output, /^never$/mu);
  });
});

test('a fence that exits its shell stops the journey, on any page', async () => {
  await withPage('## First\n\n' + fence('sh', 'echo one\nexit 0') + fence('sh', 'echo never'), async ({ dir, page }) => {
    const second = join(dir, 'second.mdx');
    await writeFile(second, '---\ntitle: s\n---\n\n## Second\n\n' + fence('sh', 'echo second'));
    const { code, output } = await run([page, second]);
    assert.equal(code, 1, output);
    assert.match(output, /the sh fence at page\.mdx line 7 \(First\) ended the shell early/u);
    assert.doesNotMatch(output, /^(never|second)$/mu);
  });
});

test('a page the shell cannot parse is blamed, not the fence before it', async () => {
  await withPage('## First\n\n' + fence('sh', 'echo one'), async ({ dir, page }) => {
    const second = join(dir, 'second.mdx');
    await writeFile(second, '---\ntitle: s\n---\n\n## Second\n\n' + fence('sh', "echo 'unclosed"));
    const { code, output } = await run([page, second]);
    assert.equal(code, 1, output);
    assert.match(output, /second\.mdx failed with exit status 2 before its first block ran/u);
    assert.doesNotMatch(output, /the sh fence at page\.mdx/u);
  });
});

test('the work directory is removed after a journey, even where it made a directory read-only', async () => {
  const body = '## Lock\n\n' + fence('sh', 'mkdir -p locked/inner\ntouch locked/inner/file\nchmod 500 locked/inner\nchmod 000 locked');
  await withPage(body, async ({ dir, page }) => {
    const temp = join(dir, 'tmp');
    await mkdir(temp);
    const { code, output } = await run([page], { TMPDIR: temp });
    assert.equal(code, 0, output);
    assert.deepEqual(await readdir(temp), []);
  });
});

test('a session that cannot be stopped keeps the work directory and fails the journey', async () => {
  const body = '## Start\n\n' + fence('sh', 'mkdir -p project/.breg/dev\necho {} >project/.breg/dev/state.json');
  await withPage(body, async ({ dir, page }) => {
    const temp = join(dir, 'tmp');
    await mkdir(temp);
    await writeFile(join(dir, 'breg'), '#!/bin/sh\n');
    await writeFile(join(dir, 'bregctl'), '#!/bin/sh\necho "stop refused" >&2\nexit 1\n');
    await chmod(join(dir, 'breg'), 0o755);
    await chmod(join(dir, 'bregctl'), 0o755);
    const { code, output } = await run(['--toolset', 'breg', page], {
      TMPDIR: temp,
      BREG_BIN: join(dir, 'breg'),
      BREGCTL_BIN: join(dir, 'bregctl'),
    });
    assert.equal(code, 1, output);
    assert.match(output, /tutorial PASS/u);
    assert.match(output, /stop refused/u);
    assert.match(output, /keeping \/\S+: stop the sessions it holds, then remove it/u);
    assert.equal((await readdir(temp)).length, 1);
  });
});

test('a gate of many journeys replays them all without warnings', async () => {
  const pages = {};
  for (let n = 0; n < 12; n += 1) pages[`tutorials/page-${n}`] = 'tutorial_test:\n  toolset: breg\n---\n\n```sh\nbregctl check\n```\n';
  await withGateDocs(pages, async (env) => {
    const { code, output } = await run(['--gate', 'breg'], env);
    assert.equal(code, 0, output);
    assert.match(output, /gate PASS: 12 journeys replayed/u);
    assert.doesNotMatch(output, /Warning/u);
  });
});

test('a gate stops at the first toolset error instead of preparing it for every journey', async () => {
  const pages = {
    'tutorials/one': 'tutorial_test:\n  toolset: breg\n---\n\n```sh\nbregctl check\n```\n',
    'tutorials/two': 'tutorial_test:\n  toolset: breg\n---\n\n```sh\nbregctl check\n```\n',
  };
  await withGateDocs(pages, async (env) => {
    const { code, output } = await run(['--gate', 'breg'], { ...env, BREGCTL_BIN: '' });
    assert.equal(code, 2, output);
    assert.equal(output.match(/set both BREG_BIN and BREGCTL_BIN/gu)?.length, 1, output);
    assert.doesNotMatch(output, /journey tutorials\/two/u);
    assert.doesNotMatch(output, /gate FAIL/u);
  });
});

test('a gate dry run builds nothing and starts nothing', async () => {
  await withGateDocs(GATE_PAGES, async (env) => {
    const bin = join(dirname(env.BREG_BIN), 'fake-bin');
    await mkdir(bin);
    for (const name of ['cargo', 'docker']) {
      await writeFile(join(bin, name), `#!/bin/sh\necho ran >>'${join(bin, 'calls')}'\n`);
      await chmod(join(bin, name), 0o755);
    }
    const { code, output } = await run(['--gate', 'breg', '--dry-run'], { ...env, BREG_BIN: '', BREGCTL_BIN: '', PATH: `${bin}:${process.env.PATH}` });
    assert.equal(code, 0, output);
    assert.equal(existsSync(join(bin, 'calls')), false, output);
  });
});
